# False Positive Patterns

<!-- markdownlint-disable MD013 -->

| Field | Value |
|-------|-------|
| Version | 1.0.0 |
| Updated | 2026-05-29 |
| Applies to | `audit_report.py` >= 1.4.0, bundle query `20_fp_role_grantees` |

## Overview

Oracle Unified Auditing has several well-documented engine behaviors that produce
audit trail records even when the intended policy restrictions are not met. Without
awareness of these behaviors, an AI analysis of an audit bundle will flag these
records as genuine security findings - producing false positives that erode trust
in the reporting output.

This document describes:

1. The Oracle engine behaviors that cause false positives
2. The policy patterns that trigger each behavior
3. How `audit_report.py` detects and flags affected findings
4. Recommended policy improvements
5. How to extend the pattern framework with custom rules

The detection framework operates **independently of specific policy names or
customer prefixes**. It works on structural properties of the CSV data (policy
binding type, WHEN condition content, event return codes) and is therefore
applicable to any Oracle 19c or 26ai installation with Unified Auditing in Pure Mode.

---

## Policy Requirements and Assumptions

The following assumptions define the "ideal" policy state. Deviations do not
break the tool but increase false positive volume in AI findings.

| # | Assumption | Affected Pattern |
|---|------------|-----------------|
| A1 | LOGON/LOGOFF auditing is centralized in a single unconditional policy covering ALL USERS. Specialized policies (BY GRANTED ROLE, BY USER, WHEN conditions) focus on post-logon actions. | FP-001, FP-002, FP-003 |
| A2 | The logon trigger that sets a custom application context always sets an explicit non-NULL value for every authenticated session (e.g. 'TRUE' or 'FALSE'), not only for the matching case. | FP-003 |
| A3 | WHEN conditions that discriminate connection type use `NETWORK_PROTOCOL IS NULL` (bequeath) rather than `IP_ADDRESS IS NULL`. | FP-002 |
| A4 | Every audit policy that is created is either explicitly enabled or explicitly dropped. No ghost policies exist in the data dictionary. | FP-004 |

---

## Pattern Catalog

### FP-001: BY GRANTED ROLE - Failed LOGONs Without Role Check

**Oracle behavior:**
Oracle Unified Auditing does not evaluate `BY GRANTED ROLE` membership for
unauthenticated sessions. When a LOGON attempt fails (ORA-01017 wrong password,
ORA-01045 no CREATE SESSION), the session is never established. The role grant
lookup against `DBA_ROLE_PRIVS` is skipped, and the audit record is written
with the attempted username regardless of whether that user holds the role.

**Trigger condition:**
Any policy that combines:

- `BY GRANTED ROLE <role>` binding, AND
- `ACTIONS ALL` (or any action list that includes `LOGON`), AND
- A WHEN condition that evaluates to TRUE for sessions with no application context
  (e.g. `ctx_attr IS NULL` arm, or no WHEN clause at all)

**Effect:**
Every failed LOGON attempt to the database appears in this policy's audit trail,
regardless of the attempted user's role membership. The volume matches the total
failed LOGON count for the instance - not just for role members.

**Detection in audit_report.py (FP-001):**

1. `03_policy_inventory.csv`: find policies with `entity_type = ROLE`
2. `05_policy_user_action.csv`: for each (policy, user) pair, check whether
   ALL events have `return_code != 0`
3. `20_fp_role_grantees.csv` (if present): verify the user is not a confirmed
   direct grantee of the role
4. If all events are failures AND user not confirmed as grantee: emit FP-001 suspect

**Policy fix:**

Option A - Remove LOGON from specialized policy scope (recommended):

```sql
-- The LOGON/LOGOFF audit is handled by a separate unconditional policy.
-- Drop and recreate without LOGON in the action list.
-- Oracle has no EXCEPT syntax; list all required actions explicitly:
DROP AUDIT POLICY <policy_name>;
CREATE AUDIT POLICY <policy_name>
  ACTIONS SELECT, INSERT, UPDATE, DELETE, EXECUTE,
          ALTER SYSTEM, ALTER DATABASE,
          CREATE USER, ALTER USER, DROP USER,
          CREATE ROLE, ALTER ROLE, DROP ROLE,
          GRANT, REVOKE,
          CREATE AUDIT POLICY, DROP AUDIT POLICY, AUDIT, NOAUDIT
  BY GRANTED ROLE <role_name>
  WHEN '<existing_when_condition>'
  EVALUATE PER SESSION;
AUDIT POLICY <policy_name>;
```

Option B - Restrict IS NULL arm to bequeath connections only:

```sql
-- Change WHEN from:
--   ctx_attr != 'TRUE' OR ctx_attr IS NULL
-- To:
--   ctx_attr != 'TRUE'
--   OR (ctx_attr IS NULL AND SYS_CONTEXT('USERENV','NETWORK_PROTOCOL') IS NULL)
-- This preserves coverage for bequeath sessions (DBA on DB host, SYS via OS auth)
-- while excluding failed TCP connections where the context is not set.
DROP AUDIT POLICY <policy_name>;
CREATE AUDIT POLICY <policy_name>
  ACTIONS ALL
  BY GRANTED ROLE <role_name>
  WHEN 'SYS_CONTEXT(''<CTX_NS>'',''<CTX_ATTR>'') != ''TRUE''
       OR (SYS_CONTEXT(''<CTX_NS>'',''<CTX_ATTR>'') IS NULL
           AND SYS_CONTEXT(''USERENV'',''NETWORK_PROTOCOL'') IS NULL)'
  EVALUATE PER SESSION;
AUDIT POLICY <policy_name>;
```

**Verify SQL:**

```sql
SELECT grantee, granted_role, admin_option
FROM   dba_role_privs
WHERE  granted_role = '<role_name>'
ORDER  BY grantee;
```

---

### FP-002: IP_ADDRESS IS NULL - Failed Remote LOGONs Captured as Local

**Oracle behavior:**
`USERENV.IP_ADDRESS` is NULL for ALL failed authentication events, including
remote TCP connections. At authentication failure time, the Oracle session
context is not fully populated: `IP_ADDRESS` is assigned at a later stage of
session initialization that is never reached for ORA-01017/ORA-01045 failures.
A WHEN condition relying on `IP_ADDRESS IS NULL` to identify bequeath/direct
connections therefore also fires for every remote connection that fails to
authenticate.

**Trigger condition:**
Any policy with `WHEN 'SYS_CONTEXT(''USERENV'',''IP_ADDRESS'') IS NULL'`
and `ACTIONS ALL` (or any action list that includes `LOGON`).

**Effect:**
Failed remote LOGONs are captured under a policy designed to detect direct
database access, inflating the direct-access event count and producing misleading
host/user combinations in the security signals section.

**Detection in audit_report.py (FP-002):**

1. `03_policy_inventory.csv`: find policies where `audit_condition` contains
   both `IP_ADDRESS` and `IS NULL` (case-insensitive)
2. `05_policy_user_action.csv`: check for LOGON events with `return_code != 0`
   under those policies
3. If both conditions match: emit FP-002 suspect per (policy, user) pair

**Policy fix:**

```sql
-- Replace IP_ADDRESS IS NULL with NETWORK_PROTOCOL IS NULL.
-- NETWORK_PROTOCOL is set at the listener/SQLNet layer before authentication:
--   bequeath/IPC connection  -> NETWORK_PROTOCOL = NULL
--   TCP connection (any auth result) -> NETWORK_PROTOCOL = 'tcp'
DROP AUDIT POLICY <policy_name>;
CREATE AUDIT POLICY <policy_name>
  ACTIONS ALL
  WHEN 'SYS_CONTEXT(''USERENV'',''NETWORK_PROTOCOL'') IS NULL'
  EVALUATE PER SESSION;
AUDIT POLICY <policy_name>;
```

**Verify NETWORK_PROTOCOL value in your environment:**

```sql
-- Run from a TCP session to confirm value:
SELECT SYS_CONTEXT('USERENV', 'NETWORK_PROTOCOL') AS net_proto,
       SYS_CONTEXT('USERENV', 'IP_ADDRESS')        AS ip_addr
FROM   dual;
-- Expected: net_proto = 'tcp', ip_addr = <client IP>

-- Run from a bequeath session (sqlplus / as sysdba on DB host):
-- Expected: net_proto = NULL, ip_addr = NULL
```

**Verify SQL:**

```sql
SELECT db_username, userhost, return_code, COUNT(*) AS cnt
FROM   unified_audit_trail
WHERE  unified_audit_policies = '<policy_name>'
AND    action_name = 'LOGON'
AND    return_code != 0
GROUP  BY db_username, userhost, return_code
ORDER  BY cnt DESC
FETCH FIRST 20 ROWS ONLY;
```

---

### FP-003: Custom App Context IS NULL - Failed LOGONs Match Defensive Arm

**Oracle behavior:**
Custom application contexts (non-USERENV namespaces set via
`DBMS_SESSION.SET_CONTEXT` in a logon trigger) are never populated for failed
LOGON events. The logon trigger does not fire when authentication fails, so
`SYS_CONTEXT('<custom_ns>', '<attr>')` returns NULL for any failed session.

A common defensive pattern `ctx_attr != 'TRUE' OR ctx_attr IS NULL` is designed
to audit sessions where the context package is not deployed (NULL = unknown state,
audit by default). The side effect is that every failed LOGON matches the IS NULL
arm, producing audit records for users who have nothing to do with the policy's
intended scope.

**Trigger condition:**
Any policy with a WHEN condition that combines:

- A `SYS_CONTEXT` call with a non-`USERENV` namespace (custom app context), AND
- An `IS NULL` branch (e.g. `OR ctx_attr IS NULL`)

**Effect:**
All failed LOGONs appear under this policy. If the policy also has `BY GRANTED ROLE`
or `BY USER` restrictions, those are also bypassed (see FP-001), compounding the
false positive volume.

**Detection in audit_report.py (FP-003):**

1. `03_policy_inventory.csv`: find policies where `audit_condition` contains
   a `SYS_CONTEXT(...)` call with a namespace that is not `USERENV` AND
   contains `IS NULL`
2. `05_policy_user_action.csv`: check for LOGON events with `return_code != 0`
3. If both conditions match: emit FP-003 suspect

**Policy fix:**

Option A - Logon trigger sets explicit value (cleanest):

Modify the logon trigger to always set the attribute to an explicit non-NULL value:

```sql
-- In the logon trigger, for non-matching sessions:
DBMS_SESSION.SET_CONTEXT('<CTX_NS>', '<CTX_ATTR>', 'FALSE');
-- (instead of leaving it unset / NULL)
```

Then remove the `OR IS NULL` arm from the WHEN condition:

```sql
DROP AUDIT POLICY <policy_name>;
CREATE AUDIT POLICY <policy_name>
  ACTIONS ALL
  BY GRANTED ROLE <role_name>
  WHEN 'SYS_CONTEXT(''<CTX_NS>'',''<CTX_ATTR>'') != ''TRUE'''
  EVALUATE PER SESSION;
AUDIT POLICY <policy_name>;
```

Option B - Restrict IS NULL to bequeath only (minimal change):

```sql
DROP AUDIT POLICY <policy_name>;
CREATE AUDIT POLICY <policy_name>
  ACTIONS ALL
  BY GRANTED ROLE <role_name>
  WHEN 'SYS_CONTEXT(''<CTX_NS>'',''<CTX_ATTR>'') != ''TRUE''
       OR (SYS_CONTEXT(''<CTX_NS>'',''<CTX_ATTR>'') IS NULL
           AND SYS_CONTEXT(''USERENV'',''NETWORK_PROTOCOL'') IS NULL)'
  EVALUATE PER SESSION;
AUDIT POLICY <policy_name>;
```

**Verify SQL:**

```sql
SELECT unified_audit_policies, db_username, action_name, return_code, COUNT(*) AS cnt
FROM   unified_audit_trail
WHERE  unified_audit_policies = '<policy_name>'
AND    action_name = 'LOGON'
GROUP  BY unified_audit_policies, db_username, action_name, return_code
ORDER  BY cnt DESC
FETCH FIRST 20 ROWS ONLY;
```

---

### FP-004: Policy Created But Never Enabled

**Oracle behavior:**
`CREATE AUDIT POLICY` registers a policy in `AUDIT_UNIFIED_POLICIES` but does
not activate event collection. A separate `AUDIT POLICY <name>` statement is
required to enable the policy (set SUCCESS/FAILURE flags). A policy that was
created but never enabled generates zero operational audit records.

**Trigger condition:**
`CREATE AUDIT POLICY` was executed (visible in the audit trail via query 16),
but no corresponding `AUDIT POLICY` activation statement was ever run.
`AUDIT_UNIFIED_POLICIES.SUCCESS = 'NO'` and `FAILURE = 'NO'` for this policy.

**Effect:**
This is not a security false positive in the same sense as FP-001 to FP-003.
There are no spurious events in the audit trail. The risk is that:

- The policy represents a planned but missing coverage area (deployment gap)
- An AI analyser may reference the policy in context that implies it is active

**Detection in audit_report.py (FP-004):**

1. `03_policy_inventory.csv`: find custom policies (oracle_supplied=NO) where
   both `success=NO` and `failure=NO` for all rows of this policy
2. `16_policy_ddl.csv`: verify the policy name appears (was created)
3. If both match: emit FP-004 structural gap notice

**Fix:**

```sql
-- Option A: enable the policy
AUDIT POLICY <policy_name>;

-- Option B: remove if intentionally deferred
DROP AUDIT POLICY <policy_name>;
-- Recreate and enable when ready.
```

**Verify SQL:**

```sql
SELECT policy_name, enabled_option, success, failure
FROM   audit_unified_policies
WHERE  policy_name = '<policy_name>';
```

---

## Extending the Pattern Framework

Custom FP patterns can be added via a JSON file passed to `--fp-patterns`:

```bash
audit_report.py BUNDLE_DIR --ai --fp-patterns custom_fp.json
```

The custom file must follow the same schema as `tools/fp_patterns.json`. The
`detection_type` field maps to a detection function in the Python engine:

| `detection_type` | Detects |
|------------------|---------|
| `role_binding_check` | BY GRANTED ROLE + all-failed-LOGON events |
| `when_condition_check` | Specific string in audit_condition + failed LOGONs |
| `context_null_check` | Non-USERENV SYS_CONTEXT IS NULL + failed LOGONs |
| `policy_enabled_check` | Policy in inventory but success=NO and failure=NO |

To add a new detection strategy, add a new `detection_type` value and implement
the corresponding `_detect_<type>(bundle, pattern)` function in `audit_report.py`.

### Minimal custom pattern example

```json
{
  "patterns": [
    {
      "id": "FP-CUST-001",
      "enabled": true,
      "name": "my_custom_pattern",
      "detection_type": "when_condition_check",
      "title": "Custom: HOSTNAME IS NULL catches failed remote LOGONs",
      "oracle_behavior": "SYS_CONTEXT('USERENV','HOST') may be NULL for failed auth.",
      "policy_requirement": "Use a more reliable discriminator.",
      "when_condition_contains": ["HOST", "IS NULL"],
      "detection_logic": "Policies with HOST IS NULL in WHEN condition + failed LOGONs.",
      "verify_sql": "SELECT db_username, return_code, count(*) FROM unified_audit_trail WHERE unified_audit_policies = '{policy_name}' AND action_name = 'LOGON' GROUP BY db_username, return_code;",
      "remediation": "Replace HOST IS NULL with NETWORK_PROTOCOL IS NULL."
    }
  ]
}
```

---

## Reference

- Oracle Documentation: [Unified Auditing](https://docs.oracle.com/en/database/oracle/oracle-database/19/dbseg/introduction-to-auditing.html)
- `tools/fp_patterns.json` - machine-readable pattern definitions
- `docs/ai-analysis-rules.md` - AI rule contract including FP cross-check instructions
- `sql/20-fp-role-grantees.sql` - role cross-reference query (supports FP-001)
