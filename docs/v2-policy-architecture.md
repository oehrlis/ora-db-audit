# V2 Audit Policy Architecture

Cross-reference for the `ODB_LOC_*_V2` policy set used as the canonical input for
`ora-db-audit` analysis and reporting.

---

## Policy Overview

<!-- markdownlint-disable MD013 MD060 -->
| Policy name | Actions | Enable scope | CIS |
| --- | --- | --- | --- |
| `ODB_LOC_LOGON_EVENTS_V2` | LOGON, LOGOFF | ALL USERS | 5.2 |
| `ODB_LOC_SYS_PARAM_V2` | ALTER DATABASE/SYSTEM, CREATE PFILE/SPFILE | ALL USERS | 5.4 |
| `ODB_LOC_SECURE_CONFIG_V2` | Critical system privileges | ALL USERS | 5.4 |
| `ODB_LOC_DIRECTORY_V2` | READ/WRITE/EXECUTE DIRECTORY | ALL USERS | 5.4 |
| `ODB_LOC_DATA_PUMP_V2` | DATAPUMP EXPORT/IMPORT | ALL USERS | 5.4 |
| `ODB_LOC_ACC_MGMT_V2` | CREATE/ALTER/DROP USER+ROLE, GRANT, REVOKE, SET ROLE | ALL USERS | 4.1 |
| `ODB_LOC_DDL_ALL_V2` | Explicit DDL action list (schema lifecycle) | ALL USERS | 5.5 |
| `ODB_LOC_CRIT_PKG_V2` | EXECUTE on 19 critical SYS packages (CIS 5.1.3) | ALL USERS | 5.1.3 / 5.3 |
| `ODB_LOC_APP_OFFPATH_V2` | DML: INSERT/UPDATE/DELETE/MERGE (context-filtered) | ALL USERS | 5.5 |
| `ODB_LOC_PRIV_DBA_ALL_V2` | Explicit DDL+DML for DBA role holders | ROLE: C##ODB_ROLE_DBA + BY SYS | 5.5 |
| `ODB_LOC_DEV_ALL_V2` | Explicit DDL+DML for developer accounts | BY user-list | 5.5 |
| `ODB_LOC_ADHOC_ALL_V2` | ACTIONS ALL (not enabled - incident reserve) | Manual | - |
<!-- markdownlint-restore -->

---

## Three-Pillar Architecture

```text
Pillar 1: Always-on baseline (no WHEN clause, ALL USERS)
  - LOGON_EVENTS, SYS_PARAM, SECURE_CONFIG, DIRECTORY, DATA_PUMP, ACC_MGMT, DDL_ALL

Pillar 2: Privileged-scope (BY ROLE + BY SYS)
  - PRIV_DBA_ALL

Pillar 3: Context-conditioned filters (EVALUATE PER SESSION WHEN ...)
  - CRIT_PKG, APP_OFFPATH, DEV_ALL, ADHOC_ALL
```

---

## ACC_MGMT_V2 - Account Management (V2.1 new)

`ODB_LOC_ACC_MGMT_V2` was introduced in V2.1 to isolate account and privilege
management from the general DDL policy:

- **Actions**: `CREATE/ALTER/DROP USER`, `CREATE/ALTER/DROP ROLE`, `GRANT`, `REVOKE`, `SET ROLE`
- **Scope**: ALL USERS (generic, Phase A)
- **CIS mapping**: 4.1 (Restrict Unnecessary Privileges - audit who grants what to whom)
- **Not included**: `PROFILE`, `CHANGE PASSWORD`, `CREATE SCHEMA` (stay in `ODB_LOC_DDL_ALL_V2`)
- `ODB_LOC_DDL_ALL_V2` and `ODB_LOC_PRIV_DBA_ALL_V2` no longer contain GRANT/REVOKE

---

## Context Attributes (`ODB_AUDIT_CTX`)

| Attribute | True when | Used by |
| --- | --- | --- |
| `IS_APP_ACCESS` | Connection from known app server | OFFPATH |
| `IS_KNOWN_CLIENT` | Known DBA workstation / jumphost | OFFPATH, DEV_ALL (NOJUMP variant) |
| `IS_OEM_ACCESS` | OEM monitoring connection | - (prepared, no active policy) |
| `IS_DEV_TOOL` | SQL Developer / Toad client detected | PRIV_DBA, DEV_ALL (NOTOOL variant) |

WHEN clauses use `!= 'TRUE'` with a NULL-safe OR arm - Oracle evaluates the WHEN on first
statement after logon. If the context is NULL (failed logon, trigger did not run),
EVALUATE PER SESSION fires as though the condition were TRUE (fail-secure), so failed
logons are audited by context-conditioned policies.

---

## OFFPATH Scope (V2.1)

`ODB_LOC_APP_OFFPATH_V2` is **DML-only** since V2.1:

- **Actions**: INSERT, UPDATE, DELETE, MERGE
- **DDL is not included**: covered by `ODB_LOC_DDL_ALL_V2` for ALL USERS - no overlap
- **WHEN clause** (evaluated per session, fail-secure):
  - `ISDBA != 'TRUE'` - SYSDBA sessions excluded (captured by PRIV_DBA_ALL_V2 instead)
  - `IS_APP_ACCESS != 'TRUE'` - known app server path excluded
  - `IS_KNOWN_CLIENT != 'TRUE'` - known DBA workstation excluded
  - NULL context triggers the audit (fail-secure)

There is **no DDL double-coverage** in V2.1: DDL_ALL covers schema changes for all
users, OFFPATH covers off-path DML. The policies are complementary, not overlapping.

---

## CRIT_PKG Policy - Object-Level Execute

`ODB_LOC_CRIT_PKG_V2` audits at the **object level** (`OBJECT ACTION`), not as
a standard `EXECUTE` action. Consequently:

- `audit_option_type` = `'OBJECT ACTION'` in `AUDIT_UNIFIED_POLICIES`
- `audit_option` = `'EXECUTE'` or `'EXECUTE ON ...'`
- Standard-action CIS 5.3 checks must include both `STANDARD ACTION` and
  `OBJECT ACTION` EXECUTE coverage (see `sql/17-cis-coverage.sql`)

Covered SYS packages (CIS Benchmark 5.1.3):

```text
DBMS_AW, DBMS_CRYPTO, DBMS_FGA, DBMS_JAVA_TEST, DBMS_JOB,
DBMS_LOGMNR, DBMS_NETWORK_ACL_ADMIN, DBMS_OBFUSCATION_TOOLKIT,
DBMS_REDACT, DBMS_REDEFINITION, DBMS_RLS, DBMS_SCHEDULER,
DBMS_SQL_TRANSLATOR, DBMS_SYS_SQL, DBMS_TSDP_MANAGE, DBMS_TSDP_PROTECT,
DBMS_XMLGEN, DBMS_XMLSTORE, OWA_UTIL
```

---

## Role-Based Audit Target (`C##ODB_ROLE_DBA`)

`ODB_LOC_PRIV_DBA_ALL_V2` uses `BY USERS WITH GRANTED ROLES C##ODB_ROLE_DBA`.
This means:

- The policy fires for any session user who holds `C##ODB_ROLE_DBA` (CDB-wide role)
- `AUDIT_UNIFIED_ENABLED_POLICIES.entity_type` = `'ROLE'`
- The privileged-activity SQL query (`14-privileged-activity.sql`) resolves
  role holders dynamically via `DBA_ROLE_PRIVS` - no static user list needed

---

## Schema Owner Exclusion from DDL_ALL_V2

`odb_policies_enable_aud.sql` may exclude schema owner accounts from DDL_ALL_V2:

```sql
NOAUDIT POLICY odb_loc_ddl_all_v2 BY <schema_owner>;
```

This creates an EXCEPT USER entry in `AUDIT_UNIFIED_ENABLED_POLICIES`
(enabled_option = 'EXCEPT OPTION EXCEPT USER'). Schema owners creating objects
in their own schema as part of normal application lifecycle are excluded to reduce
noise. Their DDL is still captured if they access objects outside their schema.

---

## 26ai-Specific DDL Actions

Oracle Database 26ai introduces additional DDL actions not present in 19c:

- `MLE MODULE` - JavaScript/multilingual engine module
- `MLE ENV` - MLE environment
- `DOMAIN` - SQL Domain
- `PROPERTY GRAPH` - Property Graph objects

The CIS coverage check (`17-cis-coverage.sql`) and the AI analysis prompt
reference these 26ai-specific actions. On a 19c database these actions simply
never appear in the audit trail.

---

## Report Sections Affected by V2

| Report section | V2 impact |
| --- | --- |
| 3 - Policy inventory | Detects ADHOC (ACTIONS ALL), shows BY-USER bindings |
| 6.1 - Privileged users | Role-holder expansion via DBA_ROLE_PRIVS |
| 6.2 - Critical packages | New section: CIS 5.1.3 package execution summary |
| 6.3 - Developer by-user | New section: DEV_ALL BY-USER policy bindings |
| 7 - Off-path signals | V2 OFFPATH cross-reference note; ISDBA exclusion (FP-005) |
| 17 - CIS coverage | CIS 5.3 and 5.5 updated for object-level EXECUTE + role targets |

---

## Source Reference

V2 policy definitions: `ora-db-audit-eng/sql/odb_policies_create_aud.sql`
V2 architecture docs: `ora-db-audit-eng/doc/04_policies.md`
