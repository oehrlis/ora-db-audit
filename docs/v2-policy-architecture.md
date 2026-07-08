# V2 Audit Policy Architecture

Cross-reference for the `ODB_LOC_*_V2` policy set used as the canonical input for
`ora-db-audit` analysis and reporting.

---

## Policy Overview

| Policy name | Subject | Scope | CIS |
|---|---|---|---|
| `ODB_LOC_LOGON_EVENTS_V2` | All login/logoff events | ALL USERS | 5.2 |
| `ODB_LOC_SYS_PARAM_V2` | System-parameter changes | SYS, SYSTEM | 5.4 |
| `ODB_LOC_SECURE_CONFIG_V2` | Security-config actions | ALL USERS | 5.4 |
| `ODB_LOC_DIRECTORY_V2` | Directory CREATE/DROP | ALL USERS | 5.4 |
| `ODB_LOC_DATA_PUMP_V2` | Data Pump operations | ALL USERS | 5.4 |
| `ODB_LOC_DDL_ALL_V2` | All DDL (SYS + SYSTEM) | SYS, SYSTEM | 5.5 |
| `ODB_LOC_CRIT_PKG_V2` | 19 critical SYS packages | ALL USERS | 5.1.3 / 5.3 |
| `ODB_LOC_APP_OFFPATH_V2` | Off-path DDL+DML (context) | ALL USERS | 5.5 |
| `ODB_LOC_PRIV_DBA_ALL_V2` | Privileged DBA role | ROLE: C##ODB_ROLE_DBA | 5.5 |
| `ODB_LOC_DEV_ALL_V2` | Developer BY USER | named users | 5.5 |
| `ODB_LOC_ADHOC_ALL_V2` | Ad-hoc tools | ALL USERS | 5.5 |

---

## Three-Pillar Architecture

```text
Pillar 1: Always-on baseline (no WHEN clause, ALL USERS)
  - LOGON_EVENTS, SYS_PARAM, SECURE_CONFIG, DIRECTORY, DATA_PUMP

Pillar 2: Privileged-scope (SYS, SYSTEM, BY ROLE)
  - DDL_ALL, PRIV_DBA_ALL

Pillar 3: Context-conditioned filters (EVALUATE PER SESSION WHEN ...)
  - CRIT_PKG, APP_OFFPATH, DEV_ALL, ADHOC_ALL
```

---

## Context Attributes (`ODB_AUDIT_CTX`)

| Attribute | True when |
|---|---|
| `IS_APP_ACCESS` | Connection comes from known application |
| `IS_KNOWN_CLIENT` | Client tool is approved / whitelisted |
| `IS_OEM_ACCESS` | OEM agent / Grid Control connection |
| `IS_DEV_TOOL` | Interactive developer tool (SQL*Plus, SQL Developer, etc.) |

WHEN clauses use `= 'FALSE'` - Oracle evaluates the WHEN on first statement after
logon. If the context is NULL (failed logon, not yet set), EVALUATE PER SESSION
fires as though the condition were FALSE, so failed logins are **not** suppressed
by OFFPATH or CRIT_PKG policies.

---

## DDL Double-Coverage (Intentional)

`ODB_LOC_DDL_ALL_V2` and `ODB_LOC_APP_OFFPATH_V2` both capture DDL for
SYS/SYSTEM. This is by design - pending final customer decision on retention scope.

Consequence for reporting: DDL events for SYS/SYSTEM may appear in **both**
the privileged-activity report (section 6) and the off-path signals (section 7).
The `ora-db-audit` report tool detects this configuration and emits an
explanatory note.

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
|---|---|
| 3 - Policy inventory | Detects ADHOC (ACTIONS ALL), shows BY-USER bindings |
| 4-7 - Volume analysis | DDL double-coverage note if DDL_ALL + OFFPATH both active |
| 6.1 - Privileged users | Role-holder expansion via DBA_ROLE_PRIVS |
| 6.2 - Critical packages | New section: CIS 5.1.3 package execution summary |
| 6.3 - Developer by-user | New section: DEV_ALL BY-USER policy bindings |
| 7 - Off-path signals | V2 OFFPATH cross-reference note |
| 17 - CIS coverage | CIS 5.3 and 5.5 updated for object-level EXECUTE + role targets |

---

## Source Reference

V2 policy definitions: `ora-db-audit-eng/sql/odb_policies_create_aud.sql`
V2 architecture docs: `ora-db-audit-eng/doc/04_policies.md`
