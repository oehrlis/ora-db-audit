# Compliance Mapping - Oracle Unified Auditing

> Mapping of `ora-db-audit` SQL checks to CIS Benchmarks, DISA STIG, and Oracle Unified Audit
> Best Practice Guidelines. Use this document to understand coverage and identify gaps.

**Scope:** Oracle Unified Auditing Pure Mode. Legacy audit parameters (`audit_trail`,
`audit_sys_operations`, `audit_syslog_level`) are out of scope.

**References used:**

- CIS Oracle Database 19c Benchmark v2.0.0 (Section 5, pp. 121-138)
- CIS Oracle Database 23ai Benchmark v1.1.0 (Section 5, pp. 125-140)
- CIS Oracle Database 26ai Benchmark v1.0.0 (Section 5, pp. 121-136)
- DISA STIG Oracle Database 19c V1R5 (JSON, 96 rules; 12 audit-relevant rules extracted)
- Oracle Database Unified Audit: Best Practice Guidelines v2.0 (April 2025)

---

## 1. CIS Benchmark Controls

All three CIS versions (19c v2.0.0, 23ai v1.1.0, 26ai v1.0.0) define the same five Level 1
Unified Auditing controls. The control numbering differs: 19c uses `5.1.x`, 23ai and 26ai use
flat `5.x`. All controls are **Automated** and apply to Level 1 - RDBMS.

### 1.1 Control Summary

<!-- markdownlint-disable MD013 MD060 -->
| Control | Title | Policy Name | 19c | 23ai | 26ai | CIS v8 | CIS v7 |
|---------|-------|-------------|-----|------|------|--------|--------|
| 5.1 (5.1.1) | Ensure All Auditable System Actions Commands Are Audited | `CIS_CDB_DDL_ACTIONS` / `CIS_PDB_DDL_ACTIONS` | 5.1.1 | 5.1 | 5.1 | 8.5 | 6.3 |
| 5.2 (5.1.2) | Ensure the 'LOGON' AND 'LOGOFF' Actions Audit Is Enabled | `CIS_CDB_LOGON_LOGOFF` | 5.1.2 | 5.2 | 5.2 | 8.2, 8.5 | 6.2, 6.3 |
| 5.3 (5.1.3) | Ensure Critical Packages Are Audited | `CIS_CDB_CRITICAL_PACKAGES` | 5.1.3 | 5.3 | 5.3 | 8.5 | 6.3 |
| 5.4 (5.1.4) | Ensure All Export Activities Are Audited | `CIS_CDB_EXPORT` | 5.1.4 | 5.4 | 5.4 | 8.5 | 6.3 |
| 5.5 (5.1.5) | Ensure The Use Of SYS\* Privileges Is Audited | `CIS_CDB_ALL_ACTIONS_BY_PRIVILEGED_USERS` | 5.1.5 | 5.5 | 5.5 | 8.5 | 6.3 |
<!-- markdownlint-enable -->

### 1.2 Control Details

#### 5.1 - Ensure All Auditable System Actions Commands Are Audited

- Scope: All DDL commands (CREATE, ALTER, DROP, GRANT, REVOKE, etc.), success and failure
- Oracle policy: `CIS_CDB_DDL_ACTIONS` (CDB) + `CIS_PDB_DDL_ACTIONS` (PDB)
- Remediation action: `ALTER AUDIT POLICY ... ADD ACTIONS <DDL>`
- Important: Check for `EXCEPT USER` clauses that may bypass auditing for specific users
- Applies identically to 19c, 23ai, 26ai

#### 5.2 - Ensure the 'LOGON' AND 'LOGOFF' Actions Audit Is Enabled

- Scope: LOGON, LOGOFF, LOGOFF BY CLEANUP; also HTTP/FTP/AUTHENTICATION protocol
- Oracle policy: `CIS_CDB_LOGON_LOGOFF`
- Audit must include both SUCCESS=YES and FAILURE=YES, BY USER, ALL USERS
- Remediation: `CREATE AUDIT POLICY CIS_CDB_LOGON_LOGOFF ACTIONS LOGON, LOGOFF ACTIONS COMPONENT=PROTOCOL HTTP, FTP, AUTHENTICATION`

#### 5.3 - Ensure Critical Packages Are Audited

- Scope: EXECUTE on 19 packages (19c) / 18 packages (23ai, 26ai)
- Oracle policy: `CIS_CDB_CRITICAL_PACKAGES`, ONLY TOPLEVEL
- 19c package list: `DBMS_AW`, `DBMS_CRYPTO`, `DBMS_FGA`, `DBMS_JAVA_TEST`, `DBMS_JOB`,
  `DBMS_LOGMNR`, `DBMS_NETWORK_ACL_ADMIN`, `DBMS_REDACT`, `DBMS_REDEFINITION`, `DBMS_RLS`,
  `DBMS_SCHEDULER`, `DBMS_SQL_TRANSLATOR`, `DBMS_SYS_SQL`, `DBMS_TSDP_MANAGE`,
  `DBMS_TSDP_PROTECT`, `DBMS_XMLGEN`, `DBMS_XMLSTORE`, `OWA_UTIL`, `DBMS_OBFUSCATION_TOOLKIT`
- 23ai/26ai drop: `DBMS_OBFUSCATION_TOOLKIT` (deprecated and removed)

#### 5.4 - Ensure All Export Activities Are Audited

- Scope: Data Pump EXPORT operations; RMAN activities are already covered by `ORA$MANDATORY`
- Oracle policy: `CIS_CDB_EXPORT` with `ACTIONS COMPONENT=datapump EXPORT`
- RMAN note: `ORA$MANDATORY` policy covers RMAN and cannot be disabled

#### 5.5 - Ensure The Use Of SYS\* Privileges Is Audited

- Scope: ALL actions by SYS, SYSKM, SYSBACKUP, SYSRAC, SYSDG, PUBLIC (=SYSOPER)
- Oracle policy: `CIS_CDB_ALL_ACTIONS_BY_PRIVILEGED_USERS`, ONLY TOPLEVEL
- Critical: SYS\* privileges are evaluated first in Oracle's privilege order; regular audit
  policies do NOT capture SYS-privileged operations unless explicitly added
- WHEN clause excludes: `emagent`, `OMS`, `RMAN`, `Perl` to prevent spillover files
- Remediation: `AUDIT POLICY ... BY SYS, SYSKM, SYSBACKUP, SYSRAC, SYSDG, PUBLIC`

### 1.3 CIS Additional Checks

The CIS benchmark also recommends checking for `EXCEPT USER` exclusions that may silently
bypass auditing:

```sql
SELECT policy_name, enabled_option, entity_name
FROM audit_unified_enabled_policies
WHERE enabled_option = 'EXCEPT USER';
```

---

## 2. DISA STIG Oracle 19c V1R5 - Audit-Relevant Rules

12 of 96 STIG rules directly address auditing and logging. Severity: all **Medium (CAT II)**.

<!-- markdownlint-disable MD013 MD060 -->
| Rule ID | STIG ID | Title | In-DB Checkable | Our SQL |
|---------|---------|-------|-----------------|---------|
| V-270502 | O19C-00-001800 | Oracle Database must provide audit record generation capability for DoD-selected auditable events | Yes | `01-config.sql` |
| V-270503 | O19C-00-001900 | Oracle Database must allow designated organizational personnel to select which auditable events are audited | Partial | `03-policy-inventory.sql`, `16-policy-ddl.sql` |
| V-270504 | O19C-00-002000 | Oracle Database must generate audit records for the DoD-selected list of auditable events | Yes | `03-policy-inventory.sql`, `13-failed-logins.sql`, `14-privileged-activity.sql` |
| V-270505 | O19C-00-005600 | Oracle Database must include organization-defined additional, more detailed information in audit records | Yes | `05-policy-user-action.sql` to `12-distinct-hosts.sql` |
| V-270506 | O19C-00-005700 | Oracle Database must allocate audit record storage capacity in accordance with organization-defined requirements | Yes | `02-storage.sql` |
| V-270507 | O19C-00-005800 | Oracle Database must off-load audit data to a separate log management facility (out-of-DB check) | No | - (SIEM/OS level) |
| V-270508 | O19C-00-005900 | Oracle Database must alert on audit storage failure | No | - (OS/alerting) |
| V-270509 | O19C-00-006000 | Oracle Database must provide immediate real-time alert on audit processing failure | No | - (infrastructure) |
| V-270510 | O19C-00-006600 | Audit information must be protected from unauthorized access, modification, and deletion | Partial | `03-policy-inventory.sql` (role check) |
| V-270511 | O19C-00-006900 | Audit tools must be protected from unauthorized access, modification, or deletion | No | - (OS level) |
| V-270537 | O19C-00-010700 | Use of the Oracle Database installation account must be logged | Partial | `14-privileged-activity.sql` |
| V-270538 | O19C-00-011300 | Database data files, transaction logs and audit files must be stored in dedicated areas | Yes | `02-storage.sql` |
| V-270540 | O19C-00-011300 | Changes to configuration options must be audited | Yes | `03-policy-inventory.sql`, `01-config.sql` |
<!-- markdownlint-enable -->

### 2.1 STIG DoD Audit Event Requirements (V-270504)

The DoD-selected list of auditable events includes:

- Successful and unsuccessful attempts to access, modify, or delete privileges, security objects,
  security levels, or categories of information
- Access attempts to accounts with special privileges
- Application initialization and shutdown
- Logon/logoff events (successful and failed)
- All privilege escalation requests
- All account creation, modification, disabling, or deletion events
- All kernel module load, unload, and restart events

---

## 3. Oracle Unified Audit Best Practice Guidelines v2.0 (April 2025)

Oracle BP v2.0 defines 17 recommended audit policy types across three categories plus trail
management recommendations.

### 3.1 Privileged User Activity Auditing

<!-- markdownlint-disable MD013 MD060 -->
| BP # | Recommendation | Predefined Policy | Available OOB | Our SQL |
|------|---------------|-------------------|---------------|---------|
| 1 | Audit administrative database user accounts | None | No | `14-privileged-activity.sql` (partial) |
| 2 | Audit database user accounts with direct database access | None | No | `05-policy-user-action.sql` (partial) |
| 3 | Audit individual high risk database user accounts | None | No | `14-privileged-activity.sql` (partial) |
<!-- markdownlint-enable -->

### 3.2 Security-Relevant Events Auditing

<!-- markdownlint-disable MD013 MD060 -->
| BP # | Recommendation | Predefined Policy | Available OOB | Our SQL |
|------|---------------|-------------------|---------------|---------|
| 4 | Audit security-management events | `ORA_SECURECONFIG`, `ORA_ACCOUNT_MGMT` | Yes | `03-policy-inventory.sql` |
| 5 | Audit account-management events | `ORA_SECURECONFIG`, `ORA_ACCOUNT_MGMT` | Yes | `03-policy-inventory.sql` |
| 6 | Audit data-security events | Mandatory + `ORA_RAS_POLICY_MGMT`, `ORA_RAS_SESSION_MGMT`, `ORA_SECURECONFIG` | Yes | `03-policy-inventory.sql` |
| 7 | Audit database-management events | Mandatory + `ORA_SECURECONFIG` | Yes | `03-policy-inventory.sql` |
| 8 | Audit data-management events | None | No | `09-top-actions.sql` (partial) |
| 9 | Audit activities with system privileges | None | No | `14-privileged-activity.sql` |
| 10 | Audit activities of unused system privileges | None | No | - (GAP: missing) |
| 11 | Audit usage of components with data implications | `ORA_RAS_POLICY_MGMT`, `ORA_DV_SCHEMA_CHANGES`, `ORA_DV_DEFAULT_PROTECTION` | Yes (partial) | `03-policy-inventory.sql` |
| 12 | Monitor suspicious user-activity: multiple failed login attempts | `ORA_LOGON_FAILURES` | Yes | `13-failed-logins.sql` |
| 13 | Monitor suspicious user-activity: sudden activity in dormant accounts | None | No | - (GAP: missing) |
| 14 | Monitor suspicious user-activity: non-business hour activities | None | No | - (GAP: missing) |
<!-- markdownlint-enable -->

### 3.3 Sensitive Data Access Auditing

<!-- markdownlint-disable MD013 MD060 -->
| BP # | Recommendation | Predefined Policy | Available OOB | Our SQL |
|------|---------------|-------------------|---------------|---------|
| 15 | Audit user access to sensitive data through untrusted path | None | No | - (out of scope: FGA, app-specific) |
| 16 | Audit user access to sensitive data | None | No | - (out of scope: app-specific) |
| 17 | Audit sensitive columns storing PII data | None | No | - (out of scope: FGA, app-specific) |
<!-- markdownlint-enable -->

BP items 15-17 require application-specific FGA policies. This tool does not generate them
(they depend on customer schema knowledge), but the report notes their absence where relevant.

### 3.4 Audit Trail Management

<!-- markdownlint-disable MD013 MD060 -->
| Recommendation | API | Our SQL |
|---------------|-----|---------|
| Relocate `AUD$UNIFIED` to a dedicated tablespace | `DBMS_AUDIT_MGMT.SET_AUDIT_TRAIL_LOCATION` | `02-storage.sql` |
| Set reasonable partition interval (default: 1 month for 19c, 1 day for 23ai+) | `DBMS_AUDIT_MGMT.ALTER_PARTITION_INTERVAL` | `02-storage.sql` |
| Archive and purge audit records periodically | `DBMS_AUDIT_MGMT.CREATE_PURGE_JOB` | `02-storage.sql` (partial) |
| Query performance: include `EVENT_TIMESTAMP_UTC` in WHERE clause | - | All trail queries in SQLs 04-15 |
| Gather statistics on `AUDSYS.AUD$UNIFIED` periodically | `DBMS_STATS.GATHER_TABLE_STATS` | - (out of scope: DBA task) |
<!-- markdownlint-enable -->

---

## 4. Gap Analysis

### 4.1 SQL Coverage Matrix

<!-- markdownlint-disable MD013 MD060 -->
| SQL File | Description | CIS 5.x | STIG V-270xxx | Oracle BP # |
|----------|-------------|---------|---------------|-------------|
| `00-setup.sql` | Session setup (NLS, pagesize, output) | - | - | - |
| `01-config.sql` | Pure-mode detection, init params, legacy param flags | - | 502, 540 | Trail mgmt |
| `02-storage.sql` | `AUD$UNIFIED` tablespace, partition state, purge job | - | 506, 538 | Trail mgmt |
| `03-policy-inventory.sql` | All defined + enabled policies, by container | 5.1-5.5 | 503, 504, 510, 540 | 4-7, 11 |
| `04-policy-volume.sql` | Record count per policy (UAP-split) | - | 506 | Trail mgmt |
| `05-policy-user-action.sql` | Top events per policy/user/action (UAP-split) | 5.1, 5.2 | 504, 505 | 1-9 |
| `06-policy-client-program.sql` | Events by client program (UAP-split) | - | 505 | 2, 9 |
| `07-policy-host.sql` | Events by host (UAP-split) | - | 505 | - |
| `08-top-users.sql` | Top users by event count | - | 505 | 1-3 |
| `09-top-actions.sql` | Top actions by event count | - | 505 | 8 |
| `10-top-objects.sql` | Top objects by event count | - | 505 | 16 |
| `11-host-user-program.sql` | Host / user / program cross-reference | - | 505 | 2 |
| `12-distinct-hosts.sql` | Distinct client hosts in trail | - | 505 | - |
| `13-failed-logins.sql` | Failed login events, user breakdown | 5.2 | 504 | 12 |
| `14-privileged-activity.sql` | SYS\* and privileged user events | 5.5 | 504, 537 | 1, 9 |
| `15-noise-candidates.sql` | High-volume policy/user/action tuning candidates | - | - | Trail mgmt |
| `16-policy-ddl.sql` | Policy DDL via `DBMS_METADATA.GET_DDL` | 5.1-5.5 | 503 | 4-12 |
<!-- markdownlint-enable -->

### 4.2 Missing Checks (Proposed New SQLs)

The following compliance gaps are not covered by any existing SQL. These are **confirmed gaps**
against the CIS/STIG/Oracle BP requirements above.

#### GAP-01: CIS Policy Coverage Check

**What:** Verify that all five CIS-required policies exist and are fully enabled for the
correct user scope and containers. Currently `03-policy-inventory.sql` lists all policies but
does not explicitly flag the absence of mandatory CIS policies.

**Standards:** CIS 5.1-5.5 (all five controls)

**Proposed:** `sql/17-cis-coverage.sql`

Checks:

- `CIS_CDB_DDL_ACTIONS` enabled, SUCCESS=YES, FAILURE=YES, BY USER, ALL USERS
- `CIS_CDB_LOGON_LOGOFF` enabled with LOGON, LOGOFF actions
- `CIS_CDB_CRITICAL_PACKAGES` enabled for all 18/19 packages
- `CIS_CDB_EXPORT` enabled for DATAPUMP EXPORT action
- `CIS_CDB_ALL_ACTIONS_BY_PRIVILEGED_USERS` enabled BY SYS, SYSKM, SYSBACKUP, SYSRAC, SYSDG, PUBLIC
- Detect `EXCEPT USER` exclusions on any of the above policies
- Red/Yellow/Green verdict per CIS control per container

#### GAP-02: Audit Role Membership Check

**What:** Who has `AUDIT_ADMIN` and `AUDIT_VIEWER` roles granted? Unauthorized grantees can
modify or read audit policies and trail data.

**Standards:** STIG V-270510 (protect audit data from unauthorized access), Oracle BP (general)

**Proposed:** `sql/18-audit-roles.sql`

Checks:

- All grantees of `AUDIT_ADMIN` (direct + through role chains)
- All grantees of `AUDIT_VIEWER`
- Non-SYS, non-AUDSYS accounts in either role

#### GAP-03: Audit Trail Health Check

**What:** Is a purge job configured? Is `LAST_ARCHIVE_TIMESTAMP` set (required before purge)?
What is the partition interval? Are there spillover files?

**Standards:** STIG V-270506 (storage capacity), Oracle BP trail management

**Proposed:** Extend `sql/02-storage.sql` or create `sql/19-trail-health.sql`

Checks:

- `DBMS_AUDIT_MGMT.GET_AUDIT_TRAIL_PROPERTY_VALUE('DB_DELETE_BATCH_SIZE')`
- Existence of scheduled purge jobs (`DBA_AUDIT_MGMT_CLEANUP_JOBS`)
- `LAST_ARCHIVE_TIMESTAMP` from `DBA_AUDIT_MGMT_LAST_ARCH_TS`
- Partition count and current partition HIGH_VALUE for `AUDSYS.AUD$UNIFIED`

### 4.3 Checks That Are Out of Scope (Tool Boundary)

These gaps exist in the standards but **cannot be checked from within the database** using a
read-only SQL-based tool:

- **STIG V-270507** - SIEM offload: requires external log management system access
- **STIG V-270508/509** - Alert on audit storage failure: requires OS/infrastructure monitoring
- **STIG V-270511** - Protect audit tools from OS-level tampering: requires OS access
- **Oracle BP 13** - Dormant account activity: requires historical baseline outside audit trail
- **Oracle BP 14** - Non-business hour activities: requires organization-defined business hours
- **Oracle BP 15-17** - Sensitive data FGA: requires customer-specific schema knowledge

### 4.4 SQL Redundancy Review

The following SQLs provide overlapping cross-dimensional views with limited standalone
compliance value. They are useful for forensic investigation but could be merged:

- `sql/06-policy-client-program.sql`, `sql/07-policy-host.sql`, `sql/11-host-user-program.sql`,
  `sql/12-distinct-hosts.sql` - all provide correlated context dimensions. Retain individually
  as they serve different investigation angles; no removal recommended.

- `sql/08-top-users.sql`, `sql/09-top-actions.sql`, `sql/10-top-objects.sql` - top-N analytics.
  Low direct compliance value but essential for noise candidate identification (feeds 15).
  Retain.

No existing SQLs are recommended for removal.

---

## 5. Proposed SQL Rework Plan

Based on the gap analysis above, the following changes are proposed for the next milestone:

### Phase 1: New SQLs (v1.0.1)

<!-- markdownlint-disable MD013 MD060 -->
| File | Purpose | Priority |
|------|---------|----------|
| `sql/17-cis-coverage.sql` | CIS 5.1-5.5 policy presence + completeness check | P1 |
| `sql/18-audit-roles.sql` | `AUDIT_ADMIN` / `AUDIT_VIEWER` membership | P2 |
<!-- markdownlint-enable -->

### Phase 2: SQL Enhancements (v1.1)

<!-- markdownlint-disable MD013 MD060 -->
| File | Change | Reason |
|------|--------|--------|
| `sql/02-storage.sql` | Add purge job + `LAST_ARCHIVE_TIMESTAMP` + partition interval queries | Oracle BP trail mgmt |
| `sql/03-policy-inventory.sql` | Add `EXCEPT USER` detection column | CIS additional info |
<!-- markdownlint-enable -->

### Phase 3: Report Integration (v1.1)

Once new SQLs produce output, extend `tools/audit_report.py` to:

- Add Section 5: CIS Coverage Dashboard (from `17-cis-coverage.sql`)
- Add Section 6: Audit Role Membership (from `18-audit-roles.sql`)
- Add STIG verdict table to Section 1 or as a new Section 7

---

## 6. CIS Predefined Policy Names Reference

This table lists the Oracle predefined audit policy names referenced by CIS controls, as well
as other Oracle-supplied policies useful for compliance. Use `03-policy-inventory.sql` to
verify which are present and enabled.

<!-- markdownlint-disable MD013 MD060 -->
| Policy Name | Purpose | CIS Control | DB Version |
|-------------|---------|-------------|------------|
| `ORA$MANDATORY` | Mandatory auditing (cannot disable) | - | All |
| `ORA_SECURECONFIG` | Security configuration events | BP 4, 5, 6, 7 | All |
| `ORA_ACCOUNT_MGMT` | Account management events | BP 4, 5 | All |
| `ORA_LOGON_FAILURES` | Failed logon attempts | BP 12 | All |
| `ORA_RAS_POLICY_MGMT` | Real Application Security policy management | BP 6, 11 | All |
| `ORA_RAS_SESSION_MGMT` | Real Application Security session management | BP 6 | All |
| `ORA_DV_SCHEMA_CHANGES` | Database Vault schema changes | BP 11 | All (if DV licensed) |
| `ORA_DV_DEFAULT_PROTECTION` | Database Vault default protection | BP 11 | All (if DV licensed) |
| `CIS_CDB_DDL_ACTIONS` | DDL actions audit (CIS 5.1) | CIS 5.1 | Customer-created |
| `CIS_CDB_LOGON_LOGOFF` | Logon/logoff audit (CIS 5.2) | CIS 5.2 | Customer-created |
| `CIS_CDB_CRITICAL_PACKAGES` | Critical package execution audit (CIS 5.3) | CIS 5.3 | Customer-created |
| `CIS_CDB_EXPORT` | Data Pump export audit (CIS 5.4) | CIS 5.4 | Customer-created |
| `CIS_CDB_ALL_ACTIONS_BY_PRIVILEGED_USERS` | SYS\* all-actions audit (CIS 5.5) | CIS 5.5 | Customer-created |
<!-- markdownlint-enable -->

---

*Document version: 1.0.0 - 2026-05-28 - Initial release based on CIS 19c v2.0.0, CIS 23ai
v1.1.0, CIS 26ai v1.0.0, DISA STIG 19c V1R5, Oracle BP v2.0 (April 2025)*
