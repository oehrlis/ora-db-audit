# AI Analysis Rules - Pure-Mode Source of Truth

<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- markdownlint-disable MD013 MD060 -->
<!-- Tables in this doc carry dense classification data; alignment + line-length are subordinate to content density. -->

> Reference document defining which findings the AI analysis (Section 9
> of the audit report) and the auto-generated narrative sections are
> permitted to raise against an Oracle Unified Auditing dataset.
>
> **Scope**: Oracle Unified Auditing in **Pure Mode** on 19c and 26ai
> (formerly 23ai). Mixed Mode and Traditional Auditing are out of scope -
> findings against those configurations are explicitly suppressed (see
> Section 2).
>
> **Audience**: (a) the LLM driving the `audit_report.py` AI section,
> (b) human reviewers cross-checking AI-generated findings, (c) future
> contributors maintaining this codebase.
>
> **Authority**: this document is the canonical Pure-Mode rule set for
> this repository. If a downstream consumer (SQL query, reporter, AI
> prompt) contradicts the rules here, the contradiction is a bug and
> this document wins.

---

## 1. Pure-Mode scope - in-scope objects and findings

The following dictionary views, init parameters, schema objects, and
filesystem locations are the **only** sources from which Pure-Mode
findings may be derived. Any finding referencing material outside this
list must be suppressed.

### 1.1 Dictionary views and tables

| Object                              | Owner   | Purpose                                                 |
|-------------------------------------|---------|---------------------------------------------------------|
| `UNIFIED_AUDIT_TRAIL`               | SYS     | Primary audit-event data source (CDB and PDB views)     |
| `AUDIT_UNIFIED_POLICIES`            | SYS     | Policy definitions (one row per policy + action pair)   |
| `AUDIT_UNIFIED_ENABLED_POLICIES`    | SYS     | Currently enabled policies (per user / by all)          |
| `AUDIT_UNIFIED_CONTEXTS`            | SYS     | Audit-context configuration                             |
| `DBA_PART_TABLES` / `DBA_TAB_PARTITIONS` | SYS | AUD$UNIFIED partition metadata + default tablespace     |
| `AUDSYS.AUD$UNIFIED`                | AUDSYS  | Physical audit trail storage (read access restricted)   |
| `V$OPTION` (`Unified Auditing`)     | SYS     | Confirms Unified Auditing is installed and enabled      |

### 1.2 PL/SQL APIs

- `DBMS_AUDIT_MGMT` package - the **only** supported API for trail
  storage configuration, partition management, archive timestamps, and
  cleanup-job creation in Pure Mode.
- `DBMS_METADATA.GET_DDL('AUDIT_POLICY', :policy_name)` - the canonical
  way to retrieve current policy DDL. Required for any suggested policy
  modification (see Section 4).

### 1.3 Schema objects and tablespaces

- `AUDSYS` schema (do not modify directly; always use DBMS_AUDIT_MGMT).
- `AUDIT_DATA` tablespace (or whatever tablespace the site has chosen
  as the audit data target - the rule is "non-SYSAUX", not literally
  `AUDIT_DATA`).
- Mandatory audit binary files: `$ORACLE_BASE/audit/$ORACLE_SID/*.aud`
  (these are emitted for SYS-DB-startup events even in Pure Mode and
  must be rotated and purged out-of-band by the OS).

### 1.4 Findings classes that ARE valid in Pure Mode

The reporter and AI section may raise findings in these classes:

1. **Policy coverage gaps**: required compliance control (CIS / STIG /
   site policy) has no matching enabled policy.
2. **Audit volume distribution**: policies generating disproportionate
   event volume (noise candidates for WHEN-clause tuning).
3. **Failed-login patterns**: spikes, brute-force candidates, recurring
   misconfigurations (e.g. expired account, wrong password from an
   automated job).
4. **Privileged user activity**: review-required events from `SYS`,
   `SYSDBA`, `AUDIT_ADMIN`, `SYSBACKUP`, `SYSKM`, `SYSRAC`, `SYSDG`.
5. **Audit trail growth and retention**: no cleanup job, no archive
   timestamp set, partition size exceeding site retention SLO.
6. **Storage misconfiguration**: AUD$UNIFIED default tablespace is
   SYSAUX (see Section 5 for the transient-state nuance), audit
   tablespace lacks autoextend, audit tablespace shared with non-audit
   segments.
7. **Mandatory binary file management**: `*.aud` directory unbounded,
   no rotation, no archival.
8. **Off-path host activity**: events from hosts not matching any
   configured app / infra / DBA pattern (the host-pattern config is
   site-specific and is passed in via `--patterns`).
9. **Mixed-mode contamination**: `AUD$` (legacy) contains recent rows
   despite `Unified Auditing = TRUE` (raise as `HIGH` - the audit
   coverage is split and incomplete).
10. **DBMS_AUDIT_MGMT configuration**: missing or stale `LAST_ARCHIVE_TIMESTAMP`,
    no `CLEAN_AUDIT_TRAIL` job, `AUDIT_TRAIL_PROPERTY` defaults not
    tuned for the site.

---

## 2. Out of scope - Legacy / Mixed-Mode artefacts (SUPPRESS findings)

The following parameters, views, and policies belong to Traditional /
Mixed-Mode auditing. They have **no effect** in a Pure-Mode deployment.
Any finding mentioning them must be either omitted or, where the user
explicitly asked for them, marked `INFO - legacy parameter, no Pure-Mode
relevance`.

### 2.1 Init parameters - SUPPRESS

| Parameter             | Why irrelevant in Pure Mode                                    |
|-----------------------|----------------------------------------------------------------|
| `audit_trail`         | Routes legacy `AUD$` writes only; Pure Mode bypasses entirely. |
| `audit_sys_operations`| In Pure Mode, SYS activity is audited via policies, not this toggle. |
| `audit_syslog_level`  | Drives legacy syslog writes; Pure Mode uses its own trail.     |
| `audit_file_dest`     | Affects legacy `*.aud` location only when traditional auditing wrote there; Pure Mode mandatory `*.aud` location is `$ORACLE_BASE/audit/$ORACLE_SID`, not affected by this param. |

**Detection rule**: if `V$OPTION.VALUE = 'TRUE'` for `Unified Auditing`
AND the Mixed-Mode contamination check (Section 6) confirms no Mixed
activity, DO NOT raise findings against the parameters above.

### 2.2 Views - DO NOT USE

| View                    | Reason                                                 |
|-------------------------|--------------------------------------------------------|
| `DBA_AUDIT_TRAIL`       | Legacy; aggregates `AUD$`, not `AUD$UNIFIED`.          |
| `DBA_AUDIT_SESSION`     | Legacy session-audit; Unified Auditing has no equivalent and does not need one. |
| `SYS.AUD$`              | Legacy table; rows here mean Mixed Mode is still active. |
| `FGA_LOG$` / `DBA_FGA_AUDIT_TRAIL` | Fine-Grained Auditing - separate concern (see `/oracle-fga` skill); not covered by Pure-Mode rules. |

### 2.3 Syntax - DO NOT GENERATE

The AI section MUST NOT emit Traditional AUDIT syntax in any
recommendation:

- `AUDIT <stmt> BY <user>;` (Legacy)
- `NOAUDIT <stmt>;` (Legacy)
- `AUDIT POLICY <name> ON CONNECT;` (this is correct Unified syntax,
  KEEP - included here only because the surrounding context can confuse)

Recommendations must use Unified syntax exclusively:

- `CREATE AUDIT POLICY ...`
- `ALTER AUDIT POLICY ...`
- `AUDIT POLICY <name>;` / `NOAUDIT POLICY <name>;` (enable / disable)
- `EXEC DBMS_AUDIT_MGMT...`

### 2.4 Known false-positive class

The most common false positive in inherited tooling: flagging
`audit_trail = DB` as a misconfiguration. In Pure Mode this value has
no effect and may be left at the Oracle default. Do not raise this as
a finding.

---

## 2.5 Ghost events - policies inactive but events present in trail

A policy can appear in `04_policy_volume.csv` (events in the trail) while
having an empty `enabled_option` in `03_policy_inventory.csv` (not currently
enabled in `audit_unified_enabled_policies`). These are **historical events**
from when the policy was active.

**Rule:** Do NOT raise a redundancy or overlap finding for a policy that is
currently not enabled. Emit at most an INFO note in the following form:

> "Historical events in trail from currently inactive policy `<NAME>` (N events).
> These were recorded while the policy was active and do not indicate a
> current configuration issue."

This situation commonly occurs with Oracle-supplied policies
(`ORA_SECURECONFIG`, `ORA_LOGIN_LOGOUT`, etc.) that were active during
initial database setup and subsequently disabled in favour of custom policies.

**Do not do:**

- Flag as "active alongside" a custom policy if `enabled_option` is empty.
- Recommend disabling a policy that is already disabled.
- Count events toward a "currently active policy" volume if `enabled_option`
  is empty.

**Source of truth:** `enabled_option` in `03_policy_inventory.csv`.
Empty string = not enabled. Non-empty = currently enabled (the option type
is the evidence, e.g. `BY USER`, `BY GRANTED ROLE`, `ALL USERS`).

---

## 2.6 Off-path events - two deployment scenarios

Off-path detection works in two fundamentally different ways depending on
whether an Oracle Application Context is deployed in the target database.
**Always identify which scenario applies before raising a finding.**

### How to tell which scenario is in place

Inspect the policy conditions in Section 3 (policy inventory) of the report
or query `dba_audit_policies.condition_eval_opt` / `dba_audit_policy_actions`.
If any policy carries a condition of the form:

```sql
CONDITION: SYS_CONTEXT('<any_name>', 'IS_APP_ACCESS') = 'FALSE'
-- or IS_KNOWN_CLIENT, IS_DEV_TOOL, or any equivalent flag
```

then **Scenario A** applies. Otherwise assume **Scenario B**.

---

### Scenario A - Application Context deployed

An Application Context (any name, customer-specific) is deployed on the
database. A LOGON trigger (or equivalent) sets session-level flags such as
`IS_APP_ACCESS`, `IS_KNOWN_CLIENT`, or `IS_DEV_TOOL` at connect time.
Audit policies that reference these flags via `SYS_CONTEXT(...)` fire
**only when the flag is FALSE** - i.e. only for off-path access.

**Consequence:** every record from a context-conditioned policy is off-path
by definition. The audit trail is already the filtered off-path view.

Finding rules:

- Context (`dba_context`) registered + LOGON trigger ENABLED + events:
  - Historical events only (timestamps before trigger deployment) →
    **INFO** or **LOW**.
  - Ongoing events → **MEDIUM** - host or client not yet registered in
    the context package whitelist. Add to the pattern list in the package.
  - Many distinct users from same unknown host → **HIGH** (active bypass).
- Context registered but LOGON trigger DISABLED or missing → **HIGH**
  (infrastructure incomplete; IS_APP_ACCESS always evaluates to FALSE,
  meaning the policy would fire for all sessions, not just off-path ones).
- Context not in `dba_context` at all → **HIGH** (not deployed).

Correct finding text when trigger is in place:
"Host `<NAME>` does not match any registered app-server pattern in the
context package; verify the host and add it to the whitelist if correct."

Never write "IS_APP_ACCESS not configured" when the context is registered
and the trigger is enabled - that phrasing implies missing infrastructure
when the real issue is an unregistered host.

---

### Scenario B - Pattern-based only (no Application Context)

No context condition appears in any audit policy. The tool derives
off-path classification from the USERHOST value alone, using the
pattern lists from `--patterns` / `DEFAULT_PATTERNS`:

- `app_host_patterns` match → **APP** (expected application tier)
- `infra_host_patterns` match → **INFRA** (database server, OEM, backup)
- `dba_host_patterns` match → **DBA** (jump hosts, admin laptops)
- No match → **OFF-PATH** (shown in Section 7.2)

Finding severity from triage heuristics (`docs/use-cases/off-path-detection.md`):

- High volume + broad action profile (`distinct_actions >= 5`) → **HIGH**
- JDBC / application client on unknown host → **MEDIUM** (possible new
  app server not yet added to patterns)
- Single login, stale timestamp → **LOW**
- `os_username = dbusername`, SQL developer tool → **INFO** (likely
  developer direct-connect; discuss policy)

**Important before raising:** a host in Section 7.2 may simply be a
legitimate server not yet added to the patterns configuration. Check
login volume, distinct users, and client program name. If it looks like
a known server, add it to the `--patterns` file - not a security finding.

---

## 2.7 Purge job metadata - use CSV values, not trail inference

`02_storage.csv` metadata lines `purge_job_count`, `purge_job_status`,
`last_archive_timestamp`, and `partition_interval` are the authoritative
source for trail-management findings.

**Rule:**

- If `purge_job_count > 0` and `last_archive_timestamp != "(not set)"`:
  trail management is configured. Do NOT raise a missing-purge-job finding.
- If `purge_job_count = 0` or value = `"0"`: no purge job. Raise as HIGH.
- If `last_archive_timestamp = "(not set)"`: purge job exists but will not
  delete rows (no archive fence). Raise as HIGH.
- If any metadata value is the literal `"(not set)"` or `"(unknown)"`:
  the collection query failed (likely `ORA-904` on `audit_trail_type`
  column - the correct column name is `audit_trail`). Do NOT infer a
  missing purge job from absent metadata. Emit an INFO noting "purge job
  metadata unavailable due to collection error."

---

## 3. UNIFIED_AUDIT_POLICIES concatenation semantics

`UNIFIED_AUDIT_TRAIL.UNIFIED_AUDIT_POLICIES` is a comma-separated
concatenation when multiple enabled policies match the same audit
event. Example value:

```text
ORA_LOGON_FAILURES,ORA_SECURECONFIG,SITE_DDL_AUDIT
```

This is **not** a single policy name. Aggregating directly on this
column is the root cause of finding F3 (per-policy semantics broken)
and F2 (Section 8.1 generates DDL against this concat string).

### 3.1 The split rule

Every SQL aggregate or filter that needs per-policy semantics MUST split
the column first. The canonical pattern (Oracle 12c+ syntax):

```sql
WITH split_uap AS (
    SELECT
        TRIM(REGEXP_SUBSTR(t.unified_audit_policies, '[^,]+', 1, lvl.col_pos)) AS policy_name,
        t.event_timestamp_utc,
        t.dbusername,
        t.userhost,
        t.action_name,
        t.client_program_name
    FROM unified_audit_trail t
    CROSS JOIN (
        SELECT LEVEL AS col_pos FROM dual CONNECT BY LEVEL <= 20
    ) lvl
    WHERE t.unified_audit_policies IS NOT NULL
      AND lvl.col_pos <= REGEXP_COUNT(t.unified_audit_policies, ',') + 1
      AND t.event_timestamp_utc >= SYSTIMESTAMP - NUMTODSINTERVAL(TO_NUMBER('&days'), 'DAY')
      AND t.dbid = con_id_to_dbid(SYS_CONTEXT('USERENV','CON_ID'))
)
SELECT policy_name, COUNT(*) AS events
FROM split_uap
GROUP BY policy_name;
```

The `CONNECT BY LEVEL <= 20` cap covers typical concatenation depth
(observed maximum at most sites: 3-5 policies). Validate per site:

```sql
SELECT MAX(REGEXP_COUNT(unified_audit_policies, ',') + 1)
FROM unified_audit_trail
WHERE unified_audit_policies IS NOT NULL;
```

If the result exceeds 15, raise the cap to 50.

### 3.2 The containment rule

When the use case is "filter events touched by policy X" (rather than
aggregate), prefer a containment test over a full split:

```sql
SELECT ...
FROM unified_audit_trail
WHERE ',' || unified_audit_policies || ',' LIKE '%,' || :policy_name || ',%';
```

This is correct for membership tests. It is NOT correct for aggregation
by policy (use the split CTE for that).

### 3.3 Policy overlap is real

Because of the concat semantics, the same audit event can legitimately
count toward multiple policies. The reporter must:

- Show per-policy totals using the split (no double-counting suppression
  at the SQL level - users want to see "ORA_LOGON_FAILURES generated X
  events" even when X events also matched site policies).
- Annotate in the report that totals across policies will exceed the
  raw event count due to overlap.

---

## 4. Suggested policy modifications - DDL source rule

Every suggested change to an audit policy (Section 8.1 of the report,
or any inline recommendation in the AI section) MUST source the current
policy state from `DBMS_METADATA.GET_DDL`. Suggestions are presented as
a delta against the actual DDL.

### 4.1 Sourcing query

```sql
SELECT p.policy_name,
       DBMS_METADATA.GET_DDL('AUDIT_POLICY', p.policy_name) AS policy_ddl
FROM   audit_unified_policies p
GROUP BY p.policy_name;
```

This is implemented as `sql/16-policy-ddl.sql` (added in Phase B). The
CSV output is consumed by `audit_report.py` Section 8.1.

### 4.2 Rules for suggested DDL

- **NEVER** synthesise an `ALTER AUDIT POLICY` from `UNIFIED_AUDIT_POLICIES`
  concat strings. The concat string is observation data, not DDL.
- **NEVER** issue a suggestion against a policy name that does not appear
  in `AUDIT_UNIFIED_POLICIES`. If the trail mentions a policy that no
  longer exists, raise that as a finding ("policy referenced in trail
  but missing from `AUDIT_UNIFIED_POLICIES` - was it dropped?") instead
  of generating modification DDL.
- **ALWAYS** present suggested changes as DDL-diff: show the existing
  WHEN clause / action filter; show the proposed addition / change;
  let the reviewer apply the change manually after reviewing impact.
- **ALWAYS** include a NOAUDIT counterpart when relevant - per
  OraDBA invariant `AUDIT` and `NOAUDIT` policy DDL come paired.

### 4.3 Privileges required

`DBMS_METADATA.GET_DDL` on audit policies requires `AUDIT_ADMIN` or
`SELECT_CATALOG_ROLE`. The runner documents this in the customer
handover template. If the privilege is missing at run time,
`sql/16-policy-ddl.sql` emits an empty result; downstream the reporter
falls back to "DDL unavailable - suggestion suppressed" rather than
fabricating DDL from concat strings.

---

## 5. Partition transient state - storage findings

`AUDSYS.AUD$UNIFIED` is interval-partitioned in 19c+. Partitioning
attributes interact with tablespace placement in ways that the naive
finding "AUD$UNIFIED partition in SYSAUX = misconfigured" gets wrong.

### 5.1 The interaction

- The **default tablespace** for new auto-created partitions is
  governed by `DBA_PART_TABLES.DEF_TABLESPACE_NAME`.
- Existing partitions retain their tablespace until explicitly moved
  (`ALTER TABLE AUDSYS.AUD$UNIFIED MOVE PARTITION <p> TABLESPACE <tbs>;`).
- Setting the default tablespace via `ALTER TABLE AUDSYS.AUD$UNIFIED
  MODIFY DEFAULT ATTRIBUTES TABLESPACE AUDIT_DATA` does NOT relocate
  existing partitions.

So when a DBA "moves AUD$UNIFIED to AUDIT_DATA" via the default
attribute, the current partition (and any older retained partitions)
stay in their original tablespace - typically SYSAUX - until the next
range boundary triggers a new auto-partition in AUDIT_DATA.

### 5.2 Decision matrix

Use the following classification when interpreting tablespace findings.
Inputs:

- `D` = `DBA_PART_TABLES.DEF_TABLESPACE_NAME` for `AUD$UNIFIED`
- `C` = tablespace of the MOST RECENT (highest interval, current write
  target) partition
- `O` = list of tablespaces of OLDER (retained) partitions

| D            | C            | O                           | Verdict                                                                                                  |
|--------------|--------------|-----------------------------|----------------------------------------------------------------------------------------------------------|
| `SYSAUX`     | `SYSAUX`     | only `SYSAUX`               | MISCONFIGURATION - default never moved off SYSAUX. Recommend `MODIFY DEFAULT ATTRIBUTES TABLESPACE ...`. |
| `AUDIT_DATA` | `AUDIT_DATA` | only `AUDIT_DATA`           | OK - fully migrated.                                                                                     |
| `AUDIT_DATA` | `AUDIT_DATA` | mix of `SYSAUX`/`AUDIT_DATA`| TRANSIENT - default is correct; older partitions awaiting drop. Optional `MOVE PARTITION` per partition. |
| `AUDIT_DATA` | `SYSAUX`     | any                         | TRANSIENT (default changed mid-interval) - the in-flight partition stays in SYSAUX until rollover. Wait or `MOVE PARTITION`. |
| `AUDIT_DATA` | (none)       | (none)                      | EMPTY - first event will create partition in AUDIT_DATA. Informational.                                  |

The reporter MUST surface `D`, `C`, and `O` as three distinct
metadata values (per `sql/02-storage.sql` revision in Phase C) so the
AI section can apply this matrix.

### 5.3 Reporter behaviour

- `MISCONFIGURATION` -> finding raised, severity `MEDIUM`, action proposed.
- `TRANSIENT` -> NOTED, severity `INFO`, with the explanation above; no
  action required unless site SLO mandates immediate relocation.
- `OK` -> no finding.

---

## 6. Pure-vs-Mixed detection

Several findings (Section 2 suppressions, the AI-section framing) depend
on whether the target instance is truly in Pure Mode. Apply this check
once per audit run; expose the result as the `audit_mode` metadata
value in `sql/01-config.sql`.

### 6.1 Canonical signals

```sql
-- Signal 1: Unified Auditing installed and enabled
SELECT VALUE
FROM   V$OPTION
WHERE  PARAMETER = 'Unified Auditing';
-- Expected in 21c+: 'TRUE' (Unified Auditing is mandatory)

-- Signal 2: Legacy parameter state
SELECT VALUE
FROM   V$PARAMETER
WHERE  NAME = 'audit_trail';
-- 'NONE'           = legacy writes disabled
-- 'DB' | 'OS' | 'XML' | 'DB,EXTENDED' = legacy writes still enabled

-- Signal 3: Recent legacy data
SELECT COUNT(*) AS recent_legacy_rows
FROM   SYS.AUD$
WHERE  NTIMESTAMP# > SYSTIMESTAMP - INTERVAL '7' DAY;
-- 0    = no legacy activity in the last week
-- > 0  = Mixed Mode actually generating data
```

### 6.2 Mode classification

| `Unified Auditing` | `audit_trail` | recent `AUD$` rows | Verdict                                          |
|--------------------|---------------|--------------------|--------------------------------------------------|
| `TRUE`             | `NONE`        | 0                  | **PURE** - all rules in this doc apply.          |
| `TRUE`             | `NONE`        | > 0                | **PURE-CONTAMINATED** - rows in AUD$ are stale (no legacy writes possible). FYI only. |
| `TRUE`             | `DB`/`OS`/`XML` | 0                | **PURE-INTENT** - legacy param still set but no recent legacy activity. Apply Pure rules; warn that param should be set to `NONE` on next bounce. |
| `TRUE`             | `DB`/`OS`/`XML` | > 0              | **MIXED** - this tool's Pure-Mode rules DO NOT apply. The report must call out the contamination as a HIGH finding and recommend migrating off Mixed Mode (see `/oracle-audit` skill, Mixed-to-Pure section). |
| `FALSE`            | any           | any                | **NOT SUPPORTED** - this tool requires Unified Auditing. Refuse to run.     |

### 6.3 Reporter behaviour

- `sql/01-config.sql` emits `# audit_mode: pure|pure-contaminated|pure-intent|mixed|unsupported`.
- The AI prompt receives the audit_mode value and uses it to gate
  Section 2 suppressions. If `audit_mode = mixed`, the AI section
  bails with a single HIGH finding ("Mixed Mode detected - this report
  is out of scope; migrate to Pure Mode first").
- The reporter Section header surfaces the audit_mode prominently so
  the human reader sees it before reading findings.

---

## 7. References

### 7.1 Authoritative sources used in this document

- **Oracle Database Unified Audit Best Practice Guidelines** (Oracle
  Corporation, white paper):
  <https://www.oracle.com/a/tech/docs/dbsec/unified-audit-best-practice-guidelines.pdf>
- **Oracle Database Security Primer** (Oracle Corporation):
  <https://download.oracle.com/database/oracle-database-security-primer.pdf>
- **Oracle Database 19c Security Guide**, chapter "Configuring Unified
  Auditing", current revision.
- **Oracle Database 26ai Security Guide** (formerly 23ai), chapter
  "Configuring Unified Auditing", current revision.

### 7.2 Compliance source documents

The CIS / STIG mapping work (Phase E) cites:

- **CIS Oracle Database 19c Benchmark**, version captured at mapping
  time. See `docs/compliance-mapping.md` for the exact version row.
- **CIS Oracle Database 21c Benchmark** (if a Pure-Mode-aware version
  exists; otherwise documented as a gap).
- **DISA STIG Oracle Database 12c** (current STIG; many controls are
  Traditional-Auditing-only and are explicitly out of scope per Section
  2 of this doc).

### 7.3 Repository cross-references

- `docs/compliance-mapping.md` - per-control mapping built on top of
  this doc's Section 2 filter.
- `sql/01-config.sql` - emits `audit_mode` metadata per Section 6.
- `sql/02-storage.sql` - emits `D` / `C` / `O` partition metadata per
  Section 5.
- `sql/04-07`, `sql/15-16` - implement the split + DDL rules per
  Sections 3 + 4.
- `tools/audit_report.py` Section 8.1 - consumes Section 4's DDL source
  to emit valid delta suggestions.
- `tools/audit_report.py` AI prompt - embeds this document or its
  rendered summary into the prompt context. Pinned to
  `# audit_mode: pure*` to gate Section 2 suppressions.

---

## 8. How to amend this document

Pure-Mode rules evolve as Oracle releases new behaviour (26ai brings
changes, future versions will too). Amendments to this document:

1. Bump the version line below.
2. Add a row to the change log.
3. If a rule reversal is involved (something previously valid now
   suppressed, or vice versa), call it out in the change log AND open
   an issue tagged `breaking-rule-change` so downstream consumers
   (audit_report.py, CI tests) update in sync.

**Version**: 0.3.0 (2026-05-28)

**Change log**:

| Date       | Version | Change                                                                        |
|------------|---------|-------------------------------------------------------------------------------|
| 2026-05-28 | 0.3.0   | Rewrite §2.6: two-scenario model (Context vs. Pattern-based); remove tool-specific names. |
| 2026-05-28 | 0.2.0   | Add sections 2.5 (ghost events), 2.6 (off-path inference), 2.7 (purge metadata reliability). |
| 2026-05-28 | 0.1.0   | Initial draft. Addresses F1-F5 from `tasks/rework-plan.md`. |
