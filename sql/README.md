# sql/

SQL analysis queries executed by `ora-db-audit.sh` via SQL*Plus.

Files are run in sequence. Each query writes its output to a CSV file in the bundle directory.

## Query Files

<!-- markdownlint-disable MD013 MD060 -->
| File | Purpose | CIS Controls |
|------|---------|--------------|
| `00-setup.sql` | Session setup, DEFINE injection (LOGDIR, days, top_n, sampled) | - |
| `01-config.sql` | Audit configuration, mode detection (pure/mixed/unsupported) | - |
| `02-storage.sql` | AUD$UNIFIED partition layout + trail management health | - |
| `03-policy-inventory.sql` | All enabled unified audit policies | 5.1-5.5 |
| `04-policy-volume.sql` | Event count per enabled policy | 5.1, 5.2 |
| `05-policy-user-action.sql` | Top (policy, user, action) combinations | 5.1, 5.2 |
| `06-policy-client-program.sql` | Top (policy, client_program) combinations | - |
| `07-policy-host.sql` | Top (policy, userhost) combinations | - |
| `08-top-users.sql` | Top DB users by event count | - |
| `09-top-actions.sql` | Top action_name values | - |
| `10-top-objects.sql` | Top accessed objects | - |
| `11-host-user-program.sql` | Host x user x program matrix | - |
| `12-distinct-hosts.sql` | Distinct userhosts with first/last seen timestamps | - |
| `13-failed-logins.sql` | Failed login attempts (ORA-01017) | 5.2 |
| `14-privileged-activity.sql` | SYS/SYSTEM/AUDIT_ADMIN/SYSBACKUP events | 5.5 |
| `15-noise-candidates.sql` | High-volume low-risk WHEN-clause tuning candidates | - |
| `16-policy-ddl.sql` | DBMS_METADATA DDL per enabled policy | 5.1-5.5 |
| `17-cis-coverage.sql` | CIS 5.1-5.5 policy presence + enabled/disabled check | 5.1-5.5 |
| `18-audit-roles.sql` | AUDIT_ADMIN and AUDIT_VIEWER role membership + risk flags | - |
| `19-offpath-candidates.sql` | Hosts not matching app/infra/DBA patterns | - |
| `20-fp-role-grantees.sql` | Cross-reference BY GRANTED ROLE policy bindings with actual role grants | - |
| `21-uncovered-users.sql` | DB users not covered by any enabled non-logon audit policy (3 coverage tiers) | 5.1, 5.2 |
| `22-crit-pkg-executions.sql` | Audit trail events for the 19 CIS 5.1.3 critical SYS packages | 5.3 |
| `23-blind-spot-pdb.sql` | Blind-spot report, PDB scope (current container, dba_* views) | 5.1, 5.2 |
| `24-blind-spot-cdb.sql` | Blind-spot report, CDB scope (CONTAINERS() + cdb_* views, all open PDBs) | 5.1, 5.2 |
| `25-policy-effectiveness.sql` | Policy effectiveness, PDB scope - enabled policies that reach nobody | 5.1, 5.2 |
| `26-policy-effectiveness-cdb.sql` | Policy effectiveness, CDB scope (CONTAINERS() + cdb_* views) | 5.1, 5.2 |
<!-- markdownlint-restore -->

Queries 08-12 and 15 support `--sample-rows N` via `ROWNUM <= N` injection for large audit trails.

---

## Standalone Queries

The `sql/standalone/` directory contains copy-paste-ready versions of selected queries.
These files are designed to run directly in SQL*Plus or SQL Developer without any tool
setup, bundle directory, or spool configuration.

<!-- markdownlint-disable MD013 MD060 -->
| File | Description |
|------|-------------|
| `sql/standalone/blind-spot-pdb.sql` | Blind-spot **summary** for a single container (PDB or Non-CDB) |
| `sql/standalone/blind-spot-cdb.sql` | Blind-spot **summary** across all open PDBs in a CDB |
<!-- markdownlint-restore -->

The standalone files are **not** copies of the numbered queries. The numbered queries emit
one CSV row per user (per container) for the reporting pipeline; the standalone files
condense the same model into a screen-readable roll-up - scorecard, container matrix,
coverage matrix, actionable blind spots, name-pattern groups and policy effectiveness.
They also cover queries 25/26, so one script answers both "who is unaudited" and "which
policy is silently doing nothing".

See [sql/standalone/README.md](standalone/README.md) for the output blocks, report
controls and required privileges.
