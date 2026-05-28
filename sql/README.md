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
<!-- markdownlint-enable -->

Queries 08-12 and 15 support `--sample-rows N` via `ROWNUM <= N` injection for large audit trails.
