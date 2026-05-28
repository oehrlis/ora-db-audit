# ora-db-audit

Oracle Unified Auditing analysis and reporting toolkit.

[![CI](https://github.com/oehrlis/ora-db-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/oehrlis/ora-db-audit/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

## What this is

`ora-db-audit` is an open-source toolkit for Oracle DBAs and security engineers
who need to review, analyse, and report on Oracle Unified Audit configurations
and audit-trail content. It runs on the target database host, collects a
structured snapshot via SQL*Plus, optionally anonymises customer-specific
identifiers, and produces DBA-friendly Markdown reports.

Key capabilities:

- **Audit posture analysis** - inventory enabled policies, trail storage health,
  retention configuration, CIS Benchmark 5.1-5.5 policy coverage
- **Audit-trail analysis** - top users, top actions, failed logins, privileged
  activity, noise candidates, host/client profiling, off-path detection
- **Compliance mapping** - CIS Oracle DB Benchmarks (19c/23ai/26ai),
  DISA STIG 19c V1R5, Oracle Unified Audit Best Practices v2.0
- **Anonymised bundle workflow** - raw bundle stays local; `--anonymize` produces
  a shippable pseudonymised bundle with a local reverse-mapping file
- **SIEM export** - convert a bundle to OCSF JSON Lines or Sentinel CSV via
  `--export-siem`
- **AI-assisted findings** - optional Claude API integration via `--ai`

Bash + SQL/PL/SQL first: no Python required for data collection. Python is
needed only for `--anonymize`, `--report`, `--ai`, and `--export-siem`.

## Target Platforms

- Oracle Database 19c and 26ai
- Multitenant (CDB/PDB) and Non-CDB
- Unified Auditing in Pure Mode (Mixed Mode detected and flagged)
- Oracle 21c+ multi-tenant is the default - always specify `--pdb` for PDB
  analysis

## Prerequisites

### On the database host

- `sqlplus` in `PATH` (source the Oracle environment first: `. oraenv`)
- `bash` 3.2 or later (macOS stock bash works)
- Write access to the output directory

### Python (optional - for reporting, anonymisation, SIEM export)

- Python 3.10 or later
- Standard library only - no third-party packages required (except `anthropic`
  for `--ai`)

The script auto-detects Python in this order:

1. `$ORACLE_HOME/python/bin/python` (Oracle-supplied Python)
2. `python3` in `PATH`
3. `python` in `PATH`

## Database Connectivity

### Default: OS-authenticated SYSDBA

```bash
# Connects as: / as sysdba
./bin/ora-db-audit.sh --days 30
```

On Oracle 21c+ multitenant databases, `/ as sysdba` connects to the **CDB$ROOT**
container. All audit trail queries run against the CDB-level view and return
combined data from all PDBs unless you add `--pdb`:

```bash
# Analyse a specific PDB
./bin/ora-db-audit.sh --days 30 --pdb AUDITPDB1
```

`--pdb` issues `ALTER SESSION SET CONTAINER = AUDITPDB1` after connect, limiting
all queries to that PDB's audit data.

### Non-SYSDBA login

Any database user with sufficient privileges can run the collection. Create a
dedicated audit analyst user:

```sql
CREATE USER audit_analyst IDENTIFIED BY "<password>";

-- Minimum read-only privileges for data collection:
GRANT CREATE SESSION          TO audit_analyst;
GRANT AUDIT_VIEWER            TO audit_analyst;  -- unified_audit_trail access
GRANT SELECT ON V_$INSTANCE   TO audit_analyst;  -- DB version metadata
GRANT SELECT ON DBA_AUDIT_MGMT_CONFIG_PARAMS TO audit_analyst;
GRANT SELECT ON DBA_AUDIT_MGMT_CLEANUP_JOBS  TO audit_analyst;
GRANT SELECT ON DBA_AUDIT_MGMT_LAST_ARCH_TS  TO audit_analyst;
GRANT SELECT ON DBA_PART_TABLES              TO audit_analyst;
GRANT SELECT ON DBA_TAB_PARTITIONS           TO audit_analyst;
GRANT SELECT ON DBA_SEGMENTS                TO audit_analyst;
GRANT SELECT ON UNIFIED_AUDIT_POLICIES       TO audit_analyst;
GRANT SELECT ON AUDIT_UNIFIED_ENABLED_POLICIES TO audit_analyst;
GRANT SELECT ON DBA_ROLE_PRIVS              TO audit_analyst;

-- For DBMS_METADATA DDL extraction (sql/16-policy-ddl.sql):
GRANT EXECUTE ON DBMS_METADATA  TO audit_analyst;

-- For CDB-wide collection (optional, CDB$ROOT only):
-- GRANT AUDIT_VIEWER TO audit_analyst CONTAINER = ALL;
```

Then connect with:

```bash
./bin/ora-db-audit.sh --days 30 \
    --connect "audit_analyst/<password>@DBSID" \
    --pdb AUDITPDB1
```

### Wallet / passwordless connection

```bash
./bin/ora-db-audit.sh --days 30 \
    --connect "/@DBSID_AUDIT" \
    --pdb AUDITPDB1
```

Requires a `sqlnet.ora` / `tnsnames.ora` / wallet entry for `DBSID_AUDIT`.

## Quick Start

```bash
# Option A - clone the repo
git clone https://github.com/oehrlis/ora-db-audit.git
cd ora-db-audit

# Option B - deploy from the release tarball
tar xzf ora-db-audit-1.2.0.tar.gz
cd ora-db-audit-1.2.0
```

Canonical entry point: `./bin/ora-db-audit.sh`
The dist tarball also ships a root convenience wrapper `./ora-db-audit` (no
`.sh`) that delegates to `bin/`.

## Use Cases

### UC-1: Local collection only (no Python needed)

Run on the database host, collect raw CSV bundle, inspect manually.

```bash
. oraenv  # source Oracle environment
./bin/ora-db-audit.sh \
    --days 30 \
    --pdb AUDITPDB1 \
    --output ./output
```

Output: `./output/ora-db-audit_<sid>_<ts>.tar.gz` (raw bundle with real data).
No Python required. Keep the bundle **local** - it contains real usernames,
hostnames, and SQL text.

### UC-2: Collect, anonymise, and share bundle

Produce a shippable bundle with pseudonymised identifiers for off-site analysis.

```bash
./bin/ora-db-audit.sh \
    --days 30 \
    --pdb AUDITPDB1 \
    --anonymize \
    --customer-prefix ACME \
    --output ./output
```

Produces:

- `ora-db-audit_<sid>_<ts>.tar.gz` - raw bundle (keep local)
- `ora-db-audit_<sid>_<ts>.anon/` - anonymised bundle (safe to share)
- `ora-db-audit_<sid>_<ts>.mapping.json` - reverse map (**keep local**)

### UC-3: Collect, anonymise, and render report locally

Full on-host workflow including a Markdown report.

```bash
./bin/ora-db-audit.sh \
    --days 30 \
    --pdb AUDITPDB1 \
    --anonymize \
    --report \
    --patterns /etc/ora-db-audit/patterns.json \
    --output ./output
```

The report is rendered against the anonymised bundle and is safe to share
externally. Add `--ai` to append Claude API findings (requires `anthropic`
package and API key).

### UC-4: Remote report from existing bundle (offline mode)

Analyst machine - no database access required. Re-render or update a report
from a bundle that was collected on another host.

```bash
# Extract and render
./bin/ora-db-audit.sh \
    --from-bundle ./bundles/ora-db-audit_free_20260528.tar.gz \
    --report \
    --output ./reports
```

```bash
# Re-render with AI findings added later
./bin/ora-db-audit.sh \
    --from-bundle ./bundles/ora-db-audit_free_20260528.tar.gz \
    --report --ai \
    --ai-model claude-opus-4-7 \
    --output ./reports
```

```bash
# Export AI prompt for manual paste into any LLM chat UI
./bin/ora-db-audit.sh \
    --from-bundle ./bundles/ora-db-audit_free_20260528.tar.gz \
    --report \
    --output ./reports
# Then from the extracted bundle directory:
python3 tools/audit_report.py ./reports/ora-db-audit_free_20260528 \
    --export-prompt ./reports/ai_prompt.txt
```

### UC-5: Large audit trails (>10M rows)

Limit source rows for the heavy profiling queries to keep collection time under
5 minutes.

```bash
./bin/ora-db-audit.sh \
    --days 30 \
    --pdb AUDITPDB1 \
    --sample-rows 500000 \
    --report \
    --output ./output
```

`--sample-rows N` injects `ROWNUM <= N` into queries 08-12 and 15. Absolute
event counts in the report become estimates; relative rankings remain
representative. The executive summary includes a sampling notice.

### UC-6: SIEM export

Convert a bundle to OCSF JSON Lines for generic SIEM ingestion, or Sentinel CSV
for Microsoft Log Analytics.

```bash
# OCSF JSON Lines
./bin/ora-db-audit.sh \
    --from-bundle ./bundles/bundle.tar.gz \
    --export-siem ocsf ./output/audit_events.jsonl

# Sentinel CSV
./bin/ora-db-audit.sh \
    --from-bundle ./bundles/bundle.tar.gz \
    --export-siem sentinel ./output/audit_events.csv
```

Or directly against the Python tool:

```bash
python3 tools/export_siem.py ./bundle_dir \
    --format ocsf \
    --output ./audit_events.jsonl
```

## Command Reference

```text
./bin/ora-db-audit.sh [OPTIONS]

Collection:
  --days N             Time window in days (default: 30)
  --top-n N            Top N rows per query (default: 100)
  --sample-rows N      Limit source rows in heavy queries 08-12,15 via
                       ROWNUM <= N. Default 0 (no limit). For large trails.
  --connect "CONN"     sqlplus connect string (default: "/ as sysdba")
                       Examples:
                         "/ as sysdba"
                         "audit_analyst/secret@DBSID"
                         "/@DBSID_WALLET"
  --pdb NAME           Switch to PDB NAME after connect via
                       ALTER SESSION SET CONTAINER.
  --output DIR         Output directory (default: ./audit_bundle)

Anonymisation:
  --anonymize          Run anonymise_bundle.py after collection.
                       Produces .anon/ + .mapping.json + .anon.tar.gz.
  --customer-prefix P  Prefix kept visible in pseudonym namespacing.
  --deanonymize        Restore real values in report .md files.
                       Requires .mapping.json next to the bundle.
  --mapping FILE       Explicit .mapping.json path (with --deanonymize).

Reporting:
  --report             Render audit_report.md from the bundle.
  --lang de|en         Report language (default: de). Requires --report.
  --export-prompt FILE Write the full AI prompt to FILE instead of calling
                       the API. Self-contained for any LLM chat UI.
                       Requires --report. No API key needed.
  --patterns FILE      Host-pattern config JSON for report classification.
  --tools-dir DIR      Override Python tools location.

  From the Python tool directly (offline):
    python3 tools/audit_report.py BUNDLE_DIR [--lang de|en]
                                             [--export-prompt FILE]
                                             [--top-n N]

AI findings:
  --ai                 Append Claude API findings (implies --report).
  --ai-model MODEL     Claude model (default: claude-sonnet-4-6).
  --ai-op-path PATH    1Password op:// path for the Anthropic API key.

SIEM export:
  --export-siem FORMAT OUTPUT
                       Convert bundle to FORMAT (ocsf|sentinel) and write
                       to OUTPUT. Runs after collection or --from-bundle.

Offline mode:
  --from-bundle FILE   Extract existing bundle and run post-processing.
                       No database connection required.

General:
  --dry-run            Print actions; do not execute.
  --yes,-y             Overwrite existing output without prompting.
  --help               Show this help.
```

## Multitenant (CDB/PDB) Reference

<!-- markdownlint-disable MD013 MD060 -->
| Scenario | Command |
| --- | --- |
| CDB-wide (all containers) | `--connect "/ as sysdba"` (no --pdb) |
| Specific PDB, SYSDBA | `--connect "/ as sysdba" --pdb MYPDB` |
| Specific PDB, named user | `--connect "user/pw@SID" --pdb MYPDB` |
| Non-CDB (19c traditional) | `--connect "/ as sysdba"` (no --pdb) |
| Wallet + PDB | `--connect "/@SID_WALLET" --pdb MYPDB` |
<!-- markdownlint-enable MD013 MD060 -->

On **Oracle 21c+** all databases are multitenant by default. Running without
`--pdb` queries the CDB$ROOT view which aggregates all PDBs; this is often what
you want for a fleet overview but not for a PDB-specific audit review.

The `UNIFIED_AUDIT_TRAIL` view is container-aware: when you switch to a PDB
with `ALTER SESSION SET CONTAINER`, it shows only that PDB's records. The
`--pdb` flag does exactly this switch.

## Output Structure

```text
output/
  ora-db-audit_<DBSID>_<TS>/
    00_setup.log              (sqlplus session log)
    01_config.csv             audit configuration + mode
    02_storage.csv            AUD$UNIFIED partition health
    03_policy_inventory.csv   enabled policies
    04_policy_volume.csv      events per policy
    05_policy_user_action.csv top (policy, user, action) combos
    06_policy_client_prog.csv top (policy, client_program) combos
    07_policy_host.csv        top (policy, userhost) combos
    08_top_users.csv          top DB users by event count
    09_top_actions.csv        top action_name values
    10_top_objects.csv        top accessed objects
    11_host_user_program.csv  host x user x program matrix
    12_distinct_hosts.csv     distinct userhosts with first/last seen
    13_failed_logins.csv      failed login attempts (ORA-01017)
    14_privileged_activity.csv SYS/AUDIT_ADMIN events
    15_noise_candidates.csv   high-volume low-risk tuning candidates
    16_policy_ddl.csv         DBMS_METADATA DDL per policy
    17_cis_coverage.csv       CIS 5.1-5.5 PASS/WARN/FAIL
    18_audit_roles.csv        AUDIT_ADMIN/AUDIT_VIEWER members
    19_offpath_candidates.csv  hosts not matching app/infra/DBA patterns
    manifest.json
    README.md
    _sqlplus.log
  ora-db-audit_<DBSID>_<TS>.tar.gz          bundle
  ora-db-audit_<DBSID>_<TS>.anon/           anonymised bundle
  ora-db-audit_<DBSID>_<TS>.mapping.json    reverse map (KEEP LOCAL)
  audit_report.md                            Markdown report
```

## Report Sections

<!-- markdownlint-disable MD013 MD060 -->
| Section | Content |
| --- | --- |
| Executive Summary | DBSID, time window, key metrics, top volume drivers, host summary |
| 1. Audit Configuration | Mode (pure/mixed/unsupported), parameters, legacy suppression |
| 2. Trail Storage | AUD$UNIFIED partition layout, tablespace verdict (MISCONFIG/OK/TRANSIENT) |
| 3. Policy Inventory | All enabled policies with type and scope |
| 4-7. Volume Analysis | Events by policy, user, client program, host |
| 8. Top-N Tables | Top users, actions, objects, host/user/program matrix |
| 8.1 Tuning Candidates | WHEN-clause suggestions grounded in actual policy DDL |
| 9. CIS Coverage | CIS 5.1-5.5 PASS/WARN/FAIL table |
| 10. Audit Roles | AUDIT_ADMIN/AUDIT_VIEWER grantees with risk flags |
| 11. AI Findings | Claude-generated security signal analysis (with --ai) |
<!-- markdownlint-enable MD013 MD060 -->

Report language: German by default (`--lang de`). English available via
`--lang en` in `audit_report.py`.

## SQL Queries

<!-- markdownlint-disable MD013 MD060 -->
| File | Purpose | CIS Controls |
| --- | --- | --- |
| `00-setup.sql` | Session setup, DEFINE injection (LOGDIR, days, top_n, sampled) | - |
| `01-config.sql` | Audit configuration, mode detection (pure/mixed/unsupported) | - |
| `02-storage.sql` | AUD$UNIFIED partition layout + trail management health | - |
| `03-policy-inventory.sql` | All enabled unified audit policies | 5.1-5.5 |
| `04-07-*.sql` | Volume by policy, user+action, client program, host | 5.1, 5.2 |
| `08-12-*.sql` | Top users, actions, objects, host/user/program, distinct hosts | - |
| `13-failed-logins.sql` | Failed logon attempts (ORA-01017) | 5.2 |
| `14-privileged-activity.sql` | SYS/SYSTEM/AUDIT_ADMIN/SYSBACKUP events | 5.5 |
| `15-noise-candidates.sql` | High-volume policy/user/action combinations (WHEN-clause tuning) | - |
| `16-policy-ddl.sql` | DBMS_METADATA DDL per enabled policy | 5.1-5.5 |
| `17-cis-coverage.sql` | CIS 5.1-5.5 policy presence + enabled/disabled check | 5.1-5.5 |
| `18-audit-roles.sql` | AUDIT_ADMIN and AUDIT_VIEWER role membership + risk flags | - |
| `19-offpath-candidates.sql` | Hosts not matching app/infra/DBA patterns | - |
<!-- markdownlint-enable MD013 -->

Queries 08-12 and 15 support `--sample-rows N` via `ROWNUM <= N` injection.

## Patterns File

`--patterns FILE` provides deployment-specific host regex patterns for
Section 7/11 host classification (APP / INFRA / DBA / OFF-PATH).

```json
{
  "app_host_patterns":   ["^webserver-", "^app-"],
  "infra_host_patterns": ["^db-", "^oem-", "^backup-"],
  "dba_host_patterns":   ["^laptop-", "^jumphost-", "^mgmt-"]
}
```

Without a patterns file, the built-in default patterns are used (suitable
for the `auditlab` test environment only; always supply your own for
production).

## SIEM Export

`tools/export_siem.py` converts aggregated bundle data to SIEM formats:

- **ocsf**: OCSF 1.3 Database Activity (class 3005) JSON Lines. One record per
  aggregate row with OCSF-mapped fields and event counts. Compatible with any
  SIEM that accepts OCSF.
- **sentinel**: Flat CSV for Microsoft Sentinel / Log Analytics custom tables.
  Columns: TimeGenerated, DbSid, Pdb, DbUser, OsUser, UserHost, ClientProgram,
  ActionName, ReturnCode, EventCount, FirstSeen, LastSeen, QuerySource,
  Classification.

Default source queries: 08, 11, 13, 14, 19. Override with `--sources 11,13`.

Note: the bundle contains aggregated rows, not individual audit events. Each
exported record has an `EventCount` field. Use for profiling and trend analysis;
not for forensic event replay.

## Development

```bash
make lint          # markdownlint + shellcheck
make test          # bats + pytest
make test-bats     # bats-core shell tests only
make test-pytest   # pytest only
make dist          # build release tarball
make release       # bump VERSION + CHANGELOG stub + tag
```

Tests require `bats-core` (for shell tests) and Python 3 (for pytest).
Pytest runs without a live Oracle database using the fixture bundle in
`tests/fixtures/sample_bundle/`.

## Compliance References

- [docs/compliance-mapping.md](docs/compliance-mapping.md) - Full CIS/STIG/Oracle BP mapping
- CIS Oracle Database Benchmarks: 19c v2.0.0, 23ai v1.1.0, 26ai v1.0.0
- DISA STIG Oracle 19c V1R5
- Oracle Unified Audit Best Practice Guidelines v2.0 (April 2025)

## Repository Layout

```text
ora-db-audit/
├── .github/workflows/    - CI (markdownlint, shellcheck, bats, pytest)
├── bin/                  - ora-db-audit.sh entry point
├── docs/                 - documentation, use cases, compliance mapping
│   └── use-cases/        - audit-analysis, audit-log-anonymisation, off-path-detection
├── scripts/              - bump_version.sh, release helpers
├── sql/                  - 19 SQL analysis queries (00-setup to 19-offpath)
├── templates/            - customer-handover.md template
├── tests/
│   ├── bats/             - shell tests (test-cli-parse, test-from-bundle)
│   ├── fixtures/         - sample_bundle/ (anonymised, commit-safe)
│   └── python/           - pytest (report render, anonymizer round-trip)
├── tools/                - Python helpers (anonymize, report, deanonymize, export_siem)
├── CHANGELOG.md
├── Makefile              - lint, test, dist, release targets
└── VERSION
```

## License

Apache License 2.0 - see [LICENSE](LICENSE).

## Related Resources

- [Stefan Oehrli - OraDBA Blog](https://www.oradba.ch)
- [Oracle Unified Auditing Documentation](https://docs.oracle.com/en/database/oracle/oracle-database/19/dbseg/configuring-audit-policies.html)
- [CIS Oracle Database Benchmarks](https://www.cisecurity.org/benchmark/oracle_database)
- [OCSF Schema](https://schema.ocsf.io/1.3.0/classes/database_activity)

## Contributing

Issues and pull requests welcome - see [CONTRIBUTING.md](CONTRIBUTING.md).

## Disclaimer

Audit data is sensitive. Read [DISCLAIMER.md](DISCLAIMER.md) and
[SECURITY.md](SECURITY.md) before running this toolkit against production
databases. The `.mapping.json` file from `--anonymize` contains real customer
values - it must stay local and never be included in bundles shared externally.
