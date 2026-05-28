# ora-db-audit

Oracle Unified Auditing analysis and reporting toolkit.

[![CI](https://github.com/oehrlis/ora-db-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/oehrlis/ora-db-audit/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

## What this is

`ora-db-audit` is an open-source toolkit that helps Oracle DBAs and security
engineers analyse Oracle Unified Audit configurations and audit-trail content.
It collects a structured snapshot from a target database, anonymises
customer-specific identifiers, and produces DBA-friendly Markdown reports.

Key capabilities:

- **Audit posture analysis** - inventory enabled policies, trail storage,
  retention configuration, CIS Benchmark coverage (5 Level 1 controls)
- **Audit-trail analysis** - top users, top actions, failed logins, privileged
  activity, noise candidates, host/client profiling
- **Compliance mapping** - CIS Oracle DB Benchmarks (19c/23ai/26ai),
  DISA STIG 19c V1R5, Oracle Unified Audit Best Practices v2.0
- **Anonymised workflow** - raw bundle stays local; `--anonymize` produces a
  shippable pseudonymised bundle with a local reverse-mapping file

The toolkit is bash + SQL/PL/SQL first (no Python required for data collection)
with optional Python tools for anonymisation, reporting, and AI-assisted
findings.

## Target Platforms

- Oracle Database 19c and 26ai
- Multitenant (CDB/PDB) and Non-CDB
- Unified Auditing in Pure Mode (Mixed Mode is detected but flagged)

## Quick Start

```bash
# Option A - clone the repo
git clone https://github.com/oehrlis/ora-db-audit.git
cd ora-db-audit

# Option B - deploy from the release tarball
tar xzf ora-db-audit-1.0.1.tar.gz
cd ora-db-audit-1.0.1
```

In both cases the canonical entry point is `./bin/ora-db-audit.sh`.
The dist tarball also includes a convenience wrapper `./ora-db-audit`
(no `.sh` extension) at the root that delegates to `bin/`.

```bash
# Run data collection against the local DB (as SYSDBA)
./bin/ora-db-audit.sh --days 30 --top-n 100 --output ./output

# With anonymisation + Markdown report
./bin/ora-db-audit.sh --days 30 --anonymize --report --output ./output

# Offline mode: re-render a report from an existing bundle
./bin/ora-db-audit.sh --from-bundle ./output/ora-db-audit_free_20260512.tar.gz \
    --report --output ./output
```

### Output structure

```text
output/
  ora-db-audit_<DBSID>_<TS>/
    01_config.csv ... 18_audit_roles.csv   # raw query data
    manifest.json
    README.md
  ora-db-audit_<DBSID>_<TS>.tar.gz        # shippable bundle
  ora-db-audit_<DBSID>_<TS>.anon/         # anonymised bundle (with --anonymize)
  ora-db-audit_<DBSID>_<TS>.mapping.json  # reverse map - KEEP LOCAL
  audit_report.md                          # Markdown report (with --report)
```

## Repository Layout

```text
ora-db-audit/
├── .github/workflows/    - CI (markdownlint, shellcheck, bats, pytest)
├── bin/                  - ora-db-audit.sh entry point
├── docs/                 - documentation, use cases, compliance mapping
│   └── use-cases/        - audit-analysis.md, audit-log-anonymisation.md
├── scripts/              - bump_version.sh, release helpers
├── sql/                  - 18 SQL analysis queries (00-setup to 18-audit-roles)
├── templates/            - customer-handover.md template
├── tests/
│   ├── bats/             - shell tests (test-cli-parse, test-from-bundle)
│   ├── fixtures/         - sample_bundle/ (anonymised, commit-safe)
│   └── python/           - pytest (report render, anonymizer round-trip)
├── tools/                - Python helpers (anonymize, report, deanonymize)
├── CHANGELOG.md
├── Makefile              - lint, test, dist, release targets
└── VERSION
```

## SQL Queries

| File                         | Purpose                                   | CIS Controls |
|------------------------------|-------------------------------------------|--------------|
| `01-config.sql`              | Audit configuration, mode detection       | -            |
| `02-storage.sql`             | AUD$UNIFIED partition + trail mgmt health | -            |
| `03-policy-inventory.sql`    | All enabled policies                      | 5.1-5.5      |
| `04-07-*.sql`                | Volume by policy, user, client, host      | 5.1, 5.2     |
| `08-12-*.sql`                | Top users, actions, objects, hosts        | -            |
| `13-failed-logins.sql`       | Failed logon attempts                     | 5.2          |
| `14-privileged-activity.sql` | SYS/SYSTEM/AUDIT_ADMIN events             | 5.5          |
| `15-noise-candidates.sql`    | High-volume low-risk candidates           | -            |
| `16-policy-ddl.sql`          | DBMS_METADATA DDL per policy              | 5.1-5.5      |
| `17-cis-coverage.sql`        | CIS 5.1-5.5 policy coverage check         | 5.1-5.5      |
| `18-audit-roles.sql`         | AUDIT_ADMIN/AUDIT_VIEWER membership       | -            |

## Development

```bash
# Lint
make lint

# Test (requires bats-core + pytest)
make test

# Build distribution tarball
make dist
```

## Compliance References

- [docs/compliance-mapping.md](docs/compliance-mapping.md) - Full CIS/STIG/Oracle BP mapping
- CIS Oracle Database Benchmarks: 19c v2.0.0, 23ai v1.1.0, 26ai v1.0.0
- DISA STIG Oracle 19c V1R5
- Oracle Unified Audit Best Practice Guidelines v2.0 (April 2025)

## License

Apache License 2.0 - see [LICENSE](LICENSE).

## Related Resources

- [Stefan Oehrli - OraDBA Blog](https://www.oradba.ch)
- [Oracle Unified Auditing Documentation](https://docs.oracle.com/en/database/oracle/oracle-database/19/dbseg/configuring-audit-policies.html)
- [CIS Oracle Database Benchmarks](https://www.cisecurity.org/benchmark/oracle_database)

## Contributing

Issues and pull requests welcome - see [CONTRIBUTING.md](CONTRIBUTING.md).

## Disclaimer

Audit data is sensitive. Read [DISCLAIMER.md](DISCLAIMER.md) and
[SECURITY.md](SECURITY.md) before running this toolkit against production
databases.
