# ora-db-audit

Oracle Unified Auditing analysis and reporting toolkit.

> **Status:** Pre-Alpha (v0.1.0) - repository scaffolding only.
> Content migration and v1.0.0 development happens in a follow-up
> session (see `INITIAL_PROMPT.md`).

## What this is

`ora-db-audit` is an open-source toolkit that helps Oracle DBAs and
security engineers analyse Oracle Unified Audit configurations and
audit-trail content. It collects a structured snapshot from a target
database, anonymises customer-specific identifiers, and produces
DBA-friendly reports.

Primary use cases:

- **Audit posture analysis** - inventory active unified audit policies,
  storage configuration, retention behaviour
- **Audit-trail analysis** - top users, top actions, failed logins,
  privileged activity, noise candidates
- **Customer engagement workflow** - reproducible audit snapshots,
  anonymised by default, suitable for off-site analysis

The toolkit is bash + SQL/PL/SQL first (DBA-friendly, no Python in PATH
required) with optional Python modules for richer reporting.

## Target Platforms

- Oracle Database 19c and 26ai (formerly 23ai)
- Multitenant (CDB/PDB) and Non-CDB
- On-premises and OCI (Autonomous Database with limitations)
- Unified Auditing in Pure Mode (Mixed Mode partially supported)

## Repository Layout

```text
ora-db-audit/
├── docs/         - documentation, use cases, handover guides
├── src/          - main bash entry point and modules
├── sql/          - SQL analysis queries
├── tools/        - optional Python reporters
├── scripts/      - build / release / helper scripts
├── templates/    - generic templates (customer handover, etc.)
├── tests/        - test scripts and fixtures
├── CLAUDE.md     - AI-assisted development guidance
├── Makefile      - lint, version, release targets
└── VERSION       - SemVer release marker
```

## Quickstart

> Will be filled in v1.0.0 - currently scaffolding only.

Planned workflow:

```bash
# 1. Configure target connect
export ORADBA_AUDIT_TARGET="user/pwd@TNS"

# 2. Run analysis snapshot (anonymised by default)
./src/ora-db-audit run --target $ORADBA_AUDIT_TARGET --output ./audit_bundle

# 3. Render reports
./tools/audit_report.py ./audit_bundle --format markdown
```

## License

Apache License 2.0 - see [LICENSE](LICENSE).

## Related Resources

- [Stefan Oehrli - OraDBA Blog](https://www.oradba.ch)
- [Oracle Unified Auditing - Oracle Docs](https://docs.oracle.com/en/database/oracle/oracle-database/26/dbseg/configuring-audit-policies.html)
- [CIS Oracle Database Benchmarks](https://www.cisecurity.org/benchmark/oracle_database)

## Contributing

Issues and pull requests welcome - see [CONTRIBUTING.md](CONTRIBUTING.md).

## Disclaimer

Audit data is sensitive. Read [DISCLAIMER.md](DISCLAIMER.md) and
[SECURITY.md](SECURITY.md) before running this toolkit against
production databases.
