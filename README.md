# ora-db-audit

Oracle Unified Auditing analysis and reporting toolkit.

[![CI](https://github.com/oehrlis/ora-db-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/oehrlis/ora-db-audit/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**Author:** Stefan Oehrli, [OraDBA](https://www.oradba.ch) |
**Repo:** <https://github.com/oehrlis/ora-db-audit> |
**License:** Apache 2.0

---

## Overview

`ora-db-audit` is an open-source toolkit for Oracle DBAs and security engineers
who need to review, analyse, and report on Oracle Unified Audit configurations
and audit-trail content. It runs on the target database host, collects a
structured snapshot via SQL*Plus, optionally anonymises customer-specific
identifiers, and produces DBA-friendly Markdown reports.

**Targets:** Oracle Database 19c and 26ai, Multitenant (CDB/PDB) and Non-CDB,
Unified Auditing Pure Mode.

**No Python required for data collection.** Python is needed only for
`--anonymize`, `--report`, `--ai`, and `--export-siem`. Use `--python PATH`
to override the auto-detected interpreter (system `python3` → `python` → `$ORACLE_HOME/python`).

### Key Capabilities

- Audit posture analysis - enabled policies, trail storage, retention
- CIS Oracle DB Benchmark 5.1-5.5 coverage check (19c/23ai/26ai)
- DISA STIG 19c V1R5 compliance mapping
- Audit trail analysis - top users, actions, failed logins, privileged activity
- Off-path host detection
- Anonymised bundle workflow (pseudonymised, safe to share off-site)
- SIEM export (OCSF JSON Lines, Sentinel CSV)
- AI-assisted security findings (Claude API or `claude` CLI)

---

## Quick Start

```bash
# Option A - clone the repo
git clone https://github.com/oehrlis/ora-db-audit.git
cd ora-db-audit

# Option B - release tarball
tar xzf ora-db-audit-1.9.1.tar.gz && cd ora-db-audit-1.9.1
```

```bash
# 0. Verify all runtime dependencies (add --python PATH if system python3 is wrong)
./bin/ora-db-audit.sh --check-requirements

# 1. Collect only (no Python needed)
. oraenv && ./bin/ora-db-audit.sh --days 30 --pdb MYPDB

# 2. Collect + anonymise + render Markdown + HTML report
./bin/ora-db-audit.sh --days 30 --pdb MYPDB --anonymize --report --to-html

# 3. Offline: generate report from an existing bundle
./bin/ora-db-audit.sh --from-bundle bundle.tar.gz --report
```

Full CLI reference, patterns, and advanced examples: [docs/usage.md](docs/usage.md)

---

## Quick Start: Blind-Spot Report

Answers one question: **which database users are actually audited, and which are not.**

Every enabled Unified Audit policy is cross-checked against the catalog views, evaluating
all three Oracle entity assignment forms - `BY USER`, `BY USERS WITH GRANTED ROLES`
(resolved transitively, including roles granted to `PUBLIC`), and `EXCEPT`. A user covered
through a role is not a blind spot. A user in an `EXCEPT` clause is reported separately as
a deliberate exemption, not as a gap.

### Run it standalone (no tool setup)

The fastest path - copy the file into SQL\*Plus or SQL Developer and run it. No install,
no Python, no spool file, no bundle.

```bash
# one container (PDB, or a Non-CDB)
sqlplus / as sysdba @sql/standalone/blind-spot-pdb.sql

# all open containers of a CDB, run from CDB$ROOT
sqlplus / as sysdba @sql/standalone/blind-spot-cdb.sql
```

Required privileges: `SYSDBA`, or any account with `SELECT ANY DICTIONARY` /
`SELECT_CATALOG_ROLE`.

### Run it as part of the tool

Queries `23-blind-spot-pdb.sql` and `24-blind-spot-cdb.sql` run automatically with every
collection and feed report section 7.4:

```bash
./bin/ora-db-audit.sh --days 30 --pdb MYPDB --report
```

### Reading the result

<!-- markdownlint-disable MD013 -->
| `coverage_status` | Meaning |
| --- | --- |
| `COVERED_DIRECT` | Named explicitly in at least one enabled policy |
| `COVERED_VIA_ROLE` | Covered through a granted role - **not** a blind spot |
| `COVERED_ALL_USERS` | Covered by an unrestricted policy |
| `EXCLUDED_EXCEPT` | Not covered, and the only reason is an `EXCEPT` clause - a deliberate exemption |
| `BLIND_SPOT` | No customer-controlled policy audits this user |
<!-- markdownlint-enable -->

`coverage_status` counts customer-controlled policies only. Oracle ships
`ORA_SECURECONFIG` enabled `BY ALL USERS` on virtually every database - counting it would
mark every user as covered and make the report meaningless. Oracle-supplied coverage is
still reported, in the `ora_supplied_cover` column.

**PDB vs CDB:** Oracle provides no `CDB_AUDIT_UNIFIED_*` views - the Unified Audit catalog
views are always container-local. The CDB variant therefore uses the `CONTAINERS()` clause,
which covers **open** containers only; a `MOUNTED` PDB is silently absent. The two queries
are deliberately kept separate: they rest on different base information, and the CDB variant
becomes unreadable on a database with many PDBs.

---

## How It Works

`./bin/ora-db-audit.sh` is the single entry point:

1. Connects to the target database via `sqlplus`
2. Runs 25 SQL analysis queries (`sql/00-setup` through `sql/24-blind-spot-cdb`)
3. Writes results to CSV files and packages them into a `.tar.gz` bundle
4. Optionally: anonymises (`--anonymize`), renders report (`--report`),
   adds AI findings (`--ai`), converts to HTML (`--to-html`),
   or exports to SIEM format (`--export-siem ocsf|sentinel`)

---

## Documentation

<!-- markdownlint-disable MD013 -->
| Document | Description |
| --- | --- |
| [Installation & Setup](docs/installation.md) | Prerequisites, database user, Python packages |
| [Configuration & CLI Reference](docs/configuration.md) | All flags, options, environment variables |
| [Usage & Examples](docs/usage.md) | Use cases, workflows, end-to-end examples |
| [Troubleshooting & FAQ](docs/troubleshooting.md) | Common errors, known issues |
| [Best Practices](docs/best-practices.md) | Data sensitivity, deployment recommendations |
| [Compliance Mapping](docs/compliance-mapping.md) | CIS/STIG/Oracle BP controls |
| [AI Analysis Rules](docs/ai-analysis-rules.md) | How AI findings are generated |
| [Roadmap](docs/roadmap.md) | Planned features |
<!-- markdownlint-enable -->

---

## Repository Layout

```text
ora-db-audit/
├── bin/          - ora-db-audit.sh main entry point
├── docs/         - documentation (installation, usage, compliance, roadmap)
│   └── use-cases/ - detailed use-case deep-dives
├── scripts/      - build and release helpers (bump_version.sh)
├── sql/          - 25 SQL analysis queries (00-setup to 24-blind-spot-cdb)
├── templates/    - customer handover template, collection quick reference
├── tests/        - bats shell tests, pytest, fixture bundle
├── tools/        - Python helpers (report, anonymize, SIEM export, HTML)
├── CHANGELOG.md
├── Makefile      - lint, test, dist, release targets
├── requirements.txt - Python package requirements
└── VERSION
```

---

## Development

```bash
make lint    # markdownlint + shellcheck
make test    # bats + pytest
make dist    # build release tarball
make release # bump VERSION + CHANGELOG stub + tag
```

Install Python dependencies:

```bash
pip install -r requirements.txt
```

---

## Community

- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md)
- Security issues: [SECURITY.md](SECURITY.md)
- Disclaimer: [DISCLAIMER.md](DISCLAIMER.md)
- License: Apache 2.0 - [LICENSE](LICENSE)

---

## Related Resources

- OraDBA Blog: <https://www.oradba.ch>
- Oracle Unified Auditing docs: <https://docs.oracle.com/en/database/oracle/oracle-database/19/dbseg/configuring-audit-policies.html>
- CIS Oracle Benchmarks: <https://www.cisecurity.org/benchmark/oracle_database>
