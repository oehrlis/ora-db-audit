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
`--anonymize`, `--report`, `--ai`, and `--export-siem`.

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
tar xzf ora-db-audit-1.4.0.tar.gz && cd ora-db-audit-1.4.0
```

```bash
# 1. Collect only (no Python needed)
. oraenv && ./bin/ora-db-audit.sh --days 30 --pdb MYPDB

# 2. Collect + anonymise + render Markdown report
./bin/ora-db-audit.sh --days 30 --pdb MYPDB --anonymize --report

# 3. Offline: generate report from an existing bundle
./bin/ora-db-audit.sh --from-bundle bundle.tar.gz --report
```

Full CLI reference, patterns, and advanced examples: [docs/usage.md](docs/usage.md)

---

## How It Works

`./bin/ora-db-audit.sh` is the single entry point:

1. Connects to the target database via `sqlplus`
2. Runs 20 SQL analysis queries (`sql/00-setup` through `sql/19-offpath`)
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
├── sql/          - 20 SQL analysis queries (00-setup to 19-offpath)
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
