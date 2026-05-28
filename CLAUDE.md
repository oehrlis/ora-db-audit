# CLAUDE.md - ora-db-audit

## Purpose

Oracle Unified Auditing analysis and reporting toolkit (open source).
This repo provides DBA-friendly scripts and queries that collect a
structured audit-trail snapshot from a target Oracle database,
anonymise customer-specific identifiers, and produce reports.

Target: Oracle 19c and 26ai (CDB/PDB and Non-CDB), Unified Auditing
in Pure Mode. Bash + SQL/PL/SQL first, optional Python for richer
reports.

---

## Repository Layout

```text
ora-db-audit/
├── .claude/                ← claude commands, rules, skills (symlinks)
├── .github/                ← GitHub workflows (later)
├── docs/                   ← documentation, use cases, handover guides
├── bin/                    ← main bash entry point (ora-db-audit.sh)
├── sql/                    ← SQL analysis queries
├── tools/                  ← optional Python reporters
├── scripts/                ← build / release / helper scripts
├── templates/              ← generic templates (customer handover etc.)
├── tests/                  ← test scripts and fixtures
├── CHANGELOG.md            ← versioned change history
├── CONTRIBUTING.md         ← how to contribute
├── DISCLAIMER.md           ← no warranty, data-sensitivity notice
├── LICENSE                 ← Apache License 2.0
├── Makefile                ← lint, version, release, changelog targets
├── README.md               ← project overview
├── SECURITY.md             ← vulnerability reporting, audit-data handling
└── VERSION                 ← SemVer release marker
```

---

## Skills

Primary skill for all audit-related work:

```text
/oracle-audit               ← canonical Oracle Unified Auditing skill (ai-toolkit)
```

Use `/oracle-audit` for: policy design (common vs local, CDB vs PDB),
trail management (DBMS_AUDIT_MGMT, purge, retention, partitioning),
compliance mapping (CIS, PCI-DSS, ISO 27001), Mixed-to-Pure migration.

Always-load supporting skills:

```text
/bash-header                ← OraDBA bash script template (mandatory for new .sh)
/makefile                   ← OraDBA Makefile standard (lint, release, version-bump)
/markdown-lint              ← markdown standards (MD013 line_length: 120)
```

Load on demand:

```text
/oracle-datasafe            ← OCI Data Safe integration
/oracle-tde                 ← Transparent Data Encryption
/oracle-security            ← cross-cutting database security
```

---

## Coding Conventions

### Bash

- `set -euo pipefail` at the top of every script
- OraDBA header (use `/bash-header` skill) for every new script
- No subshell anti-patterns in loops (run `/bash-perf-audit` after
  significant additions)
- Quote all variable expansions: `"${var}"` not `$var`

### SQL / PL/SQL

- Audit policy names use a customer-configurable prefix (default
  placeholder: `OUA_` for "Oracle Unified Audit")
- Always pair `AUDIT POLICY` with `NOAUDIT POLICY` for clean teardown
- Use `dbms_output.put_line` consistently for status messages
- Apache 2.0 header in every standalone SQL file

### Python (optional reporters)

- Python 3.10+
- Standard library first; external deps only when necessary
- Type hints for public functions
- `ruff` + `mypy` clean

### Markdown

- `markdownlint` MD013 line_length: 120 (see `.markdownlint.json`)
- Hyphen-minus only (no em-dash / en-dash typography)
- First line must be a top-level heading (MD041)

---

## Versioning and Releases

- SemVer (MAJOR.MINOR.PATCH) in `VERSION`
- Every release entry in `CHANGELOG.md` follows Keep a Changelog format
- Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:` ...)
- Pre-v1.0: breaking changes allowed in MINOR bumps; documented
  explicitly in CHANGELOG
- `make release` workflow (defined in Makefile) bumps VERSION,
  updates CHANGELOG, tags

---

## Data Sensitivity

This toolkit collects audit-trail data, which routinely contains:

- DB usernames, OS usernames, host names
- Client program names, terminal identifiers
- IP addresses (network audit)
- SQL text (full SQL_TEXT in some audit unified records)

The default operating mode is **anonymise at source** - mapping
customer-specific values to placeholders before any output bundle
leaves the target environment. Mapping files (`*.mapping.json`)
stay local and are gitignored.

When reviewing or modifying anonymisation logic: always assume the
data could re-identify individuals if mishandled.

---

## Cross-Refs

- Internal predecessor (NDA / customer-engineering): `ora-db-audit-eng/artefacts/audit_pack-0.5.0/`
- PKM project tracker: `~/notes/projects/audit-tool.md`
- Follow-up session briefing: `INITIAL_PROMPT.md`
- OraDBA blog: <https://www.oradba.ch>
