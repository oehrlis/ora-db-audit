# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.1] - 2026-05-28

### Added

- `ora-db-audit.sh` root wrapper in the dist tarball - thin delegating
  script (`exec .../bin/ora-db-audit.sh "$@"`) so both
  `./ora-db-audit.sh` and `./bin/ora-db-audit.sh` work after extracting
  the tarball.

### Changed

- `Makefile` dist layout: `bin/ora-db-audit.sh` is now placed inside a
  `bin/` subdirectory (matching the repo-clone layout) instead of the
  tarball root. `dist_manifest.json` entrypoint field updated accordingly.
- `README.md` Quick Start: documents Option A (clone) and Option B (tarball)
  install paths; clarifies `./bin/ora-db-audit.sh` as the canonical entry
  point in both environments with the root wrapper as a convenience alias.

### Fixed

- `Makefile` dist / `bin/ora-db-audit.sh` - `REPO_ROOT` was computed as
  `parent(SCRIPT_DIR)` which resolves correctly only when the script lives
  in `bin/`. The v1.0.0 tarball placed the script at the install root,
  making `REPO_ROOT` point one directory too high and causing
  `ERROR: missing query file: .../sql/00-setup.sql` on every run. Fixed by
  keeping the `bin/` layout in the dist tarball so the path calculation is
  identical whether running from a clone or a tarball extract.
- `.github/workflows/ci.yml` - `sudo npm install -g bats` fixes EACCES
  permission error on Ubuntu runner (`/usr/local/share/man/man7`).
- `Makefile` `test-pytest` - pytest availability now checked at recipe
  execution time via `python -m pytest --version` instead of the
  parse-time `PYTEST` variable, which silently evaluated to empty when
  pytest is available as a module but not as a standalone binary in `PATH`.

## [1.0.0] - 2026-05-28

### Added

- `sql/00-setup.sql` through `sql/15-noise-candidates.sql` - 16 audit
  analysis SQL queries migrated from audit_pack-0.5.0, sanitised, with
  Apache 2.0 SPDX headers and hyphenated naming.
- `sql/16-policy-ddl.sql` - sources `DBMS_METADATA.GET_DDL('AUDIT_POLICY',
  policy_name)` per enabled policy. Replaces the F2 bug where Section 8.1
  generated wrong DDL from `UNIFIED_AUDIT_POLICIES` concat strings.
- `sql/17-cis-coverage.sql` (GAP-01) - CIS 5.1-5.5 policy presence and
  completeness check. Emits PASS/WARN/FAIL verdict per control based on
  policy existence, enabled status, SUCCESS/FAILURE flags, and EXCEPT USER
  exclusions.
- `sql/18-audit-roles.sql` (GAP-02) - AUDIT_ADMIN and AUDIT_VIEWER role
  membership check. Two-level role chain; classifies grantees as USER/ROLE
  with STANDARD/INFO/WARN/REVIEW risk flags.
- `bin/ora-db-audit.sh` - bash entry-point (was run_analysis_pack.sh),
  sanitised, OraDBA header, CUSTOMER_PREFIX default removed,
  shellcheck-clean.
- `tools/audit_report_messages.py` - centralised message dictionary
  enabling future dual-language output (DE default, EN ready in v1.1+).
  Lightweight dict-based design; rejects gettext infrastructure.
- `tools/audit_report.py` Phase D rewrite:
  - `_read_policy_ddl_csv` + `load_policy_ddl` + `extract_when_clause`
    helpers parse the multi-line CLOB output of `sql/16-policy-ddl.sql`
    via Oracle-identifier-pattern row detection (QUOTE OFF markup).
  - `when_clause_for(noise_row, headers, policy_ddl_map)` returns a
    structured dict grounded in actual policy DDL.
  - `render_section_08_tuning(file_data, top_n, policy_ddl_map)` emits
    DDL-context + condition-expression suggestions (NOT standalone
    ALTER statements - F2 fix).
  - `render_section_01_config` / `render_section_02_storage` apply the
    Pure-Mode decision matrices from ai-analysis-rules.md sections 5 + 6.
  - `--lang` CLI argument (de default; SUPPORTED_LANGUAGES is the i18n contract).
- `templates/customer-handover.md` - genericised customer handover
  template (no engagement-specific values).
- `docs/roadmap.md` - versioned roadmap v0.1 -> v1.0 with post-v1.0
  candidate features (v1.1 dual-language output, Off-Path Detection,
  v2.0 Policy Generator + Mixed-to-Pure migration helper).
- `docs/ai-analysis-rules.md` - Pure-Mode source of truth document
  defining which findings the AI report may raise, which Legacy
  artefacts to suppress, canonical UAP-concat split CTE, partition
  transient-state decision matrix, and Pure-vs-Mixed detection.
- `docs/compliance-mapping.md` - CIS Benchmark (19c v2.0.0, 23ai v1.1.0,
  26ai v1.0.0), DISA STIG 19c V1R5, and Oracle Unified Audit Best Practice
  Guidelines v2.0 compliance mapping. Includes SQL coverage matrix and gap
  analysis (GAP-01, GAP-02, GAP-03).
- `docs/use-cases/audit-analysis.md` + `docs/use-cases/audit-log-anonymisation.md` -
  sanitised use-case documentation.
- `tests/fixtures/sample_bundle/` - 18 anonymised CSV fixture files
  (Oracle 23ai Free, example.com hostnames, no NDA content), with
  v0.2.0 metadata format (`# audit_mode:`, `# cis_controls:`, trail health
  metadata). Fixture-level `.gitignore` excludes generated artefacts.
- `tests/bats/test-cli-parse.bats` - 10 bats tests for CLI flag parsing,
  validation, and error paths. sqlplus-gated tests use `require_sqlplus()`
  helper to skip cleanly without a live Oracle environment.
- `tests/bats/test-from-bundle.bats` - 5 bats tests for offline
  `--from-bundle` mode: extraction, dry-run, and Markdown report rendering.
  Bundle tarball is created on-demand from the fixture directory in setup().
- `tests/python/test_report_render.py` - 7 pytest tests verifying
  `audit_report.py` renders on the sample bundle without raising and produces
  expected output structure.
- `tests/python/test_anonymizer_roundtrip.py` - 5 pytest tests verifying
  `anonymize_bundle.py` produces a correct mapping.json, pseudonymises PSEUDO
  columns, and preserves whitelisted Oracle system accounts.
- `scripts/bump_version.sh` - SemVer bump script (patch/minor/major) with
  CHANGELOG stub creation.
- `.github/workflows/ci.yml` - GitHub Actions CI: markdownlint,
  shellcheck, bats, pytest (Python 3.10/3.11/3.12).

### Changed

- Repository layout: `src/` renamed to `bin/` for executable entry-point.
- `CLAUDE.md` repo layout reflects `bin/` instead of `src/`.
- `Makefile` - full rewrite following OraDBA Makefile standard: grouped
  sections (Lint, Test, Build/Distribution, Cleanup, Version Management,
  Release Management, Info), color output, proper tool detection at
  recipe evaluation time, `make dist` for deployable tarball,
  `make test-bats` and `make test-pytest` for test runners.
- `README.md` - rewritten for OSS audience: Quick Start, output structure,
  SQL query table with CIS mappings, compliance references, CI badge.
- `INITIAL_PROMPT.md` moved to `docs/history/initial-prompt-2026-05-27.md`.

### Fixed

- **F1** - AI prompt (`AI_USER_PROMPT_TEMPLATE` in `tools/audit_report.py`)
  no longer asks Claude to evaluate `audit_sys_operations` and
  `audit_trail Status` (Mixed-Mode-only parameters). The prompt now begins
  with an `audit_mode` check that short-circuits the analysis to a single
  Mixed-Mode-contamination finding when the database is not in Pure Mode.
- **F2** - `tools/audit_report.py` Section 8.1 no longer emits the
  Oracle-invalid `ALTER AUDIT POLICY <policy> CONDITION DROP` pattern.
  Suggestions are now boolean condition expressions grounded in actual
  `DBMS_METADATA.GET_DDL` output (from `sql/16-policy-ddl.sql`),
  accompanied by an explicit manual-apply instruction.
- **F3** - SQL queries 04, 05, 06, 07, 15 now apply the canonical UAP-concat
  split CTE (`REGEXP_SUBSTR` + `CONNECT BY LEVEL`) per
  `docs/ai-analysis-rules.md` Section 3. Previously these aggregated on
  the raw concatenated `UNIFIED_AUDIT_POLICIES` column, producing one
  row per concat-string instead of per individual policy.
- **F4** - `sql/02-storage.sql` exposes three distinct tablespace metadata
  values (default-for-new-partitions, current-partition, older-partitions)
  per `docs/ai-analysis-rules.md` Section 5. The reporter can now apply
  the D/C/O decision matrix and distinguish MISCONFIGURATION from TRANSIENT
  state after `ALTER TABLE MODIFY DEFAULT ATTRIBUTES TABLESPACE`.
- **F5** - `sql/01-config.sql` emits `# audit_mode:` metadata
  (`pure | pure-intent | pure-contaminated | mixed | unsupported`) per
  `docs/ai-analysis-rules.md` Section 6, and tags legacy parameters via a
  `legacy_param` schema-hint column so the reporter suppresses false-positive
  findings on them when mode is pure-ish.
- `bin/ora-db-audit.sh` - introduced `SQL_DIR=${REPO_ROOT}/sql` variable;
  replaced all `${SCRIPT_DIR}/${q}` references with `${SQL_DIR}/${q}`. The
  previous code looked for SQL files in `bin/` alongside the script, which
  was always wrong since SQL files live in `sql/`.
- `sql/02-storage.sql` (GAP-03, rev 0.3.0) - Phase 3 captures
  `purge_job_count`, `purge_job_status`, `last_archive_timestamp`, and
  `partition_interval` from `DBA_AUDIT_MGMT_CLEANUP_JOBS`,
  `DBA_AUDIT_MGMT_LAST_ARCH_TS`, and `DBA_PART_TABLES` into SQL*Plus
  DEFINEs. Four new `PROMPT #` metadata lines emitted in the CSV preamble.

## [0.1.0] - 2026-05-27

### Added

- Initial repository scaffolding
- Apache License 2.0
- Standard OraDBA repo layout (docs, src, scripts, sql, tools,
  templates, tests)
- CLAUDE.md with oracle-audit, bash-header, makefile skill references
- README, CONTRIBUTING, DISCLAIMER, SECURITY documentation stubs
- Slim Makefile (lint, version, changelog targets)
- INITIAL_PROMPT.md as briefing document for the follow-up
  development session

### Notes

This release is a **scaffolding marker** only. Content migration from
the internal audit_pack 0.5.0 tool (currently embedded in
`ora-db-audit-eng/artefacts/audit_pack-0.5.0/`) and v1.0.0 feature
development happen in a follow-up Claude Code session.
