# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.3.2] - 2026-05-28

### Fixed

- **CIS Section 9 empty** (`sql/17-cis-coverage.sql`) - `ORA-00904` on
  `P.ENTITY_TYPE`: `entity_name` and `entity_type` are columns of
  `AUDIT_UNIFIED_ENABLED_POLICIES` (alias `e`), not `AUDIT_UNIFIED_POLICIES`
  (alias `p`). Fixed by changing `p.entity_name` / `p.entity_type` to
  `e.entity_name` / `e.entity_type` in the `active_policies` CTE.

### Changed

- **Section 3 Policy Inventory restructured** (`tools/audit_report.py`):
  - Header count now shows unique policy names (was raw action-row count -
    e.g. "3383" instead of the correct number of distinct policies).
  - New overview table: one row per unique `(policy_name, entity, type,
    enabled_option)` - mirrors `aud_policies_show_aud.sql` format. Custom
    policies listed before Oracle-supplied; `audit_condition` shown once
    per policy (truncated to 60 chars).
  - Full action-level detail moved to appendix subsection (`--include-appendix`
    flag); no row cap - never truncated regardless of `--top-n`.
  - Executive summary "Active Audit Policies" metric also fixed to show
    unique policy count.

- **Section 9 CIS Coverage - detail subsection added**
  (`tools/audit_report.py`): after the 5-row summary table a new subsection
  lists every policy that covers at least one CIS 5.1-5.5 requirement,
  cross-referenced from `03_policy_inventory.csv`. Columns: CIS controls
  covered, policy name, ORA flag, enabled option, entity, type, S/F flags.
  Never truncated.

## [1.3.1] - 2026-05-28

### Fixed

- **`--export-prompt` language** - the exported AI prompt file now uses the
  same language as the report (`--lang de` -> German prompts,
  `--lang en` -> English prompts). Previously the prompt was always German
  regardless of `--lang`. Both the system prompt and the user task prompt
  are now language-keyed (`AI_SYSTEM_PROMPTS`, `AI_USER_PROMPT_TEMPLATES`
  dicts); the live AI analysis path (`--ai`) inherits the same fix.

## [1.3.0] - 2026-05-28

### Added

- **ORA$MANDATORY metric** - executive summary Kennzahlen now shows the
  `ORA$MANDATORY` event count as a dedicated row in the metrics table
  (source: `04_policy_volume.csv`).
- **CIS action-based coverage** (`sql/17-cis-coverage.sql`,
  `tools/audit_report.py`) - Section 9 now compares the actual audit actions
  of enabled policies against CIS 5.1-5.5 requirements instead of checking
  for hard-coded policy names (`CIS_CDB_*`). New output columns:
  `custom_policies` (covering custom policies, drives the verdict) and
  `oracle_policies` (Oracle-supplied policies, informational only). Verdicts:
  PASS (full unconditional coverage by a custom policy), PARTIAL (only
  conditional or user-scoped coverage), FAIL (no custom policy covers it).
- **`--export-prompt` optional FILE** - the FILE argument to `--export-prompt`
  is now optional. Without it, the prompt is written to
  `<bundle_dir>/<bundle_name>_prompt.txt` automatically.

### Fixed

- **top-n display default** - `tools/audit_report.py` now defaults the table
  row cap to the bundle manifest's `top_n` value (set during collection) rather
  than a hard-coded 20. Pass `--top-n N` to override explicitly; `--top-n 0`
  removes the cap entirely (show all rows).
- **UNIFIED AUDIT TRAIL FILES not legacy** - `sql/01-config.sql` now correctly
  marks `UNIFIED AUDIT TRAIL FILES` entries as `legacy_param=0` (not legacy).
  Previously they were labelled `_(legacy)_` in Section 1 despite being part
  of the Unified Audit infrastructure.
- **`--export-prompt` unbound variable** - running `--export-prompt` without
  a file argument no longer causes an `unbound variable` crash (`$2` guard
  added). The flag now accepts an optional filename.

### Changed

- `sql/17-cis-coverage.sql` CSV schema changed: old 9-column format
  (`policy_name`, `policy_exists`, `policy_enabled`, `except_user_count`, ...)
  replaced by 5-column action-coverage format
  (`cis_control`, `cis_title`, `verdict`, `custom_policies`, `oracle_policies`).
  Bundles generated with earlier versions render with a legacy fallback path.
- `tools/audit_report.py` version `1.2.0` -> `1.3.0`.
- `bin/ora-db-audit.sh` version `1.2.4` -> `1.3.0`.

## [1.2.4] - 2026-05-28

### Fixed

- **B10** - `bin/ora-db-audit.sh`: when `--from-bundle` is used without an
  explicit `--lang` flag, the report language is now auto-detected from the
  `"lang"` field in the bundle's `manifest.json`. Previously, reprocessing a
  bundle always defaulted to `de` regardless of the language used during
  collection, so `--report --ai --from-bundle <bundle>` would produce a German
  report even when the original run used `--lang en`. An explicit `--lang`
  still takes precedence over the manifest value.

### Changed

- `write_manifest()` now records the active report language as `"lang"` in
  `manifest.json` so future `--from-bundle` runs can restore it automatically.
- `bin/ora-db-audit.sh` version `1.2.3` -> `1.2.4`.

## [1.2.3] - 2026-05-28

### Fixed

- **B9** - `bin/ora-db-audit.sh`: bundle directory and tarball name now
  includes the PDB name when `--pdb` is set. Previously the name was
  `ora-db-audit_<DBSID>_<TS>` regardless of PDB, making it impossible to
  distinguish bundles from different PDBs in the same CDB collected on the
  same host. New pattern: `ora-db-audit_<DBSID>[_<PDB>]_<TS>` (PDB
  lowercased for consistency with DBSID). The `manifest.json` now includes a
  `"pdb"` field, and the bundle `README.md` shows the PDB row.

## [1.2.2] - 2026-05-28

### Fixed

- **B8** - `bin/ora-db-audit.sh`: `--lang`, `--export-prompt`, and
  `--customer-prefix` were not forwarded to `tools/audit_report.py` when
  `--report` was used. `--lang en` caused `ERROR: unknown option: --lang`
  because the flag was consumed by the shell script's `parse_args()` and then
  silently dropped. Fixed by passing all three to `render_report()` via
  `report_args`. `--customer-prefix` was already wired to `anonymize_bundle.py`
  but not to `audit_report.py` (where it controls the AI prompt context).

### Changed

- `bin/ora-db-audit.sh` version `1.2.0` -> `1.2.2`.
- README: document `--lang` and `--export-prompt` in the command reference.

## [1.2.1] - 2026-05-28

### Added

- `Makefile` dist target now includes `docs/` and `docs/use-cases/` in the
  release tarball so the documentation is available to users who deploy from
  a tarball without a git clone. Also includes `CHANGELOG.md` in the dist.
- `DOCS_DIR := docs` variable added to Makefile for consistency.
- `dist-verify` now checks `tools/export_siem.py`, `README.md`, and
  `CHANGELOG.md` as required tarball entries.

### Changed

- README.md: comprehensive documentation covering usage, purpose, all flags,
  multitenant CDB/PDB handling, user privilege requirements for non-SYSDBA
  login, six use cases (local collect, anonymise+share, full on-host, remote
  report, large trails with --sample-rows, SIEM export), patterns file,
  report sections, SIEM export section, updated SQL query table.

## [1.2.0] - 2026-05-28

### Added

- **R3** - `--sample-rows N` flag in `bin/ora-db-audit.sh`: limits the source
  rows fed into the heavy profiling queries (08-12, 15) via `ROWNUM <= N`
  in the WHERE clause. Default `0` (no limit). Export `ORADBA_SAMPLE_ROWS`
  injected via `sql/00-setup.sql` into `DEFINE SAMPLE_WHERE` and
  `DEFINE sampled`. Each affected query emits `# sampled: true/false` in
  its CSV preamble. The executive summary notes the sampling blind spot when
  `manifest.json` reports `sample_rows > 0`.
- **D2** - `tools/export_siem.py`: reads an anonymised (or raw) bundle and
  writes OCSF 1.3 Database Activity JSON Lines (`--format ocsf`) or a
  Microsoft Sentinel / Log Analytics CSV (`--format sentinel`). Default
  sources: queries 08, 11, 13, 14, 19 (off-path candidates if present).
  Wired into `bin/ora-db-audit.sh` via `--export-siem FORMAT OUTPUT`.
- `sql/00-setup.sql`: sampling DEFINE injection block (single-line HOST
  conditional for `SAMPLE_WHERE` and `sampled` SQL*Plus DEFINEs).

### Fixed

- **B6** - `bin/ora-db-audit.sh` sanity check used `${q%.sql}.csv`
  (hyphenated, e.g. `01-config.csv`) but SQL SPOOL commands produce
  underscored filenames (`01_config.csv`). Fixed by normalising
  `${stem//-/_}` before the existence check. All 18 outputs were
  previously reported as missing even when they existed.
- **B7** - `tools/anonymize_bundle.py`: `TABLESPACE_STATE` schema hint
  (used by `sql/02-storage.sql` for tablespace_name) was not in
  `VALID_KEEP_TYPES`, causing a spurious `WARN: unknown schema type`
  on every anonymisation run. Added to `VALID_KEEP_TYPES`.
- **UX1** - `bin/ora-db-audit.sh` invoked without arguments now displays
  `--help` instead of attempting a `/ as sysdba` collection against the
  CDB$ROOT. On 21c+ multitenant databases (the default), a no-arg run
  almost never yields useful results.

### Changed

- File-level version numbers (`# Version:` headers, `TOOL_VERSION`
  constants, `bundle_version` / `tool_version` in `manifest.json`) now
  align with the repo SemVer (`VERSION` file). Previously internal tool
  files used a separate `0.x.x` numbering, causing confusion when the
  manifest reported `tool_version: 0.x.x` against a `1.x.x` release.
- `bin/ora-db-audit.sh` version bumped to `1.2.0`.
- `tools/audit_report.py` `TOOL_VERSION` bumped to `1.2.0`.
- `tools/audit_report_messages.py` version bumped to `1.2.0`.
- `tools/anonymize_bundle.py` `VALID_KEEP_TYPES` extended with
  `TABLESPACE_STATE`.

## [1.1.1] - 2026-05-28

### Added

- **R5** - Dual-language output (`--lang en|de`, default `de`) in
  `tools/audit_report.py`. `MESSAGES["en"]` populated in
  `tools/audit_report_messages.py` with full English translations of all
  user-facing strings: section titles, table column headers, verdict messages,
  audit-mode blockquotes, storage verdicts, CIS and audit-roles notes, tuning
  rationale strings. `SUPPORTED_LANGUAGES` extended to `("de", "en")`.
  `validate_catalog("en")` returns empty (no drift).
- **D1** - Off-path detection use case (`docs/use-cases/off-path-detection.md`):
  covers pattern-based vs. application-context-based detection, configuration
  options, triage heuristic, and comparison table.
- **D1** - `sql/19-offpath-candidates.sql`: surfaces host + user combinations
  not matching `APP_PATTERN` / `INFRA_PATTERN` / `DBA_PATTERN`. No
  `ODB_AUDIT_CTX` deployment required. Output schema compatible with
  `anonymize_bundle.py` (PSEUDO:HOST, PSEUDO:DBUSER, COUNT anonymisation).
- 2 new pytest tests for EN catalog completeness and EN report content
  (38 total, all passing).

### Changed

- `tools/audit_report_messages.py` version `0.2.0` -> `0.3.0`.

## [1.1.0] - 2026-05-28

### Added

- **R1** - `render_section_09_cis_coverage()` in `tools/audit_report.py`: new
  Section 9 emits a per-control PASS/**WARN**/**FAIL** table for CIS Benchmark
  controls 5.1-5.5. Reads `17_cis_coverage.csv` from the bundle; falls back
  gracefully when the file is absent (older bundles).
- **R2** - `render_section_10_audit_roles()` in `tools/audit_report.py`: new
  Section 10 lists `AUDIT_ADMIN` / `AUDIT_VIEWER` grantees with their
  risk flags (**WARN** / **REVIEW** rows highlighted). Reads
  `18_audit_roles.csv`; falls back gracefully when absent.
- **R4** - `--export-prompt FILE` flag in `tools/audit_report.py`: writes the
  full AI analysis prompt (report data embedded) to FILE instead of sending it
  to the Claude API. Output includes a provider-agnostic header with paste
  instructions for claude.ai, ChatGPT, Gemini, and API callers. Works without
  an API key or Claude CLI installed.
- 5 new pytest tests covering Section 9, Section 10, and `--export-prompt`
  (36 total, all passing).

### Changed

- AI-Findings section renumbered from `## 9.` to `## 11.` to make room for
  the new CIS and Audit-Roles sections (9 and 10).
- `TOOL_VERSION` bumped to `0.3.0`.

## [1.0.2] - 2026-05-28

### Fixed

- **B1** - `sql/01-config.sql`, `sql/02-storage.sql`, and ten further SQL
  files had `PROMPT # cis_controls: -` where the trailing `-` is the
  SQL\*Plus line-continuation character. The next PROMPT line was silently
  merged into the same output line, causing `# audit_mode:` and other
  metadata markers to vanish from the CSV preamble. Changed to
  `PROMPT # cis_controls:` (no trailing dash) in all 12 affected files.
- **B2** - `sql/02-storage.sql` Phase 3 SELECT consumed SQL files 03-06 as
  variable values. Two root causes: (a) `INTERVAL` is an Oracle reserved
  word and raised `ORA-00904` when used unquoted as a column name in
  `dba_part_tables`; (b) no `DEFINE` defaults existed for
  `PURGE_JOB_COUNT`, `PURGE_JOB_STATUS`, `LAST_ARCH_TS`, `PART_INTERVAL`,
  so a failing SELECT left them undefined and SQL\*Plus prompted interactively,
  reading the next `@.../03-*.sql` paths as values. Fixed by adding four
  `DEFINE` defaults before the SELECT and quoting `"INTERVAL"`.
- **B3** - `sql/16-policy-ddl.sql` raised `ORA-22848: cannot use DISTINCT
  with LOB columns` because `SELECT DISTINCT` with a `DBMS_METADATA.GET_DDL`
  CLOB column forces a CLOB-equality comparison. Fixed by deduplicating
  `policy_name` in a subquery first and then calling `GET_DDL` once per
  unique policy.
- **B4** - `sql/01-config.sql` emitted `legacy_param=0` for
  `dba_audit_mgmt_config_params` rows whose `audit_trail` is
  `OS AUDIT TRAIL`, `XML AUDIT TRAIL`, `STANDARD AUDIT TRAIL`, or
  `FGA AUDIT TRAIL`. Those rows belong to Traditional Auditing and must be
  suppressed in Pure-Mode reports. Fixed with a `CASE UPPER(audit_trail)
  WHEN 'UNIFIED AUDIT TRAIL' THEN 0 ... ELSE 1 END` expression. `ORDER BY`
  changed from `1, 2` (source, name) to `1, 4, 2` (source, trail, name)
  so Unified and non-Unified rows for the same parameter are grouped.
- **B5** - `tools/anonymize_bundle.py` pseudonymised every value in
  `PSEUDO:OBJECT` columns regardless of owner, turning Oracle-supplied
  objects such as `SYS.DUAL`, `AUDSYS` packages, and dictionary views into
  `OBJECT_NNN`. Added `ORACLE_SYSTEM_SCHEMAS` constant (union of
  `ORACLE_USERS` plus additional Oracle-supplied schemas) and made
  `anonymise_row` context-aware: when the companion `object_schema` / `owner`
  column in the same row resolves to a system schema, the object name is
  kept verbatim.

## [1.0.1] - 2026-05-28

### Added

- `ora-db-audit` root wrapper (no `.sh` extension) in the dist tarball -
  thin delegating script (`exec .../bin/ora-db-audit.sh "$@"`) so both
  `./ora-db-audit` and `./bin/ora-db-audit.sh` work after extracting the
  tarball. No extension distinguishes the user-facing command from the
  implementation script in `bin/`.

### Changed

- `Makefile` dist layout: `bin/ora-db-audit.sh` placed in a `bin/`
  subdirectory (matching the repo-clone layout) instead of the tarball
  root. Root convenience wrapper renamed `ora-db-audit` (no extension)
  to distinguish user-facing command from implementation script.
  `dist_manifest.json` entrypoint updated to `bin/ora-db-audit.sh`.
- `README.md` Quick Start: documents Option A (clone) and Option B (tarball)
  install paths; clarifies `./bin/ora-db-audit.sh` as the canonical entry
  point in both environments with the root wrapper as a convenience alias.

### Fixed

- `bin/ora-db-audit.sh` `--from-bundle` without explicit `--output` now
  defaults `OUTPUT_DIR` to the directory that contains the bundle file
  instead of `${PWD}/audit_bundle`. The report and extracted directory
  land next to the bundle, matching the v0.5.0 behaviour. Explicit
  `--output DIR` still overrides this default.
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
