# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `tasks/migration-plan.md` - confirmed file-by-file migration plan from
  audit_pack-0.5.0 to v1.0.0 (Stefan sign-off 2026-05-28).
- `tasks/rework-plan.md` - v1.0 blocker plan addressing Pure-Mode
  correctness issues identified during migration (UAP-concat semantics,
  legacy-parameter false positives, partition transient state, DDL
  source rule).
- `docs/roadmap.md` - versioned roadmap v0.1 -> v1.0 with post-v1.0
  candidate features (v1.1 dual-language output, Off-Path Detection,
  v2.0 Policy Generator + Mixed-to-Pure migration helper).
- `docs/ai-analysis-rules.md` - Pure-Mode source of truth document
  defining which findings the AI report may raise + which Legacy
  artefacts to suppress + canonical UAP-concat split CTE + partition
  transient-state decision matrix + Pure-vs-Mixed detection.
- `sql/00-setup.sql` through `sql/15-noise-candidates.sql` - 16 audit
  analysis SQL queries migrated from audit_pack-0.5.0, sanitised, with
  Apache 2.0 SPDX headers and hyphenated naming.
- `sql/16-policy-ddl.sql` (new) - sources `DBMS_METADATA.GET_DDL('AUDIT_POLICY',
  policy_name)` per enabled policy. Replaces the F2 bug where Section 8.1
  generated wrong DDL from `UNIFIED_AUDIT_POLICIES` concat strings.
- `tools/audit_report_messages.py` (new) - centralised message dictionary
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
- `--lang` CLI argument on `audit_report.py` (de default; SUPPORTED_LANGUAGES
  is the i18n contract).
- `bin/ora-db-audit.sh` - bash entry-point (was run_analysis_pack.sh),
  sanitised, OraDBA header, CUSTOMER_PREFIX default removed,
  shellcheck-clean.
- `templates/customer-handover.md` - genericised customer handover
  template (no ODB prefix examples, no engagement-specific values).
- `docs/use-cases/audit-analysis.md` + `docs/use-cases/audit-log-anonymisation.md` -
  sanitised use-case documentation.
- AI-toolkit symlinks via `init-repo.sh --ai-only --profile shell --profile oracle`.

### Changed

- Repository layout: `src/` renamed to `bin/` for executable entry-point
  (migration plan decision D6 amendment).
- CLAUDE.md repo layout reflects `bin/` instead of `src/`.

### Fixed

- **F1** - AI prompt (`AI_USER_PROMPT_TEMPLATE` in `tools/audit_report.py`)
  no longer asks Claude to evaluate `audit_sys_operations and audit_trail
  Status` (line 106 of the original Section B). Both are Mixed-Mode-only
  parameters - findings citing them are now explicitly listed as
  out-of-scope. The prompt now begins with an `audit_mode` check that
  short-circuits the analysis to a single Mixed-Mode-contamination
  finding when the database is not in Pure Mode.
- **F2** - `tools/audit_report.py` Section 8.1 (`when_clause_for` +
  `render_section_08_tuning`) no longer emits the (Oracle-invalid)
  `ALTER AUDIT POLICY <policy> CONDITION DROP` pattern against
  `UNIFIED_AUDIT_POLICIES` concat strings. Suggestions are now boolean
  condition expressions grounded in actual `DBMS_METADATA.GET_DDL` output
  (sourced from `sql/16-policy-ddl.sql`), accompanied by an explicit
  manual-apply instruction (`DROP AUDIT POLICY; CREATE AUDIT POLICY ...
  WHEN '(<existing>) AND (<new>)'`).
- **F3** - SQL queries 04, 05, 06, 07, 15 now apply the canonical UAP-concat
  split CTE (`REGEXP_SUBSTR` + `CONNECT BY LEVEL`) per
  `docs/ai-analysis-rules.md` Section 3. Previously these aggregated on
  the raw concatenated `UNIFIED_AUDIT_POLICIES` column, producing one
  row per concat-string instead of per individual policy. Per-policy
  semantics now correct.
- **F5** - `sql/01-config.sql` emits `# audit_mode:` metadata
  (`pure | pure-intent | pure-contaminated | mixed | unsupported`) per
  `docs/ai-analysis-rules.md` Section 6, and tags legacy parameters
  (`audit_trail`, `audit_sys_operations`, `audit_syslog_level`,
  `audit_file_dest`) via a new `legacy_param` schema-hint column so the
  reporter can suppress false-positive findings on them when mode is
  pure-ish.
- **F4** - `sql/02-storage.sql` exposes three distinct tablespace
  metadata values (default-for-new-partitions, current-partition,
  older-partitions) per `docs/ai-analysis-rules.md` Section 5. The
  reporter can now apply the D/C/O decision matrix and distinguish
  MISCONFIGURATION from TRANSIENT state after `ALTER TABLE MODIFY
  DEFAULT ATTRIBUTES TABLESPACE`.

- `docs/compliance-mapping.md` (new) - CIS Benchmark (19c v2.0.0, 23ai v1.1.0, 26ai v1.0.0),
  DISA STIG 19c V1R5, and Oracle Unified Audit Best Practice Guidelines v2.0 compliance mapping.
  Includes SQL coverage matrix, gap analysis (GAP-01 CIS coverage check, GAP-02 audit roles,
  GAP-03 trail health), and proposed SQL rework plan for v1.0.1 and v1.1.

### Notes

Phases B (UAP-split SQL rewrites), C (config + storage interpretation
fixes), D (audit_report.py Section 8.1 rewrite + AI prompt cleanup +
Pure-Mode-aware Section 1+2 interpretation + i18n-ready message dict),
and E (CIS / STIG / Oracle BP compliance mapping doc) are complete.
Group F (tests) remains before a tagged v0.2.0 release.

Commit-history footnote: the Phase B 04-07 changes are bundled with
the CHANGELOG update in commit `25e5c6d` due to sub-agent worktree
sync ordering; subsequent Phase B commits (`240620d`, `be8de1d`) land
cleanly. A pre-public-release rebase may tidy this if desired.

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
