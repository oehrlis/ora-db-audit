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

### Notes

Phase B (UAP-split SQL rewrites) and Phase C (config + storage
interpretation fixes) are complete. Phase D (audit_report.py Section
8.1 rewrite + AI prompt cleanup + i18n-ready message dict) and Phase E
(CIS / STIG / Oracle BP compliance mapping doc) remain before a tagged
v0.2.0 release.

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
