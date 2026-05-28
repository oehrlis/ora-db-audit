# Roadmap

Status: **DRAFT - aligned with `tasks/migration-plan.md` (2026-05-27)**

This roadmap supersedes the milestone block in
`~/notes/projects/audit-tool.md` once Stefan confirms the migration plan.
The earlier audit-tool.md milestones were written before the reality of
audit_pack-0.5.0 (already includes anonymisation + AI) was reconciled into
the plan.

---

## Version Table

| Version | State    | Date target | Scope                                                                                  |
|---------|----------|-------------|----------------------------------------------------------------------------------------|
| 0.1.0   | released | 2026-05-27  | Scaffolding (this commit history start)                                                |
| 0.2.0   | planned  | +1 week     | SQL + Python tools migrated, sanitised, no integration tests yet                       |
| 0.5.0   | planned  | +2 weeks    | Full feature parity with audit_pack-0.5.0; tests green; internal RC                    |
| 0.9.0   | planned  | +3 weeks    | CIS-mapping formalised, OSS polish, security review pass                               |
| 1.0.0   | planned  | +4 weeks    | Public release on github.com/oehrlis/ora-db-audit                                      |
| 1.x     | future   | -           | Off-Path-Detection use case, additional CIS controls, Mixed-to-Pure helpers            |
| 2.0     | future   | -           | Policy generator, Compliance-Report module (PCI-DSS / ISO 27001 mapping), STIG profile |

Dates assume 1-2 evenings + 1 weekend day per week of effort. Adjust as
real cadence emerges.

---

## v0.2.0 - "SQL + Tools landed"

Goal: every file from audit_pack-0.5.0 lives in this repo, sanitised, with
Apache 2.0 headers and the new naming convention. No CIS-mapping yet, no
new tests yet. The bash entry-point runs end-to-end against a sample
bundle.

Acceptance:

- `bin/ora-db-audit.sh --help` prints the full flag set
- `bin/ora-db-audit.sh --from-bundle tests/fixtures/sample_bundle.anon.tar.gz --report` produces `audit_report.md`
- `git grep -E '\bODB\b' -- ':!docs/history/' ':!tests/fixtures/*.mapping.json'` returns 0 matches
- `make lint` passes (shellcheck + markdownlint + ruff/mypy)

Deliverables: Migration commits B-E from `tasks/migration-plan.md`.

---

## v0.5.0 - "Feature parity + tests"

Goal: same capability surface as audit_pack-0.5.0, but verified by tests
and ready for an internal release candidate review by Stefan + selected
trusted reviewers.

Acceptance:

- `make test` green (bats + pytest)
- `tests/python/test_anonymizer_roundtrip.py` proves anon -> de-anon is
  identity outside the whitelist
- Sample bundle round-trip works in offline `--from-bundle` mode
- AI integration smoke-tested with one real `--ai` run (needs ANTHROPIC_API_KEY)

Deliverables: Migration commits F + initial CI workflow.

---

## v0.9.0 - "Compliance-aware + OSS-polished"

Goal: each SQL is tagged with its CIS-Oracle-Benchmark control(s). README
and use-case docs target the OSS audience (no Accenture-internal framing).
Security review pass against own SECURITY.md threats.

Acceptance:

- Every SQL has a `# cis_controls:` metadata line (or explicit `# cis_controls: none`)
- `docs/compliance-mapping.md` documents the full CIS mapping with control IDs and benchmark version
- `audit_report.py` surfaces CIS controls in the executive summary
- README walks a new user from zero -> first bundle without referencing internal Accenture-engineering vocabulary
- `/security-check` run produces no actionable findings on the staged changes

Deliverables: Migration commits G + H + reviewer agent pass.

---

## v1.0.0 - "Public release"

Goal: the tool is on `github.com/oehrlis/ora-db-audit`, tagged, with
release notes, ready for the blog announcement.

Acceptance:

- GitHub repository created (public, Apache 2.0, default branch `main`)
- v1.0.0 tag pushed
- Release notes derived from `CHANGELOG.md`
- README badges: license, CI status, latest release
- Blog announcement drafted on oradba.ch (not necessarily published yet)
- `audit-tool.md` PKM project Status flipped to `done`
- `INITIAL_PROMPT.md` archived under `docs/history/`

---

## Highly Recommended v1.0.1 - "Post-release fixes and features"

- Handle usability for audit trails with several million records. What kind of
  possibilities do we have? Right now we have several queries with join, group by etc.
- Find a solution to have a good overview also for large audit trails. Maybe a
  summary report with the most important KPIs and only a sample of the findings?
  But clearly identify blind spots when not all data can be processed in a
  reasonable time frame.
-

---

## Beyond v1.0 - candidate features (no commitment yet)

The list below is intentionally not prioritised. It is the staging area
for ideas surfaced during the audit_pack engagement work or community
feedback after release.

- **v1.1 - Dual-language output (DE + EN)**: v1.0 ships German-only.
  v1.1 adds English translations via `--lang en|de` flag. Phase D
  rewrite in v1.0 already designs for this (centralised message dict),
  so v1.1 is an additive change.
- **v1.1 - Off-Path-Detection use case**: import
  `uc_offpath_detection.md` from eng repo; sanitised + new SQL queries
  detecting unexpected host/user combinations beyond the existing
  host-pattern classification.
- **v1.1 - Additional SQL queries**: per-policy success/failure breakdown,
  long-running session detection, audit-trail-vs-listener log cross-check.
- **v1.2 - SIEM export adapters**: opt-in OCS / CSV-to-OCSF / Sentinel
  format helpers (the audit data structure is already there, just an
  output adapter).
- **v1.x - Oracle 26ai-specific checks**: leverage 26ai unified audit
  enhancements once the public docs stabilise.
- **v2.0 - Policy Generator**: from a "I want to audit X actions by role
  Y" requirement, generate the unified audit policy DDL + cleanup
  NOAUDIT. Cross-references the existing `/oracle-audit` skill.
- **v2.0 - Mixed-to-Pure Unified Audit migration helper**: detect mixed
  mode artefacts, propose migration order, generate the cutover script.
- **v2.0 - Compliance-Report module**: PCI-DSS / ISO 27001 / STIG mapping
  on top of the CIS base, with gap-analysis report rendering.
- **v2.0 - GUI / dashboard**: out of scope unless community demand emerges.

---

## Out of scope (permanent)

- Traditional auditing (`AUDIT_TRAIL=DB|OS|XML` legacy mode) -
  desupported in 23ai+, no point.
- Read-from-binary mandatory `*.aud` files - already covered by Oracle's
  shipped utilities.
- GUI dashboard as a v1.0 deliverable - Markdown report is the contract.

---

## How to evolve this roadmap

- Stefan owns priority changes. Discuss in `~/notes/projects/audit-tool.md` first, then update this file.
- New candidate features: append to "Beyond v1.0" section; do not promote to a versioned milestone without a deliverable/acceptance pair defined.
- Release dates are aspirational. Real cadence is logged via git tags + CHANGELOG entries.
