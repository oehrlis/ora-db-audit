# Roadmap

Current release: **v1.2.1** - Updated: 2026-05-28

---

## Version History

<!-- markdownlint-disable MD013 MD060 -->
| Version | State    | Released   | Scope |
|---------|----------|------------|-------|
| 0.1.0   | released | 2026-05-27 | Repository scaffold, Apache 2.0, CLAUDE.md |
| 1.0.0   | released | 2026-05-28 | Full feature port from audit_pack-0.5.0; 19 SQL queries; Python reporter + anonymizer; bats + pytest; CIS/STIG compliance mapping; CI/CD |
| 1.0.1   | released | 2026-05-28 | Dist tarball layout fix (REPO_ROOT path), `--from-bundle` output dir default, base64 dist artifact, root wrapper without `.sh` |
| 1.0.2   | released | 2026-05-28 | Bundle quality fixes B1-B5: SQL*Plus continuation char, Phase 3 variable defaults, ORA-22848 CLOB DISTINCT, legacy_param for audit_mgmt rows, context-aware PSEUDO:OBJECT anonymization |
| 1.1.0   | released | 2026-05-28 | R1+R2: CIS coverage (Section 9) + Audit-Roles (Section 10) report sections; R4: --export-prompt flag; AI section renumbered to 11 |
| 1.1.1   | released | 2026-05-28 | R5: dual-language DE/EN output; D1: off-path detection doc + sql/19-offpath-candidates.sql |
| 1.2.0   | released | 2026-05-28 | R3: --sample-rows flag; D2: export_siem.py (OCSF + Sentinel); B6: CSV sanity check; B7: TABLESPACE_STATE; UX1: no-arg -> --help; version alignment |
| 1.2.1   | released | 2026-05-28 | docs/use-cases/ + CHANGELOG.md in dist tarball; comprehensive README.md |
<!-- markdownlint-enable MD013 MD060 -->

---

## v1.1.0 - "Report completeness + usability"

Goal: surface CIS coverage and audit-role membership in the Markdown
report (currently collected but not rendered), improve usability for
large audit trails, and add an offline AI prompt export for use with
any provider.

### Deliverables

**R1 - CIS coverage section in report** (`audit_report.py`)

- Add `render_section_09_cis_coverage(file_data)` that reads
  `17_cis_coverage.csv` and emits a per-control PASS/WARN/FAIL table.
- Wire into `render_report()` after Section 8 (tuning).
- Acceptance: report contains a "CIS 5.1-5.5 Abdeckung" section;
  FAIL rows are clearly highlighted.

**R2 - Audit roles section in report** (`audit_report.py`)

- Add `render_section_10_audit_roles(file_data)` that reads
  `18_audit_roles.csv` and emits WARN/REVIEW rows prominently.
- Add `render_report()` call.
- Acceptance: report surfaces any non-STANDARD risk flags for
  AUDIT_ADMIN / AUDIT_VIEWER grantees.

#### R3 - Large audit trail performance

- Add `--sample-rows N` flag to `bin/ora-db-audit.sh` (default: no
  limit) that injects `FETCH FIRST N ROWS ONLY` into the heavy
  profiling queries (08-12, 15).
- Add a `# sampled: true` metadata line when sampling is active so
  the reporter and AI prompt can note the blind spot.
- Acceptance: on a 10M-row trail, `--sample-rows 500000` completes
  in under 5 minutes.

**R4 - `--export-prompt` flag** (`tools/audit_report.py`)

- New flag: `--export-prompt FILE`. Builds the full AI prompt (with
  report data embedded) and writes it to FILE instead of sending to
  the API.
- Output includes a short header comment: provider-agnostic
  instructions (paste into claude.ai, ChatGPT, etc.).
- Acceptance: `--export-prompt prompt.txt` writes a self-contained
  file that produces useful analysis when pasted into any LLM chat UI.

#### R5 - Dual-language output (DE / EN)

- Architecture is ready (`tools/audit_report_messages.py` exists).
- Populate `MESSAGES["en"]` with English translations of all
  user-facing strings.
- Wire `--lang en|de` flag (default `de`).
- Acceptance: `--lang en` produces a fully English Markdown report;
  `--lang de` (default) is unchanged.

### Acceptance (v1.1.0 release gate)

- `make test` green (bats + pytest, ≥ 31 passing)
- `make lint` clean
- `bin/ora-db-audit.sh --help` documents `--sample-rows`
- Report contains CIS coverage section and audit-roles section
- `--export-prompt` works without API key or Claude CLI installed

---

## v1.2.0 - "Off-path detection + SIEM adapters" (released)

Goal: formalise the off-path detection use case and add an optional
SIEM-friendly output format. Also includes `--sample-rows` for large
audit trails and three bug fixes from field testing.

### Deliverables

#### D1 - Off-path detection use case doc (done in v1.1.1)

- `docs/use-cases/off-path-detection.md` and
  `sql/19-offpath-candidates.sql` shipped in v1.1.1.

#### D2 - SIEM export adapter (done)

- `tools/export_siem.py`: reads an anonymised bundle and writes
  OCSF 1.3 Database Activity JSON Lines (`--format ocsf`) or
  Microsoft Sentinel / Log Analytics CSV (`--format sentinel`).
- Wired into `bin/ora-db-audit.sh` via `--export-siem FORMAT OUTPUT`.

#### R3 - Large audit trail performance (done)

- `--sample-rows N` flag added to `bin/ora-db-audit.sh`.
- `DEFINE SAMPLE_WHERE` injected via `sql/00-setup.sql` into queries
  08-12, 15; each emits `# sampled: true/false` in its CSV preamble.
- Executive summary notes the sampling blind spot.

#### Bug fixes (done)

- B6: CSV sanity-check filename mismatch (hyphens vs underscores).
- B7: TABLESPACE_STATE schema type missing from anonymiser allowlist.
- UX1: No-arg invocation now shows `--help` (multitenant default).

---

## v2.0.0 - "Policy Generator + Migration helper"

Goal: close the audit lifecycle loop - go from compliance requirement
to ready-to-deploy DDL, and assist Mixed-to-Pure migrations.

### Deliverables

#### P1 - Policy Generator

- Interactive CLI: `bin/ora-db-audit.sh --generate-policy`.
- Input: compliance requirement (CIS control ID, STIG rule ID, or
  free-text action list) + scope (CDB / PDB, user/role, object).
- Output: ready-to-run `CREATE AUDIT POLICY ... AUDIT ... WHEN ...` +
  matching `NOAUDIT POLICY ...` cleanup stub.
- Integrates with `/oracle-audit` skill for policy-design guidance.

#### P2 - Mixed-to-Pure migration helper

- New SQL `sql/20-legacy-audit-inventory.sql`: lists `AUD$`,
  `FGA_LOG$`, `AUDIT TRAIL` entries from Traditional Auditing.
- Report section: migration impact assessment - row counts, retained
  policies, estimated cutover risk.
- Generates a phased cutover script:
  `NOAUDIT ALL; ALTER SYSTEM SET audit_trail=NONE SCOPE=SPFILE;`
  with required `DBMS_AUDIT_MGMT` cleanup sequence.

#### P3 - Extended compliance mapping

- Add PCI-DSS v4.0 and ISO 27001:2022 controls to
  `docs/compliance-mapping.md`.
- New report section: compliance gap table per standard.

---

## Beyond v2.0 - candidate ideas (no commitment)

- Oracle 26ai-specific unified audit enhancements (once docs stabilise)
- GUI / dashboard (out of scope unless community demand emerges)
- `ora-db-audit` as a Python package (pip-installable)
- Multi-PDB parallel collection mode

---

## Out of scope (permanent)

- Traditional auditing (`AUDIT_TRAIL=DB|OS|XML` legacy mode) -
  desupported in 23ai+.
- Reading binary mandatory `*.aud` files - covered by Oracle utilities.
- GUI dashboard as a primary deliverable.

---

## How to evolve this roadmap

- Stefan owns priority changes. Discuss in
  `~/notes/projects/audit-tool.md` first, then update this file.
- New candidate features: append to "Beyond v2.0" section; do not
  promote to a versioned milestone without deliverable + acceptance
  criteria defined.
- Real cadence is tracked via git tags + `CHANGELOG.md` entries.
