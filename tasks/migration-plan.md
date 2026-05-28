# Migration Plan: audit_pack-0.5.0 -> ora-db-audit v1.0.0

Status: **CONFIRMED 2026-05-28** (Stefan sign-off, amendments below applied)
Author: Claude (sessions 2026-05-27 / 2026-05-28)
Source repo: `~/repos/own/oehrlis/ora-db-audit-eng/artefacts/audit_pack-0.5.0/`
Target repo: `~/repos/own/oehrlis/ora-db-audit/` (this repo)
Target version: 1.0.0 (public, Apache 2.0)

---

## 0. Realignment - why this plan diverges from INITIAL_PROMPT.md

`INITIAL_PROMPT.md` was written assuming audit_pack-0.5.0 is a "slim core +
reporting" tool that becomes v1.0 after sanitisation, with CIS / AI / policy
generator deferred to v2.0. The actual source is materially more capable:

| Feature                                              | INITIAL_PROMPT.md says | Reality in audit_pack-0.5.0                                                    |
|------------------------------------------------------|------------------------|--------------------------------------------------------------------------------|
| Anonymisation pipeline                               | "add for v1.0"         | **Already built** (3 Python tools, type-hint-driven, mapping.json round-trip)  |
| De-anonymisation (customer-side)                     | not mentioned          | **Already built** (`deanonymize_report.py`)                                    |
| AI integration (Claude API)                          | "v2.0"                 | **Already built** (`--ai`, `--ai-model`, `--ai-op-path`, 1Password support)    |
| Offline `--from-bundle` mode                         | not mentioned          | **Already built**                                                              |
| Host-pattern classification (App/Infra/DBA/Off-Path) | not mentioned          | **Already built**                                                              |
| CIS Benchmark references                             | "v2.0"                 | Referenced in AI prompt (not formalised)                                       |
| Output format                                        | CSV (implied)          | CSV with metadata preamble + `# schema:` type-hint line driving the anonymiser |

`audit-tool.md` (PKM project doc) is closer to reality - it lists AI +
Anonymisation as M3=v1.0. We follow that roadmap.

**v1.0 is therefore primarily a sanitisation + repackaging exercise, not a
feature-build exercise.** The substantial new work is CIS formalisation,
tests, OSS-audience docs, and the OraDBA-standard Makefile.

## 1. Decisions (locked)

| #  | Decision                | Value                                                                                                                                                                                    | Reasoning                                                                                                                                                                                                                                                                  |
|----|-------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1  | v1.0 scope              | Sanitised port + formalised CIS-tagging + AI (already built)                                                                                                                             | Follow `audit-tool.md` M3 = v1.0. Matches existing code maturity.                                                                                                                                                                                                          |
| 2  | License                 | Apache 2.0                                                                                                                                                                               | Per CLAUDE.md + LICENSE in scaffold.                                                                                                                                                                                                                                       |
| 3  | Output format           | **CSV stays canonical**, JSON optional via Python reporter                                                                                                                               | **REVERSED from earlier session**: the type-hint `# schema:` line in each SQL drives the anonymiser. CSV is wired deep; JSON switch = major rewrite (anonymizer, 16 SQLs, reporter). Adding optional `--export-json` to the Python reporter is the 90/10 fix.              |
| 4  | SQL filenames           | `00-setup.sql ... 15-noise-candidates.sql` (underscore -> hyphen)                                                                                                                        | **REVERSED from earlier session**: the implicit metadata (`# query_id:` + `# schema:` + filename order) already serves as a self-describing manifest. External `sql/manifest.json` would be redundant infrastructure. Hyphen-form aligns with markdown-lint/OraDBA naming. |
| 5  | Customer prefix default | Removed default; flag becomes optional with NO default value                                                                                                                             | Current default `ODB` is customer-visible. OSS tool should not bake a default in. Empty default means "no namespace prefix" - explicit opt-in for anonymisation namespacing.                                                                                               |
| 6  | Bash entry-point name   | `bin/ora-db-audit.sh` (Stefan amendment 2026-05-28: `bin/` not `src/`, `.sh` extension kept)                                                                                             | `bin/` is the OS-convention directory for executable entry-points (FHS-aligned); `.sh` extension keeps shell-tooling (shellcheck globs, editor mode detection, IDE handling) deterministic. `src/` reserved for compiled/processed sources if ever needed.                 |
| 7  | Python tool naming      | `tools/audit_report.py`, `tools/anonymize_bundle.py`, `tools/anonymize_audit_log.py`, `tools/deanonymize_report.py` (underscores kept; only `audit_pack_report.py` -> `audit_report.py`) | Q1 confirmed: scripts run directly, never imported - underscores stay for Python-idiom + tooling compatibility. Only the `audit_pack` -> `audit_` rename removes the internal-tool branding.                                                                               |
| 8  | Bundle tarball naming   | `audit_analysis_<DBSID>_<TS>.tar.gz` -> `ora-db-audit_<DBSID>_<TS>.tar.gz`                                                                                                               | Brand consistency.                                                                                                                                                                                                                                                         |
| 9  | Python tools location   | `tools/` (top-level, as in eng repo)                                                                                                                                                     | Mirror eng/source layout; runner already auto-detects `tools/` and `src/../tools/`.                                                                                                                                                                                        |
| 10 | `deanonymize_report.py` | **Included in v1.0**                                                                                                                                                                     | Round-trip story (analyst returns anon report; customer de-anonymises locally with mapping.json) is a feature, not a v2.0 nice-to-have.                                                                                                                                    |
| 11 | Anonymisation mode      | Default **OFF** (raw bundle), `--anonymize` flag required                                                                                                                                | Same default as source; preserves DBA-trust ("nothing leaves before you flag it").                                                                                                                                                                                         |

## 2. Open Questions (resolved 2026-05-28)

| #  | Question                                            | Decision                                                    | Note                                                                                                                     |
|----|-----------------------------------------------------|-------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------|
| Q1 | Python filename underscore vs hyphen                | **Keep underscores** (scripts run directly, never imported) | Only rename `audit_pack_report.py` -> `audit_report.py` for brand cleanup.                                               |
| Q2 | Env-var prefix `ORADBA_*` keep or rebrand           | **Keep `ORADBA_*`**                                         | Stefan owns the OraDBA namespace via blog/profile.                                                                       |
| Q3 | Bring `tests/sample_bundle*` verbatim or regenerate | **Bring over verbatim**                                     | Already anonymised (post-anon output); validates round-trip from day one. Inspect mapping.json for residual real values. |
| Q4 | Commit style: 1 mega-commit vs ~12 atomic           | **(b) Atomic commits** per logical unit                     | Reviewable history, per-group rollback. Commit groupings in section 3 are the contract.                                  |

## 3. File-by-file migration order

Group order matches commit order. Each row = one staged source file. Tests
land after the artefact they exercise.

### Group A - Build/CI Foundation (no source migration)

Commit: `chore: lock migration plan + bootstrap ai-toolkit symlinks`

| Source                      | Target                                 | Sanitisation |
|-----------------------------|----------------------------------------|--------------|
| (none - new file)           | `tasks/migration-plan.md` (this file)  | n/a          |
| (none - new file)           | `docs/roadmap.md`                      | n/a          |
| ai-toolkit/init-repo.sh ran | `.claude/skills/`, `.claude/commands/` | already done |

### Group B - SQL queries (clean, lowest risk)

Commit 1: `feat(sql): import setup + config + storage queries (00-02)`
Commit 2: `feat(sql): import policy queries (03-07)`
Commit 3: `feat(sql): import top-N profiling queries (08-12)`
Commit 4: `feat(sql): import security + tuning queries (13-15)`

| Source                         | Target                             | Sanitisation                          |
|--------------------------------|------------------------------------|---------------------------------------|
| `00_setup.sql`                 | `sql/00-setup.sql`                 | Add Apache 2.0 SPDX line; rename file |
| `01_config.sql`                | `sql/01-config.sql`                | Apache header; rename                 |
| `02_storage.sql`               | `sql/02-storage.sql`               | Apache header; rename                 |
| `03_policy_inventory.sql`      | `sql/03-policy-inventory.sql`      | Apache header; rename                 |
| `04_policy_volume.sql`         | `sql/04-policy-volume.sql`         | Apache header; rename                 |
| `05_policy_user_action.sql`    | `sql/05-policy-user-action.sql`    | Apache header; rename                 |
| `06_policy_client_program.sql` | `sql/06-policy-client-program.sql` | Apache header; rename                 |
| `07_policy_host.sql`           | `sql/07-policy-host.sql`           | Apache header; rename                 |
| `08_top_users.sql`             | `sql/08-top-users.sql`             | Apache header; rename                 |
| `09_top_actions.sql`           | `sql/09-top-actions.sql`           | Apache header; rename                 |
| `10_top_objects.sql`           | `sql/10-top-objects.sql`           | Apache header; rename                 |
| `11_host_user_program.sql`     | `sql/11-host-user-program.sql`     | Apache header; rename                 |
| `12_distinct_hosts.sql`        | `sql/12-distinct-hosts.sql`        | Apache header; rename                 |
| `13_failed_logins.sql`         | `sql/13-failed-logins.sql`         | Apache header; rename                 |
| `14_privileged_activity.sql`   | `sql/14-privileged-activity.sql`   | Apache header; rename                 |
| `15_noise_candidates.sql`      | `sql/15-noise-candidates.sql`      | Apache header; rename                 |

Sanitisation diff per SQL: ~0 lines (no customer references in any SQL).
Pure file rename + Apache 2.0 SPDX comment line addition. Filename order
must also be updated in `run_analysis_pack.sh` (-> `bin/ora-db-audit.sh`).

### Group C - Python tools

Commit 5: `feat(tools): import anonymizer + audit-log column-aware sanitiser`
Commit 6: `feat(tools): import bundle anonymizer + de-anonymizer`
Commit 7: `feat(tools): import audit report generator`

| Source                         | Target                         | Sanitisation (per-file)                                                                                                                                                                                                                                      |
|--------------------------------|--------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `tools/anonymize_audit_log.py` | `tools/anonymize_audit_log.py` | line 29 comment: `(default: ODB)` -> `(default: empty)`; line 152 `ODBC` is **false positive** (ODBC driver name) - keep; line 556-558: change `--customer-prefix default="ODB"` -> `default=""` + update help text                                          |
| `tools/anonymize_bundle.py`    | `tools/anonymize_bundle.py`    | line 91: `DEFAULT_CUSTOMER_PREFIX = "ODB"` -> `""`                                                                                                                                                                                                           |
| `tools/audit_pack_report.py`   | `tools/audit_report.py`        | line 57: `DEFAULT_CUSTOMER_PREFIX = "ODB"` -> `""`; line 93 prompt text: `ODB_AUDIT_CTX` -> `<CUSTOMER>_AUDIT_CTX` placeholder; line 122 comment: `lab + Accenture customer prefix` -> `community / customer-configurable prefix`; line 1084 help text: same |
| `tools/deanonymize_report.py`  | `tools/deanonymize_report.py`  | No customer refs found - just add Apache 2.0 SPDX line                                                                                                                                                                                                       |

All four files: ensure Apache 2.0 SPDX-License-Identifier near top.

### Group D - Bash entry-point

Commit 8: `feat(bash): import ora-db-audit entry-point (was run_analysis_pack.sh)`

| Source                 | Target                | Sanitisation                                                                                                                                                                                                                                                                                                               |
|------------------------|-----------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `run_analysis_pack.sh` | `bin/ora-db-audit.sh` | OraDBA header (use `/bash-header` skill); line 44 `CUSTOMER_PREFIX="ODB"` -> `CUSTOMER_PREFIX=""`; update usage text accordingly; SQL filename references `00_setup.sql` -> `00-setup.sql` (all 16); bundle tarball prefix change; verify `set -euo pipefail`; verify no subshell anti-patterns (`/bash-perf-audit` after) |

### Group E - Templates + use cases

Commit 9: `docs: import customer handover template (genericised)`
Commit 10: `docs: import use-case docs (analysis + anonymisation)`

| Source                                        | Target                                      | Sanitisation                                                                                                                             |
|-----------------------------------------------|---------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|
| `templates/customer_audit_pack_handover.md`   | `templates/customer-handover.md`            | Line 19 `(z.B. ODB)` -> remove "z.B. ODB" example - leave only `<CUSTOMER-PREFIX>`. Replace `audit_pack` references with `ora-db-audit`. |
| `doc/use-cases/uc_audit_pack_analysis.md`     | `docs/use-cases/audit-analysis.md`          | Strip `audit_pack` -> `ora-db-audit`; review for customer hostnames / engagement references; sanitise any embedded examples.             |
| `doc/use-cases/uc_audit_log_anonymisation.md` | `docs/use-cases/audit-log-anonymisation.md` | Same sanitisation pass.                                                                                                                  |
| (eng) `doc/use-cases/uc_offpath_detection.md` | **defer to v1.1** (not in v1.0)             | Stays in eng repo for now.                                                                                                               |

### Group F - Tests

Commit 11: `test: import sample bundle + add bats + pytest harness`

| Source                                   | Target                                      | Sanitisation                                                        |
|------------------------------------------|---------------------------------------------|---------------------------------------------------------------------|
| `tools/tests/sample_bundle/`             | `tests/fixtures/sample_bundle/`             | Verify already-anon; remove if not                                  |
| `tools/tests/sample_bundle.anon/`        | `tests/fixtures/sample_bundle.anon/`        | n/a                                                                 |
| `tools/tests/sample_bundle.mapping.json` | `tests/fixtures/sample_bundle.mapping.json` | Inspect for residual real values                                    |
| `tools/tests/sample_input.log`           | `tests/fixtures/sample_input.log`           | Inspect                                                             |
| (new)                                    | `tests/bats/test-cli-parse.bats`            | Bash flag parse smoke                                               |
| (new)                                    | `tests/bats/test-from-bundle.bats`          | Offline mode smoke                                                  |
| (new)                                    | `tests/python/test_anonymizer_roundtrip.py` | Round-trip integrity (anon + de-anon == original outside whitelist) |
| (new)                                    | `tests/python/test_report_render.py`        | Reporter renders without exception on sample bundle                 |

### Group G - CIS-mapping formalisation

Commit 12: `feat(compliance): add CIS-control metadata to each SQL`

For each SQL, add a `# cis_controls:` line to the metadata preamble (lives
between `# query_id:` and `# schema:`). Example for `03-policy-inventory.sql`:

```text
# cis_controls: 4.1, 4.2
```

Mapping reference table goes into `docs/compliance-mapping.md` (new file).
Initial CIS-Oracle-Benchmark v1.x.x reference - mark version explicitly.

Reporter is updated to surface CIS controls in the executive summary table
("Section 9 - Compliance Mapping").

### Group H - OSS Polish

Commit 13: `docs: rewrite README + CHANGELOG for OSS audience`
Commit 14: `build: complete Makefile (lint, test, release, dist targets)`
Commit 15: `ci: add GitHub Actions (lint, bats, pytest)`

- README.md - drop customer-engineering framing, add Quick Start, link to use cases.
- CHANGELOG.md - sections for 0.2.0 (migration of SQL+tools), 0.5.0 (full
  feature parity with audit_pack-0.5.0), 1.0.0 (CIS + tests + release-ready).
- Makefile - per `/makefile` skill: `make lint`, `make test`, `make release`,
  `make dist` (tarball builder, mirrors `dist-audit-pack` from eng).
- `.github/workflows/ci.yml` - markdownlint, shellcheck, bats, pytest.

### Group I - Final pre-release

Commit 16: `chore: bump VERSION to 1.0.0, finalise CHANGELOG`

- Move `INITIAL_PROMPT.md` -> `docs/history/initial-prompt-2026-05-27.md`
  (kept for record per audit-tool.md final task).
- Verify no `git grep -E 'ODB|Volkswagen|VW\b|Accenture' -- ':!docs/history/'`
  hits remain.
- Tag `v1.0.0` (Stefan, manual step).

## 4. Sanitisation Cheat-Sheet (post-migration verify)

```bash
# Must return 0 matches in active source:
git grep -nE '\bODB\b' -- ':!docs/history/' ':!tests/fixtures/*.mapping.json'
git grep -nE 'Volkswagen|\bVW\b' -- ':!docs/history/'
git grep -nE 'Accenture' -- 'src/**' 'tools/**' 'sql/**'  # Templates/docs may mention it neutrally

# OK to keep:
git grep -nE 'ODBC|stefan\.oehrli@oradba\.ch|OraDBA'     # ODBC driver, Stefan brand
```

## 5. Sub-agent strategy (per Stefan's "use efficient model for impl")

| Phase                                 | Model               | Agent                                                     |
|---------------------------------------|---------------------|-----------------------------------------------------------|
| Migration planning (this doc)         | Opus (this session) | foreground                                                |
| SQL rename + Apache headers (Group B) | Sonnet              | `claude` agent (mechanical, parallel-safe)                |
| Python sanitisation (Group C)         | Sonnet              | `claude` agent (line-precise edits)                       |
| Bash refactor (Group D)               | Sonnet              | `claude` agent with `bash-header` skill                   |
| Use-case doc sanitisation (Group E)   | Sonnet              | `claude` agent                                            |
| Tests authoring (Group F)             | Sonnet              | `claude` agent with `superpowers:test-driven-development` |
| CIS-mapping formalisation (Group G)   | Opus                | foreground (domain-knowledge-heavy)                       |
| OSS polish (Group H)                  | Sonnet              | `claude` agent                                            |
| Independent code review pre-tag       | Opus                | `reviewer` agent                                          |

## 6. Estimated effort

- Group B-D: ~2 hours (mostly mechanical) - parallelisable across sub-agents
- Group E: ~1 hour (manual sanitisation review)
- Group F: ~3 hours (test writing is real work)
- Group G: ~2 hours (CIS mapping needs domain reasoning per SQL)
- Group H: ~2 hours
- Total: ~10 hours active work, spread across multiple sessions

## 7. Confirmation Checklist (signed off 2026-05-28)

1. ✅ Sign-off on this plan (with D6 amendment: `bin/ora-db-audit.sh`).
2. ✅ Open questions Q1-Q4 resolved (see section 2 table).
3. ✅ v1.0 includes Group G (CIS-mapping) - **not** split off to v0.9.
   Roadmap label "v0.9.0 = Compliance-aware + OSS-polished" therefore
   becomes a *milestone within* the v1.0 cycle, not a separate release.
   Will fold `docs/roadmap.md` v0.9 acceptance into v1.0 in a follow-up edit.
4. ✅ GitHub repo (`oehrlis/ora-db-audit`) created **after** v1.0 tag,
   not earlier. Initial push includes the full sanitised history.

Group A is complete (this plan + roadmap committed + ai-toolkit symlinks
mounted). Proceeding to Group B (SQL migration) with parallel Sonnet
sub-agents per commit unit.
