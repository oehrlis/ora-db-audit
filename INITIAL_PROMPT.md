# Initial Prompt for Follow-up Session

> **Purpose**: This document briefs the next Claude Code session that
> picks up `ora-db-audit` development. Keep it compact - the follow-up
> session reads the source repo itself and plans from there.

## Goal

Migrate the internal `audit_pack` tool (v0.5.0, currently embedded in
`~/repos/own/oehrlis/ora-db-audit-eng/artefacts/audit_pack-0.5.0/`)
into this open-source repository, sanitise customer-specific
identifiers, and reach a publishable v1.0.0.

Repository: `github.com/oehrlis/ora-db-audit` (public, Apache 2.0).
Current state: v0.1.0 scaffolding only.

## Scope of v1.0.0 (MVP)

**Standard tier**: Slim Core + Reporting/Export

- Bash entry point (single `ora-db-audit` command, replaces
  `run_analysis_pack.sh`)
- SQL analysis queries (the 16 numbered SQLs from audit_pack-0.5.0,
  see source list below)
- Anonymisation at source (customer-prefix-driven mapping, keeps
  `*.mapping.json` local)
- Optional Python reporter (Markdown / CSV / JSON output)
- Customer handover template (generic, no `ODB` hardcoded prefix)

**Out of scope for v1.0.0**: Policy-Generator, Compliance-Mapping
(CIS/PCI-DSS/ISO), Mixed-to-Pure Migration. These can land in a v2.0
roadmap.

## Source Material to Migrate

All four sources live in `~/repos/own/oehrlis/ora-db-audit-eng/`:

| Source | Purpose | Target in this repo |
|--------|---------|---------------------|
| `artefacts/audit_pack-0.5.0/run_analysis_pack.sh` | Main bash entry point (~24KB) | `src/ora-db-audit` (rename, refactor) |
| `artefacts/audit_pack-0.5.0/*.sql` (16 files: 00_setup.sql ... 15_noise_candidates.sql) | SQL analysis queries | `sql/` (keep numbering or rename to descriptive names - design decision) |
| `tools/audit_pack_report.py` | Python reporter | `tools/audit_report.py` (check if newer than `artefacts/.../tools/audit_pack_report.py`) |
| `templates/customer_audit_pack_handover.md` | Customer handover template (currently `ODB`-prefixed) | `templates/customer_handover.md` (genericise prefix to variable) |
| `doc/use-cases/uc_audit_pack_analysis.md` | Use-case documentation | `docs/use-case-analysis.md` |

Also worth pulling for context (do not migrate, but read):

- `artefacts/audit_pack-0.5.0/README.md` (~19KB) - the existing tool README
- `artefacts/audit_pack-0.5.0/dist_manifest.json` - the existing manifest
  format

## Migration Rules

1. **No customer references**. Search for and remove: `ODB`,
   customer-specific hostnames, real usernames, real SIDs, "VW" or
   similar. Replace with placeholders or document as configurable
   variables.
2. **No NDA content**. The tool itself is fine; specific findings,
   screenshots from customer environments, customer handover documents
   with real values - all stay out.
3. **Apache 2.0 header** in every source file (SQL, bash, Python).
4. **Conventional Commits** for the migration. Use `feat:`, `refactor:`,
   `docs:` etc. consistently.
5. **Atomic commits** per logical unit (one SQL file = one commit, or
   group thematically - e.g. "all policy-inventory SQL").

## Suggested First Steps in the Follow-up Session

1. Read this document + `CLAUDE.md` + `README.md`
2. Read the source `artefacts/audit_pack-0.5.0/README.md` for the
   current tool design and CLI contract
3. Diff `tools/audit_pack_report.py` against
   `artefacts/audit_pack-0.5.0/tools/audit_pack_report.py` - decide
   which is the canonical version
4. Write `tasks/migration-plan.md` proposing the file-by-file
   migration order with explicit sanitisation steps per file
5. Wait for Stefan's confirmation before starting the actual file
   moves

## Bootstrap Commands

After landing in the new session at `~/repos/own/oehrlis/ora-db-audit/`:

```bash
# Connect ai-toolkit symlinks (skills, rules, shared commands)
~/repos/own/oehrlis/ai-toolkit/init-repo.sh

# Verify skills are mounted
ls .claude/skills/
# expected (symlinks): bash-header  makefile  markdown-lint  oracle-audit

# Smoke-test
make help
```

## Cross-Refs

- PKM project tracker: `~/notes/projects/audit-tool.md`
- CLAUDE.md (repo conventions): [`CLAUDE.md`](CLAUDE.md)
- Source repo (NDA-aware, internal engineering toolkit):
  `~/repos/own/oehrlis/ora-db-audit-eng/`

## When v1.0.0 is reached

- Create GitHub repository `oehrlis/ora-db-audit` (public,
  Apache 2.0, default branch `main`)
- Push initial history
- Tag `v1.0.0`, write release notes from CHANGELOG.md
- Announce on Stefan's blog (<https://www.oradba.ch>) and Oracle ACE
  channels
- Update `~/notes/projects/audit-tool.md` Status to `done`

This file (`INITIAL_PROMPT.md`) can then be deleted or moved to
`docs/history/` for the project record.
