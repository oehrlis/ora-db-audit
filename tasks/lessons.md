# tasks/lessons.md - ora-db-audit

Patterns extracted from corrections and fix commits. Updated by `/evolve`.

---

## L-01: ALTER AUDIT POLICY CONDITION is invalid Oracle syntax

`ALTER AUDIT POLICY ... CONDITION` / `WHEN` does not exist in Oracle.
Changing a WHEN clause requires DROP AUDIT POLICY + recreate.

**Why:** Emitting ALTER statements caused the report to suggest SQL that cannot
be executed. Documented in `docs/ai-analysis-rules.md §4`.

**How to apply:** When generating WHEN-clause tuning suggestions, emit a boolean
condition expression only (for manual DROP+CREATE), never a full ALTER statement.

**verify:** `grep -rn "ALTER AUDIT POLICY" tools/ | grep -i "condition\|when"` → 0 matches

[promoted → rule: oracle-audit.md §WHEN Clause Changes]

---

## L-02: Unified Audit view column ownership confusion

`entity_name` / `entity_type` belong to `AUDIT_UNIFIED_ENABLED_POLICIES`, not
`AUDIT_UNIFIED_POLICIES`. `audit_trail_type` does not exist; correct column is
`audit_trail` in `DBA_AUDIT_MGMT_*` views.

**Why:** ORA-00904 occurred twice (v1.3.2, v1.4.1) with wrong column names,
causing false HIGH findings in the report.

**How to apply:** Before writing any CTE join against audit views, verify column
names from the correct view definition.

**verify:** `grep -rn "audit_trail_type\|\.entity_name\|\.entity_type" sql/` - must confirm join is to correct view

[promoted → rule: oracle-audit.md §Unified Audit View Column Ownership]

---

## L-03: Oracle LONG columns cannot appear in SQL JOINs

`HIGH_VALUE` (and other LONG-type columns) raise ORA-00997 in JOIN context
or mixed SELECT. Must be read via PL/SQL cursor loop.

**Why:** v1.4.2 fix - `sql/02-storage.sql` had to be rewritten to use a
PL/SQL cursor to emit partition HIGH_VALUE as metadata lines.

**How to apply:** Any query touching `DBA_TAB_PARTITIONS.HIGH_VALUE` must use
PL/SQL, not plain SQL JOIN.

**verify:** `grep -rn "HIGH_VALUE" sql/` → all occurrences inside PL/SQL blocks

[promoted → rule: oracle-audit.md §Oracle LONG Columns in SQL]

---

## L-04: New shell flags must be wired to Python reporter

When adding a new flag to `bin/ora-db-audit.sh`, always verify it is also
passed through to `tools/audit_report.py` in the `report_args` array.

**Why:** Missed multiple times (`--lang`, `--export-prompt`, `--customer-prefix`
in v1.3.1 fix). Flag worked at shell level but silently had no effect on report.

**How to apply:** After adding any flag: search `report_args+=` in
`ora-db-audit.sh` and confirm the new flag appears there too.

**verify:** `grep -A2 "report_args+=" bin/ora-db-audit.sh | grep "<new-flag>"`

[promoted → rule: CLAUDE.md Known Traps]

---

## L-05: Task descriptions must use actual file names

Task entries referencing this repo must use the real file paths:
`tools/audit_report.py`, `bin/ora-db-audit.sh`.

**Why:** Tasks T-01/T-02/T-03 referenced `audit_pack_report.py` /
`run_analysis_pack.sh` (from an internal predecessor artefact), causing
confusion when verifying completion.

**How to apply:** When writing tasks, confirm file existence with `ls` before
referencing a path.

**verify:** `ls bin/ora-db-audit.sh tools/audit_report.py` → both files exist

[promoted → rule: CLAUDE.md Known Traps]
