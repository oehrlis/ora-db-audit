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

---

## L-06: Verify a guard by triggering it, not by unit-testing its shape

A guard that never fires is worse than no guard: it makes the unsafe path look
covered. Three guards written in the v1.10.0 session passed their own tests
and were still ineffective on real data.

**Why:**

- The pseudonym guard for block D checked only the *actionable* principals and
  required a sample of 5. The actionable subset is often 3-4 rows, so the check
  never ran - while a bogus `DBUSER_*` group needs only `grp_min` (3) members
  to appear. A ratio test was equally wrong: the anonymiser whitelists
  Oracle-maintained schemas, so pseudonyms are a minority of rows even in a
  fully anonymised bundle. Fixed by matching the anonymiser's own literal
  token format (`DBUSER_NNN`) - a signal from the tool, not a heuristic.
- A bats assertion on the section headers `### 7.4` / `### 7.5` passed with
  the fixtures deleted, because both sections print their header plus a
  "not in bundle" note when the CSV is missing.
- The sample-bundle tarball was rebuilt only when *absent*, so a stale local
  tarball silently shadowed new fixtures. Gitignored, so CI was fine and only
  local runs were affected - the case nobody notices.

**How to apply:** For every guard, filter or assertion, produce the state it is
meant to catch and confirm it actually fires. Delete the input, feed the
anonymised copy, touch the fixture - then look. Never accept a green test as
evidence that the negative case is covered.

**verify:** for each new assertion, run it once with the condition removed and
confirm it fails; record that you did

---

## L-07: An ampersand anywhere in a SQL*Plus script is an input prompt

SQL*Plus performs substitution everywhere in a `.sql` file, including inside
`--` comments and inside string literals. A stray `&` stops the script and
prompts for a value.

**Why:** A comment documenting `account_status` values contained
`EXPIRED(GRACE) & LOCKED(TIMED)`. The shipped standalone script stopped with
"Enter value for locked:" and `SP2-0546`. It was caught only because the
script was executed against a live database, not merely reviewed.

**How to apply:** In `sql/` and `sql/standalone/`, the only `&<name>` forms
allowed are the intended substitution variables. Describe combined account
states in words instead.

Only `&` followed by a letter or underscore starts a substitution. `&*_PATTERN`
in a comment (`sql/19-offpath-candidates.sql:29`) is harmless - measured
2026-09-02 against Oracle FREE: zero prompts. So the check must match the
`&<name>` form, otherwise it reports a false positive on that line.

**verify:** `grep -onE '&[A-Za-z_][A-Za-z0-9_]*' sql/*.sql sql/standalone/*.sql`
→ only declared DEFINE / positional variables appear
