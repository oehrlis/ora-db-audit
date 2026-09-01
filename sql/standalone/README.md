# sql/standalone/

Copy-paste-ready blind-spot **summaries** for SQL*Plus and SQL Developer.

These files are self-contained: they require no tool setup, no bundle directory, and write
no spool file. Run them directly in an interactive SQL*Plus session or paste them into SQL
Developer's worksheet. Output is printed to the screen only, via `dbms_output`.

They are read-only - no table, no temporary object, no session setting beyond display
formatting is created.

---

## Summary, not a listing

This is the key difference to the numbered queries in `sql/`:

<!-- markdownlint-disable MD013 MD060 -->
| | `sql/23`, `sql/24` | `sql/standalone/blind-spot-*.sql` |
|---|---|---|
| Purpose | data collection | reading the result |
| Granularity | one row per user (per container) | aggregated roll-up |
| Output | CSV spool file for the report pipeline | formatted screen output |
| Rows on a 250-account database | ~250 (or ~1000 CDB-wide) | ~20 |
<!-- markdownlint-restore -->

A row-per-user listing is the right shape for a CSV that a reporting tool consumes. On
screen it is unusable: the overwhelming majority of rows are locked or Oracle-maintained
accounts covered by `ORA_SECURECONFIG`, and the handful of accounts that actually need a
decision is buried among them.

The standalone scripts therefore print six blocks:

<!-- markdownlint-disable MD013 MD060 -->
| Block | Content | Answers |
|-------|---------|---------|
| A Scorecard | policy count, user count, coverage percentage, blind spots, actionable blind spots | "how bad is it" |
| F Container matrix (CDB only) | one line per open container, incl. enabled customer policies per container | "which PDB do I look at" |
| B Coverage matrix | account class x login capability x coverage status | "are the gaps real or housekeeping" |
| C Blind spots | only the accounts that need a decision | "what do I do" |
| D Blind-spot groups | actionable blind spots collapsed by name pattern | "how many findings is that really" |
| E Policy effectiveness | enabled policies that reach nobody | "which policy is silently doing nothing" |
<!-- markdownlint-restore -->

Blocks A-D walk the **users**. Block E is the reverse view and walks the **policy
enablements** - see below.

Both scripts use the same classification as their numbered counterparts, including the
derived `account_class` / `login_enabled` / `actionable` columns, so the numbers on screen
match section 7.4 of the generated report exactly.

---

## The actionable subset

`actionable = Y` means all three of the following hold:

- `coverage_status = BLIND_SPOT` - no customer policy audits this user
- `account_class = CUSTOMER` - not an Oracle-shipped schema
- `login_enabled = Y` - `account_status` does not contain `LOCKED`

Everything else is context, not a finding. A blind spot on a locked account cannot be
exploited by logging in; a blind spot on an Oracle-maintained schema is normal.

Block C lists only the actionable subset by default. It never drops the rest silently -
the count of suppressed rows and the switch that reveals them are always printed.

---

## Block D - one finding, not forty rows

A database with numbered accounts (`ISC_DEV_01` .. `ISC_DEV_40`, `APP_SVC_1` ..
`APP_SVC_9`) produces one blind-spot row per account, but only **one** decision: either a
policy covers the pattern, or the pattern is deliberately exempt. Block D collapses the
actionable subset accordingly.

The pattern rule is deliberately conservative - a pattern that merges unrelated accounts
would hide a single finding inside a group, which is exactly the failure this block exists
to prevent:

- only a **trailing** run of digits is collapsed to `*` (`ISC_DEV_01` -> `ISC_DEV_*`)
- the remaining stem must be at least 4 characters (`X9` stays ungrouped)
- a pattern with fewer than `grp_min` members is not a group; its members are folded back
  into the `(ungrouped)` count, so members + ungrouped always equals the actionable total

In the CDB script a `PDBS` column shows in how many containers the pattern occurs. The
same pattern across three PDBs is one finding with one remedy per container.

Set `grp_min = 0` to switch block D off.

---

## Block E - policies that reach nobody

Blocks A-D answer "who is unaudited". Block E answers the reverse question, and it is one
the user-side view **structurally cannot** answer: a policy that is enabled, looks correct
in `AUDIT_UNIFIED_ENABLED_POLICIES`, and audits nothing.

<!-- markdownlint-disable MD013 MD060 -->
| Verdict | Meaning | Finding? |
|---------|---------|----------|
| `ENTITY_MISSING` | the named user or role does not exist - dropped, renamed, typo | **yes** |
| `ROLE_NO_GRANTEES` | the role exists, but no account holds it (transitively, PUBLIC included) | **yes** |
| `NO_USERS` | resolves, but reaches no account | **yes** |
| `EXCLUSION_DEAD` | an `EXCEPT` clause naming a non-existent user - drift marker, no coverage gap | no |
| `EXCLUSION` | an `EXCEPT` clause, entity exists | no |
| `ALL_USERS` | unrestricted enablement | no |
| `OK` | resolves and reaches at least one account | no |
<!-- markdownlint-restore -->

Grain is one row per **policy x enablement form x entity** - the grain Oracle itself uses.
A single policy routinely has several rows: enabling one policy `BY GRANTED ROLE <role>`
and additionally `BY USER SYS` is the recommended pattern for privileged-activity
policies, so "the scope of a policy" is not a single value and must not be squashed into
one column.

Unlike blocks A-D, block E does **not** filter out logon-only policies. Whether an
enablement resolves is independent of which actions the policy audits, and a dead LOGON
policy is just as broken as a dead DDL policy.

---

## Files

<!-- markdownlint-disable MD013 MD060 -->
| File | Purpose | Scope |
|------|---------|-------|
| `blind-spot-pdb.sql` | Blind-spot summary + policy effectiveness | Current container (PDB or Non-CDB) |
| `blind-spot-cdb.sql` | Blind-spot summary + policy effectiveness, all open PDBs | CDB-wide (run from CDB$ROOT) |
<!-- markdownlint-restore -->

---

## Report Controls

Both scripts define two substitution variables at the top. Edit them in place and re-run.

<!-- markdownlint-disable MD013 MD060 -->
| Variable | Default | Effect |
|----------|---------|--------|
| `bs_scope` | `ACTIONABLE` | `ACTIONABLE` customer accounts that can still log in; `CUSTOMER` every customer-account blind spot incl. locked; `ALL` every blind spot incl. Oracle-maintained |
| `bs_max_rows` | `25` | Hard cap on rows listed in block C |
| `grp_min` | `3` | Minimum members before a name pattern is reported as a group in block D. `0` disables block D |
<!-- markdownlint-restore -->

Example - show every blind spot on the database:

```sql
DEFINE bs_scope    = ALL
DEFINE bs_max_rows = 500
```

Blocks A, B and F always cover **all** users regardless of `bs_scope`; the scope only
controls which rows block C lists individually. Block D always groups the **actionable**
subset, independently of `bs_scope`. Block E is unaffected by all three - it walks policy
enablements, not users.

> **Never write a literal ampersand into these files**, not even inside a comment.
> SQL*Plus performs substitution everywhere and would stop to prompt for a value. The only
> ampersands in each file are the substitution variables listed above.

---

## Required Privileges

Either of the following is sufficient:

- `SYSDBA` (always sufficient)
- `SELECT ANY DICTIONARY` + `SELECT_CATALOG_ROLE` (for non-SYSDBA accounts)

For `blind-spot-cdb.sql`, the connecting user must be a **common user** in CDB$ROOT. A local
PDB user cannot access `CONTAINERS()` or the `CDB_*` catalog views.

`blind-spot-cdb.sql` additionally reads `V$PDBS` to detect `MOUNTED` containers. Without
that privilege the script still runs and says so explicitly instead of reporting zero.

---

## How to Run

### SQL*Plus

```bash
sqlplus sys@<tns_alias> as sysdba @sql/standalone/blind-spot-pdb.sql
```

```bash
sqlplus sys@<cdb_tns_alias> as sysdba @sql/standalone/blind-spot-cdb.sql
```

### SQL Developer

1. Open a connection to the target PDB (for `blind-spot-pdb.sql`) or to CDB$ROOT (for
   `blind-spot-cdb.sql`).
2. Open the file via **File > Open** or paste the contents into a SQL Worksheet.
3. Run as script (**F5**) - not as a single statement (**F9**), since the files contain
   SQL*Plus commands and an anonymous PL/SQL block.
4. Make sure script output is enabled (**View > DBMS Output**, or rely on the `SET
   SERVEROUTPUT ON` in the file - SQL Developer honours it when running as a script).

---

## Example Output

```text
------------------------------------------------------------------------------
UNIFIED AUDIT COVERAGE - CDB FREE - 2026-09-01 11:24
------------------------------------------------------------------------------
Containers analysed: 2
User-container rows: 88 (18 customer, 70 oracle-maintained)
Customer accounts covered by a customer policy: 14 of 18 (78%)
Deliberate exemptions (EXCLUDED_EXCEPT): 0
Blind spots: 40 - thereof actionable: 4

F) CONTAINER MATRIX (one line per open container)

CON_ID  CONTAINER               POL  USERS  COVERED  EXCEPT  BLIND  ACTIONABLE
1       CDB$ROOT                  0     40        0       0     40           4
4       AUDITPDB1                 9     48       48       0      0           0

POL = enabled customer activity policies in that container.
POL = 0 is the finding itself: nothing there can ever be covered.
```

The finding here is one line, not 88: `CDB$ROOT` has no customer policy at all, and four
common accounts that can log in are unaudited.

---

## Caveats

- `blind-spot-cdb.sql` uses `CONTAINERS()`, which requires a CDB. On a Non-CDB the query
  fails; use `blind-spot-pdb.sql` there.
- `CONTAINERS()` only returns **OPEN** containers. A PDB in `MOUNTED` state does not appear
  in the result - block F prints how many, so the omission is visible rather than implied.
- `PDB$SEED` is not returned by `CONTAINERS()` and therefore absent from the matrix. This is
  intentional; the seed template has no accounts worth auditing.
- When `blind-spot-cdb.sql` is run from inside a PDB (not CDB$ROOT), `CONTAINERS()` degrades
  to that one container - expected and verified behaviour.
- `SET TAB OFF` is required and set by both scripts. SQL*Plus defaults to `TAB ON`, which
  replaces runs of spaces in the output with tab characters and destroys the column
  alignment of every table depending on the terminal tab stop.
- Block D needs **real** account names. It is therefore standalone-only in practice: on an
  anonymised bundle every principal becomes `DBUSER_nnn` and all patterns are destroyed.
  `tools/audit_report.py` detects the anonymiser's own `DBUSER_NNN` token format and says
  that grouping was skipped instead of printing one meaningless catch-all group. Note that
  a *ratio*-based detection does not work there: the anonymiser whitelists
  Oracle-maintained schemas, so pseudonyms are a minority of the rows even in a fully
  anonymised bundle.
- Policy names longer than the column width are truncated in the output. The full values
  are in `25_policy_effectiveness.csv` / `26_policy_effectiveness_cdb.csv`.
- These files share their classification logic with the numbered queries. If the coverage
  model in `sql/23-blind-spot-pdb.sql` / `sql/24-blind-spot-cdb.sql`, or the effectiveness
  model in `sql/25-policy-effectiveness.sql` / `sql/26-policy-effectiveness-cdb.sql`,
  changes, then the standalone files plus `render_section_07_4_blind_spot()` and
  `render_section_07_5_policy_effectiveness()` in `tools/audit_report.py` must be updated
  with it.
