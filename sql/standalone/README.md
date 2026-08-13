# sql/standalone/

Copy-paste-ready SQL queries for SQL*Plus and SQL Developer.

These files are self-contained: they require no tool setup, no bundle directory, and write
no spool file. Run them directly in an interactive SQL*Plus session or paste them into SQL
Developer's worksheet. Output is printed to the screen only.

---

## Files

<!-- markdownlint-disable MD013 MD060 -->
| File | Purpose | Scope |
|------|---------|-------|
| `blind-spot-pdb.sql` | Blind-spot report - who is not audited | Current container (PDB or Non-CDB) |
| `blind-spot-cdb.sql` | Blind-spot report across all open PDBs | CDB-wide (run from CDB$ROOT) |
<!-- markdownlint-enable -->

Both files implement the same coverage model as their numbered counterparts
(`sql/23-blind-spot-pdb.sql` and `sql/24-blind-spot-cdb.sql`). The standalone versions add
column formatting and remove the SPOOL/DEFINE wiring that the main tool injects.

---

## Required Privileges

Either of the following is sufficient:

- `SYSDBA` (always sufficient)
- `SELECT ANY DICTIONARY` + `SELECT_CATALOG_ROLE` (for non-SYSDBA accounts)

For `blind-spot-cdb.sql`, the connecting user must be a **common user** in CDB$ROOT. A local
PDB user cannot access `CONTAINERS()` or the `CDB_*` catalog views.

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
   multiple SQL and SQL*Plus commands.

---

## Caveats

- `blind-spot-cdb.sql` uses `CONTAINERS()`, which requires a CDB. On a Non-CDB the query
  fails; use `blind-spot-pdb.sql` there.
- `CONTAINERS()` only returns **OPEN** containers. A PDB in `MOUNTED` state does not appear
  in the result. Cross-check with `V$PDBS` if you expect more PDBs than the report shows.
- When `blind-spot-cdb.sql` is run from inside a PDB (not CDB$ROOT), `CONTAINERS()` degrades
  to that one container - expected and verified behaviour.
- These files are generated from the same source logic as the main numbered queries; if the
  main queries are updated, the standalone files should be refreshed accordingly.
