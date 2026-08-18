# Customer DBA Quick Reference - ora-db-audit Collection

<!-- markdownlint-disable MD013 MD060 -->
| Field | Value |
|-------|-------|
| Tool version | `1.9.1` |
| Engagement | `<ENGAGEMENT-ID>` |
| Contact (analyst) | `<NAME> <EMAIL>` |
| Date | `<YYYY-MM-DD>` |
<!-- markdownlint-enable -->

---

## Step 1 - Prerequisites (10 min)

- [ ] `sqlplus` available: run `. oraenv` to source the Oracle environment
- [ ] Connect user has `AUDIT_VIEWER` role (or `SYSDBA`)
- [ ] Python 3.6 or later available: `python3 --version` (only needed for `--anonymize` / `--report`)
- [ ] Output directory exists with write access and at least 200 MB free space

Verify all requirements in one step after unpacking:

```bash
bash bin/ora-db-audit.sh --check-requirements
```

If `python3` in PATH is too old or missing, specify the interpreter explicitly:

```bash
bash bin/ora-db-audit.sh --python /opt/oracle/product/26ai/dbhomeFree/python/bin/python \
    --check-requirements
```

A `FAIL` on Python or a tool script means `--anonymize` / `--report` will not work - contact
your analyst. A `WARN` on `anthropic` or `pandoc` is harmless unless `--ai` or `--to-html` is needed.

---

## Step 2 - Download / Copy the Tool

```bash
# Option A: unpack the tarball provided by your analyst
tar xzf ora-db-audit-1.9.1.tar.gz
cd ora-db-audit-1.9.1

# Option B: clone from GitHub
git clone https://github.com/oehrlis/ora-db-audit.git
cd ora-db-audit
```

---

## Step 3 - Run the Collection

Replace `<PDB>` with your PDB name (or omit `--pdb` for Non-CDB / CDB-wide):

```bash
. oraenv    # source Oracle environment (sets ORACLE_SID, ORACLE_HOME, PATH)

bash bin/ora-db-audit.sh \
    --days 30 \
    --pdb <PDB> \
    --anonymize \
    --report \
    --to-html \
    --lang de \
    --output ./audit_output
```

For SYSDBA-less connect (dedicated user):

```bash
bash bin/ora-db-audit.sh \
    --days 30 \
    --pdb <PDB> \
    --connect "audit_analyst/<password>@<TNS>" \
    --anonymize \
    --report \
    --to-html \
    --lang de \
    --output ./audit_output
```

---

## Step 4 - What to Send

After the run, your output directory will contain:

```text
audit_output/
  ora-db-audit_<SID>_<TS>.tar.gz         <- raw bundle  DO NOT SHARE
  ora-db-audit_<SID>_<TS>.anon.tar.gz    <- anonymised  SEND THIS
  ora-db-audit_<SID>_<TS>.mapping.json   <- reverse map KEEP LOCAL
```

**Send only the `.anon.tar.gz` file** to your analyst.
Keep the raw `.tar.gz` and `.mapping.json` on the database host.

---

## Step 5 - Troubleshooting

<!-- markdownlint-disable MD013 MD060 -->
| Problem | Fix |
|---------|-----|
| `ORA-01017: invalid username/password` | Check connect string or wallet |
| `missing or empty output: NN_query.csv` | Check `_sqlplus.log` - probably missing privileges |
| `python not found` | Run `. oraenv` to set `ORACLE_HOME`; or contact analyst |
| `SyntaxError: future feature annotations` | Python version too old (< 3.6); use `--check-requirements` to diagnose |
| `python not found` / wrong version | Use `--python /path/to/python3` to override; verify with `--check-requirements` |
| Bundle > 100 MB | Re-run with `--top-n 50 --days 14` |
<!-- markdownlint-enable -->

Questions? Contact your analyst: `<NAME>` at `<EMAIL>`.
