# Best Practices and Recommendations

This document covers recommended practices for data handling, connectivity, performance,
and compliance when using `ora-db-audit`.

---

## Data Sensitivity

### What the Bundle Contains

Every collected bundle may contain the following categories of sensitive data:

- DB usernames and OS usernames
- Host names and IP addresses (network audit records)
- Client program names and terminal identifiers
- Full SQL text (`SQL_TEXT` column in some `UNIFIED_AUDIT_TRAIL` records)

### Rules

1. Never push a raw bundle (`*.tar.gz`) to a public repository or shared cloud storage.
2. Always use `--anonymize` before transferring bundles off the database host.
3. Store the `.mapping.json` file locally on the database host only - never share it.
4. The `.anon.tar.gz` (anonymised bundle) is safe to share with analysts and support teams.
5. After the engagement, delete raw bundles and mapping files from the analyst machine.

---

## Database Connectivity

- Prefer a dedicated `audit_analyst` user over `SYSDBA` for the principle of least privilege.
- Use a wallet (`--connect "/@DBSID_AUDIT"`) for automated or scripted runs - avoids passwords
  appearing in shell history or process lists.
- Grant the `AUDIT_VIEWER` role rather than individual `SELECT` grants where possible.
- For CDB-wide analysis, grant `AUDIT_VIEWER TO audit_analyst CONTAINER = ALL` from `CDB$ROOT`.

---

## Output Directory

- Use an absolute path for `--output` to avoid ambiguity when running from different working
  directories.
- Choose a directory with at least 200 MB free space. Bundles are typically 1-50 MB; multiple
  runs accumulate.
- Place the output directory outside the Oracle home and datafile directories.
- Do not use a cloud-synced directory (Dropbox, OneDrive, etc.) if it may contain raw bundles.

---

## Python Environment

- Pin the Python interpreter: set `ORACLE_HOME` so `$ORACLE_HOME/python/bin/python` is the
  auto-detected interpreter.
- In container or VM environments, use a dedicated virtual environment:

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
```

- For `--ai` with an API key, store the key in 1Password and use `--ai-op-path` instead of
  setting the `ANTHROPIC_API_KEY` environment variable directly:

```bash
./bin/ora-db-audit.sh \
    --from-bundle bundle.tar.gz \
    --report --ai \
    --ai-op-path "op://vault/anthropic/api-key"
```

---

## Collection Cadence

<!-- markdownlint-disable MD013 MD060 -->
| Phase | Frequency | Recommended flags |
|---|---|---|
| Initial baseline | Once | `--days 30 --anonymize --report` |
| Workshop preparation | Once per workshop | `--days 30 --anonymize --report --patterns patterns.json` |
| Monthly trend | Monthly | `--days 30 --anonymize --report` |
| Post-policy deployment | 7 days after each policy change | `--days 7 --top-n 50 --anonymize --report` |
<!-- markdownlint-enable -->

---

## Performance

- For audit trails with more than 10M rows, always use `--sample-rows 500000` to keep
  collection under 5 minutes.
- Run during off-peak hours - the SQL queries perform a full scan of `UNIFIED_AUDIT_TRAIL`.
- Use `--top-n 50` for initial scans; increase to `--top-n 200` for detailed analysis.

---

## Report Quality

- Always provide a `--patterns` file for production environments. The built-in defaults are
  for the `auditlab` test environment only and will produce low-quality findings on real data.
- Use `--lang en` for international engagements; `--lang de` (default) for German-speaking
  customers.
- Add `--include-appendix` to include the full DDL of all audit policies in the report
  (adds approximately 5-20 pages depending on environment).
- Use `--ai` for security signal analysis - it significantly improves report quality and
  actionability by identifying patterns that rule-based analysis misses.

---

## Compliance

- Map enabled policies to CIS Oracle DB Benchmark controls 5.1-5.5 using `17_cis_coverage.csv`
  or the report Section 9.
- Review `18_audit_roles.csv` (Section 10) for excessive `AUDIT_ADMIN` grants.
- See [compliance-mapping.md](compliance-mapping.md) for the full CIS/STIG/Oracle BP control
  mapping table.
