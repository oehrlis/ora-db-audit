# Troubleshooting and FAQ

This document covers common errors, their causes, and how to resolve them, followed by
frequently asked questions.

---

## Common Errors

<!-- markdownlint-disable MD013 MD060 -->
| Symptom / Error | Cause | Fix |
|---|---|---|
| `ERROR: bundle not found: <path>` | Relative path not resolvable | Use an absolute path or run from the directory containing the bundle |
| `ModuleNotFoundError: No module named 'markdown'` | `markdown` package not installed | `pip install markdown` or `pip install -r requirements.txt` |
| `ModuleNotFoundError: No module named 'anthropic'` | `anthropic` package not installed | Uncomment in `requirements.txt` and run `pip install -r requirements.txt` |
| `ORA-01017: invalid username/password` | Wrong connect string | Check connect string, wallet, or `sqlnet.ora` |
| `missing or empty output: <NN>_query.csv` | Insufficient privileges or query error | Check `_sqlplus.log` in the bundle directory; verify database grants |
| `[FATAL] Bundle has no manifest.json` | Wrong input path or `.tar.gz` not extracted | Pass the `.tar.gz` file directly to `--from-bundle` (script extracts it automatically) |
| `Bundle dir already exists` prompt | Re-running on the same output directory | Use `--yes` to overwrite, or choose a different `--output` directory |
| `anonymize_bundle.py: python not found` | Python not in expected location | Set `ORACLE_HOME` or use `--tools-dir` to specify the Python interpreter path |
| `ERROR: no python3 interpreter found` | Python not in PATH | Install Python 3.10+ or source the Oracle environment (`. oraenv`) |
| `command not found: pandoc` during `make to-html` | pandoc not installed | `pip install markdown` (Python fallback, no pandoc needed) |
| Mixed Mode detected and flagged | Database is using Mixed Mode audit | Informational only - collection still works; consider migrating to Pure Mode |
<!-- markdownlint-enable -->

---

## FAQ

**Q: Do I need Python for basic data collection?**

No. The `--days`, `--pdb`, `--connect`, and `--output` flags only require `sqlplus`.
Python is only needed for `--report`, `--anonymize`, `--export-siem`, `--to-html`, and `--ai`.

---

**Q: Can I run this on a non-CDB (traditional) 19c database?**

Yes. Use `./bin/ora-db-audit.sh --days 30` without `--pdb`. CDB-specific queries degrade
gracefully on Non-CDB instances.

---

**Q: The bundle is larger than expected. How do I reduce it?**

Use `--top-n 50` to reduce rows per query from 100 to 50, or `--sample-rows 500000` to limit
heavy queries. Also try a shorter `--days` window.

---

**Q: Can I re-run the report without re-collecting data?**

Yes. Use `--from-bundle` with the existing `.tar.gz` bundle:

```bash
./bin/ora-db-audit.sh --from-bundle ./output/bundle.tar.gz --report --lang en
```

---

**Q: How do I run the report in English instead of German?**

Pass `--lang en` with `--report`:

```bash
./bin/ora-db-audit.sh --from-bundle bundle.tar.gz --report --lang en
```

---

**Q: The AI findings take too long. Can I use a faster model?**

The default model is `claude-sonnet-4-6`. Use `claude-haiku-4-5-20251001` for faster,
cheaper results:

```bash
./bin/ora-db-audit.sh --from-bundle bundle.tar.gz --report --ai --ai-model claude-haiku-4-5-20251001
```

---

**Q: How do I verify the collection worked?**

Check `_sqlplus.log` in the bundle directory. Successful runs show output for all 20 SQL
queries. If a query fails, the log file will contain the error message and the corresponding
CSV file will be empty or missing.

---

**Q: What does "Pure Mode required" mean?**

The tool is designed for Oracle Unified Auditing in Pure Mode. In Mixed Mode, traditional
audit tables (`AUD$`, `FGA_LOG$`) are also active. The tool detects this condition in
`01_config.csv` and flags it. Full functionality is still available; the report includes a
recommendation to migrate to Pure Mode.
