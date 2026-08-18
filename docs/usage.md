# Usage and Examples

This document provides copy-paste-ready commands for the most common `ora-db-audit` workflows.
For installation and prerequisites, see [installation.md](installation.md).

---

## UC-1: Local Collection Only (No Python Needed)

Run on the database host to collect a raw CSV bundle. No Python installation required.

```bash
. oraenv
./bin/ora-db-audit.sh \
    --days 30 \
    --pdb AUDITPDB1 \
    --output ./output
```

Output: `./output/ora-db-audit_<sid>_<ts>.tar.gz` - raw bundle containing real usernames, hostnames,
and SQL text.

**Important:** Keep the raw bundle local. Do not transfer it off the host without anonymising first.

---

## UC-2: Collect, Anonymise, and Share Bundle

Produce a shippable bundle with pseudonymised identifiers.

```bash
./bin/ora-db-audit.sh \
    --days 30 \
    --pdb AUDITPDB1 \
    --anonymize \
    --customer-prefix ACME \
    --output ./output
```

Produces three artefacts:

- `ora-db-audit_<sid>_<ts>.tar.gz` - raw bundle (keep local, contains real data)
- `ora-db-audit_<sid>_<ts>.anon/` - anonymised bundle (safe to share with analysts)
- `ora-db-audit_<sid>_<ts>.mapping.json` - reverse mapping table (keep local, never share)

---

## UC-3: Collect, Anonymise, and Render Report Locally

Full on-host workflow including Markdown report generation. Requires Python 3.6+.

```bash
./bin/ora-db-audit.sh \
    --days 30 \
    --pdb AUDITPDB1 \
    --anonymize \
    --report \
    --patterns /etc/ora-db-audit/patterns.json \
    --output ./output
```

Add `--to-html` to also generate an HTML report. Requires `pip install markdown`.

```bash
./bin/ora-db-audit.sh \
    --days 30 \
    --pdb AUDITPDB1 \
    --anonymize \
    --report \
    --to-html \
    --patterns /etc/ora-db-audit/patterns.json \
    --output ./output
```

---

## UC-4: Remote Report from Existing Bundle (Offline Mode)

Analyst machine workflow - no database access required. Operates entirely from a previously
collected bundle.

```bash
# Basic report from bundle
./bin/ora-db-audit.sh \
    --from-bundle ./bundles/ora-db-audit_free_20260528.tar.gz \
    --report

# Re-render with AI findings
./bin/ora-db-audit.sh \
    --from-bundle ./bundles/ora-db-audit_free_20260528.tar.gz \
    --report --ai \
    --ai-model claude-opus-4-7

# Generate HTML report
./bin/ora-db-audit.sh \
    --from-bundle ./bundles/ora-db-audit_free_20260528.tar.gz \
    --report --to-html
```

---

## UC-5: Large Audit Trails (>10M Rows)

Use `--sample-rows` to limit heavy profiling queries and keep collection under 5 minutes.

```bash
./bin/ora-db-audit.sh \
    --days 30 \
    --pdb AUDITPDB1 \
    --sample-rows 500000 \
    --report \
    --output ./output
```

`--sample-rows N` injects `ROWNUM <= N` into queries 08-12 and 15. Event counts become
estimates; rankings remain representative. The executive summary includes a sampling notice.

---

## UC-6: SIEM Export

Export audit data in formats suitable for ingestion into a SIEM platform.

```bash
# OCSF JSON Lines
./bin/ora-db-audit.sh \
    --from-bundle ./bundles/bundle.tar.gz \
    --export-siem ocsf ./output/audit_events.jsonl

# Sentinel CSV
./bin/ora-db-audit.sh \
    --from-bundle ./bundles/bundle.tar.gz \
    --export-siem sentinel ./output/audit_events.csv

# Direct via Python tool
python3 tools/export_siem.py ./bundle_dir \
    --format ocsf \
    --output ./audit_events.jsonl
```

---

## UC-7: AI Findings with Claude CLI (No API Key)

```bash
./bin/ora-db-audit.sh \
    --from-bundle ./bundles/bundle.tar.gz \
    --report --ai
```

When no `ANTHROPIC_API_KEY` is set, the tool falls back to the `claude` CLI if it is installed.
Output is appended to `audit_report.md` and also written to `audit_ai_findings.md`.

> **Note:** Expected runtime is ~2-3 minutes via the Anthropic API and ~6 minutes via the
> `claude` CLI. Plan accordingly before starting an interactive session.

To use a specific model with an API key:

```bash
export ANTHROPIC_API_KEY="your-key"
./bin/ora-db-audit.sh \
    --from-bundle ./bundles/bundle.tar.gz \
    --report --ai \
    --ai-model claude-sonnet-4-6
```

---

## UC-8: Export AI Prompt for Any LLM

Generate a self-contained prompt file that can be pasted into any LLM chat interface
(ChatGPT, Gemini, etc.).

```bash
./bin/ora-db-audit.sh \
    --from-bundle ./bundles/bundle.tar.gz \
    --report \
    --export-prompt ./ai_prompt.txt
```

The prompt file includes all relevant audit data and analysis instructions. No API key or
`claude` CLI required.

---

---

## UC-9: Blind-Spot Report - Who Is Not Audited?

The blind-spot report answers the question "which database users have no customer-defined
audit policy covering their activity?" It is the most direct way to identify gaps in audit
coverage before a compliance review or security audit.

### What it answers

For every database user, the report assigns a `coverage_status`:

<!-- markdownlint-disable MD013 MD060 -->
| coverage_status | Meaning |
|-----------------|---------|
| `COVERED_DIRECT` | User is named explicitly in at least one enabled customer policy |
| `COVERED_VIA_ROLE` | User holds a role that is referenced by an enabled policy (transitively resolved) |
| `COVERED_ALL_USERS` | An unrestricted policy covers all users in the container |
| `EXCLUDED_EXCEPT` | User is excluded via an EXCEPT clause - a deliberate exemption, not an accidental gap |
| `BLIND_SPOT` | No enabled customer policy covers this user |
<!-- markdownlint-enable -->

Only customer-controlled policies (`oracle_supplied = 'NO'`) count toward `coverage_status`.
Oracle-supplied coverage (e.g. `ORA_SECURECONFIG`) is always present and would mark every user
as covered, making the report meaningless. Oracle-supplied coverage is reported separately in the
`ora_supplied_cover` column: a user flagged `BLIND_SPOT` with `ora_supplied_cover = YES` is still
caught by Oracle baseline policies, but no customer policy audits that user's activity.

### When to use 23 vs 24

<!-- markdownlint-disable MD013 MD060 -->
| Query | When to use |
|-------|-------------|
| `23-blind-spot-pdb.sql` | Single PDB, Non-CDB, or CDB$ROOT (reports only that container) |
| `24-blind-spot-cdb.sql` | CDB-wide view - run from CDB$ROOT to cover all open PDBs in one pass |
<!-- markdownlint-enable -->

### Non-CDB and PDB caveats

- `24-blind-spot-cdb.sql` uses `CONTAINERS()` to fan queries across containers. On a Non-CDB,
  the query fails gracefully (the error is written to `_sqlplus.log`; use `23` instead).
- When `24` is run from inside a PDB (not CDB$ROOT), `CONTAINERS()` degrades to that one container
  only - this is expected and verified behaviour.
- `CONTAINERS()` only returns **OPEN** containers. A PDB in `MOUNTED` state is silently absent from
  the result. Cross-check with `CDB_PDBS` or `V$PDBS` before declaring all PDBs clean.
- For a true Non-CDB, always use `23-blind-spot-pdb.sql`.

### Running standalone (no tool setup)

The `sql/standalone/` directory contains copy-paste-ready versions that write no spool file and
require no bundle directory. See [sql/standalone/README.md](../sql/standalone/README.md).

---

## Detailed Use-Case Documentation

For in-depth workflows, see:

- [docs/use-cases/audit-analysis.md](use-cases/audit-analysis.md) - CSV bundle pipeline
- [docs/use-cases/audit-log-anonymisation.md](use-cases/audit-log-anonymisation.md) - anonymisation workflow
- [docs/use-cases/off-path-detection.md](use-cases/off-path-detection.md) - off-path host detection
