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

Full on-host workflow including Markdown report generation. Requires Python 3.10+.

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

## Detailed Use-Case Documentation

For in-depth workflows, see:

- [docs/use-cases/audit-analysis.md](use-cases/audit-analysis.md) - CSV bundle pipeline
- [docs/use-cases/audit-log-anonymisation.md](use-cases/audit-log-anonymisation.md) - anonymisation workflow
- [docs/use-cases/off-path-detection.md](use-cases/off-path-detection.md) - off-path host detection
