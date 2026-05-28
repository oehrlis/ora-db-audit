# tools/

Python helper scripts for reporting, anonymisation, SIEM export, and HTML conversion.

**Python 3.10+ required.** Core collection does not require these tools.

## Scripts

<!-- markdownlint-disable MD013 MD060 -->
| Script | Purpose | Python packages |
|--------|---------|-----------------|
| `audit_report.py` | Render `audit_report.md` from a CSV bundle | stdlib only |
| `audit_report_messages.py` | Localised string constants (DE/EN) for the report | stdlib only |
| `anonymize_bundle.py` | Pseudonymise a raw bundle - replaces real identifiers with tokens | stdlib only |
| `anonymize_audit_log.py` | Anonymise a single audit log file | stdlib only |
| `deanonymize_report.py` | Restore real values in report .md files using .mapping.json | stdlib only |
| `export_siem.py` | Convert bundle to OCSF JSON Lines or Sentinel CSV | stdlib only |
| `md_to_html.py` | Convert `audit_report.md` to standalone HTML | `markdown>=3.0` |
<!-- markdownlint-enable -->

## Install Python Packages

```bash
pip install -r requirements.txt       # markdown (for --to-html)
# pip install anthropic               # optional: for --ai with API key
```

## Direct Usage

```bash
# Render report directly
python3 tools/audit_report.py ./bundle_dir --lang en

# Export AI prompt without API
python3 tools/audit_report.py ./bundle_dir --export-prompt ./ai_prompt.txt

# Anonymise a bundle
python3 tools/anonymize_bundle.py ./bundle_dir --prefix ACME

# SIEM export
python3 tools/export_siem.py ./bundle_dir --format ocsf --output events.jsonl

# HTML conversion
python3 tools/md_to_html.py audit_report.md audit_report.html "Report Title" docs/report.css
```
