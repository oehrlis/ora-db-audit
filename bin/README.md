# bin/

This directory contains the main entry point for the toolkit.

**`ora-db-audit.sh`** - main shell script. Orchestrates collection, anonymisation, reporting,
and HTML conversion.

## Usage

```bash
# Source Oracle environment
. oraenv

# Basic collection
./bin/ora-db-audit.sh --days 30 --pdb MYPDB

# Full workflow
./bin/ora-db-audit.sh --days 30 --pdb MYPDB --anonymize --report --to-html

# Show all options
./bin/ora-db-audit.sh --help
```

## Key Flags

| Flag | Description |
|------|-------------|
| `--days N` | Time window for audit trail queries |
| `--pdb NAME` | Target PDB (required on 21c+ for PDB-level analysis) |
| `--connect "CONN"` | SQL*Plus connect string (default: `/ as sysdba`) |
| `--anonymize` | Anonymise bundle after collection |
| `--report` | Render Markdown analysis report |
| `--to-html` | Convert report to HTML (requires `pip install markdown`) |
| `--ai` | Add AI findings (implies `--report`) |
| `--from-bundle FILE` | Offline mode from existing bundle |
| `--dry-run` | Print actions without executing |

See [docs/configuration.md](../docs/configuration.md) for the full CLI reference.
