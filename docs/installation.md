# Installation and Setup

This guide covers prerequisites, installation options, database user setup, and verification
for the `ora-db-audit` toolkit.

---

## Prerequisites

### On the Database Host

- `sqlplus` in PATH - source the Oracle environment before running: `. oraenv`
- Bash 3.2 or later (macOS stock bash is sufficient)
- Write access to the output directory
- Oracle Unified Auditing in **Pure Mode** - Mixed Mode is detected automatically and flagged
  in the report

### Python (Optional - for Reporting, Anonymisation, SIEM Export, HTML)

Python is not required for data collection. It is needed only for post-processing steps.

**Minimum version:** Python 3.10 or later

**Auto-detection order** (first match wins):

1. `$ORACLE_HOME/python/bin/python`
2. `python3` in PATH
3. `python` in PATH

**Package requirements by feature:**

| Feature flag        | Required packages                                         |
|---------------------|-----------------------------------------------------------|
| `--report`          | stdlib only - no packages needed                          |
| `--anonymize`       | stdlib only - no packages needed                          |
| `--export-siem`     | stdlib only - no packages needed                          |
| `--to-html`         | `pip install markdown`                                    |
| `--ai` with API key | `pip install anthropic` (uncomment in `requirements.txt`) |

---

## Installation

### Option A - Git Clone (Recommended for Development)

```bash
git clone https://github.com/oehrlis/ora-db-audit.git
cd ora-db-audit
# Optional: install Python packages for reporting
pip install -r requirements.txt
```

### Option B - Release Tarball (Recommended for Production Deployment)

```bash
tar xzf ora-db-audit-1.4.0.tar.gz
cd ora-db-audit-1.4.0
pip install -r requirements.txt
```

### Option C - Makefile (for Contributors)

```bash
make help   # show available targets
make lint   # run markdownlint + shellcheck
make test   # run bats + pytest
```

---

## Database User Setup

Two connection methods are supported.

### Default: OS-Authenticated SYSDBA

The simplest approach. Runs at CDB level on Oracle 21c+ by default.

```bash
. oraenv
./bin/ora-db-audit.sh --days 30
```

Use `--pdb MYPDB` to target a specific PDB after the initial SYSDBA connect.

### Dedicated Audit Analyst User (Principle of Least Privilege - Recommended)

Create a named user with the minimum privileges required to run all collection queries:

```sql
CREATE USER audit_analyst IDENTIFIED BY "<password>";
GRANT CREATE SESSION                          TO audit_analyst;
GRANT AUDIT_VIEWER                            TO audit_analyst;
GRANT SELECT ON V_$INSTANCE                   TO audit_analyst;
GRANT SELECT ON DBA_AUDIT_MGMT_CONFIG_PARAMS  TO audit_analyst;
GRANT SELECT ON DBA_AUDIT_MGMT_CLEANUP_JOBS   TO audit_analyst;
GRANT SELECT ON DBA_AUDIT_MGMT_LAST_ARCH_TS   TO audit_analyst;
GRANT SELECT ON DBA_PART_TABLES               TO audit_analyst;
GRANT SELECT ON DBA_TAB_PARTITIONS            TO audit_analyst;
GRANT SELECT ON DBA_SEGMENTS                  TO audit_analyst;
GRANT SELECT ON UNIFIED_AUDIT_POLICIES        TO audit_analyst;
GRANT SELECT ON AUDIT_UNIFIED_ENABLED_POLICIES TO audit_analyst;
GRANT SELECT ON DBA_ROLE_PRIVS               TO audit_analyst;
GRANT EXECUTE ON DBMS_METADATA               TO audit_analyst;
-- CDB-wide collection (optional, grant from CDB$ROOT only):
-- GRANT AUDIT_VIEWER TO audit_analyst CONTAINER = ALL;
```

Connect with the named user:

```bash
./bin/ora-db-audit.sh --days 30 --connect "audit_analyst/<password>@DBSID" --pdb MYPDB
```

### Wallet / Passwordless Connection

Use an Oracle wallet entry to avoid embedding credentials in scripts or command history:

```bash
./bin/ora-db-audit.sh --days 30 --connect "/@DBSID_AUDIT" --pdb MYPDB
```

This requires a matching entry in `sqlnet.ora` / `tnsnames.ora` and an Oracle wallet configured
for `DBSID_AUDIT`.

---

## Verification

Check that the script is accessible and shows help:

```bash
./bin/ora-db-audit.sh --help
```

Run a dry-run to validate the connect string and SQL paths without touching the database:

```bash
./bin/ora-db-audit.sh --dry-run --days 7 --pdb MYPDB
```

Verify Python packages:

```bash
python3 -c "import markdown; print('markdown OK')"
python3 -c "import anthropic; print('anthropic OK')"   # only needed for --ai with API key
```
