# Configuration and CLI Reference

This guide covers the complete CLI reference, multitenant scenarios, patterns file configuration,
output structure, report sections, and SIEM export formats.

---

## Full CLI Reference

```text
./bin/ora-db-audit.sh [OPTIONS]

Collection:
  --days N             Time window in days (default: 30)
  --top-n N            Top N rows per query (default: 100)
  --sample-rows N      Limit source rows in queries 08-12, 15 via ROWNUM <= N.
                       Default 0 (no limit). Use for large trails (>10M rows).
  --connect "CONN"     sqlplus connect string (default: "/ as sysdba")
                       Examples: "/ as sysdba" | "user/pw@DBSID" | "/@DBSID_WALLET"
  --pdb NAME           Switch to PDB NAME after connect (ALTER SESSION SET CONTAINER).
  --output DIR         Output directory (default: ./audit_bundle)

Anonymisation:
  --anonymize          Run anonymise_bundle.py after collection.
                       Produces .anon/ + .mapping.json + .anon.tar.gz.
  --customer-prefix P  Prefix kept visible in pseudonym namespacing.
  --deanonymize        Restore real values in report .md files.
                       Requires .mapping.json next to the bundle.
  --mapping FILE       Explicit .mapping.json path (with --deanonymize).

Reporting:
  --report             Render audit_report.md from the bundle.
  --lang de|en         Report language (default: de). Requires --report.
  --patterns FILE      Host-pattern config JSON for report classification.
  --include-appendix   Append a full policy DDL listing to the report.
  --export-prompt FILE Write the full AI prompt to FILE (any LLM). Requires --report.
  --tools-dir DIR      Override Python tools location.

AI findings:
  --ai                 Append Claude API findings (implies --report).
  --ai-model MODEL     Claude model (default: claude-sonnet-4-6).
  --ai-op-path PATH    1Password op:// path for the Anthropic API key.

HTML output:
  --to-html            Convert audit_report.md to audit_report.html (implies --report).
                       Requires: pip install markdown

SIEM export:
  --export-siem FORMAT OUTPUT
                       Convert bundle to FORMAT (ocsf|sentinel) and write to OUTPUT.
                       Runs after collection or --from-bundle.

Offline mode:
  --from-bundle FILE   Extract existing bundle and run post-processing.
                       No database connection required.

General:
  --dry-run            Print actions; do not execute.
  --yes, -y            Overwrite existing output without prompting.
  --help               Show this help.
```

---

## Multitenant (CDB/PDB) Reference

On Oracle 21c and later, all databases are multitenant by default. Running without `--pdb`
connects to CDB$ROOT and aggregates data from all PDBs visible to the connected user.
Use `--pdb` to scope the collection to a single PDB.

<!-- markdownlint-disable MD013 MD060 -->
| Scenario | Connect string | PDB flag |
|---|---|---|
| CDB-wide (all containers) | `/ as sysdba` | no `--pdb` |
| Specific PDB via SYSDBA | `/ as sysdba` | `--pdb MYPDB` |
| Specific PDB via named user | `user/pw@SID` | `--pdb MYPDB` |
| Non-CDB (19c traditional) | `/ as sysdba` | no `--pdb` |
| Wallet + PDB | `/@SID_WALLET` | `--pdb MYPDB` |
<!-- markdownlint-enable -->

---

## Patterns File

The `--patterns FILE` option accepts a JSON file that controls host classification in report
Sections 7 and 11. Hosts are matched against regex patterns and assigned to one of four tiers.

Priority order (highest to lowest): INFRA > APP > DBA > OFF-PATH

```json
{
  "app_host_patterns":   ["^webserver-", "^app-", "-[a-z0-9]{10}-[a-z0-9]{5}$", "-[0-9]{10}-"],
  "infra_host_patterns": ["^db-", "^oem-", "^backup-"],
  "dba_host_patterns":   ["^laptop-", "^jumphost-", "^mgmt-"]
}
```

Hosts that do not match any pattern are classified as OFF-PATH and surfaced in Section 7.2.2
and in `19_offpath_candidates.csv`.

### Built-in Default Patterns

When no `--patterns` file is provided the following defaults apply. They cover common naming
conventions including generic Kubernetes pod patterns and are suitable as a starting point.
Customer-specific prefixes must be added via `--patterns`.

```json
{
  "app_host_patterns": [
    "^auditlab-app-",
    "^app-",
    "^wls-",
    "-[a-z0-9]{10}-[a-z0-9]{5}$",
    "-[0-9]{10}-"
  ],
  "infra_host_patterns": ["^auditlab-db", "^oem-"],
  "dba_host_patterns":   ["^laptop-", "^jumphost-"]
}
```

The two generic Kubernetes patterns require no customer-specific configuration:

| Pattern | Matches | Example |
| --- | --- | --- |
| `-[a-z0-9]{10}-[a-z0-9]{5}$` | K8s ReplicaSet/Deployment pod | `my-svc-6c4d8bbdfd-jdbsd` |
| `-[0-9]{10}-` | K8s CronJob pod (Unix timestamp embedded) | `batch-1774600200-main-xyz` |

Customer-specific host prefixes (e.g. `^ejpdxa`, `^eap`, `^wls-prod-`) must be added to a
customer `--patterns` file. Running `sql/19-offpath-candidates.sql` standalone requires
overriding the `APP_PATTERN` DEFINE variable accordingly.

### Application Context (Scenario A)

If the target database has an Oracle Application Context deployed (recognisable by
`SYS_CONTEXT(...)` conditions in Section 3 of the report), the tool automatically detects
it and shows the context variables in Section 7.2.1. In this scenario the audit trail already
contains only off-path records for context-conditioned policies - pattern classification in
Section 7.2.2 provides additional coverage for policies without conditions.

See `docs/use-cases/off-path-detection.md` for the full two-scenario model.

---

## Output Structure

After a full run the output directory contains the following files and subdirectories:

```text
output/
  ora-db-audit_<DBSID>_<TS>/
    00_setup.log               sqlplus session log
    01_config.csv              audit configuration + mode
    02_storage.csv             AUD$UNIFIED partition health
    03_policy_inventory.csv    enabled policies
    04_policy_volume.csv       events per policy
    05_policy_user_action.csv  top (policy, user, action) combos
    06_policy_client_prog.csv  top (policy, client_program) combos
    07_policy_host.csv         top (policy, userhost) combos
    08_top_users.csv           top DB users by event count
    09_top_actions.csv         top action_name values
    10_top_objects.csv         top accessed objects
    11_host_user_program.csv   host x user x program matrix
    12_distinct_hosts.csv      distinct userhosts with first/last seen
    13_failed_logins.csv       failed login attempts (ORA-01017)
    14_privileged_activity.csv SYS/AUDIT_ADMIN events
    15_noise_candidates.csv    high-volume low-risk tuning candidates
    16_policy_ddl.csv          DBMS_METADATA DDL per policy
    17_cis_coverage.csv        CIS 5.1-5.5 PASS/WARN/FAIL
    18_audit_roles.csv         AUDIT_ADMIN/AUDIT_VIEWER members
    19_offpath_candidates.csv  hosts not matching app/infra/DBA patterns
    manifest.json              bundle metadata
    _sqlplus.log               raw sqlplus transcript
  ora-db-audit_<DBSID>_<TS>.tar.gz           raw bundle archive
  ora-db-audit_<DBSID>_<TS>.anon/            anonymised bundle (--anonymize)
  ora-db-audit_<DBSID>_<TS>.mapping.json     reverse map - KEEP LOCAL, never share
  audit_report.md                             Markdown report (--report)
  audit_report.html                           HTML report (--to-html)
```

The `.mapping.json` file contains the reverse mapping from pseudonyms to real values. It must
remain on the system where anonymisation was performed and must never be included in bundles
shared externally.

---

## Report Sections

The generated `audit_report.md` is structured as follows. Report language is German by default
(`--lang de`); use `--lang en` for English output.

<!-- markdownlint-disable MD013 MD060 -->
| Section | Content |
|---|---|
| Executive Summary | DBSID, time window, key metrics, top volume drivers, host summary |
| 1. Audit Configuration | Mode (pure/mixed/unsupported), parameters, legacy suppression |
| 2. Trail Storage | AUD$UNIFIED partition layout, tablespace verdict |
| 3. Policy Inventory | All enabled policies with type and scope |
| 4-7. Volume Analysis | Events by policy, user, client program, host |
| 8. Top-N Tables | Top users, actions, objects, host/user/program matrix |
| 8.1 Tuning Candidates | WHEN-clause suggestions grounded in actual policy DDL |
| 9. CIS Coverage | CIS 5.1-5.5 PASS/WARN/FAIL table |
| 10. Audit Roles | AUDIT_ADMIN/AUDIT_VIEWER grantees with risk flags |
| 11. AI Findings | Claude-generated security signal analysis (with --ai) |
<!-- markdownlint-enable -->

---

## SIEM Export Formats

`tools/export_siem.py` converts bundle CSV data to structured formats for ingestion into
security platforms. Invoke via the main script with `--export-siem FORMAT OUTPUT`, or run
the Python tool directly for offline re-export from an existing bundle.

### Supported Formats

- **ocsf** - OCSF 1.3 Database Activity (class 3005) JSON Lines format, suitable for
  platforms that support the Open Cybersecurity Schema Framework
- **sentinel** - Flat CSV for Microsoft Sentinel / Log Analytics workspace ingestion via
  the HTTP Data Collector API or a custom table

### Default Source Queries

Queries 08, 11, 13, 14, and 19 are included by default. Override the selection with
`--sources 11,13` to include only specific query outputs.

### Important Note on Data Granularity

The bundle contains **aggregated rows**, not individual audit events. Each exported record
includes an `EventCount` field reflecting the aggregation. Use SIEM export for profiling,
trend analysis, and anomaly detection. It is not suitable for forensic event replay or
chain-of-custody purposes.
