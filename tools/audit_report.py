#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# ------------------------------------------------------------------------------
# OraDBA - Oracle Database Infrastructure and Security, 5630 Muri, Switzerland
# ------------------------------------------------------------------------------
# Name.......: audit_report.py
# Author.....: Stefan Oehrli (oes) stefan.oehrli@oradba.ch
# Editor.....: Stefan Oehrli
# Date.......: 2026.05.28
# Version....: 1.2.0
# Purpose....: Read a (raw or anonymised) ora-db-audit bundle and render a
#              structured Markdown report for DBA, Security Engineer and
#              Auditor audiences. Generates an executive summary plus
#              per-query detail sections, host-pattern classification
#              (App / Infra / Off-Path) and tuning recommendations with
#              WHEN-clause templates for the noisiest policy-user-action
#              combinations.
# Notes......: Works on either the raw bundle (real customer values) or
#              the anonymised sibling bundle - the report does not change
#              its structure based on which one is fed in. Pattern config
#              defaults to a small built-in set; pass --patterns FILE.json
#              for customer-specific host classification patterns.
#
# Usage......: audit_report.py BUNDLE_DIR [--output FILE]
#                              [--patterns FILE.json]
#                              [--include-appendix]
#                              [--top-n N]
#                              [--customer-prefix PREFIX]
#                              [--export-prompt FILE]
#                              [--dry-run] [--yes] [--verbose]
#
# License....: Apache License Version 2.0, January 2004 as shown
#              at http://www.apache.org/licenses/
# ------------------------------------------------------------------------------
# CHANGE LOG:
# 2026.05.28  oes  R3: sampling note in exec summary; align version to     1.2.0
#                  repo SemVer (VERSION file = single source of truth).
# 2026.05.28  oes  R1+R2: CIS coverage (Section 9) and Audit-Roles        1.1.0
#                  (Section 10) report sections; R4: --export-prompt flag;
#                  AI section renumbered to 11.
# 2026.05.28  oes  Sanitised port from audit_pack-0.5.0 (renamed from     1.0.0
#                  audit_pack_report.py). DEFAULT_CUSTOMER_PREFIX cleared,
#                  ODB_AUDIT_CTX placeholder generalised.
# ------------------------------------------------------------------------------

import argparse
import csv
import io
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

# Re-use the bundle parser from the anonymiser - same '# schema:' format,
# identical preamble / CSV handling. Keeping both tools in sync avoids
# drift in how queries are interpreted.
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
from anonymize_bundle import (  # noqa: E402
    find_schema_line,
    parse_schema_line,
    split_preamble,
)
from audit_report_messages import (  # noqa: E402
    DEFAULT_LANGUAGE,
    SUPPORTED_LANGUAGES,
    t,
)


TOOL_VERSION = "1.3.2"
DEFAULT_TOP_N = None  # None = use bundle manifest top_n; 0 = unlimited
DEFAULT_CUSTOMER_PREFIX = ""
DEFAULT_AI_MODEL = "claude-sonnet-4-6"
DEFAULT_AI_OP_PATH = ""
# Active language for user-facing strings. Set by parse_args(); the
# renderers read this module-level state via the t() helper.
# v1.0.0 ships German-only; v1.1+ adds EN via SUPPORTED_LANGUAGES.
LANG = DEFAULT_LANGUAGE

# AI prompts are language-keyed. Keys match SUPPORTED_LANGUAGES ("de", "en").
# Updating the rules doc (docs/ai-analysis-rules.md) and both prompt versions
# together keeps them in sync.
AI_SYSTEM_PROMPTS: dict[str, str] = {
    "de": (
        "Du bist ein Oracle Security Architect mit Expertise in Oracle "
        "Unified Auditing (Pure Mode) auf 19c und 26ai. Analysiere "
        "Audit-Reports nach den unten verbindlichen Pure-Mode-Regeln. "
        "Strikte Trennung: Findings zu Traditional / Mixed-Mode-Artefakten "
        "sind ausdruecklich KEINE gueltigen Findings - der Tool-Scope ist "
        "Pure Mode. Bewerte die im Report generierten Tuning-Vorschlaege "
        "(Abschnitt 8.1) als Bedingungs-Ausdruecke, die manuell via "
        "DROP + CREATE AUDIT POLICY anzuwenden sind. Antworte auf Deutsch; "
        "Oracle-Objekt-Namen, SQL und Code-Bloecke bleiben Englisch."
    ),
    "en": (
        "You are an Oracle Security Architect with expertise in Oracle "
        "Unified Auditing (Pure Mode) on 19c and 26ai. Analyse audit "
        "reports according to the binding Pure-Mode rules below. Strict "
        "separation: findings about Traditional / Mixed-Mode artefacts are "
        "explicitly NOT valid findings - the tool scope is Pure Mode. "
        "Evaluate the tuning suggestions in the report (Section 8.1) as "
        "condition expressions to be applied manually via "
        "DROP + CREATE AUDIT POLICY. Reply in English; Oracle object names, "
        "SQL, and code blocks stay in English."
    ),
}

AI_USER_PROMPT_TEMPLATES: dict[str, str] = {
    "de": """\
Analysiere den folgenden Oracle Unified Audit-Report.

## Audit-Modus pruefen (zuerst!)

Im Report-Header steht `audit_mode: <wert>`. Vor jeder weiteren Analyse:

- `audit_mode = mixed` -> Tool-Scope ueberschritten. Gib EIN Finding aus:
  HIGH-Severity "Mixed-Mode-Kontamination", Empfehlung "Migration nach
  Pure Mode" (siehe `/oracle-audit` skill Mixed-to-Pure Section).
  KEINE weiteren Pure-Mode-Findings produzieren.
- `audit_mode = unsupported` -> EIN Finding: HIGH "Unified Auditing nicht
  aktiviert; Tool-Scope nicht anwendbar".
- `audit_mode in (pure, pure-intent, pure-contaminated)` -> normal weiter.

## Kontext

- Audit-Modus laut Report: siehe `audit_mode` Metadata oben
- Policy-Namensraum: {customer_prefix}_* (Custom), ORA_* nur als Referenz
- Hostnamen / Benutzernamen koennen anonymisiert sein (HOST_NNN, DBUSER_NNN, ...)
- Audit-Kontext-Variable (z.B. zur Off-Path-Klassifizierung): typisch
  `<CUSTOMER>_AUDIT_CTX` - falls nicht konfiguriert, fehlt Applikationskontext

## Regel-Kontrakt (Pure-Mode) - aus docs/ai-analysis-rules.md

### Out of scope (NICHT als Finding melden)

Findings, die folgende Legacy-Artefakte zitieren, sind ungueltig und
muessen UNTERDRUECKT werden:

- `audit_trail` Init-Parameter (Legacy; in Pure Mode ohne Effekt -
  auch der Wert `DB` ist KEIN Finding)
- `audit_sys_operations` (Legacy; in Pure Mode wird SYS per Policy auditiert)
- `audit_syslog_level` (Legacy)
- `audit_file_dest` als Audit-Trail-Konfiguration (Legacy)
- Traditional-AUDIT-Syntax in Empfehlungen (`AUDIT <stmt> BY ...`,
  `NOAUDIT <stmt>`); ausschliesslich Unified-Syntax verwenden
- Einzelne AUD$UNIFIED-Partitionen in SYSAUX wenn
  `audit_data_tablespace_default = AUDIT_DATA` (transient nach
  `ALTER TABLE MODIFY DEFAULT ATTRIBUTES TABLESPACE` - keine
  Misconfiguration)

### Gueltige Findings (Pure Mode)

Diese Finding-Klassen sind erwuenscht:

- DBMS_AUDIT_MGMT.CLEAN_AUDIT_TRAIL Job: konfiguriert?
- LAST_ARCHIVE_TIMESTAMP gesetzt vor Cleanup?
- AUD$UNIFIED Default-Tablespace ist SYSAUX (Misconfiguration)
- Policy-Coverage-Luecken (z.B. CIS-Pflicht-Bereiche ohne enabled policy)
- ORA_*-Policies (Oracle-supplied) aktiv obwohl Custom-Policies dieselben
  Events besser zugeschnitten abdecken
- Failed-Login-Muster (ORA-01017 Spitzen, Brute-Force-Verdacht,
  fehlkonfigurierter Job mit altem Passwort)
- Privilegierte Aktivitaet (SYS, SYSDBA, AUDIT_ADMIN, SYSBACKUP, ...)
- Off-Path-Hosts (nicht in App/Infra/DBA-Pattern klassifiziert)
- Mixed-Mode-Kontamination (AUD$ mit aktuellen Zeilen trotz Pure)
- Mandatory binary `*.aud` files: ungesteuertes Wachstum / keine Rotation

### Tuning-Vorschlaege (Abschnitt 8.1)

Die im Report gelisteten WHEN-Klausel-Vorschlaege sind Bedingungs-
Ausdruecke. Sie sind manuell anzuwenden via:

```sql
DROP AUDIT POLICY <name>;
CREATE AUDIT POLICY <name> ... WHEN '(<bestehend>) AND (<vorschlag>)' ...;
```

Bewerte jeden Vorschlag:

- Compliance-Risiko: Darf laut Site-Policy supprimiert werden?
- Praezision: Kombination User+Programm ist enger als nur User - bevorzugen
- Falls KEIN Vorschlag sicher anwendbar: alternativen Ansatz begruenden
  (Audit-Context, Whitelist, separate Suppression-Policy)

## Audit-Report

{report_text}

## Ausgabe

Falls `audit_mode = mixed` oder `unsupported`: nur das Einzel-Finding
gemaess "Audit-Modus pruefen" - keine Tabelle, keine A/B/C-Sektionen.

Sonst Findings-Tabelle (Uebersicht):

| # | Finding | Abschnitt | Risiko | Massnahme |
|---|---------|-----------|--------|-----------|

Dann drei strukturierte Abschnitte:

### A - Security Signals

Risikobewertung HIGH / MEDIUM / LOW / INFO:

- Echte Security-Events vs. erwartetes Betriebsverhalten
- Failed Logins (ORA-01017): Brute-Force, Konfig-Fehler, automatisierter Job?
- Off-Path-Hosts: echte Bedrohung oder fehlende App-Kontext-Konfiguration?
- Ungewoehnliche User + Host + Programm-Kombinationen

### B - Konfigurationsluecken (Pure-Mode-CIS, nicht Legacy)

Beziehe dich AUSSCHLIESSLICH auf Pure-Mode-Konfiguration (siehe Out-of-Scope
Liste oben). Insbesondere KEINE Findings zu `audit_trail`,
`audit_sys_operations`, `audit_syslog_level` und keine Traditional-
AUDIT-Empfehlungen.

### C - Tuning-Empfehlungen qualifizieren

Pro Kandidat aus Abschnitt 8.1: empfohlene Variante + Begruendung
ODER alternativer Ansatz wenn keine sicher anwendbar ist.

Pro Finding (Nummer aus Tabelle): ein Absatz mit Begruendung und ggf.
konkretem Unified-SQL oder Konfigurations-Schritt.
""",
    "en": """\
Analyse the following Oracle Unified Audit report.

## Check audit mode (first!)

The report header contains `audit_mode: <value>`. Before any further analysis:

- `audit_mode = mixed` -> Tool scope exceeded. Produce ONE finding:
  HIGH-severity "Mixed-Mode Contamination", recommendation "Migrate to
  Pure Mode" (see `/oracle-audit` skill Mixed-to-Pure section).
  Do NOT produce any further Pure-Mode findings.
- `audit_mode = unsupported` -> ONE finding: HIGH "Unified Auditing not
  enabled; tool scope not applicable".
- `audit_mode in (pure, pure-intent, pure-contaminated)` -> proceed normally.

## Context

- Audit mode per report: see `audit_mode` metadata above
- Policy namespace: {customer_prefix}_* (custom), ORA_* for reference only
- Hostnames / usernames may be anonymised (HOST_NNN, DBUSER_NNN, ...)
- Audit context variable (e.g. for off-path classification): typically
  `<CUSTOMER>_AUDIT_CTX` - if not configured, application context is missing

## Rule contract (Pure Mode) - from docs/ai-analysis-rules.md

### Out of scope (do NOT report as finding)

Findings referencing the following legacy artefacts are invalid and
MUST BE SUPPRESSED:

- `audit_trail` init parameter (Legacy; has no effect in Pure Mode -
  even the value `DB` is NOT a finding)
- `audit_sys_operations` (Legacy; SYS is audited via policy in Pure Mode)
- `audit_syslog_level` (Legacy)
- `audit_file_dest` as audit trail configuration (Legacy)
- Traditional AUDIT syntax in recommendations (`AUDIT <stmt> BY ...`,
  `NOAUDIT <stmt>`); use Unified Auditing syntax only
- Individual AUD$UNIFIED partitions in SYSAUX when
  `audit_data_tablespace_default = AUDIT_DATA` (transient after
  `ALTER TABLE MODIFY DEFAULT ATTRIBUTES TABLESPACE` - not a
  misconfiguration)

### Valid findings (Pure Mode)

These finding classes are expected:

- DBMS_AUDIT_MGMT.CLEAN_AUDIT_TRAIL job: configured?
- LAST_ARCHIVE_TIMESTAMP set before cleanup?
- AUD$UNIFIED default tablespace is SYSAUX (misconfiguration)
- Policy coverage gaps (e.g. CIS-mandatory areas without an enabled policy)
- ORA_* policies (Oracle-supplied) active while custom policies cover
  the same events more precisely
- Failed login patterns (ORA-01017 spikes, brute-force suspicion,
  misconfigured job with stale password)
- Privileged activity (SYS, SYSDBA, AUDIT_ADMIN, SYSBACKUP, ...)
- Off-path hosts (not classified in App/Infra/DBA patterns)
- Mixed-Mode contamination (AUD$ with recent rows despite Pure Mode)
- Mandatory binary `*.aud` files: uncontrolled growth / no rotation

### Tuning suggestions (Section 8.1)

The WHEN-clause suggestions listed in the report are condition expressions.
Apply them manually via:

```sql
DROP AUDIT POLICY <name>;
CREATE AUDIT POLICY <name> ... WHEN '(<existing>) AND (<suggestion>)' ...;
```

Evaluate each suggestion:

- Compliance risk: may it be suppressed according to site policy?
- Precision: user+program combination is narrower than user alone - prefer it
- If NO suggestion is safely applicable: justify an alternative approach
  (audit context, whitelist, separate suppression policy)

## Audit Report

{report_text}

## Output

If `audit_mode = mixed` or `unsupported`: only the single finding per
"Check audit mode" - no table, no A/B/C sections.

Otherwise findings table (overview):

| # | Finding | Section | Risk | Action |
|---|---------|---------|------|--------|

Then three structured sections:

### A - Security Signals

Risk rating HIGH / MEDIUM / LOW / INFO:

- Real security events vs. expected operational behaviour
- Failed logins (ORA-01017): brute force, config error, automated job?
- Off-path hosts: real threat or missing application context configuration?
- Unusual user + host + program combinations

### B - Configuration gaps (Pure-Mode-CIS, not Legacy)

Refer EXCLUSIVELY to Pure-Mode configuration (see Out-of-Scope list above).
In particular NO findings about `audit_trail`, `audit_sys_operations`,
`audit_syslog_level`, and no Traditional-AUDIT recommendations.

### C - Qualify tuning recommendations

Per candidate from Section 8.1: recommended variant + justification
OR alternative approach if none can be safely applied.

Per finding (number from table): one paragraph with justification and,
if applicable, concrete Unified SQL or configuration step.
""",
}

# Backward-compat aliases (used by _generate_via_sdk / _generate_via_cli at
# module level; runtime code should use the dicts and LANG instead).
AI_SYSTEM_PROMPT = AI_SYSTEM_PROMPTS["de"]
AI_USER_PROMPT_TEMPLATE = AI_USER_PROMPT_TEMPLATES["de"]

# Built-in pattern set. Community / customer-configurable default;
# override with --patterns config.json for deployment-specific patterns.
DEFAULT_PATTERNS = {
    "app_host_patterns": [
        r"^auditlab-app-",
        r"^wls-",
    ],
    "infra_host_patterns": [
        r"^auditlab-db",
        r"^oem-",
    ],
    "dba_host_patterns": [
        r"^laptop-",
        r"^jumphost-",
    ],
}

# Section / query map - id -> filename stem produced by the SQL scripts.
QUERY_FILES = {
    "01": "01_config",
    "02": "02_storage",
    "03": "03_policy_inventory",
    "04": "04_policy_volume",
    "05": "05_policy_user_action",
    "06": "06_policy_client_program",
    "07": "07_policy_host",
    "08": "08_top_users",
    "09": "09_top_actions",
    "10": "10_top_objects",
    "11": "11_host_user_program",
    "12": "12_distinct_hosts",
    "13": "13_failed_logins",
    "14": "14_privileged_activity",
    "15": "15_noise_candidates",
    "17": "17_cis_coverage",
    "18": "18_audit_roles",
}


# ---------------------------------------------------------------------------
# Bundle reader
# ---------------------------------------------------------------------------

def _csv_rows(data_lines):
    reader = csv.reader(io.StringIO("".join(data_lines)), delimiter="|")
    rows = list(reader)
    if not rows:
        return None, []
    return rows[0], rows[1:]


def _strip_quotes(value):
    """csv.reader keeps surrounding quotes when QUOTE_ALL emits them
    inside cell values (SQL*Plus 'QUOTE ON' mode produces "X"-style
    fields that csv handles natively - but header cells emitted by the
    same mode look the same and survive parsing). Belt-and-braces."""
    v = value.strip()
    if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
        return v[1:-1]
    return v


def _read_csv_file(path):
    """Return a dict {meta, schema_cols, headers, rows} or None if the
    file has no schema preamble (we cannot reason about it)."""
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    lines = text.splitlines(keepends=True)
    preamble, data_lines = split_preamble(lines)

    meta = {}
    for line in preamble:
        s = line.strip()
        if not s.startswith("#"):
            continue
        body = s[1:].strip()
        if ":" not in body:
            continue
        key, _, value = body.partition(":")
        meta[key.strip()] = value.strip()

    schema_line = find_schema_line(preamble)
    if not schema_line:
        return None
    try:
        schema_cols = parse_schema_line(schema_line)
    except ValueError as exc:
        print(f"WARN: {path.name} schema parse failed: {exc}",
              file=sys.stderr)
        return None

    header_row, data_rows = _csv_rows(data_lines)
    if header_row is None:
        return {
            "meta": meta,
            "schema_cols": schema_cols,
            "headers": [c for c, _ in schema_cols],
            "rows": [],
        }
    headers = [_strip_quotes(h) for h in header_row]
    cleaned_rows = []
    for row in data_rows:
        cleaned_rows.append([_strip_quotes(c) for c in row])
    return {
        "meta": meta,
        "schema_cols": schema_cols,
        "headers": headers,
        "rows": cleaned_rows,
    }


def read_bundle(bundle_dir):
    """Load manifest.json + every known query CSV into a dict keyed by
    query id ('01'..'15', '17', '18'). Missing files are silently skipped
    (older bundle versions or partial runs)."""
    bundle = {"_path": bundle_dir, "_manifest": {}, "_files": {}}
    manifest = bundle_dir / "manifest.json"
    if manifest.is_file():
        try:
            bundle["_manifest"] = json.loads(
                manifest.read_text(encoding="utf-8")
            )
        except json.JSONDecodeError as exc:
            print(f"WARN: manifest.json unreadable: {exc}", file=sys.stderr)

    for qid, stem in QUERY_FILES.items():
        path = bundle_dir / f"{stem}.csv"
        if not path.is_file():
            continue
        parsed = _read_csv_file(path)
        if parsed is None:
            continue
        bundle["_files"][qid] = parsed
    return bundle


# ---------------------------------------------------------------------------
# Markdown helpers
# ---------------------------------------------------------------------------

def _md_escape(value):
    """Escape Markdown table-cell metacharacters that would break the
    pipe-delimited layout. We keep this minimal: pipe and newline."""
    s = str(value) if value is not None else ""
    return s.replace("|", r"\|").replace("\n", " ").replace("\r", " ")


def render_table(headers, rows, max_rows=None):
    """Emit a GitHub-flavoured Markdown table. None / empty list returns
    a placeholder so the section still renders cleanly."""
    if not headers:
        return "_(keine Spalten)_\n"
    body_rows = list(rows or [])
    truncated = False
    if max_rows is not None and len(body_rows) > max_rows:
        body_rows = body_rows[:max_rows]
        truncated = True

    lines = []
    lines.append("| " + " | ".join(_md_escape(h) for h in headers) + " |")
    lines.append("|" + "|".join(["---"] * len(headers)) + "|")
    if not body_rows:
        empty = "| " + " | ".join(["_(keine Daten)_"] * len(headers)) + " |"
        lines.append(empty)
    else:
        for row in body_rows:
            cells = list(row) + [""] * (len(headers) - len(row))
            lines.append("| " + " | ".join(
                _md_escape(c) for c in cells[:len(headers)]
            ) + " |")
    text = "\n".join(lines) + "\n"
    if truncated:
        text += (
            f"\n_Tabelle nach {max_rows} Zeilen abgeschnitten - "
            f"vollständige Daten siehe Appendix oder Roh-CSV._\n"
        )
    return text


def section_header(level, title, anchor=None):
    """Return a Markdown header line with optional comment-anchor for
    pandoc cross-references."""
    prefix = "#" * level
    if anchor:
        return f"{prefix} {title} <!-- {anchor} -->\n\n"
    return f"{prefix} {title}\n\n"


def fmt_int(value):
    """Format possibly-empty numeric strings with thousands separator.
    Non-numeric values pass through unchanged."""
    if value is None or value == "":
        return ""
    s = str(value).strip()
    try:
        return f"{int(s):,}".replace(",", "'")
    except (TypeError, ValueError):
        try:
            return f"{float(s):,.2f}".replace(",", "'")
        except (TypeError, ValueError):
            return s


# ---------------------------------------------------------------------------
# Aggregation helpers
# ---------------------------------------------------------------------------

def _col_index(file_data, name):
    """Return the column index by header name (case-insensitive). -1 if
    not present."""
    if file_data is None:
        return -1
    needle = name.lower()
    for i, header in enumerate(file_data.get("headers", [])):
        if header.lower() == needle:
            return i
    return -1


def _row_get(row, idx):
    if idx < 0 or idx >= len(row):
        return ""
    return row[idx]


def _to_int(value, default=0):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _sum_column(file_data, col_name):
    idx = _col_index(file_data, col_name)
    if idx < 0:
        return 0
    return sum(_to_int(_row_get(r, idx)) for r in file_data.get("rows", []))


def _unique_policy_count(inv_data):
    """Return (unique_total, custom_count, oracle_count) from 03_policy_inventory data."""
    if not inv_data:
        return 0, 0, 0
    rows = inv_data.get("rows", [])
    idx_pol = _col_index(inv_data, "policy_name")
    idx_ora = _col_index(inv_data, "oracle_supplied")
    seen: dict[str, bool] = {}  # policy_name -> is_oracle_supplied
    for r in rows:
        pol = _row_get(r, idx_pol)
        if not pol or pol in seen:
            continue
        ora = _row_get(r, idx_ora).upper().startswith("Y")
        seen[pol] = ora
    oracle_cnt = sum(1 for v in seen.values() if v)
    return len(seen), len(seen) - oracle_cnt, oracle_cnt


def _parse_policy_names(s: str) -> list[str]:
    """Extract policy names from a custom_policies / oracle_policies cell value.

    Handles the SQL output formats:
      - '(none)'                  -> []
      - 'POL1, POL2'              -> ['POL1', 'POL2']
      - '(partial) POL1, POL2'    -> ['POL1', 'POL2']
      - 'POL1 (+partial: P2, P3)' -> ['POL1', 'P2', 'P3']
    """
    s = (s or "").strip()
    if not s or s == "(none)":
        return []
    s = s.removeprefix("(partial) ")
    if " (+partial: " in s:
        full_part, rest = s.split(" (+partial: ", 1)
        parts = [full_part, rest.rstrip(")")]
    else:
        parts = [s]
    names = []
    for part in parts:
        for name in part.split(","):
            name = name.strip()
            if name:
                names.append(name)
    return names


def _dedup_policy_rows(inv_data, filter_policies=None):
    """Return a sorted list of ((policy, entity, etype, opt), row) pairs.

    Deduplicates the per-action rows from 03_policy_inventory to one row
    per unique (policy_name, entity_name, entity_type, enabled_option).
    filter_policies: if given, only include rows for those policy names.
    Sort order: inactive last, Oracle-supplied last, then policy name, entity.
    """
    if not inv_data:
        return []
    rows = inv_data.get("rows", [])
    idx_pol = _col_index(inv_data, "policy_name")
    idx_ora = _col_index(inv_data, "oracle_supplied")
    idx_ent = _col_index(inv_data, "entity_name")
    idx_etype = _col_index(inv_data, "entity_type")
    idx_opt = _col_index(inv_data, "enabled_option")

    seen: dict = {}
    for r in rows:
        pol = _row_get(r, idx_pol)
        if filter_policies is not None and pol not in filter_policies:
            continue
        key = (pol, _row_get(r, idx_ent), _row_get(r, idx_etype), _row_get(r, idx_opt))
        if key not in seen:
            seen[key] = r

    def _sort(item):
        (pol, ent, _etype, opt), r = item
        is_inactive = 0 if opt else 1
        is_oracle = 1 if _row_get(r, idx_ora).upper().startswith("Y") else 0
        return (is_inactive, is_oracle, pol, ent or "")

    return sorted(seen.items(), key=_sort)



# ---------------------------------------------------------------------------
# Host-pattern classification
# ---------------------------------------------------------------------------

class HostClassifier:
    """Compile pattern lists once, then bucket each host name into
    'APP', 'INFRA', 'DBA' or 'OFF-PATH'. Pattern priority is fixed:
    INFRA > APP > DBA > OFF-PATH (an OEM/DB host that also matches a
    weaker pattern stays INFRA)."""

    def __init__(self, patterns):
        def compile_list(key):
            return [re.compile(p, re.IGNORECASE)
                    for p in patterns.get(key, [])]
        self.infra = compile_list("infra_host_patterns")
        self.app = compile_list("app_host_patterns")
        self.dba = compile_list("dba_host_patterns")

    def classify(self, host):
        if not host:
            return "OFF-PATH"
        for pat in self.infra:
            if pat.search(host):
                return "INFRA"
        for pat in self.app:
            if pat.search(host):
                return "APP"
        for pat in self.dba:
            if pat.search(host):
                return "DBA"
        return "OFF-PATH"


# ---------------------------------------------------------------------------
# WHEN-clause templates
# ---------------------------------------------------------------------------

# Match WHEN '...' allowing escaped single quotes ('') inside the WHEN body.
# DBMS_METADATA emits DDL with single-quoted strings; doubled '' is the
# Oracle escape for an embedded quote.
_WHEN_RE = re.compile(
    r"\bWHEN\s+'((?:[^']|'')*)'",
    re.IGNORECASE | re.DOTALL,
)
# Oracle identifier start at column 0 of a CSV row in 16-policy-ddl.csv.
# Used to detect the start of a new logical row when the DDL column
# contains embedded newlines (CLOB with QUOTE OFF markup).
_POLICY_ROW_START = re.compile(r"^[A-Z][A-Z0-9_$#]{0,127}\|")


def _read_policy_ddl_csv(path):
    """Parse sql/16-policy-ddl.csv into {policy_name -> ddl_text}.

    The DDL column is a CLOB with embedded newlines and the SQL*Plus CSV
    markup uses QUOTE OFF (consistent with the rest of the bundle), so
    standard csv.reader cannot handle the multi-line cells. We use a
    heuristic row-detection based on the Oracle identifier pattern at
    column 0 of each line. Anything between two row-start lines is
    concatenated as continuation of the previous DDL cell.

    Returns an empty dict if the file is missing, has no schema preamble,
    or the runner lacked DBMS_METADATA privileges (in which case the SQL
    emits an empty result set per docs/ai-analysis-rules.md Section 4.3).
    """
    if not path.is_file():
        return {}
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    lines = text.splitlines(keepends=False)

    body_lines = []
    in_body = False
    for line in lines:
        if not in_body:
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                continue
            # Header row: contains the column names. Skip and start body.
            if "|" in line and "policy_name" in line.lower():
                in_body = True
            continue
        body_lines.append(line)

    if not body_lines:
        return {}

    rows = []
    current = []
    for line in body_lines:
        if _POLICY_ROW_START.match(line):
            if current:
                rows.append(current)
            current = [line]
        else:
            if current:
                current.append(line)
            # If no current row yet (leading whitespace before first row),
            # discard the line silently.

    if current:
        rows.append(current)

    result = {}
    for row_lines in rows:
        first = row_lines[0]
        idx = first.find("|")
        if idx < 0:
            continue
        policy_name = first[:idx].strip()
        head = first[idx + 1:]
        ddl_parts = [head] + row_lines[1:]
        # DBMS_METADATA emits PRETTY DDL ending with ';'; trim trailing whitespace
        # but preserve internal newlines for readability in the report.
        ddl_text = "\n".join(ddl_parts).rstrip()
        if policy_name:
            result[policy_name] = ddl_text
    return result


def load_policy_ddl(bundle_dir):
    """Locate 16_policy_ddl.csv (or hyphenated variant) in the bundle and
    parse it via _read_policy_ddl_csv. Returns an empty dict if the file
    is absent - the renderer then emits a "DDL unavailable" note rather
    than fabricating DDL from concat strings.
    """
    candidates = [
        bundle_dir / "16_policy_ddl.csv",
        bundle_dir / "16-policy-ddl.csv",
    ]
    for path in candidates:
        if path.is_file():
            return _read_policy_ddl_csv(path)
    return {}


def extract_when_clause(ddl):
    """Pull the WHEN '...' body from an AUDIT POLICY DDL string.

    Returns the raw text inside the WHEN single-quotes (with Oracle's
    doubled-single-quote escaping preserved), or None if the policy has
    no WHEN clause.
    """
    if not ddl:
        return None
    m = _WHEN_RE.search(ddl)
    if not m:
        return None
    return m.group(1).strip() or None


def when_clause_for(noise_row, headers, policy_ddl_map):
    """Build a structured tuning recommendation for a 15-noise-candidates row.

    Per docs/ai-analysis-rules.md Section 4 (DDL source rule), suggestions
    are presented as boolean condition expressions intended to be
    AND-combined with the policy's existing WHEN clause via a manual
    DROP + CREATE sequence. We never synthesise standalone
    `ALTER AUDIT POLICY` statements from the row's UAP context - that
    pattern was finding F2 and was functionally wrong (Oracle has no
    `ALTER AUDIT POLICY ... CONDITION` syntax; the WHEN clause is set
    at CREATE time and changing it requires DROP + recreate).

    Returns a dict the renderer (render_section_08_tuning) formats into
    a Markdown sub-section. Shape:

      {
        "policy_name":  str,
        "current_ddl":  str | None,   # from DBMS_METADATA via 16-policy-ddl.csv
        "existing_when": str | None,  # parsed from current_ddl, if present
        "recap":        list[(label, value)],
        "suggestions":  [
            {
              "label":          str,
              "condition_expr": str | None,  # AND-combinable bool expression
              "rationale":      str,
            },
            ...
        ],
      }
    """
    def get(name):
        idx = -1
        needle = name.lower()
        for i, h in enumerate(headers):
            if h.lower() == needle:
                idx = i
                break
        if idx < 0 or idx >= len(noise_row):
            return ""
        return noise_row[idx].strip()

    policy = get("policy_name") or "<POLICY>"
    user = get("dbusername")
    program = get("client_program_name")
    action = get("action_name")
    events = get("events")

    current_ddl = policy_ddl_map.get(policy) if policy_ddl_map else None
    existing_when = extract_when_clause(current_ddl)

    suggestions = []

    if user and user.upper() not in {"(NULL)", ""}:
        suggestions.append({
            "label": t("tuning.suppress_user", lang=LANG,
                       user=user, policy=policy),
            "condition_expr": (
                f"SYS_CONTEXT(''USERENV'',''SESSION_USER'') != ''{user}''"
            ),
            "rationale": t("tuning.rationale_user", lang=LANG,
                           user=user, policy=policy),
        })

    if program:
        suggestions.append({
            "label": t("tuning.suppress_program", lang=LANG,
                       program=program, policy=policy),
            "condition_expr": (
                f"SYS_CONTEXT(''USERENV'',''CLIENT_PROGRAM_NAME'') "
                f"!= ''{program}''"
            ),
            "rationale": t("tuning.rationale_program", lang=LANG,
                           program=program),
        })

    if user and program and user.upper() not in {"(NULL)", ""}:
        suggestions.append({
            "label": t("tuning.suppress_combo", lang=LANG,
                       user=user, program=program, policy=policy),
            "condition_expr": (
                f"NOT (SYS_CONTEXT(''USERENV'',''SESSION_USER'') = ''{user}'' "
                f"AND SYS_CONTEXT(''USERENV'',''CLIENT_PROGRAM_NAME'') "
                f"= ''{program}'')"
            ),
            "rationale": t("tuning.rationale_combo", lang=LANG,
                           user=user, program=program),
        })

    if not suggestions:
        suggestions.append({
            "label": t("tuning.no_template", lang=LANG, policy=policy),
            "condition_expr": None,
            "rationale": t("tuning.rationale_no_template", lang=LANG,
                           action=action or "<n/a>"),
        })

    return {
        "policy_name":   policy,
        "current_ddl":   current_ddl,
        "existing_when": existing_when,
        "recap": [
            ("policy_name",         policy),
            ("dbusername",          user or "<n/a>"),
            ("action_name",         action or "<n/a>"),
            ("client_program_name", program or "<n/a>"),
            ("events",              events or "<n/a>"),
        ],
        "suggestions": suggestions,
    }


# ---------------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------------

def render_executive_summary(bundle, classifier, top_n):
    """Top-of-report summary - DBSID, time window, key totals and the
    three loudest volume drivers. Designed to fit on half a page."""
    manifest = bundle.get("_manifest", {})
    files = bundle["_files"]

    dbsid = manifest.get("dbsid", "?")
    pdb = ""
    if "01" in files and files["01"]["rows"]:
        pdb = files["01"]["meta"].get("pdb", "")
    elif "04" in files:
        pdb = files["04"]["meta"].get("pdb", "")
    days = manifest.get("time_window_days", "?")
    top_n_pack = manifest.get("top_n", "?")

    out = section_header(1, t("report.page_title", lang=LANG,
                              dbsid=dbsid, pdb=pdb or "?"))

    out += section_header(2, t("section.executive_summary", lang=LANG))
    out += (
        f"- {t('exec.dbsid', lang=LANG, dbsid=dbsid)}\n"
        f"- {t('exec.pdb', lang=LANG, pdb=pdb or '?')}\n"
        f"- {t('exec.window', lang=LANG, days=days)}\n"
        f"- {t('exec.top_n', lang=LANG, top_n=top_n_pack)}\n"
        f"- {t('exec.generated', lang=LANG, ts=manifest.get('generated_at', '?'))}\n"
        f"- {t('exec.version', lang=LANG, version=manifest.get('bundle_version', '?'))}\n\n"
    )

    pol_events = _sum_column(files.get("04"), "events")
    user_events = _sum_column(files.get("08"), "events")
    failed_total = _sum_column(files.get("13"), "failed_attempts")

    # ORA$MANDATORY event count from policy_volume (query 04).
    mandatory_events = 0
    fd04 = files.get("04")
    if fd04:
        idx_pname = _col_index(fd04, "policy_name")
        idx_pevts = _col_index(fd04, "events")
        for r in fd04.get("rows", []):
            if _row_get(r, idx_pname).strip() == "ORA$MANDATORY":
                try:
                    mandatory_events = int(_row_get(r, idx_pevts).replace("'", ""))
                except ValueError:
                    pass

    out += section_header(3, t("section.metrics", lang=LANG))
    metrics_rows = [
        [t("metric.pol_events", lang=LANG), fmt_int(pol_events)],
        [t("metric.user_events", lang=LANG), fmt_int(user_events)],
        [t("metric.failed_logins", lang=LANG), fmt_int(failed_total)],
        [t("metric.mandatory_events", lang=LANG), fmt_int(mandatory_events)],
        [t("metric.active_policies", lang=LANG),
         fmt_int(_unique_policy_count(files.get("03"))[0])],
        [t("metric.storage_partitions", lang=LANG),
         fmt_int(len(files.get("02", {}).get("rows", [])))],
    ]
    out += render_table(
        [t("label.metric", lang=LANG), t("label.value", lang=LANG)],
        metrics_rows,
    )

    # Top 3 volume drivers from policy_volume (sorted desc already).
    if "04" in files:
        pol = files["04"]
        idx_policy = _col_index(pol, "policy_name")
        idx_events = _col_index(pol, "events")
        rows = pol.get("rows", [])[:3]
        if rows:
            out += "\n" + section_header(3, t("section.top3_volume", lang=LANG))
            top_rows = []
            for r in rows:
                top_rows.append([
                    _row_get(r, idx_policy),
                    fmt_int(_row_get(r, idx_events)),
                ])
            out += render_table(
                [t("label.policy", lang=LANG), t("label.events", lang=LANG)],
                top_rows,
            )

    # Sampling notice when --sample-rows was active during collection.
    sample_rows = manifest.get("sample_rows", 0)
    if sample_rows and int(sample_rows) > 0:
        out += "\n" + t("exec.sampling_note", lang=LANG,
                        n=fmt_int(sample_rows)) + "\n\n"

    # Off-path indicator via host pattern check on 12_distinct_hosts.
    if "12" in files:
        offpath = _classify_hosts_in(files["12"], "userhost", classifier)
        counts = defaultdict(int)
        for cls in offpath.values():
            counts[cls] += 1
        if counts:
            out += "\n" + section_header(3, t("section.host_summary", lang=LANG))
            out += render_table(
                [t("label.class", lang=LANG), t("label.host_count", lang=LANG)],
                [
                    ["APP", fmt_int(counts.get("APP", 0))],
                    ["INFRA", fmt_int(counts.get("INFRA", 0))],
                    ["DBA", fmt_int(counts.get("DBA", 0))],
                    ["OFF-PATH", fmt_int(counts.get("OFF-PATH", 0))],
                ],
            )
            if counts.get("OFF-PATH", 0):
                out += "\n" + t("offpath.hint", lang=LANG) + "\n\n"
    return out


def _classify_hosts_in(file_data, col_name, classifier):
    """Return dict host -> class for hosts that appear in column."""
    idx = _col_index(file_data, col_name)
    if idx < 0:
        return {}
    out = {}
    for row in file_data.get("rows", []):
        host = _row_get(row, idx).strip()
        if not host:
            continue
        out[host] = classifier.classify(host)
    return out


_AUDIT_MODE_LABELS = {
    "pure":               "audit_mode.pure",
    "pure-intent":        "audit_mode.pure_intent",
    "pure-contaminated":  "audit_mode.pure_contaminated",
    "mixed":              "audit_mode.mixed",
    "unsupported":        "audit_mode.unsupported",
}


def render_section_01_config(file_data):
    """Section 1 - audit configuration + Pure-vs-Mixed mode interpretation.

    Reads the `# audit_mode:` metadata produced by sql/01-config.sql
    (Phase C revision) and the `legacy_param` schema-hint column to
    suppress findings against legacy init parameters when the instance
    is in Pure Mode. See docs/ai-analysis-rules.md Section 6 for the
    decision matrix.
    """
    out = section_header(2, t("section.01_config", lang=LANG))
    if file_data is None:
        out += t("note.no_data", lang=LANG) + "\n\n"
        return out

    meta = file_data.get("meta", {})
    audit_mode = (meta.get("audit_mode") or "").strip().lower() or "unknown"
    recent_legacy = (meta.get("recent_aud_legacy_rows") or "").strip()

    mode_key = _AUDIT_MODE_LABELS.get(audit_mode)
    mode_label = t(mode_key, lang=LANG) if mode_key else audit_mode

    out += f"**{t('report.audit_mode', lang=LANG, audit_mode=mode_label)}**\n\n"

    if audit_mode == "mixed":
        out += t("mode.mixed_note", lang=LANG) + "\n\n"
    elif audit_mode == "pure-contaminated":
        out += t("mode.pure_contaminated_note", lang=LANG) + "\n\n"
    elif audit_mode == "pure-intent":
        out += t("mode.pure_intent_note", lang=LANG) + "\n\n"
    elif audit_mode == "unsupported":
        out += t("mode.unsupported_note", lang=LANG) + "\n\n"
    elif audit_mode == "pure":
        pass
    else:
        out += t("mode.unknown_note", lang=LANG) + "\n\n"

    if recent_legacy and recent_legacy != "0" and recent_legacy.lower() != "null":
        out += t("mode.aud_recent_rows", lang=LANG, n=recent_legacy) + "\n\n"

    out += t("note.source_01", lang=LANG) + "\n\n"

    # Find the legacy_param column to mark legacy parameters in the table.
    idx_legacy = _col_index(file_data, "legacy_param")
    rows = file_data.get("rows", [])
    if idx_legacy >= 0 and rows:
        # Render an annotated table: append "(legacy - no effect in Pure Mode)"
        # marker to rows where legacy_param == 1.
        headers = list(file_data["headers"])
        annotated_rows = []
        for r in rows:
            new_r = list(r)
            flag = _row_get(r, idx_legacy).strip()
            if flag == "1":
                # Annotate the parameter_name column (column 0 by convention).
                if new_r:
                    new_r[0] = f"{new_r[0]} _(legacy)_"
            annotated_rows.append(new_r)
        out += render_table(headers, annotated_rows)
        out += "\n" + t("mode.legacy_params_footer", lang=LANG) + "\n\n"
    else:
        out += render_table(file_data["headers"], rows)
        out += "\n"
    return out


def render_section_02_storage(file_data):
    """Section 2 - Trail Storage + D/C/O partition-tablespace decision matrix.

    Reads the metadata emitted by sql/02-storage.sql (Phase C):
      - audit_data_tablespace_default       (D)
      - audit_data_tablespace_current       (C, most recent partition)
      - audit_data_tablespace_older_partitions (O, comma-joined older set)

    Classifies into MISCONFIGURATION / OK / TRANSIENT / EMPTY per
    docs/ai-analysis-rules.md Section 5.2. The verdict appears before
    the partition listing so the human reader sees it first.
    """
    out = section_header(2, t("section.02_storage", lang=LANG))
    if file_data is None:
        out += t("note.no_data", lang=LANG) + "\n\n"
        return out

    meta = file_data.get("meta", {})
    tbs_default = (meta.get("audit_data_tablespace_default") or "").strip()
    tbs_current = (meta.get("audit_data_tablespace_current") or "").strip()
    tbs_older = (meta.get("audit_data_tablespace_older_partitions") or "").strip()

    older_set = set()
    if tbs_older:
        older_set = {tbs.strip() for tbs in tbs_older.split(",") if tbs.strip()}

    rows = file_data.get("rows", [])
    total_rows = sum(_to_int(_row_get(r, _col_index(file_data, "num_rows")))
                     for r in rows)
    total_mb = 0.0
    idx_mb = _col_index(file_data, "size_mb")
    if idx_mb >= 0:
        for r in rows:
            try:
                total_mb += float(_row_get(r, idx_mb) or 0)
            except (TypeError, ValueError):
                pass

    # Decision matrix per ai-analysis-rules.md Section 5.2.
    verdict_label = None
    verdict_note = None
    if tbs_default:
        if tbs_default.upper() == "SYSAUX":
            verdict_label = "MISCONFIGURATION"
            verdict_note = t("storage.verdict_misconfig", lang=LANG)
        elif tbs_default.upper() == tbs_current.upper() and not older_set - {tbs_default.upper()}:
            verdict_label = "OK"
            verdict_note = t("storage.verdict_ok", lang=LANG, tbs=tbs_default)
        elif tbs_default.upper() == tbs_current.upper():
            verdict_label = "TRANSIENT"
            verdict_note = t("storage.verdict_transient_older", lang=LANG,
                             tbs_default=tbs_default,
                             tbs_older=", ".join(sorted(older_set)))
        elif tbs_current and tbs_default.upper() != tbs_current.upper():
            verdict_label = "TRANSIENT"
            verdict_note = t("storage.verdict_transient_current", lang=LANG,
                             tbs_default=tbs_default, tbs_current=tbs_current)
        elif not tbs_current:
            verdict_label = "EMPTY"
            verdict_note = t("storage.verdict_empty", lang=LANG,
                             tbs_default=tbs_default)

    if verdict_label:
        out += t("storage.verdict_fmt", lang=LANG,
                 label=verdict_label, note=verdict_note) + "\n\n"
    else:
        out += t("storage.verdict_unknown", lang=LANG) + "\n\n"

    if tbs_default or tbs_current or tbs_older:
        out += render_table(
            [t("label.value", lang=LANG), "Tablespace"],
            [
                [t("storage.row_default", lang=LANG), tbs_default or "_(n/a)_"],
                [t("storage.row_current", lang=LANG), tbs_current or "_(n/a)_"],
                [t("storage.row_older", lang=LANG), tbs_older or t("storage.none", lang=LANG)],
            ],
        )
        out += "\n"

    out += t("storage.partitions_summary", lang=LANG,
             n=len(rows), rows=fmt_int(total_rows),
             mb=fmt_int(round(total_mb, 2))) + "\n\n"
    out += render_table(file_data["headers"], rows)
    out += "\n"
    return out


def render_section_03_policy_inventory(file_data, top_n, include_appendix):
    out = section_header(2, t("section.03_policy_inventory", lang=LANG))
    if file_data is None:
        out += t("note.csv_missing", lang=LANG,
                 fname="03_policy_inventory.csv") + "\n\n"
        return out
    rows = file_data.get("rows", [])

    # Counts based on unique policy names (not raw action rows)
    n_total, n_custom, n_oracle = _unique_policy_count(file_data)
    out += t("policy.unique_count", lang=LANG,
             n=n_total, n_custom=n_custom, n_oracle=n_oracle) + "\n\n"

    # ----------------------------------------------------------------
    # Overview table: one row per unique (policy, entity, type, option)
    # audit_condition shown (truncated) only on first entity for each policy
    # ----------------------------------------------------------------
    idx_ora = _col_index(file_data, "oracle_supplied")
    idx_ent = _col_index(file_data, "entity_name")
    idx_cond = _col_index(file_data, "audit_condition")
    idx_opt = _col_index(file_data, "enabled_option")
    idx_suc = _col_index(file_data, "success")
    idx_fal = _col_index(file_data, "failure")

    deduped = _dedup_policy_rows(file_data)
    policy_cond_shown: set = set()
    overview_rows = []
    for (pol, ent, etype, opt), r in deduped:
        cond = ""
        if pol not in policy_cond_shown:
            raw = _row_get(r, idx_cond)
            cond = (raw[:57] + "...") if len(raw) > 60 else raw
            policy_cond_shown.add(pol)
        overview_rows.append([
            pol,
            _row_get(r, idx_ora),
            opt or "-",
            ent or "-",
            etype or "-",
            _row_get(r, idx_suc),
            _row_get(r, idx_fal),
            cond,
        ])

    out += render_table(
        [t("label.policy", lang=LANG), t("label.ora", lang=LANG),
         t("label.policy_option", lang=LANG), t("label.entity", lang=LANG),
         t("label.entity_type", lang=LANG),
         t("label.success_short", lang=LANG), t("label.failure_short", lang=LANG),
         t("label.condition", lang=LANG)],
        overview_rows,
    )
    out += "\n"

    # ----------------------------------------------------------------
    # Full action-level detail: appendix only, never truncated
    # ----------------------------------------------------------------
    if include_appendix:
        out += section_header(3, t("section.03_detail", lang=LANG))
        out += render_table(file_data["headers"], rows)
        out += "\n"
    else:
        out += t("policy.see_appendix", lang=LANG) + "\n\n"
    return out


def render_section_04_07_volumes(files, top_n):
    out = section_header(2, t("section.04_07_volumes", lang=LANG))
    sub_specs = [
        ("04", "section.04_1", "04_policy_volume.csv"),
        ("08", "section.04_2", "08_top_users.csv"),
        ("09", "section.04_3", "09_top_actions.csv"),
        ("10", "section.04_4", "10_top_objects.csv"),
        ("06", "section.04_5", "06_policy_client_program.csv"),
        ("07", "section.04_6", "07_policy_host.csv"),
        ("05", "section.04_7", "05_policy_user_action.csv"),
    ]
    for qid, title_key, fname in sub_specs:
        out += section_header(3, t(title_key, lang=LANG))
        fd = files.get(qid)
        if fd is None:
            out += t("note.csv_missing", lang=LANG, fname=fname) + "\n\n"
            continue
        out += render_table(fd["headers"], fd["rows"], max_rows=top_n)
        out += "\n"
    return out


def render_section_05_connect_profile(files, classifier, top_n):
    out = section_header(2, t("section.05_connect_profile", lang=LANG))
    out += section_header(3, t("section.05_1_hosts", lang=LANG))
    fd12 = files.get("12")
    if fd12 is None:
        out += t("note.csv_missing", lang=LANG,
                 fname="12_distinct_hosts.csv") + "\n\n"
    else:
        out += render_table(fd12["headers"], fd12["rows"], max_rows=top_n)
        out += "\n"

    out += section_header(3, t("section.05_2_pattern", lang=LANG))
    if fd12 is not None:
        idx_host = _col_index(fd12, "userhost")
        idx_logins = _col_index(fd12, "logins")
        rows = []
        for row in fd12.get("rows", []):
            host = _row_get(row, idx_host).strip()
            if not host:
                continue
            cls = classifier.classify(host)
            rows.append([host, cls, fmt_int(_row_get(row, idx_logins))])
        out += render_table(
            [t("label.host", lang=LANG),
             t("label.class", lang=LANG),
             t("label.logins", lang=LANG)],
            rows, max_rows=top_n,
        )
        out += "\n"
    else:
        out += t("note.hosts_unclassifiable", lang=LANG) + "\n\n"

    out += section_header(3, t("section.05_3_matrix", lang=LANG))
    fd11 = files.get("11")
    if fd11 is None:
        out += t("note.csv_missing", lang=LANG,
                 fname="11_host_user_program.csv") + "\n\n"
    else:
        out += render_table(fd11["headers"], fd11["rows"], max_rows=top_n)
        out += "\n"
    return out


def render_section_06_privileged(file_data, top_n):
    out = section_header(2, t("section.06_privileged", lang=LANG))
    if file_data is None:
        out += t("note.csv_missing", lang=LANG,
                 fname="14_privileged_activity.csv") + "\n\n"
        return out
    out += t("section.06_intro", lang=LANG) + "\n\n"
    out += render_table(file_data["headers"], file_data["rows"],
                        max_rows=top_n)
    out += "\n"
    return out


def render_section_07_security_signals(files, classifier, top_n):
    out = section_header(2, t("section.07_security_signals", lang=LANG))
    out += section_header(3, t("section.07_1_failed", lang=LANG))
    fd13 = files.get("13")
    if fd13 is None:
        out += t("note.csv_missing", lang=LANG,
                 fname="13_failed_logins.csv") + "\n\n"
    else:
        out += render_table(fd13["headers"], fd13["rows"], max_rows=top_n)
        out += "\n"

    out += section_header(3, t("section.07_2_offpath", lang=LANG))
    fd12 = files.get("12")
    if fd12 is None:
        out += t("note.offpath_skipped", lang=LANG) + "\n\n"
        return out

    idx_host = _col_index(fd12, "userhost")
    idx_logins = _col_index(fd12, "logins")
    idx_users = _col_index(fd12, "distinct_users")
    offpath_rows = []
    for row in fd12.get("rows", []):
        host = _row_get(row, idx_host).strip()
        if not host:
            continue
        if classifier.classify(host) != "OFF-PATH":
            continue
        offpath_rows.append([
            host,
            fmt_int(_row_get(row, idx_logins)),
            fmt_int(_row_get(row, idx_users)),
        ])
    if not offpath_rows:
        out += t("offpath.none", lang=LANG) + "\n\n"
    else:
        out += t("offpath.found", lang=LANG, n=len(offpath_rows)) + "\n\n"
        out += render_table(
            [t("label.host", lang=LANG),
             t("label.logins", lang=LANG),
             t("label.distinct_users", lang=LANG)],
            offpath_rows, max_rows=top_n,
        )
        out += "\n"
    return out


def render_section_08_tuning(file_data, top_n, policy_ddl_map):
    """Section 8 (noise candidates) + Section 8.1 (DDL-grounded WHEN-
    clause tuning suggestions).

    `policy_ddl_map` comes from load_policy_ddl(bundle_dir) and contains
    {policy_name: DBMS_METADATA.GET_DDL output}. If empty, the per-
    candidate sub-sections emit a "DDL unavailable" note instead of
    fabricating DDL.
    """
    out = section_header(2, t("section.08_tuning", lang=LANG))
    if file_data is None:
        out += t("tuning.csv_missing", lang=LANG) + "\n\n"
        return out
    rows = file_data.get("rows", [])
    if not rows:
        out += t("tuning.no_candidates", lang=LANG) + "\n\n"
        return out

    out += t("tuning.intro", lang=LANG) + "\n\n"
    out += render_table(file_data["headers"], rows, max_rows=top_n)
    out += "\n"

    out += section_header(3, t("section.08_1_when_clauses", lang=LANG))
    headers = file_data["headers"]
    candidate_count = min(len(rows), 5)
    for i, row in enumerate(rows[:candidate_count], start=1):
        result = when_clause_for(row, headers, policy_ddl_map)
        out += f"#### {t('tuning.candidate_header', lang=LANG, n=i)}\n\n"

        # Observed combination from the noise-candidate row.
        out += f"**{t('tuning.observed_combo', lang=LANG)}**:\n\n"
        for label, value in result["recap"]:
            out += f"- `{label}`: `{value}`\n"
        out += "\n"

        # Current DDL (from DBMS_METADATA) + existing WHEN clause.
        if result["current_ddl"]:
            out += f"**{t('tuning.current_ddl_label', lang=LANG)}**:\n\n"
            out += "```sql\n"
            out += result["current_ddl"]
            if not result["current_ddl"].endswith("\n"):
                out += "\n"
            out += "```\n\n"
            if result["existing_when"]:
                out += f"**{t('tuning.existing_when', lang=LANG)}**:\n\n"
                out += "```text\n"
                out += result["existing_when"] + "\n"
                out += "```\n\n"
            else:
                out += (
                    f"**{t('tuning.existing_when', lang=LANG)}**: "
                    f"{t('tuning.no_existing_when', lang=LANG)}\n\n"
                )
        else:
            out += t("note.policy_ddl_unavailable", lang=LANG) + "\n\n"

        # Suggested condition expressions (NOT full ALTER DDL - see
        # ai-analysis-rules.md Section 4 + rationale in when_clause_for).
        for v, suggestion in enumerate(result["suggestions"], start=1):
            out += (
                f"##### {t('tuning.suggestion_header', lang=LANG, n=i, v=v, label=suggestion['label'])}\n\n"
            )
            out += suggestion["rationale"] + "\n\n"
            if suggestion["condition_expr"]:
                out += "```sql\n"
                out += suggestion["condition_expr"] + "\n"
                out += "```\n\n"
                out += (
                    f"**{t('tuning.apply_instructions', lang=LANG)}**: "
                    f"{t('tuning.apply_template', lang=LANG, policy=result['policy_name'], new=suggestion['condition_expr'])}\n\n"
                )
    out += t("note.tuning_disclaimer", lang=LANG) + "\n\n"
    return out


def render_appendix(bundle, top_n):
    out = section_header(2, t("section.appendix", lang=LANG))
    out += section_header(3, t("section.appendix_manifest", lang=LANG))
    manifest = bundle.get("_manifest", {})
    out += "```json\n"
    out += json.dumps(manifest, indent=2, ensure_ascii=False)
    out += "\n```\n\n"
    for qid in ("03", "04", "05"):
        fd = bundle["_files"].get(qid)
        if fd is None:
            continue
        out += section_header(3, t("section.appendix_full_data", lang=LANG,
                                   name=QUERY_FILES[qid]))
        out += render_table(fd["headers"], fd["rows"])
        out += "\n"
    return out


# ---------------------------------------------------------------------------
# Top-level renderer
# ---------------------------------------------------------------------------

def render_section_09_cis_coverage(file_data, inv_data=None):
    """Section 9 - CIS Benchmark 5.1-5.5 coverage per-control PASS/WARN/FAIL table.

    Reads 17_cis_coverage.csv (v1.3+ format). Each row represents one CIS
    control (5.1-5.5). Coverage is determined by comparing actual policy
    actions against CIS requirements - NOT by checking for specific policy
    names. Verdicts: PASS (custom policy with full unconditional coverage),
    PARTIAL (custom policy exists but is conditional or user-scoped),
    FAIL (no custom policy covers the control at all).
    Oracle-supplied policies are shown separately for information.
    """
    out = section_header(2, t("section.09_cis_coverage", lang=LANG))
    if file_data is None:
        out += t("note.csv_missing_cis", lang=LANG) + "\n\n"
        return out

    rows = file_data.get("rows", [])
    if not rows:
        out += t("note.cis_no_data", lang=LANG) + "\n\n"
        return out

    idx_control = _col_index(file_data, "cis_control")
    idx_title = _col_index(file_data, "cis_title")
    idx_verdict = _col_index(file_data, "verdict")
    idx_custom = _col_index(file_data, "custom_policies")
    idx_oracle = _col_index(file_data, "oracle_policies")

    # Support both old format (policy_name column) and new format (custom_policies).
    # Old format: idx_custom == -1; fall back to legacy rendering.
    if idx_custom < 0:
        # Legacy fallback: reuse old rendering path with available columns.
        idx_policy = _col_index(file_data, "policy_name")
        idx_exists = _col_index(file_data, "policy_exists")
        idx_enabled = _col_index(file_data, "policy_enabled")
        fail_count = sum(1 for r in rows if _row_get(r, idx_verdict).upper() == "FAIL")
        if fail_count:
            out += t("cis.fail_count", lang=LANG,
                     n=fail_count, total=len(rows)) + "\n\n"
        table_rows = []
        for r in rows:
            v = _row_get(r, idx_verdict).upper()
            vm = {"PASS": "PASS", "WARN": "**WARN**", "FAIL": "**FAIL**"}.get(v, v)
            table_rows.append([
                _row_get(r, idx_control), _row_get(r, idx_title),
                _row_get(r, idx_policy) if idx_policy >= 0 else "",
                _row_get(r, idx_exists) if idx_exists >= 0 else "",
                _row_get(r, idx_enabled) if idx_enabled >= 0 else "",
                vm,
            ])
        out += render_table(
            [t("label.cis_control", lang=LANG), t("label.cis_title", lang=LANG),
             t("label.cis_policy", lang=LANG), t("label.cis_exists", lang=LANG),
             t("label.cis_enabled", lang=LANG), t("label.cis_verdict", lang=LANG)],
            table_rows,
        )
        out += "\n" + t("cis.source", lang=LANG) + "\n\n"
        return out

    fail_count = sum(1 for r in rows if _row_get(r, idx_verdict).upper() == "FAIL")
    partial_count = sum(1 for r in rows if _row_get(r, idx_verdict).upper() == "PARTIAL")
    pass_count = sum(1 for r in rows if _row_get(r, idx_verdict).upper() == "PASS")

    if fail_count:
        out += t("cis.fail_count", lang=LANG,
                 n=fail_count, total=len(rows)) + "\n\n"
    if partial_count:
        out += t("cis.partial_count", lang=LANG, n=partial_count) + "\n\n"
    if pass_count == len(rows):
        out += t("cis.all_pass", lang=LANG) + "\n\n"

    table_rows = []
    for r in rows:
        verdict = _row_get(r, idx_verdict).upper()
        verdict_marker = {
            "PASS":    "PASS",
            "PARTIAL": "**PARTIAL**",
            "FAIL":    "**FAIL**",
        }.get(verdict, verdict)
        table_rows.append([
            _row_get(r, idx_control),
            _row_get(r, idx_title),
            verdict_marker,
            _row_get(r, idx_custom),
            _row_get(r, idx_oracle) if idx_oracle >= 0 else "",
        ])

    out += render_table(
        [t("label.cis_control", lang=LANG), t("label.cis_title", lang=LANG),
         t("label.cis_verdict", lang=LANG),
         t("label.cis_custom", lang=LANG), t("label.cis_oracle", lang=LANG)],
        table_rows,
    )
    out += "\n" + t("cis.coverage_note", lang=LANG) + "\n"
    out += t("cis.source", lang=LANG) + "\n\n"

    # ----------------------------------------------------------------
    # Detail table: policies from inventory that cover CIS requirements
    # Cross-referenced from inv_data (03_policy_inventory).
    # Never truncated.
    # ----------------------------------------------------------------
    if inv_data is not None:
        out += section_header(3, t("section.09_detail", lang=LANG))
        out += t("cis.detail_intro", lang=LANG) + "\n\n"

        # Build policy -> set of CIS controls mapping from 17 data
        policy_to_cis: dict[str, list[str]] = {}
        for r in rows:
            ctrl = _row_get(r, idx_control)
            for col_idx in (idx_custom, idx_oracle):
                if col_idx >= 0:
                    for pol in _parse_policy_names(_row_get(r, col_idx)):
                        policy_to_cis.setdefault(pol, [])
                        if ctrl not in policy_to_cis[pol]:
                            policy_to_cis[pol].append(ctrl)

        if not policy_to_cis:
            out += t("note.no_data", lang=LANG) + "\n\n"
        else:
            deduped = _dedup_policy_rows(inv_data,
                                         filter_policies=set(policy_to_cis))
            inv_idx_ora = _col_index(inv_data, "oracle_supplied")
            inv_idx_opt = _col_index(inv_data, "enabled_option")
            inv_idx_ent = _col_index(inv_data, "entity_name")
            inv_idx_etype = _col_index(inv_data, "entity_type")
            inv_idx_suc = _col_index(inv_data, "success")
            inv_idx_fal = _col_index(inv_data, "failure")
            detail_rows = []
            for (pol, ent, etype, opt), r in deduped:
                cis_str = ", ".join(sorted(policy_to_cis.get(pol, [])))
                detail_rows.append([
                    cis_str,
                    pol,
                    _row_get(r, inv_idx_ora),
                    opt or "-",
                    ent or "-",
                    etype or "-",
                    _row_get(r, inv_idx_suc),
                    _row_get(r, inv_idx_fal),
                ])
            out += render_table(
                [t("label.cis_controls", lang=LANG),
                 t("label.policy", lang=LANG), t("label.ora", lang=LANG),
                 t("label.policy_option", lang=LANG),
                 t("label.entity", lang=LANG), t("label.entity_type", lang=LANG),
                 t("label.success_short", lang=LANG),
                 t("label.failure_short", lang=LANG)],
                detail_rows,
            )
            out += "\n"

    return out


def render_section_10_audit_roles(file_data):
    """Section 10 - AUDIT_ADMIN / AUDIT_VIEWER membership and risk flags.

    Reads 18_audit_roles.csv. Highlights WARN and REVIEW grantees prominently.
    SYS and STANDARD entries are listed without special emphasis.
    """
    out = section_header(2, t("section.10_audit_roles", lang=LANG))
    if file_data is None:
        out += t("note.csv_missing_roles", lang=LANG) + "\n\n"
        return out

    rows = file_data.get("rows", [])
    if not rows:
        out += t("note.roles_no_data", lang=LANG) + "\n\n"
        return out

    idx_role = _col_index(file_data, "target_role")
    idx_grantee = _col_index(file_data, "grantee")
    idx_gtype = _col_index(file_data, "grantee_type")
    idx_path = _col_index(file_data, "grant_path")
    idx_admin = _col_index(file_data, "admin_option")
    idx_flag = _col_index(file_data, "risk_flag")

    review_rows = [
        r for r in rows
        if _row_get(r, idx_flag).upper() in {"WARN", "REVIEW"}
    ]
    if review_rows:
        out += t("roles.review_count", lang=LANG, n=len(review_rows)) + "\n\n"

    table_rows = []
    for r in rows:
        flag = _row_get(r, idx_flag).upper()
        flag_marker = {
            "WARN": "**WARN**",
            "REVIEW": "**REVIEW**",
        }.get(flag, flag)
        table_rows.append([
            _row_get(r, idx_role),
            _row_get(r, idx_grantee),
            _row_get(r, idx_gtype),
            _row_get(r, idx_path),
            _row_get(r, idx_admin),
            flag_marker,
        ])

    out += render_table(
        [t("label.role_target", lang=LANG), t("label.role_grantee", lang=LANG),
         t("label.role_type", lang=LANG), t("label.role_path", lang=LANG),
         t("label.role_admin", lang=LANG), t("label.role_flag", lang=LANG)],
        table_rows,
    )
    out += "\n" + t("roles.source", lang=LANG) + "\n\n"
    return out


def render_report(bundle, classifier, top_n, include_appendix,
                  policy_ddl_map=None):
    files = bundle["_files"]
    if policy_ddl_map is None:
        policy_ddl_map = {}
    out = "<!-- markdownlint-disable MD013 MD033 MD060 -->\n"
    out += render_executive_summary(bundle, classifier, top_n)
    out += render_section_01_config(files.get("01"))
    out += render_section_02_storage(files.get("02"))
    out += render_section_03_policy_inventory(
        files.get("03"), top_n, include_appendix,
    )
    out += render_section_04_07_volumes(files, top_n)
    out += render_section_05_connect_profile(files, classifier, top_n)
    out += render_section_06_privileged(files.get("14"), top_n)
    out += render_section_07_security_signals(files, classifier, top_n)
    out += render_section_08_tuning(files.get("15"), top_n, policy_ddl_map)
    out += render_section_09_cis_coverage(files.get("17"), inv_data=files.get("03"))
    out += render_section_10_audit_roles(files.get("18"))
    if include_appendix:
        out += render_appendix(bundle, top_n)
    out += "---\n\n"
    out += (
        f"_Generiert von `audit_report.py` v{TOOL_VERSION} - "
        f"Bundle: `{bundle['_path']}`_\n"
    )
    return out


# ---------------------------------------------------------------------------
# AI analysis
# ---------------------------------------------------------------------------

def _claude_cli_available() -> bool:
    """Return True if the claude CLI (Claude Code) is installed and reachable."""
    import subprocess
    try:
        subprocess.run(
            ["claude", "--version"],
            capture_output=True, check=True, timeout=10,
        )
        return True
    except (FileNotFoundError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired):
        return False


def _get_api_key(op_path: str) -> str:
    """Return Anthropic API key, or '' if none found (triggers CLI fallback).

    Priority: ANTHROPIC_API_KEY env var > op read > '' (no key).
    Raises RuntimeError only for hard failures (op CLI missing, op read error).
    """
    import os
    import subprocess
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if key:
        return key
    if not op_path:
        return ""
    try:
        result = subprocess.run(
            ["op", "read", op_path],
            capture_output=True, text=True, check=True,
        )
        return result.stdout.strip()
    except FileNotFoundError:
        raise RuntimeError(
            "'op' CLI not found. Install 1Password CLI or set ANTHROPIC_API_KEY."
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"op read failed ({op_path}): {exc.stderr.strip()}"
        )


def _generate_via_sdk(
    user_prompt: str,
    model: str,
    api_key: str,
    lang: str = "de",
) -> str:
    """Generate findings via the Anthropic Python SDK."""
    try:
        import anthropic
    except ImportError:
        raise RuntimeError(
            "'anthropic' package not installed. Run: pip install anthropic"
        )
    sys_prompt = AI_SYSTEM_PROMPTS.get(lang, AI_SYSTEM_PROMPTS["de"])
    client = anthropic.Anthropic(api_key=api_key)
    message = client.messages.create(
        model=model,
        max_tokens=4096,
        system=sys_prompt,
        messages=[{"role": "user", "content": user_prompt}],
    )
    return message.content[0].text


def _generate_via_cli(user_prompt: str, model: str, lang: str = "de") -> str:
    """Generate findings via the claude CLI (Claude Code, uses claude.ai auth).

    Passes the prompt via stdin (input=) to avoid OS argument-length limits.
    stderr is discarded to prevent the stdout/stderr communicate() deadlock
    that occurs when capture_output=True and claude writes progress to stderr.
    Timeout is 600 s to allow for slow API responses on large reports.
    """
    import subprocess
    sys_prompt = AI_SYSTEM_PROMPTS.get(lang, AI_SYSTEM_PROMPTS["de"])
    combined = f"{sys_prompt}\n\n---\n\n{user_prompt}"
    try:
        result = subprocess.run(
            ["claude", "--output-format", "text", "--model", model],
            input=combined,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True, check=True, timeout=600,
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        raise RuntimeError("claude CLI timed out after 600 s")
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"claude CLI failed (exit {exc.returncode})")


def _generate_ai_findings(
    report_text: str,
    model: str,
    api_key: str,
    customer_prefix: str,
    lang: str = "de",
) -> str:
    """Call Claude and return findings text.

    Backend selection:
      api_key set  -> Anthropic Python SDK
      api_key ''   -> claude CLI (Claude Code, claude.ai authentication)
      neither      -> RuntimeError with setup instructions
    """
    tmpl = AI_USER_PROMPT_TEMPLATES.get(lang, AI_USER_PROMPT_TEMPLATES["de"])
    user_prompt = tmpl.format(
        customer_prefix=customer_prefix,
        report_text=report_text,
    )
    if api_key:
        return _generate_via_sdk(user_prompt, model, api_key, lang=lang)
    if _claude_cli_available():
        print("[AI] No API key - using claude CLI (Claude Code)...", file=sys.stderr)
        return _generate_via_cli(user_prompt, model, lang=lang)
    raise RuntimeError(
        "No AI backend available. One of:\n"
        "  1. Set ANTHROPIC_API_KEY (console.anthropic.com)\n"
        "  2. Pass --ai-op-path op://Vault/Item/field (1Password)\n"
        "  3. Install Claude Code CLI (uses claude.ai subscription)"
    )


def _run_ai_analysis(
    args,
    bundle_dir: Path,
    report_path: Path,
    report_text: str,
) -> int:
    """Append AI Section 9 to the report and write standalone audit_ai_findings.md."""
    from datetime import datetime, timezone
    print(f"[AI] Generating findings (model: {args.ai_model})...", file=sys.stderr)
    try:
        api_key = _get_api_key(args.ai_op_path)
        ai_text = _generate_ai_findings(
            report_text, args.ai_model, api_key, args.customer_prefix,
            lang=LANG,
        )
    except RuntimeError as exc:
        print(f"ERROR (AI): {exc}", file=sys.stderr)
        return 3

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    ai_section = (
        "\n## 11. AI-Findings (Claude)\n\n"
        f"> Generiert: `{ts}` | Modell: `{args.ai_model}`  \n"
        "> Automatisch generierte Analyse - Findings sind zu verifizieren.\n\n"
        + ai_text + "\n"
    )
    with report_path.open("a", encoding="utf-8") as fh:
        fh.write(ai_section)
    print(f"Appended AI findings    -> {report_path}")

    standalone_path = bundle_dir / "audit_ai_findings.md"
    standalone = (
        "<!-- markdownlint-disable MD013 MD033 MD060 -->\n"
        "# AI-Findings - Audit Trail Analyse\n\n"
        f"| Feld | Wert |\n"
        f"|------|------|\n"
        f"| Generiert | `{ts}` |\n"
        f"| Modell | `{args.ai_model}` |\n"
        f"| Bundle | `{bundle_dir.name}` |\n\n"
        "> **Automatisch generierte Analyse - Findings sind zu verifizieren.**\n\n"
        + ai_text + "\n\n"
        "---\n\n"
        f"_Generiert von `audit_report.py` v{TOOL_VERSION} via Claude API_\n"
    )
    standalone_path.write_text(standalone, encoding="utf-8")
    print(f"Wrote standalone findings -> {standalone_path}")
    return 0


# ---------------------------------------------------------------------------
# Export-prompt helper (R4)
# ---------------------------------------------------------------------------

_EXPORT_PROMPT_HEADER = """\
# ora-db-audit - AI Analysis Prompt Export
# ==========================================
# Paste the content below this header into any LLM chat interface to get
# an AI-powered audit analysis. Provider-specific instructions:
#
#   claude.ai  : paste as-is into the chat input
#   ChatGPT    : paste as-is (GPT-4/o1 supports long inputs)
#   Gemini     : paste as-is into Gemini Advanced
#   API callers: use AI_SYSTEM_PROMPT as the system prompt and the rest as
#                the user message (see audit_report.py AI_SYSTEM_PROMPT)
#
# Note: no API key or Claude Code CLI is required to use this file.
# ==========================================

"""


def _write_export_prompt(
    report_text: str,
    customer_prefix: str,
    dest: Path,
    lang: str = "de",
) -> None:
    """Build the full AI user prompt and write it to dest.

    The exported file is self-contained: it includes both the system-level
    context (inlined as a plain-text block) and the user prompt with the
    full report embedded. This makes it paste-ready for any LLM chat UI.
    The prompt language matches the report language (lang parameter).
    """
    sys_prompt = AI_SYSTEM_PROMPTS.get(lang, AI_SYSTEM_PROMPTS["de"])
    tmpl = AI_USER_PROMPT_TEMPLATES.get(lang, AI_USER_PROMPT_TEMPLATES["de"])
    user_prompt = tmpl.format(
        customer_prefix=customer_prefix,
        report_text=report_text,
    )
    if lang == "en":
        section_header = "## Context / System Prompt\n\n"
        task_header = "## Analysis Task (User Prompt)\n\n"
    else:
        section_header = "## Kontext / System-Prompt\n\n"
        task_header = "## Analyse-Auftrag (User-Prompt)\n\n"
    content = (
        _EXPORT_PROMPT_HEADER
        + section_header
        + sys_prompt
        + "\n\n---\n\n"
        + task_header
        + user_prompt
    )
    dest.write_text(content, encoding="utf-8")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv):
    p = argparse.ArgumentParser(
        prog="audit_report.py",
        description=(
            "Render a Markdown audit-trail analysis report from a "
            "(raw or anonymised) ora-db-audit bundle directory."
        ),
        epilog=(
            "Use --patterns config.json with the keys "
            "'app_host_patterns', 'infra_host_patterns', "
            "'dba_host_patterns' for deployment-specific host "
            "classification.\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("bundle", type=Path,
                   help="Path to the ora-db-audit bundle directory.")
    p.add_argument("--output", "-o", type=Path,
                   help="Output Markdown file (default: "
                        "<bundle>/audit_report.md).")
    p.add_argument("--patterns", type=Path,
                   help="JSON file with host-pattern lists "
                        "(default: built-in community / customer-configurable set).")
    p.add_argument("--top-n", type=int, default=None,
                   metavar="N",
                   help="Row cap per table in the report. "
                        "Default: reads top_n from bundle manifest. "
                        "Use 0 for unlimited (show all rows).")
    p.add_argument("--customer-prefix", default=DEFAULT_CUSTOMER_PREFIX,
                   help=f"Customer prefix for narrative passages "
                        f"(default: {DEFAULT_CUSTOMER_PREFIX!r} - empty).")
    p.add_argument("--lang", default=DEFAULT_LANGUAGE,
                   choices=list(SUPPORTED_LANGUAGES),
                   help=f"Report language (default: {DEFAULT_LANGUAGE}). "
                        f"v1.0.0 ships German-only; additional languages "
                        f"land in v1.1+ - the message catalog is already "
                        f"structured to receive them without code changes.")
    p.add_argument("--include-appendix", action="store_true",
                   help="Append manifest + full tables for "
                        "03/04/05 to the report.")
    p.add_argument("--dry-run", action="store_true",
                   help="Render but do not write the output file.")
    p.add_argument("--yes", "-y", action="store_true",
                   help="Overwrite existing output without prompting.")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="Print which CSV files were used / skipped.")
    p.add_argument("--export-prompt", type=Path, dest="export_prompt",
                   metavar="FILE",
                   help="Write the full AI analysis prompt (with report data "
                        "embedded) to FILE instead of sending it to an API. "
                        "The output is paste-ready for claude.ai, ChatGPT, "
                        "Gemini, or any LLM chat UI. "
                        "Does not require an API key or Claude CLI.")
    ai_grp = p.add_argument_group("AI analysis (requires 'anthropic' package)")
    ai_grp.add_argument("--ai", action="store_true",
                        help="Generate AI findings via Claude API. Appends "
                             "Section 9 to audit_report.md and writes "
                             "standalone audit_ai_findings.md.")
    ai_grp.add_argument("--ai-model", default=DEFAULT_AI_MODEL, dest="ai_model",
                        metavar="MODEL",
                        help=f"Claude model to use (default: {DEFAULT_AI_MODEL}).")
    ai_grp.add_argument("--ai-op-path", default=DEFAULT_AI_OP_PATH, dest="ai_op_path",
                        metavar="OP_PATH",
                        help="1Password op:// path for the Anthropic API key. "
                             "Used when ANTHROPIC_API_KEY env var is not set "
                             "(e.g. op://Private/Anthropic/credential).")
    return p.parse_args(argv)


def _load_patterns(path):
    if path is None:
        return dict(DEFAULT_PATTERNS)
    if not path.is_file():
        raise FileNotFoundError(f"patterns file not found: {path}")
    raw = json.loads(path.read_text(encoding="utf-8"))
    merged = dict(DEFAULT_PATTERNS)
    for key in ("app_host_patterns", "infra_host_patterns",
                "dba_host_patterns"):
        if key in raw:
            merged[key] = list(raw[key])
    return merged


def _confirm_overwrite(path, assume_yes):
    if not path.exists() or assume_yes:
        return True
    answer = input(f"Overwrite {path}? [y/N] ").strip().lower()
    return answer == "y"


def main(argv=None):
    args = parse_args(argv)

    # Activate selected language for all subsequent t() calls.
    global LANG
    LANG = args.lang

    bundle_dir = args.bundle.resolve()
    if not bundle_dir.is_dir():
        print(f"ERROR: bundle directory not found: {bundle_dir}",
              file=sys.stderr)
        return 2

    try:
        patterns = _load_patterns(args.patterns)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    classifier = HostClassifier(patterns)

    bundle = read_bundle(bundle_dir)
    files = bundle["_files"]
    if args.verbose:
        print(f"Bundle:     {bundle_dir}")
        print(f"Manifest:   {'yes' if bundle['_manifest'] else 'no'}")
        for qid in sorted(QUERY_FILES):
            label = QUERY_FILES[qid]
            status = "OK" if qid in files else "missing"
            print(f"  [{qid}] {label:<32} {status}")

    if not files:
        print(f"ERROR: no parseable CSV files found in {bundle_dir}",
              file=sys.stderr)
        return 2

    # Resolve top_n: explicit arg > manifest > fallback 20.
    # 0 means unlimited (None in render_table).
    if args.top_n is None:
        top_n = int(bundle.get("_manifest", {}).get("top_n") or 20)
    elif args.top_n == 0:
        top_n = None  # unlimited
    else:
        top_n = args.top_n

    # Section 8.1 tuning suggestions need actual policy DDL from
    # DBMS_METADATA (sql/16-policy-ddl.csv). Empty if unavailable -
    # the renderer falls back to a "DDL unavailable" note instead of
    # fabricating DDL from concat strings (per ai-analysis-rules.md
    # Section 4 / finding F2).
    policy_ddl_map = load_policy_ddl(bundle_dir)
    if args.verbose:
        if policy_ddl_map:
            print(f"Policy DDL: {len(policy_ddl_map)} policies loaded "
                  f"from 16-policy-ddl.csv")
        else:
            print("Policy DDL: 16-policy-ddl.csv missing or empty "
                  "(Section 8.1 will note 'DDL unavailable')")

    report_text = render_report(
        bundle, classifier, top_n, args.include_appendix,
        policy_ddl_map=policy_ddl_map,
    )

    if args.export_prompt:
        _write_export_prompt(report_text, args.customer_prefix,
                             args.export_prompt, lang=LANG)
        print(f"Wrote AI prompt export  -> {args.export_prompt}")
        return 0

    output = args.output or (bundle_dir / "audit_report.md")
    if args.dry_run:
        print(report_text)
        print(f"\n(dry-run: would write {output})", file=sys.stderr)
        if args.ai:
            print(
                f"(dry-run: would call Claude API model={args.ai_model})",
                file=sys.stderr,
            )
        return 0

    if not _confirm_overwrite(output, args.yes):
        print("Aborted.", file=sys.stderr)
        return 1

    output.write_text(report_text, encoding="utf-8")
    print(f"Wrote report            -> {output}")

    if args.ai:
        return _run_ai_analysis(args, bundle_dir, output, report_text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
