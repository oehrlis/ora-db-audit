#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# ------------------------------------------------------------------------------
# OraDBA - Oracle Database Infrastructure and Security, 5630 Muri, Switzerland
# ------------------------------------------------------------------------------
# Name.......: export_siem.py
# Author.....: Stefan Oehrli (oes) stefan.oehrli@oradba.ch
# Editor.....: Stefan Oehrli
# Date.......: 2026.05.28
# Version....: 1.2.0
# Purpose....: Convert an ora-db-audit bundle to a SIEM-ingestible format.
#              Supports OCSF (Open Cybersecurity Schema Framework) JSON Lines
#              and Microsoft Sentinel / Log Analytics CSV.
#              Works on raw or anonymised bundles.
# Notes......: The bundle contains aggregated data (top-N rows per query),
#              not a full event log. Each output record represents a
#              distinct (user, host, program) or (user, action, policy)
#              combination with an aggregated event count. Use for trend
#              analysis and host profiling; not for forensic event replay.
#
# Usage......: export_siem.py BUNDLE_DIR
#                             --format ocsf|sentinel
#                             --output FILE
#                             [--sources QUERY_ID,...]
#                             [--dry-run] [--help]
#
# License....: Apache License Version 2.0, January 2004 as shown
#              at http://www.apache.org/licenses/
# ------------------------------------------------------------------------------
# CHANGE LOG:
# 2026.05.28  oes  Initial release. D2 SIEM export adapter.               1.2.0
# ------------------------------------------------------------------------------

import argparse
import csv
import io
import json
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
from anonymize_bundle import split_preamble, find_schema_line  # noqa: E402

TOOL_VERSION = "1.2.0"
OCSF_VERSION = "1.3.0"
OCSF_DATABASE_ACTIVITY_CLASS_UID = 3005

# Queries to export by default (aggregated data with host/user/event info).
DEFAULT_SOURCES = ["08", "11", "13", "14", "19"]

# Map query stem -> source label used in unmapped.query_source field.
QUERY_STEMS = {
    "08": "08_top_users",
    "11": "11_host_user_program",
    "13": "13_failed_logins",
    "14": "14_privileged_activity",
    "19": "19_offpath_candidates",
}

SENTINEL_COLUMNS = [
    "TimeGenerated",
    "DbSid",
    "Pdb",
    "DbUser",
    "OsUser",
    "UserHost",
    "ClientProgram",
    "ActionName",
    "ReturnCode",
    "EventCount",
    "FirstSeen",
    "LastSeen",
    "QuerySource",
    "Classification",
]


# ---------------------------------------------------------------------------
# Bundle reader (minimal - we only need meta + rows)
# ---------------------------------------------------------------------------

def _read_csv(path):
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
        k, _, v = body.partition(":")
        meta[k.strip()] = v.strip()

    reader = csv.reader(io.StringIO("".join(data_lines)), delimiter="|")
    rows = list(reader)
    if not rows:
        return meta, [], []
    headers = [c.strip().strip('"') for c in rows[0]]
    data = [[c.strip().strip('"') for c in r] for r in rows[1:]]
    return meta, headers, data


def _col(headers, name):
    needle = name.lower()
    for i, h in enumerate(headers):
        if h.lower() == needle:
            return i
    return -1


def _get(row, headers, name, default=""):
    idx = _col(headers, name)
    if idx < 0 or idx >= len(row):
        return default
    return row[idx].strip() or default


def read_bundle(bundle_dir):
    manifest = {}
    manifest_path = bundle_dir / "manifest.json"
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass

    files = {}
    for qid, stem in QUERY_STEMS.items():
        path = bundle_dir / f"{stem}.csv"
        if not path.is_file():
            continue
        meta, headers, rows = _read_csv(path)
        if headers:
            files[qid] = {"meta": meta, "headers": headers, "rows": rows}
    return manifest, files


# ---------------------------------------------------------------------------
# OCSF record builder
# ---------------------------------------------------------------------------

def _ocsf_status(return_code):
    rc = str(return_code).strip()
    if rc in ("0", "", "(null)"):
        return 1, "Success"
    return 2, "Failure"


def _ocsf_severity(return_code, classification=""):
    rc = str(return_code).strip()
    if classification == "OFF-PATH":
        return 3, "Medium"
    if rc not in ("0", "", "(null)"):
        return 3, "Medium"
    return 1, "Informational"


def _ocsf_record(dbsid, pdb, query_source, row, headers, ts_now):
    user = _get(row, headers, "dbusername")
    host = _get(row, headers, "userhost")
    os_user = _get(row, headers, "os_username")
    program = _get(row, headers, "client_program_name")
    action = _get(row, headers, "action_name")
    policy = _get(row, headers, "policy_name")
    return_code = _get(row, headers, "return_code", "0")
    events = _get(row, headers, "events") or _get(row, headers, "logins") or "1"
    first_seen = _get(row, headers, "first_seen")
    last_seen = _get(row, headers, "last_seen")
    classification = _get(row, headers, "classification")

    status_id, status = _ocsf_status(return_code)
    severity_id, severity = _ocsf_severity(return_code, classification)

    record = {
        "class_uid": OCSF_DATABASE_ACTIVITY_CLASS_UID,
        "class_name": "Database Activity",
        "category_uid": 5,
        "category_name": "Database Activity",
        "activity_id": 1,
        "activity_name": "Query",
        "type_uid": OCSF_DATABASE_ACTIVITY_CLASS_UID * 100 + 1,
        "time": last_seen or ts_now,
        "start_time": first_seen or ts_now,
        "end_time": last_seen or ts_now,
        "count": int(events) if events.isdigit() else 1,
        "status_id": status_id,
        "status": status,
        "severity_id": severity_id,
        "severity": severity,
        "actor": {
            "user": {
                "name": user,
                "type": "Database User",
            },
        },
        "src_endpoint": {
            "hostname": host,
        },
        "database": {
            "name": pdb or dbsid,
            "instance": dbsid,
        },
        "metadata": {
            "version": OCSF_VERSION,
            "product": {
                "name": "Oracle Unified Audit",
                "vendor_name": "Oracle",
                "lang": "en",
            },
        },
        "unmapped": {
            "query_source": query_source,
        },
    }

    if os_user:
        record["actor"]["session"] = {"credential_uid": os_user}
    if program:
        record["actor"]["process"] = {"name": program}
    if action:
        record["unmapped"]["action_name"] = action
    if policy:
        record["unmapped"]["policy_name"] = policy
    if return_code:
        record["unmapped"]["return_code"] = return_code
    if classification:
        record["unmapped"]["classification"] = classification

    return record


# ---------------------------------------------------------------------------
# Sentinel record builder
# ---------------------------------------------------------------------------

def _sentinel_record(dbsid, pdb, query_source, row, headers, ts_now):
    return {
        "TimeGenerated": _get(row, headers, "last_seen") or ts_now,
        "DbSid": dbsid,
        "Pdb": pdb,
        "DbUser": _get(row, headers, "dbusername"),
        "OsUser": _get(row, headers, "os_username"),
        "UserHost": _get(row, headers, "userhost"),
        "ClientProgram": _get(row, headers, "client_program_name"),
        "ActionName": _get(row, headers, "action_name"),
        "ReturnCode": _get(row, headers, "return_code"),
        "EventCount": (
            _get(row, headers, "events")
            or _get(row, headers, "logins")
            or "1"
        ),
        "FirstSeen": _get(row, headers, "first_seen"),
        "LastSeen": _get(row, headers, "last_seen"),
        "QuerySource": query_source,
        "Classification": _get(row, headers, "classification"),
    }


# ---------------------------------------------------------------------------
# Export functions
# ---------------------------------------------------------------------------

def export_ocsf(manifest, files, sources, output_path, dry_run=False):
    from datetime import datetime, timezone
    ts_now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    dbsid = manifest.get("dbsid", "unknown")

    records = []
    for qid in sources:
        if qid not in files:
            continue
        fd = files[qid]
        pdb = fd["meta"].get("pdb", "")
        stem = QUERY_STEMS.get(qid, qid)
        for row in fd["rows"]:
            rec = _ocsf_record(dbsid, pdb, stem, row, fd["headers"], ts_now)
            records.append(rec)

    print(f"OCSF records: {len(records)}", file=sys.stderr)
    if dry_run:
        print(f"dry-run: would write {len(records)} OCSF records -> {output_path}",
              file=sys.stderr)
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(f"Wrote OCSF JSON Lines ({len(records)} records) -> {output_path}",
          file=sys.stderr)
    return 0


def export_sentinel(manifest, files, sources, output_path, dry_run=False):
    from datetime import datetime, timezone
    ts_now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    dbsid = manifest.get("dbsid", "unknown")

    rows = []
    for qid in sources:
        if qid not in files:
            continue
        fd = files[qid]
        pdb = fd["meta"].get("pdb", "")
        stem = QUERY_STEMS.get(qid, qid)
        for row in fd["rows"]:
            rows.append(_sentinel_record(dbsid, pdb, stem, row,
                                         fd["headers"], ts_now))

    print(f"Sentinel rows: {len(rows)}", file=sys.stderr)
    if dry_run:
        print(f"dry-run: would write {len(rows)} Sentinel rows -> {output_path}",
              file=sys.stderr)
        return 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=SENTINEL_COLUMNS,
                                extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote Sentinel CSV ({len(rows)} rows) -> {output_path}",
          file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(
        description=(
            "Convert an ora-db-audit bundle to a SIEM-ingestible format. "
            "Supports OCSF JSON Lines and Microsoft Sentinel CSV."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Formats:
  ocsf      OCSF 1.3 Database Activity (class 3005) JSON Lines.
            One record per aggregate row; suitable for any SIEM that
            accepts OCSF. Append to a streaming ingest endpoint or
            import as a batch.
  sentinel  Flat CSV for Microsoft Sentinel / Log Analytics custom table.
            Upload via az monitor log-analytics workspace table create
            and az monitor log-analytics query.

Sources:
  Default: 08 (top users), 11 (host/user/program), 13 (failed logins),
           14 (privileged activity), 19 (off-path candidates if present).
  Pass --sources 11,13 to restrict the export.

Note:
  The bundle contains aggregated rows, not individual audit events.
  EventCount reflects the aggregate; use the bundle for profiling and
  trend analysis, not forensic event replay.
""",
    )
    parser.add_argument("bundle_dir", type=Path,
                        help="Bundle directory (extracted) or tarball")
    parser.add_argument("--format", choices=["ocsf", "sentinel"],
                        default="ocsf",
                        help="Output format (default: ocsf)")
    parser.add_argument("--output", "-o", type=Path, required=True,
                        help="Output file path")
    parser.add_argument("--sources",
                        default=",".join(DEFAULT_SOURCES),
                        help=(f"Comma-separated query IDs to include "
                              f"(default: {','.join(DEFAULT_SOURCES)})"))
    parser.add_argument("--dry-run", action="store_true",
                        help="Print what would be written; do not write")
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {TOOL_VERSION}")

    args = parser.parse_args(argv)

    bundle_dir = args.bundle_dir.resolve()
    if not bundle_dir.is_dir():
        print(f"ERROR: bundle directory not found: {bundle_dir}",
              file=sys.stderr)
        return 1

    sources = [s.strip() for s in args.sources.split(",") if s.strip()]
    manifest, files = read_bundle(bundle_dir)

    if not files:
        print("WARN: no known query CSV files found in bundle", file=sys.stderr)

    if args.format == "ocsf":
        return export_ocsf(manifest, files, sources, args.output, args.dry_run)
    return export_sentinel(manifest, files, sources, args.output, args.dry_run)


if __name__ == "__main__":
    sys.exit(main() or 0)
