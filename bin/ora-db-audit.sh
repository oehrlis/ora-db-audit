#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# ------------------------------------------------------------------------------
# OraDBA - Oracle Database Infrastructure and Security, 5630 Muri, Switzerland
# ------------------------------------------------------------------------------
# Name.......: ora-db-audit.sh
# Author.....: Stefan Oehrli (oes) stefan.oehrli@oradba.ch
# Editor.....: Stefan Oehrli
# Date.......: 2026.05.28
# Version....: 0.2.0
# Purpose....: Extract Oracle Unified Audit Trail data from a target database,
#              produce a self-contained CSV bundle, optionally anonymise it,
#              and render a Markdown analysis report. Designed to be executed
#              on the customer database server by the DBA.
# Notes......: Requires sqlplus in PATH (typical with a sourced ORACLE_HOME).
#              By default the raw CSV bundle contains real customer values
#              and must be anonymised before sharing. Pass --anonymize to
#              run tools/anonymize_bundle.py against the bundle right after
#              generation (sibling .anon/ + .mapping.json + .anon.tar.gz).
#              Pass --report to also render a Markdown analysis report
#              (tools/audit_report.py) - rendered against the anonymised
#              bundle if --anonymize is set, otherwise against the raw one.
# Usage......: ./ora-db-audit.sh [--days N] [--top-n N]
#                                [--connect "CONN"] [--output DIR]
#                                [--anonymize] [--customer-prefix P]
#                                [--report] [--patterns FILE]
#                                [--tools-dir DIR]
#                                [--dry-run] [--yes] [--help]
# Reference..: https://github.com/oehrlis/ora-db-audit
# License....: Apache License Version 2.0, January 2004 as shown
#              at http://www.apache.org/licenses/
# ------------------------------------------------------------------------------
# CHANGE LOG:
# 2026.05.28  oes  Initial release (port from audit_pack-0.5.0)         0.2.0
# ------------------------------------------------------------------------------

set -euo pipefail

# ------------------------------------------------------------------------------
# Defaults
# ------------------------------------------------------------------------------
DAYS=30
TOP_N=100
CONNECT="/ as sysdba"
PDB=""
OUTPUT_DIR="${PWD}/audit_bundle"
DRY_RUN=0
ASSUME_YES=0
ANONYMIZE=0
DEANONYMIZE=0
MAPPING_FILE=""
CUSTOMER_PREFIX=""
REPORT=0
PATTERNS_FILE=""
TOOLS_DIR_OVERRIDE=""
FROM_BUNDLE=""
AI=0
AI_MODEL="claude-sonnet-4-6"
AI_OP_PATH=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Repo root = one level up (bin/ -> repo).
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Query files - executed in this order (00 = setup).
QUERIES=(
    "00-setup.sql"
    "01-config.sql"
    "02-storage.sql"
    "03-policy-inventory.sql"
    "04-policy-volume.sql"
    "05-policy-user-action.sql"
    "06-policy-client-program.sql"
    "07-policy-host.sql"
    "08-top-users.sql"
    "09-top-actions.sql"
    "10-top-objects.sql"
    "11-host-user-program.sql"
    "12-distinct-hosts.sql"
    "13-failed-logins.sql"
    "14-privileged-activity.sql"
    "15-noise-candidates.sql"
    "16-policy-ddl.sql"
    "17-cis-coverage.sql"
    "18-audit-roles.sql"
)

# ------------------------------------------------------------------------------
# usage - print help and exit
# ------------------------------------------------------------------------------
usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Run Oracle Unified Audit Trail extraction against the local DB and bundle
the CSV output for off-line analysis.

Options:
  --days N             Time window in days (default: ${DAYS})
  --top-n N            Top N rows per query (default: ${TOP_N})
  --connect "CONN"     sqlplus connect string (default: "${CONNECT}")
                       Examples: "/ as sysdba"
                                 "auditadmin/secret@ISC"
                                 "/@ISC_AUDIT" (with wallet)
  --pdb NAME           Switch to PDB NAME after connect via
                       ALTER SESSION SET CONTAINER. Required for
                       SYSDBA connects when querying a PDB.
  --output DIR         Output directory (default: ${OUTPUT_DIR})
                       A subdir ora-db-audit_<DBSID>_<TS> is created.
  --anonymize          Run tools/anonymize_bundle.py against the bundle
                       after generation. Produces sibling .anon/ +
                       .mapping.json + .anon.tar.gz. Mapping file MUST
                       stay local - it contains real customer values.
  --deanonymize        After report generation, run tools/deanonymize_report.py
                       to restore real values in the report files.
                       Requires .mapping.json next to the bundle, or
                       combine with --mapping to specify it explicitly.
                       Output: *.deanon.md alongside original reports.
                       SECURITY: output contains real data - keep LOCAL.
  --mapping FILE       Explicit path to the .mapping.json file.
                       Only used with --deanonymize.
  --customer-prefix P  Customer-namespace prefix kept visible during
                       anonymisation (default: empty (no namespace prefix)).
                       Only used with --anonymize.
  --report             Render audit_report.md from the bundle (via
                       tools/audit_report.py). When combined with
                       --anonymize the report runs on the anonymised
                       bundle and is safe to share externally.
  --patterns FILE      Host-pattern config (JSON) for the report. Keys:
                       app_host_patterns, infra_host_patterns,
                       dba_host_patterns. Only used with --report.
  --tools-dir DIR      Path to the python helper tools
                       (anonymize_bundle.py, audit_report.py).
                       Default search order:
                         1. \$AUDIT_PACK_TOOLS env var
                         2. <script-dir>/tools/  (self-contained pack)
                         3. <repo-root>/tools/   (repo layout)
                       Required when --anonymize or --report is used.
  --from-bundle FILE   Offline mode: extract an existing bundle .tar.gz
                       instead of running a sqlplus data collection.
                       Use with --report [--ai] to (re-)generate reports.
                       No database connection required.
  --ai                 Generate AI findings via Claude API after the
                       Markdown report (implies --report).
                       Requires 'anthropic' Python package.
                       API key: ANTHROPIC_API_KEY env var or --ai-op-path.
  --ai-model MODEL     Claude model (default: claude-sonnet-4-6).
  --ai-op-path PATH    1Password op:// path for the Anthropic API key.
                       Used when ANTHROPIC_API_KEY is not set.
                       Example: op://Private/Anthropic/credential
  --dry-run            Print actions, do not execute
  --yes,-y             Overwrite existing output without prompting
  --help               Show this help

The bundle directory contains:
  <NN>-<query>.csv     one CSV per query, with metadata + schema preamble
  manifest.json        bundle metadata (DBSID, time window, query list)
  README.md            included for the analyst

After completion the directory is tarred to <bundle>.tar.gz next to it.
EOF
    exit 0
}

# ------------------------------------------------------------------------------
# log - timestamped stderr message
# ------------------------------------------------------------------------------
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >&2
}

err() {
    echo "ERROR: $*" >&2
}

# ------------------------------------------------------------------------------
# parse_args - parse command-line arguments
# ------------------------------------------------------------------------------
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --days)     DAYS="$2"; shift 2 ;;
            --top-n)    TOP_N="$2"; shift 2 ;;
            --connect)  CONNECT="$2"; shift 2 ;;
            --pdb)      PDB="$2"; shift 2 ;;
            --output)           OUTPUT_DIR="$2"; shift 2 ;;
            --anonymize)        ANONYMIZE=1; shift ;;
            --deanonymize)      DEANONYMIZE=1; shift ;;
            --mapping)          MAPPING_FILE="$2"; shift 2 ;;
            --customer-prefix)  CUSTOMER_PREFIX="$2"; shift 2 ;;
            --report)           REPORT=1; shift ;;
            --patterns)         PATTERNS_FILE="$2"; shift 2 ;;
            --tools-dir)        TOOLS_DIR_OVERRIDE="$2"; shift 2 ;;
            --from-bundle)  FROM_BUNDLE="$2"; shift 2 ;;
            --ai)           AI=1; shift ;;
            --ai-model)     AI_MODEL="$2"; shift 2 ;;
            --ai-op-path)   AI_OP_PATH="$2"; shift 2 ;;
            --dry-run)      DRY_RUN=1; shift ;;
            --yes|-y)       ASSUME_YES=1; shift ;;
            --help|-h)      usage ;;
            *)              err "unknown option: $1"; exit 2 ;;
        esac
    done

    if ! [[ "${DAYS}" =~ ^[0-9]+$ ]]; then
        err "--days must be a positive integer (got: ${DAYS})"
        exit 2
    fi
    if ! [[ "${TOP_N}" =~ ^[0-9]+$ ]]; then
        err "--top-n must be a positive integer (got: ${TOP_N})"
        exit 2
    fi
}

# ------------------------------------------------------------------------------
# preflight - verify sqlplus availability and connectivity
# ------------------------------------------------------------------------------
preflight() {
    if ! command -v sqlplus >/dev/null 2>&1; then
        err "sqlplus not found in PATH. Source the Oracle environment first."
        exit 1
    fi

    for q in "${QUERIES[@]}"; do
        if [[ ! -f "${SCRIPT_DIR}/${q}" ]]; then
            err "missing query file: ${SCRIPT_DIR}/${q}"
            exit 1
        fi
    done

    log "preflight: sqlplus available, ${#QUERIES[@]} query files found"
}

# ------------------------------------------------------------------------------
# get_dbsid - resolve DBSID via sqlplus to build the bundle directory name
# ------------------------------------------------------------------------------
get_dbsid() {
    sqlplus -S -L "${CONNECT}" <<'SQL' 2>/dev/null | tr -d '[:space:]'
SET HEADING OFF FEEDBACK OFF PAGESIZE 0
SELECT LOWER(SYS_CONTEXT('USERENV','INSTANCE_NAME')) FROM dual;
EXIT
SQL
}

# ------------------------------------------------------------------------------
# write_manifest - small manifest.json next to the CSVs
# ------------------------------------------------------------------------------
write_manifest() {
    local bundle_dir="$1" dbsid="$2" ts="$3"
    cat > "${bundle_dir}/manifest.json" <<EOF
{
  "bundle_version": "0.2.0",
  "generated_at":   "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
  "dbsid":          "${dbsid}",
  "timestamp_tag":  "${ts}",
  "time_window_days": ${DAYS},
  "top_n":          ${TOP_N},
  "queries": [
$(printf '    "%s",\n' "${QUERIES[@]:1}" | sed '$ s/,$//')
  ],
  "tool":           "ora-db-audit.sh",
  "tool_version":   "0.2.0"
}
EOF
}

# ------------------------------------------------------------------------------
# write_readme - human-readable note inside the bundle
# ------------------------------------------------------------------------------
write_readme() {
    local bundle_dir="$1" dbsid="$2"
    cat > "${bundle_dir}/README.md" <<EOF
# Audit Analysis Bundle

| Field      | Value |
|------------|-------|
| DBSID      | \`${dbsid}\` |
| Generated  | $(date '+%Y-%m-%d %H:%M:%S %Z') |
| Time Window| last ${DAYS} days |
| Top N      | ${TOP_N} rows per query |

## Files

Each CSV is pipe-delimited (\`|\`) with a metadata preamble:

\`\`\`text
# query: <name>
# query_id: <NN>
# dbsid: <sid>
# pdb: <pdb>
# generated: <iso-timestamp>
# date_range_days: <days>
# top_n: <n>
# schema: col1=KEEP|col2=PSEUDO:HOST|col3=COUNT|...
<column-headers>
<data rows>
\`\`\`

The \`# schema:\` line tells the column-aware anonymiser exactly which
columns to pseudonymise. Type-hints:

- **KEEP** - copy as-is (policy names, action names, Oracle defaults)
- **PSEUDO:HOST / DBUSER / OSUSER / SCHEMA / OBJECT / CLIENT** - replace
  with deterministic pseudonyms across the whole bundle
- **COUNT, TIMESTAMP, BYTES** - numeric/temporal, copy as-is
- **REDACT** - mask completely (free-text fields)

## Bundle contains REAL customer values

This raw bundle has not been anonymised. Run
\`tools/anonymize_bundle.py\` before sharing externally.
EOF
}

# ------------------------------------------------------------------------------
# resolve_tools_dir - locate the python helper tools directory
#   Order: --tools-dir > $AUDIT_PACK_TOOLS > <script-dir>/tools > <repo-root>/tools
# Prints absolute path on success, non-zero exit otherwise.
# ------------------------------------------------------------------------------
resolve_tools_dir() {
    local marker="anonymize_bundle.py"
    local -a candidates=()

    if [[ -n "${TOOLS_DIR_OVERRIDE}" ]]; then
        candidates+=( "${TOOLS_DIR_OVERRIDE}" )
    fi
    if [[ -n "${AUDIT_PACK_TOOLS:-}" ]]; then
        candidates+=( "${AUDIT_PACK_TOOLS}" )
    fi
    candidates+=( "${SCRIPT_DIR}/tools" )
    candidates+=( "${REPO_ROOT}/tools" )

    local dir
    for dir in "${candidates[@]}"; do
        if [[ -f "${dir}/${marker}" ]]; then
            (cd "${dir}" && pwd)
            return 0
        fi
    done

    err "could not find ${marker} - searched:"
    for dir in "${candidates[@]}"; do
        err "  ${dir}"
    done
    err "fix one of:"
    err "  - pass --tools-dir DIR"
    err "  - export AUDIT_PACK_TOOLS=/path/to/tools"
    err "  - run from a self-contained pack (make dist)"
    return 1
}

# ------------------------------------------------------------------------------
# resolve_python - pick a Python 3 interpreter, preferring $ORACLE_HOME/python
# ------------------------------------------------------------------------------
resolve_python() {
    local candidate
    if [[ -n "${ORACLE_HOME:-}" && -x "${ORACLE_HOME}/python/bin/python" ]]; then
        candidate="${ORACLE_HOME}/python/bin/python"
    elif command -v python3 >/dev/null 2>&1; then
        candidate="$(command -v python3)"
    elif command -v python >/dev/null 2>&1; then
        candidate="$(command -v python)"
    else
        return 1
    fi
    # Require Python 3.6+
    if ! "${candidate}" -c "import sys; sys.exit(0 if sys.version_info >= (3,6) else 1)" 2>/dev/null; then
        local ver
        ver="$("${candidate}" --version 2>&1)"
        err "Python 3.6 or later required, found: ${ver}"
        return 1
    fi
    echo "${candidate}"
}

# ------------------------------------------------------------------------------
# anonymize_bundle - run tools/anonymize_bundle.py against the bundle dir
# ------------------------------------------------------------------------------
anonymize_bundle() {
    local bundle_dir="$1"
    local tools_dir
    if ! tools_dir="$(resolve_tools_dir)"; then
        return 1
    fi
    local script="${tools_dir}/anonymize_bundle.py"

    local python_bin
    if ! python_bin="$(resolve_python)"; then
        err "no python3 interpreter found (set ORACLE_HOME or install python3)"
        return 1
    fi

    log "anonymising bundle with ${python_bin} (tools: ${tools_dir})..."
    "${python_bin}" "${script}" \
        "${bundle_dir}" \
        --customer-prefix "${CUSTOMER_PREFIX}" \
        --yes
}

# ------------------------------------------------------------------------------
# render_report - run tools/audit_report.py against the bundle dir
# ------------------------------------------------------------------------------
render_report() {
    local bundle_dir="$1"
    local tools_dir
    if ! tools_dir="$(resolve_tools_dir)"; then
        return 1
    fi
    local script="${tools_dir}/audit_report.py"

    local python_bin
    if ! python_bin="$(resolve_python)"; then
        err "no python3 interpreter found (set ORACLE_HOME or install python3)"
        return 1
    fi

    local -a report_args=( "${bundle_dir}" --yes )
    if [[ -n "${PATTERNS_FILE}" ]]; then
        if [[ ! -f "${PATTERNS_FILE}" ]]; then
            err "--patterns file not found: ${PATTERNS_FILE}"
            return 1
        fi
        report_args+=( --patterns "${PATTERNS_FILE}" )
    fi
    if [[ ${AI} -eq 1 ]]; then
        report_args+=( --ai --ai-model "${AI_MODEL}" )
        if [[ -n "${AI_OP_PATH}" ]]; then
            report_args+=( --ai-op-path "${AI_OP_PATH}" )
        fi
    fi

    log "rendering report with ${python_bin} (tools: ${tools_dir})..."
    "${python_bin}" "${script}" "${report_args[@]}"
}

# ------------------------------------------------------------------------------
# deanonymize_report - restore real values in report .md files
# Uses deanonymize_report.py with the .mapping.json next to the bundle,
# or MAPPING_FILE if set explicitly via --mapping.
# ------------------------------------------------------------------------------
deanonymize_report() {
    local bundle_dir="$1"
    local tools_dir
    if ! tools_dir="$(resolve_tools_dir)"; then
        return 1
    fi
    local script="${tools_dir}/deanonymize_report.py"
    if [[ ! -f "${script}" ]]; then
        err "deanonymize_report.py not found in tools dir: ${tools_dir}"
        return 1
    fi

    local python_bin
    if ! python_bin="$(resolve_python)"; then
        err "no python3 interpreter found"
        return 1
    fi

    local -a deanon_args=( "${bundle_dir}" --yes )
    if [[ -n "${MAPPING_FILE}" ]]; then
        deanon_args+=( --mapping "${MAPPING_FILE}" )
    fi

    log "de-anonymising reports in ${bundle_dir}..."
    "${python_bin}" "${script}" "${deanon_args[@]}"
    log "SECURITY: .deanon.md files contain real customer data - keep LOCAL."
}

# ------------------------------------------------------------------------------
# extract_bundle - extract a .tar.gz bundle to OUTPUT_DIR
# Prints the extracted directory path on stdout.
# ------------------------------------------------------------------------------
extract_bundle() {
    local bundle_tar="$1"
    if [[ ! -f "${bundle_tar}" ]]; then
        err "bundle not found: ${bundle_tar}"
        return 1
    fi
    mkdir -p "${OUTPUT_DIR}"
    log "extracting ${bundle_tar} -> ${OUTPUT_DIR}/"
    tar xzf "${bundle_tar}" -C "${OUTPUT_DIR}"
    local bundle_name="${bundle_tar##*/}"
    bundle_name="${bundle_name%.tar.gz}"
    local extracted="${OUTPUT_DIR}/${bundle_name}"
    if [[ ! -d "${extracted}" ]]; then
        err "expected directory not found after extraction: ${extracted}"
        err "ensure the .tar.gz contains a top-level directory named: ${bundle_name}"
        return 1
    fi
    echo "${extracted}"
}

# ------------------------------------------------------------------------------
# run_from_bundle - offline mode: extract existing bundle and run post-processing
# Skips sqlplus entirely. Supports --anonymize, --report (implied by --ai), --ai.
# ------------------------------------------------------------------------------
run_from_bundle() {
    log "offline mode: --from-bundle ${FROM_BUNDLE}"
    log "config: output=${OUTPUT_DIR}"

    if [[ ${DRY_RUN} -eq 1 ]]; then
        log "dry-run: would extract ${FROM_BUNDLE} -> ${OUTPUT_DIR}/"
        [[ ${ANONYMIZE} -eq 1 ]] && log "dry-run: would anonymise bundle"
        [[ ${REPORT} -eq 1 ]] && log "dry-run: would render report"
        [[ ${AI} -eq 1 ]] && log "dry-run: would call Claude API (model: ${AI_MODEL})"
        [[ ${DEANONYMIZE} -eq 1 ]] && log "dry-run: would de-anonymise report .md files"
        return 0
    fi

    local bundle_dir
    if ! bundle_dir="$(extract_bundle "${FROM_BUNDLE}")"; then
        return 1
    fi
    log "bundle dir = ${bundle_dir}"

    local report_target="${bundle_dir}"
    if [[ ${ANONYMIZE} -eq 1 ]]; then
        anonymize_bundle "${bundle_dir}"
        log "anonymised outputs next to ${bundle_dir}"
        log "reminder: keep <bundle>.mapping.json LOCAL."
        if [[ -d "${bundle_dir}.anon" ]]; then
            report_target="${bundle_dir}.anon"
        fi
    fi

    if [[ ${REPORT} -eq 1 ]]; then
        render_report "${report_target}"
        log "report rendered into ${report_target}/audit_report.md"
        if [[ ${AI} -eq 1 ]]; then
            log "AI findings appended into ${report_target}/audit_report.md"
            log "standalone: ${report_target}/audit_ai_findings.md"
        fi
    fi

    if [[ ${DEANONYMIZE} -eq 1 ]]; then
        deanonymize_report "${report_target}"
    fi
}

# ------------------------------------------------------------------------------
# run - execute the queries in one sqlplus session
# ------------------------------------------------------------------------------
run() {
    parse_args "$@"

    # --ai implies --report
    if [[ ${AI} -eq 1 ]]; then
        REPORT=1
    fi

    # Offline mode: skip data collection entirely
    if [[ -n "${FROM_BUNDLE}" ]]; then
        run_from_bundle
        return $?
    fi

    log "config: days=${DAYS} top_n=${TOP_N} connect='${CONNECT}' pdb='${PDB:-(none)}'"
    log "config: output=${OUTPUT_DIR}"

    preflight

    if [[ ${DRY_RUN} -eq 1 ]]; then
        log "dry-run: would query DBSID, then execute the following:"
        for q in "${QUERIES[@]}"; do
            log "  @${SCRIPT_DIR}/${q}"
        done
        log "dry-run: bundle would land in ${OUTPUT_DIR}/ora-db-audit_<DBSID>_<TS>/"
        return 0
    fi

    log "resolving DBSID via sqlplus..."
    local dbsid
    dbsid="$(get_dbsid)"
    if [[ -z "${dbsid}" ]]; then
        err "could not resolve DBSID (sqlplus connection failed?)"
        exit 1
    fi
    log "DBSID = ${dbsid}"

    local ts bundle_dir
    ts="$(date '+%Y%m%d_%H%M%S')"
    bundle_dir="${OUTPUT_DIR}/ora-db-audit_${dbsid}_${ts}"

    if [[ -d "${bundle_dir}" ]]; then
        if [[ ${ASSUME_YES} -eq 0 ]]; then
            read -r -p "Overwrite existing ${bundle_dir}? [y/N] " ans
            [[ "${ans}" == "y" || "${ans}" == "Y" ]] || { err "aborted."; exit 1; }
        fi
        rm -rf "${bundle_dir}"
    fi
    mkdir -p "${bundle_dir}"
    log "bundle dir = ${bundle_dir}"

    # Export parameters for setup.sql to read.
    export ORADBA_LOG="${bundle_dir}"
    export ORADBA_DAYS="${DAYS}"
    export ORADBA_TOP_N="${TOP_N}"
    export ORADBA_PDB="${PDB}"

    # Build the @-chain. Setup must be the first script.
    local -a sqlplus_cmds=()
    for q in "${QUERIES[@]}"; do
        sqlplus_cmds+=( "@${SCRIPT_DIR}/${q}" )
    done
    sqlplus_cmds+=( "EXIT" )

    log "running sqlplus session with ${#QUERIES[@]} scripts..."
    printf '%s\n' "${sqlplus_cmds[@]}" \
        | sqlplus -S -L "${CONNECT}" \
        | tee "${bundle_dir}/_sqlplus.log"

    # Quick sanity-check: did each query produce a CSV?
    local missing=0
    for q in "${QUERIES[@]:1}"; do
        local csv="${bundle_dir}/${q%.sql}.csv"
        if [[ ! -s "${csv}" ]]; then
            err "missing or empty output: ${csv}"
            missing=$((missing + 1))
        fi
    done
    if (( missing > 0 )); then
        err "${missing} query output(s) missing - check ${bundle_dir}/_sqlplus.log"
    fi

    write_manifest "${bundle_dir}" "${dbsid}" "${ts}"
    write_readme   "${bundle_dir}" "${dbsid}"

    log "creating tarball..."
    (cd "${OUTPUT_DIR}" && tar czf "ora-db-audit_${dbsid}_${ts}.tar.gz" \
        "ora-db-audit_${dbsid}_${ts}")
    log "bundle tarball: ${OUTPUT_DIR}/ora-db-audit_${dbsid}_${ts}.tar.gz"

    local sz
    sz=$(du -h "${OUTPUT_DIR}/ora-db-audit_${dbsid}_${ts}.tar.gz" | cut -f1)
    log "bundle size: ${sz}"

    local report_target="${bundle_dir}"
    if [[ ${ANONYMIZE} -eq 1 ]]; then
        anonymize_bundle "${bundle_dir}"
        log "anonymised outputs next to ${bundle_dir}"
        log "reminder: keep <bundle>.mapping.json LOCAL."
        # When the anonymised bundle exists, prefer it for the report
        # so the rendered file is safe to share externally.
        if [[ -d "${bundle_dir}.anon" ]]; then
            report_target="${bundle_dir}.anon"
        fi
    else
        log "done. Reminder: bundle contains real customer values - "
        log "          run with --anonymize or call tools/anonymize_bundle.py"
        log "          before sharing externally."
    fi

    if [[ ${REPORT} -eq 1 ]]; then
        render_report "${report_target}"
        log "report rendered into ${report_target}/audit_report.md"
        if [[ ${AI} -eq 1 ]]; then
            log "AI findings appended into ${report_target}/audit_report.md"
            log "standalone: ${report_target}/audit_ai_findings.md"
        fi
    fi

    if [[ ${DEANONYMIZE} -eq 1 ]]; then
        deanonymize_report "${report_target}"
    fi
}

run "$@"
# --- EOF ----------------------------------------------------------------------
