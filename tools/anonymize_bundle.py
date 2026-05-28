#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# ------------------------------------------------------------------------------
# OraDBA - Oracle Database Infrastructure and Security, 5630 Muri, Switzerland
# ------------------------------------------------------------------------------
# Name.......: anonymize_bundle.py
# Author.....: Stefan Oehrli (oes) stefan.oehrli@oradba.ch
# Editor.....: Stefan Oehrli
# Date.......: 2026.05.28
# Version....: 0.2.0
# Purpose....: Column-aware anonymiser for ora-db-audit CSV bundles. Each
#              CSV carries a "# schema: col=TYPE_HINT|..." preamble line;
#              this tool parses that hint and pseudonymises only the columns
#              that ask for it. The resulting mapping is shared across all
#              CSVs in the bundle - HOST_001 is the same host everywhere.
# Notes......: Type hints supported:
#                KEEP                          copy as-is
#                PSEUDO:HOST | DBUSER | OSUSER
#                        | CLIENT | SCHEMA
#                        | OBJECT              pseudonymise per category
#                COUNT | TIMESTAMP | BYTES     copy as-is (numeric / temporal)
#                REDACT                        replace non-empty value with
#                                             "[REDACTED]"
#
#              Cross-category dedup: a value that appears in DBUSER and
#              OSUSER gets exactly one pseudonym (first category in fixed
#              priority order wins).
#
#              Whitelist re-uses ORACLE_USERS / ORACLE_SCHEMA_PREFIXES /
#              ORACLE_OBJECT_PREFIXES / FQDN_WHITELIST / CLIENT_WHITELIST /
#              PLACEHOLDER_VALUES from anonymize_audit_log.py.
#
#              Input may be an unpacked bundle directory or a .tar.gz; in
#              both cases output is written next to the original input:
#                <bundle>.anon/        anonymised bundle (sibling dir)
#                <bundle>.mapping.json reverse-lookup (KEEP LOCAL)
#                <bundle>.anon.tar.gz  shippable tarball
#
# Usage......: anonymize_bundle.py INPUT [--load-mapping FILE]
#                                   [--customer-prefix PREFIX]
#                                   [--whitelist FILE]
#                                   [--no-tar] [--dry-run] [--yes]
#                                   [--verbose]
#
# License....: Apache License Version 2.0, January 2004 as shown
#              at http://www.apache.org/licenses/
# ------------------------------------------------------------------------------
# CHANGE LOG:
# 2026.05.28  oes  Sanitised port from audit_pack-0.5.0                   0.2.0
# ------------------------------------------------------------------------------

import argparse
import csv
import datetime as _dt
import io
import json
import shutil
import sys
import tarfile
import tempfile
from collections import defaultdict
from pathlib import Path

# Re-use whitelist + ambiguity logic from the spool-file anonymiser. Both
# tools must classify identical strings the same way (CIS user lists,
# Oracle-supplied prefixes, customer prefix, placeholder values).
_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))
from anonymize_audit_log import (  # noqa: E402
    is_ambiguous,
    is_whitelisted,
    ORACLE_USERS as _ORACLE_USERS,
)

# Oracle-supplied schemas whose objects must not be pseudonymised.
# When a row has a companion object_schema / owner column whose value
# is in this set, PSEUDO:OBJECT columns are kept verbatim.
ORACLE_SYSTEM_SCHEMAS = _ORACLE_USERS | {
    "SYS", "AUDSYS", "SYSTEM", "DBSNMP", "XDB", "WMSYS", "CTXSYS",
    "ORDSYS", "MDSYS", "LBACSYS", "DVSYS", "DVF", "OJVMSYS",
    "SYS$UMF", "OUTLN",
}


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Fixed priority order for pseudonym assignment when a value appears in
# multiple PSEUDO categories. First category in this list wins, the value
# is reused as-is for subsequent categories (cross-category dedup).
CATEGORY_ORDER = ("HOST", "DBUSER", "OSUSER", "CLIENT", "SCHEMA", "OBJECT")

# Type hints valid in a "# schema:" line. Anything else triggers a warning
# (we keep the column unchanged to avoid data loss).
VALID_KEEP_TYPES = {"KEEP", "COUNT", "TIMESTAMP", "BYTES", "TABLESPACE_STATE"}
VALID_PSEUDO_TYPES = {f"PSEUDO:{c}" for c in CATEGORY_ORDER}
VALID_TYPES = VALID_KEEP_TYPES | VALID_PSEUDO_TYPES | {"REDACT"}

# Token written into REDACT cells. Kept short so the redacted bundle stays
# diff-friendly against the original.
REDACTED_TOKEN = "[REDACTED]"

# Default customer prefix for KEEP namespace (mirrors anonymize_audit_log.py).
DEFAULT_CUSTOMER_PREFIX = ""

# Schema-preamble marker.
SCHEMA_PREFIX = "# schema:"


# ---------------------------------------------------------------------------
# Schema parsing
# ---------------------------------------------------------------------------

def parse_schema_line(line):
    """Parse '# schema: col1=KEEP|col2=PSEUDO:HOST|...' into a list of
    (column-name, type-hint) tuples in column order.

    The schema line drives every downstream decision. A missing or
    malformed schema line is a hard error.
    """
    body = line[len(SCHEMA_PREFIX):].strip()
    if not body:
        raise ValueError("empty schema body")
    cols = []
    for spec in body.split("|"):
        spec = spec.strip()
        if not spec:
            continue
        name, _, hint = spec.partition("=")
        name = name.strip()
        hint = hint.strip()
        if not name or not hint:
            raise ValueError(f"malformed schema spec: {spec!r}")
        if hint not in VALID_TYPES:
            # Unknown hint -> safe default: do not touch the column.
            print(
                f"WARN: unknown schema type {hint!r} for column "
                f"{name!r} - treating as KEEP",
                file=sys.stderr,
            )
            hint = "KEEP"
        cols.append((name, hint))
    if not cols:
        raise ValueError("schema line declared no columns")
    return cols


def split_preamble(lines):
    """Split a CSV file into (comment-preamble, data-lines).

    Comment lines (start with '#') and blank lines before the first data
    row form the preamble. The data section starts at the first line that
    is not a comment.
    """
    preamble = []
    data_start = 0
    for i, line in enumerate(lines):
        stripped = line.lstrip()
        if stripped.startswith("#") or not stripped:
            preamble.append(line)
            data_start = i + 1
            continue
        data_start = i
        break
    return preamble, lines[data_start:]


def find_schema_line(preamble):
    """Locate the '# schema:' line in a preamble. Returns the raw line
    (with whitespace stripped) or None if not found."""
    for line in preamble:
        s = line.strip()
        if s.startswith(SCHEMA_PREFIX):
            return s
    return None


# ---------------------------------------------------------------------------
# Collection pass
# ---------------------------------------------------------------------------

def _csv_rows(data_lines):
    """Yield (header_row, data_row_iter) for a CSV body. The first row is
    the column-header line emitted by SQL*Plus (with or without quotes,
    depending on QUOTE ON/OFF). csv.reader transparently handles both."""
    reader = csv.reader(io.StringIO("".join(data_lines)), delimiter="|")
    rows = list(reader)
    if not rows:
        return None, []
    return rows[0], rows[1:]


def collect_values(csv_files):
    """First pass over all CSV files in the bundle. Returns:

      collected: dict[category] -> set(values)
      file_meta: dict[path] -> (preamble_lines, schema_cols, header_row,
                                data_rows)
    """
    collected = defaultdict(set)
    file_meta = {}

    for path in csv_files:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
        lines = text.splitlines(keepends=True)
        preamble, data_lines = split_preamble(lines)

        schema_line = find_schema_line(preamble)
        if not schema_line:
            print(f"WARN: {path.name} has no '# schema:' line - skipped",
                  file=sys.stderr)
            continue

        try:
            schema_cols = parse_schema_line(schema_line)
        except ValueError as e:
            print(f"ERROR: {path.name} schema parse failed: {e}",
                  file=sys.stderr)
            continue

        header_row, data_rows = _csv_rows(data_lines)
        if header_row is None:
            # Empty data section - still record the meta so we copy the
            # preamble through unchanged.
            file_meta[path] = (preamble, schema_cols, None, [])
            continue

        # Per-column harvest.
        for row in data_rows:
            for i, (_name, hint) in enumerate(schema_cols):
                if i >= len(row):
                    break
                if not hint.startswith("PSEUDO:"):
                    continue
                category = hint.split(":", 1)[1]
                value = row[i].strip()
                if not value:
                    continue
                collected[category].add(value)

        file_meta[path] = (preamble, schema_cols, header_row, data_rows)

    return collected, file_meta


# ---------------------------------------------------------------------------
# Mapping build
# ---------------------------------------------------------------------------

def build_mapping(collected, customer_prefix, extra_whitelist,
                  existing=None):
    """Assign deterministic pseudonyms.

    Cross-category dedup: a value already mapped under category A keeps
    that pseudonym when it appears later under category B. CATEGORY_ORDER
    defines the priority.

    Returns:
        mapping: dict[value] -> pseudonym
        stats:   dict[category] -> [kept, anonymised, ambiguous]
        ambiguous_samples: dict[category] -> [sample values]
    """
    mapping = dict(existing or {})

    used_indices = defaultdict(set)
    for pseudo in mapping.values():
        if "_" in pseudo:
            cat, idx = pseudo.rsplit("_", 1)
            if idx.isdigit():
                used_indices[cat].add(int(idx))

    stats = {cat: [0, 0, 0] for cat in CATEGORY_ORDER}
    ambiguous_samples = defaultdict(list)

    for category in CATEGORY_ORDER:
        values = sorted(collected.get(category, set()))
        for value in values:
            if value in mapping:
                # Already mapped (possibly in an earlier category).
                continue
            if is_ambiguous(value, category):
                stats[category][2] += 1
                if len(ambiguous_samples[category]) < 5:
                    ambiguous_samples[category].append(value)
                continue
            if is_whitelisted(value, category, customer_prefix,
                              extra_whitelist):
                stats[category][0] += 1
                continue
            idx = 1
            while idx in used_indices[category]:
                idx += 1
            used_indices[category].add(idx)
            mapping[value] = f"{category}_{idx:03d}"
            stats[category][1] += 1

    return mapping, stats, dict(ambiguous_samples)


# ---------------------------------------------------------------------------
# Apply pass
# ---------------------------------------------------------------------------

def _schema_for_object_col(i, schema_cols, row):
    """Return the schema/owner value from the companion column for a
    PSEUDO:OBJECT column at position i, or None if no companion exists.

    Looks for a column named 'object_schema' or 'owner' in schema_cols.
    """
    for j, (col_name, _hint) in enumerate(schema_cols):
        if col_name.lower() in ("object_schema", "owner"):
            if j < len(row):
                return row[j].strip().upper()
    return None


def anonymise_row(row, schema_cols, mapping):
    """Return a new row with PSEUDO columns substituted and REDACT
    columns masked. KEEP / COUNT / TIMESTAMP / BYTES columns pass through
    unchanged.

    PSEUDO:OBJECT is context-aware: if the row's companion schema column
    (object_schema / owner) resolves to an Oracle system schema, the
    object name is kept verbatim to avoid pseudonymising SYS.DUAL,
    AUDSYS packages, etc.
    """
    out = list(row)
    for i, (_name, hint) in enumerate(schema_cols):
        if i >= len(out):
            break
        value = out[i]
        if hint == "REDACT":
            if value.strip():
                out[i] = REDACTED_TOKEN
            continue
        if not hint.startswith("PSEUDO:"):
            continue
        stripped = value.strip()
        if not stripped:
            continue
        if hint == "PSEUDO:OBJECT":
            owner = _schema_for_object_col(i, schema_cols, out)
            if owner and owner in ORACLE_SYSTEM_SCHEMAS:
                continue
        pseudo = mapping.get(stripped)
        if pseudo is not None:
            # Preserve incidental leading/trailing whitespace from the
            # source. SQL*Plus rarely emits any, but stay faithful.
            prefix = value[:len(value) - len(value.lstrip())]
            suffix = value[len(value.rstrip()):]
            out[i] = f"{prefix}{pseudo}{suffix}"
    return out


def _emit_csv_text(header_row, data_rows, original_data_lines):
    """Render header + data rows back as a pipe-delimited CSV string.

    Quoting mode is inferred from the first non-empty original data line:
    if it starts with a double-quote, use QUOTE_ALL to match SQL*Plus
    QUOTE ON output; otherwise QUOTE_MINIMAL to match QUOTE OFF.
    """
    quote_all = False
    for line in original_data_lines:
        s = line.lstrip()
        if s:
            quote_all = s.startswith('"')
            break

    buf = io.StringIO()
    writer = csv.writer(
        buf,
        delimiter="|",
        quoting=csv.QUOTE_ALL if quote_all else csv.QUOTE_MINIMAL,
        lineterminator="\n",
    )
    if header_row is not None:
        writer.writerow(header_row)
    for row in data_rows:
        writer.writerow(row)
    return buf.getvalue()


def write_anonymised_csv(out_path, preamble, schema_cols, header_row,
                         data_rows, original_data_lines, mapping):
    """Write a single anonymised CSV file."""
    new_rows = [
        anonymise_row(row, schema_cols, mapping) for row in data_rows
    ]
    body = _emit_csv_text(header_row, new_rows, original_data_lines)
    out_path.write_text("".join(preamble) + body, encoding="utf-8")


# ---------------------------------------------------------------------------
# Bundle handling
# ---------------------------------------------------------------------------

def is_tarball(path: Path) -> bool:
    name = path.name.lower()
    return name.endswith(".tar.gz") or name.endswith(".tgz")


def extract_tarball(tar_path: Path, work_dir: Path) -> Path:
    """Extract a bundle tarball into work_dir. Returns the inner bundle
    directory (single top-level directory expected)."""
    with tarfile.open(tar_path, "r:gz") as tar:
        members = tar.getmembers()
        top = set()
        for m in members:
            parts = Path(m.name).parts
            if parts:
                top.add(parts[0])
        if len(top) != 1:
            raise ValueError(
                f"tarball {tar_path.name} expected one top-level "
                f"directory, found {sorted(top)}"
            )
        # Python 3.12+ requires 'filter' to suppress the deprecation
        # warning. 'data' refuses unsafe paths (absolute / outside dest).
        try:
            tar.extractall(work_dir, filter="data")
        except TypeError:  # Python < 3.12
            tar.extractall(work_dir)
        return work_dir / top.pop()


def derive_output_paths(input_path: Path, source_bundle_name: str):
    """Build sibling anon-dir / mapping / tarball paths next to the
    original input. The bundle stem comes from the source bundle dir name
    (so `.tar.gz` input still yields nicely named outputs)."""
    parent = input_path.parent
    anon_dir = parent / f"{source_bundle_name}.anon"
    mapping_path = parent / f"{source_bundle_name}.mapping.json"
    tarball_path = parent / f"{source_bundle_name}.anon.tar.gz"
    return anon_dir, mapping_path, tarball_path


def copy_non_csv(src: Path, dst: Path, *, anon_marker: str):
    """Copy auxiliary files (manifest.json, README.md) into the anon
    bundle, adding a short marker so consumers can tell raw from anon."""
    if src.name == "manifest.json":
        try:
            data = json.loads(src.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            shutil.copy2(src, dst)
            return
        data["anonymised_at"] = anon_marker
        data["anonymised_by"] = "anonymize_bundle.py"
        dst.write_text(
            json.dumps(data, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return
    if src.name == "README.md":
        text = src.read_text(encoding="utf-8")
        banner = (
            "\n\n> **Anonymised bundle** - generated by "
            f"`anonymize_bundle.py` at {anon_marker}.\n"
            "> Real values have been replaced with deterministic "
            "pseudonyms (HOST_NNN, DBUSER_NNN, ...).\n"
        )
        dst.write_text(text + banner, encoding="utf-8")
        return
    shutil.copy2(src, dst)


# Files that are excluded from the anonymised bundle entirely (raw logs
# may contain values that the column-aware pass cannot scrub safely).
SKIP_FILES = {"_sqlplus.log"}


# ---------------------------------------------------------------------------
# Mapping persistence
# ---------------------------------------------------------------------------

def load_mapping_file(path: Path):
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return data.get("mapping", {})


def save_mapping_file(path: Path, mapping, meta):
    payload = {
        "meta": meta,
        "mapping": dict(sorted(mapping.items())),
    }
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv):
    p = argparse.ArgumentParser(
        prog="anonymize_bundle.py",
        description=(
            "Column-aware anonymiser for ora-db-audit CSV bundles. "
            "Uses the '# schema:' hint line in each CSV to pseudonymise "
            "only the columns flagged PSEUDO:<category>, with a shared "
            "mapping across the whole bundle."
        ),
        epilog=(
            "Outputs are written next to the input:\n"
            "  <bundle>.anon/         anonymised bundle (directory)\n"
            "  <bundle>.mapping.json  reverse-lookup table (KEEP LOCAL)\n"
            "  <bundle>.anon.tar.gz   shippable tarball\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("input", type=Path,
                   help="Bundle directory or .tar.gz from ora-db-audit.sh.")
    p.add_argument("--load-mapping", type=Path,
                   help="Pre-load an existing mapping JSON to keep "
                        "pseudonyms stable across multiple bundles.")
    p.add_argument("--whitelist", type=Path,
                   help="Optional JSON file with a 'whitelist' array of "
                        "additional values to keep visible.")
    p.add_argument("--customer-prefix", default=DEFAULT_CUSTOMER_PREFIX,
                   help="Schema/object/user prefix to keep visible "
                        f"(default: {DEFAULT_CUSTOMER_PREFIX!r} - disabled). "
                        "Pass an explicit value to protect your prefix.")
    p.add_argument("--no-tar", action="store_true",
                   help="Skip the .anon.tar.gz archive (directory only).")
    p.add_argument("--dry-run", action="store_true",
                   help="Report stats only, do not write any files.")
    p.add_argument("--yes", "-y", action="store_true",
                   help="Overwrite existing outputs without prompting.")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="Print sample mappings per category.")
    return p.parse_args(argv)


def _confirm_overwrite(path: Path, assume_yes: bool) -> bool:
    if not path.exists() or assume_yes:
        return True
    answer = input(f"Overwrite {path}? [y/N] ").strip().lower()
    return answer == "y"


def _print_stats(stats, ambiguous_samples, verbose, mapping):
    print(f"{'Category':<10} {'kept':>8} {'anonymised':>12} {'ambiguous':>11}")
    print(f"{'-' * 10} {'-' * 8} {'-' * 12} {'-' * 11}")
    totals = [0, 0, 0]
    for cat in CATEGORY_ORDER:
        k, a, amb = stats.get(cat, (0, 0, 0))
        print(f"{cat:<10} {k:>8} {a:>12} {amb:>11}")
        totals[0] += k
        totals[1] += a
        totals[2] += amb
    print(f"{'-' * 10} {'-' * 8} {'-' * 12} {'-' * 11}")
    print(
        f"{'TOTAL':<10} {totals[0]:>8} {totals[1]:>12} {totals[2]:>11}"
    )
    if totals[2]:
        print("\n(ambiguous = numeric-only or too-short values left "
              "unchanged because they would collide with non-sensitive "
              "tokens elsewhere)")
        if verbose:
            for cat, samples in ambiguous_samples.items():
                if samples:
                    print(f"  [{cat}] sample ambiguous values: "
                          + ", ".join(repr(s) for s in samples))
    if verbose:
        for cat in CATEGORY_ORDER:
            samples = sorted(
                k for k, v in mapping.items() if v.startswith(cat + "_")
            )[:5]
            if samples:
                print(f"\n[{cat}] sample mappings:")
                for s in samples:
                    print(f"  {s!r} -> {mapping[s]}")


def main(argv=None):
    args = parse_args(argv)
    inp: Path = args.input.resolve()

    if not inp.exists():
        print(f"ERROR: input not found: {inp}", file=sys.stderr)
        return 2

    # Resolve source-bundle directory (either inp itself or extracted).
    tmp_root = None
    try:
        if inp.is_dir():
            bundle_dir = inp
            source_bundle_name = bundle_dir.name
            anchor = inp
        elif inp.is_file() and is_tarball(inp):
            tmp_root = Path(tempfile.mkdtemp(prefix="anonbundle_"))
            bundle_dir = extract_tarball(inp, tmp_root)
            # Strip both .tar.gz / .tgz when deriving sibling names.
            stem = inp.name
            for suffix in (".tar.gz", ".tgz"):
                if stem.lower().endswith(suffix):
                    stem = stem[: -len(suffix)]
                    break
            source_bundle_name = stem
            anchor = inp
        else:
            print(f"ERROR: input must be a bundle dir or .tar.gz: {inp}",
                  file=sys.stderr)
            return 2

        csv_files = sorted(bundle_dir.glob("*.csv"))
        if not csv_files:
            print(f"ERROR: no .csv files found in {bundle_dir}",
                  file=sys.stderr)
            return 2

        customer_prefix = (args.customer_prefix or "").upper()
        extra_whitelist = set()
        if args.whitelist:
            if not args.whitelist.is_file():
                print(f"ERROR: whitelist file not found: {args.whitelist}",
                      file=sys.stderr)
                return 2
            data = json.loads(args.whitelist.read_text(encoding="utf-8"))
            extra_whitelist = set(data.get("whitelist", []))

        existing_mapping = {}
        if args.load_mapping:
            existing_mapping = load_mapping_file(args.load_mapping)

        # --- Pass 1: collect values per category ------------------------
        collected, file_meta = collect_values(csv_files)

        # --- Pass 2: build mapping --------------------------------------
        mapping, stats, ambiguous_samples = build_mapping(
            collected, customer_prefix, extra_whitelist,
            existing=existing_mapping,
        )

        anon_dir, mapping_path, tarball_path = derive_output_paths(
            anchor, source_bundle_name,
        )

        print(f"Input:           {inp}")
        print(f"Bundle dir:      {bundle_dir}")
        print(f"CSV files:       {len(csv_files)}")
        print(f"Output dir:      {anon_dir}")
        print(f"Mapping:         {mapping_path}")
        if not args.no_tar:
            print(f"Tarball:         {tarball_path}")
        print(f"Customer prefix: {customer_prefix or '(disabled)'}")
        if existing_mapping:
            print(f"Loaded mapping:  {args.load_mapping} "
                  f"({len(existing_mapping)} entries)")
        print()
        _print_stats(stats, ambiguous_samples, args.verbose, mapping)

        if args.dry_run:
            print("\n(dry-run: no files written)")
            return 0

        # --- Output checks ---------------------------------------------
        if anon_dir.exists():
            if not _confirm_overwrite(anon_dir, args.yes):
                print("Aborted.", file=sys.stderr)
                return 1
            shutil.rmtree(anon_dir)
        if not _confirm_overwrite(mapping_path, args.yes):
            print("Aborted.", file=sys.stderr)
            return 1
        if not args.no_tar and not _confirm_overwrite(tarball_path,
                                                     args.yes):
            print("Aborted.", file=sys.stderr)
            return 1

        anon_dir.mkdir(parents=True)

        # --- Pass 3: write anonymised CSV files ------------------------
        anon_marker = _dt.datetime.now(_dt.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        for path in csv_files:
            preamble, schema_cols, header_row, data_rows = (
                file_meta.get(path, (None, None, None, None))
            )
            if preamble is None:
                # No schema line - copy through unchanged.
                shutil.copy2(path, anon_dir / path.name)
                continue
            original_lines = path.read_text(
                encoding="utf-8-sig", errors="replace"
            ).splitlines(keepends=True)
            _, original_data_lines = split_preamble(original_lines)
            write_anonymised_csv(
                anon_dir / path.name,
                preamble, schema_cols, header_row, data_rows,
                original_data_lines, mapping,
            )

        # --- Auxiliary files (manifest, README) ------------------------
        for path in sorted(bundle_dir.iterdir()):
            if path.suffix == ".csv":
                continue
            if path.name in SKIP_FILES:
                continue
            if not path.is_file():
                continue
            copy_non_csv(path, anon_dir / path.name,
                         anon_marker=anon_marker)

        # --- Mapping file ----------------------------------------------
        meta = {
            "source_bundle":   str(inp),
            "categories":      list(CATEGORY_ORDER),
            "customer_prefix": customer_prefix,
            "total_mappings":  len(mapping),
            "anonymised_at":   anon_marker,
            "tool":            "anonymize_bundle.py",
            "tool_version":    "0.2.0",
        }
        save_mapping_file(mapping_path, mapping, meta)

        # --- Tarball ---------------------------------------------------
        if not args.no_tar:
            with tarfile.open(tarball_path, "w:gz") as tar:
                tar.add(anon_dir, arcname=anon_dir.name)

        print(f"\nWrote anonymised bundle -> {anon_dir}")
        print(f"Wrote mapping           -> {mapping_path}")
        if not args.no_tar:
            print(f"Wrote tarball           -> {tarball_path}")
        print("\nReminder: the mapping file contains real values. "
              "KEEP LOCAL.")
        return 0
    finally:
        if tmp_root is not None and tmp_root.exists():
            shutil.rmtree(tmp_root, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
