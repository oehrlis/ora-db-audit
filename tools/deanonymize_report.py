#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# ------------------------------------------------------------------------------
# OraDBA - Oracle Database Infrastructure and Security, 5630 Muri, Switzerland
# ------------------------------------------------------------------------------
# Name.......: deanonymize_report.py
# Author.....: Stefan Oehrli (oes) stefan.oehrli@oradba.ch
# Editor.....: Stefan Oehrli
# Date.......: 2026.05.28
# Version....: 0.2.0
# Purpose....: Reverse anonymisation of audit report Markdown files.
#              Reads the .mapping.json produced by anonymize_bundle.py and
#              replaces all pseudonyms (DBUSER_NNN, HOST_NNN, ...) with the
#              original real values. For local, customer-side use only.
# Notes......: The mapping file contains real customer values - keep LOCAL.
#              Never share the mapping file or the de-anonymised reports.
#              Output files get a .deanon.md suffix (original .md is kept).
# Usage......: deanonymize_report.py BUNDLE_DIR
#                                    [--mapping FILE]
#                                    [--output DIR]
#                                    [--dry-run] [--yes] [--help]
# License....: Apache License Version 2.0, January 2004 as shown
#              at http://www.apache.org/licenses/
# ------------------------------------------------------------------------------
# CHANGE LOG:
# 2026.05.28  oes  Sanitised port from audit_pack-0.5.0                   0.2.0
# ------------------------------------------------------------------------------

import argparse
import json
import os
import re
import sys
from pathlib import Path

TOOL_VERSION = "0.2.0"

# Report files to process (in order).
REPORT_FILES = ["audit_report.md", "audit_ai_findings.md"]


def load_mapping(path):
    """Load mapping.json and return reversed dict: pseudo -> real."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit("ERROR: cannot read mapping file {}: {}".format(path, exc))
    raw = data.get("mapping", {})
    if not raw:
        raise SystemExit("ERROR: mapping file has no 'mapping' key or is empty: {}".format(path))
    # Reverse: real_value -> pseudo  becomes  pseudo -> real_value
    return {pseudo: real for real, pseudo in raw.items()}


def derive_mapping_path(bundle_dir):
    """Auto-detect mapping file next to the .anon bundle directory.

    Given /path/to/foo.anon/ returns /path/to/foo.mapping.json.
    Raises SystemExit if the bundle dir name does not end with .anon.
    """
    p = Path(bundle_dir).resolve()
    if not p.name.endswith(".anon"):
        raise SystemExit(
            "ERROR: cannot auto-detect mapping - bundle dir does not end with '.anon'.\n"
            "       Pass --mapping <file> explicitly."
        )
    stem = p.name[: -len(".anon")]
    candidate = p.parent / "{}.mapping.json".format(stem)
    if not candidate.exists():
        raise SystemExit(
            "ERROR: mapping file not found: {}\n"
            "       Pass --mapping <file> explicitly.".format(candidate)
        )
    return candidate


def apply_substitutions(text, reverse_mapping):
    """Replace all pseudo tokens in text with real values.

    Sorts by pseudo length descending to avoid partial matches
    (e.g. HOST_01 before HOST_0 if both existed).
    """
    # Build sorted list: longest pseudo first
    substitutions = sorted(reverse_mapping.items(), key=lambda kv: len(kv[0]), reverse=True)
    count = 0
    for pseudo, real in substitutions:
        if pseudo in text:
            text = text.replace(pseudo, real)
            count += text.count(real)  # approximation after replace
    # Re-count accurately
    count = sum(
        len(re.findall(re.escape(real), text))
        for _, real in substitutions
        if real in text
    )
    return text, count


def confirm_overwrite(path, assume_yes):
    if not path.exists() or assume_yes:
        return True
    answer = input("Overwrite {}? [y/N] ".format(path)).strip().lower()
    return answer in ("y", "yes")


def main():
    parser = argparse.ArgumentParser(
        prog="deanonymize_report.py",
        description=(
            "Reverse anonymisation of audit report .md files.\n"
            "Reads the .mapping.json and replaces pseudonyms with real values.\n"
            "Output: *.deanon.md alongside the original files.\n\n"
            "SECURITY: output files contain real customer data - keep LOCAL."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "bundle_dir",
        metavar="BUNDLE_DIR",
        help="Path to the .anon bundle directory containing the report .md files.",
    )
    parser.add_argument(
        "--mapping", "-m",
        metavar="FILE",
        default=None,
        help=(
            "Path to the .mapping.json file. "
            "Default: auto-detected as <bundle_stem>.mapping.json "
            "next to BUNDLE_DIR."
        ),
    )
    parser.add_argument(
        "--output", "-o",
        metavar="DIR",
        default=None,
        help=(
            "Output directory for .deanon.md files. "
            "Default: same directory as the source .md file."
        ),
    )
    parser.add_argument(
        "--dry-run", "-n",
        action="store_true",
        help="Show what would be replaced without writing any files.",
    )
    parser.add_argument(
        "--yes", "-y",
        action="store_true",
        help="Overwrite existing .deanon.md files without prompting.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="deanonymize_report.py {}".format(TOOL_VERSION),
    )
    args = parser.parse_args()

    bundle_dir = Path(args.bundle_dir).resolve()
    if not bundle_dir.is_dir():
        raise SystemExit("ERROR: bundle dir not found: {}".format(bundle_dir))

    # Resolve mapping file
    mapping_path = Path(args.mapping).resolve() if args.mapping else derive_mapping_path(bundle_dir)
    print("[deanon] mapping: {}".format(mapping_path))

    reverse_mapping = load_mapping(mapping_path)
    print("[deanon] {} pseudo tokens loaded".format(len(reverse_mapping)))

    # Collect report files that exist in the bundle dir
    targets = []
    for name in REPORT_FILES:
        candidate = bundle_dir / name
        if candidate.is_file():
            targets.append(candidate)
    if not targets:
        raise SystemExit(
            "ERROR: no report files found in {}\n"
            "       Expected: {}".format(bundle_dir, ", ".join(REPORT_FILES))
        )

    output_dir = Path(args.output).resolve() if args.output else None
    if output_dir and not args.dry_run:
        output_dir.mkdir(parents=True, exist_ok=True)

    total_files = 0
    for src in targets:
        stem = src.stem  # e.g. "audit_report"
        dest_dir = output_dir if output_dir else src.parent
        dest = dest_dir / "{}.deanon.md".format(stem)

        text = src.read_text(encoding="utf-8")
        deanon_text, n_replacements = apply_substitutions(text, reverse_mapping)

        if args.dry_run:
            print("[deanon] dry-run: {} -> {} ({} token occurrences)".format(
                src.name, dest.name, n_replacements))
            continue

        if not confirm_overwrite(dest, args.yes):
            print("[deanon] skipped: {}".format(dest))
            continue

        dest.write_text(deanon_text, encoding="utf-8")
        print("[deanon] wrote: {} ({} token occurrences replaced)".format(dest, n_replacements))
        total_files += 1

    if not args.dry_run:
        print("[deanon] done: {} file(s) written".format(total_files))
        print("[deanon] SECURITY: .deanon.md files contain real customer data - keep LOCAL.")


if __name__ == "__main__":
    main()
