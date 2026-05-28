"""Round-trip integrity tests for anonymize_bundle.py.

Anonymize the sample_bundle fixture, then verify that:
  1. A mapping.json is produced with the expected real->pseudo entries.
  2. Pseudonymised columns in the anon bundle no longer contain real values.
  3. Whitelisted values (SYS, SYSTEM, Oracle-supplied policies) are preserved.
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TOOLS_DIR = REPO_ROOT / "tools"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"
SAMPLE_BUNDLE = FIXTURES_DIR / "sample_bundle"

# Values that MUST be replaced in files where they appear as PSEUDO columns.
# Format: (filename_stem, real_value)
# Only check the specific CSV where the column is typed PSEUDO:* so we don't
# flag values that legitimately survive in KEEP columns (e.g. host_name in
# 01_config.csv is value=KEEP - the DB hostname is always visible there).
MUST_PSEUDONYMISE_IN = [
    ("11_host_user_program", "stefan.oehrli"),
    ("11_host_user_program", "TVD_HR"),
    ("11_host_user_program", "SCOTT"),
    ("11_host_user_program", "auditlab-app-classic.example.com"),
    ("08_top_users", "stefan.oehrli"),
    ("08_top_users", "TVD_HR"),
    ("08_top_users", "SCOTT"),
]

# Values that MUST survive anonymisation (whitelisted Oracle/system accounts)
MUST_KEEP = [
    "SYS",
    "SYSTEM",
]


@pytest.fixture(scope="module")
def anon_bundle(tmp_path_factory):
    """Run anonymize_bundle.py on a fresh copy of the sample_bundle fixture."""
    tmp = tmp_path_factory.mktemp("anon")
    bundle_copy = tmp / "sample_bundle"
    shutil.copytree(SAMPLE_BUNDLE, bundle_copy)

    result = subprocess.run(
        [
            sys.executable,
            str(TOOLS_DIR / "anonymize_bundle.py"),
            str(bundle_copy),
            "--customer-prefix", "ODB",
            "--yes",
            "--no-tar",
        ],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    assert result.returncode == 0, (
        f"anonymize_bundle.py failed:\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}"
    )
    return tmp


def test_mapping_json_created(anon_bundle):
    mapping_path = anon_bundle / "sample_bundle.mapping.json"
    assert mapping_path.is_file(), "mapping.json not created by anonymizer"


def test_mapping_json_is_valid(anon_bundle):
    mapping_path = anon_bundle / "sample_bundle.mapping.json"
    data = json.loads(mapping_path.read_text())
    assert "mapping" in data
    assert "meta" in data
    assert data["meta"]["customer_prefix"] == "ODB"
    assert len(data["mapping"]) >= 5


def test_real_values_pseudonymised_in_anon_bundle(anon_bundle):
    """Real values must not appear in data rows of files where they are PSEUDO columns.
    KEEP columns (e.g. host_name=KEEP in 01_config.csv) are excluded from this check
    because the hostname legitimately passes through there unchanged."""
    anon_dir = anon_bundle / "sample_bundle.anon"
    assert anon_dir.is_dir(), "sample_bundle.anon/ not created"

    csv_files = list(anon_dir.glob("*.csv"))
    assert len(csv_files) >= 10, "expected at least 10 CSVs in anon bundle"

    for stem, real_value in MUST_PSEUDONYMISE_IN:
        csv_path = anon_dir / f"{stem}.csv"
        if not csv_path.is_file():
            continue
        # Exclude preamble lines (# ...) - only check CSV data rows
        data_lines = [
            line for line in csv_path.read_text(encoding="utf-8").splitlines()
            if not line.startswith("#")
        ]
        data_text = "\n".join(data_lines)
        assert real_value not in data_text, (
            f"real value '{real_value}' still in data rows of {stem}.csv "
            "after anonymization"
        )


def test_whitelisted_values_preserved(anon_bundle):
    """Oracle-system account names must survive anonymisation unchanged."""
    anon_dir = anon_bundle / "sample_bundle.anon"
    csv_files = list(anon_dir.glob("*.csv"))
    all_text = "\n".join(f.read_text(encoding="utf-8") for f in csv_files)
    for keep_value in MUST_KEEP:
        assert keep_value in all_text, (
            f"whitelisted value '{keep_value}' was incorrectly pseudonymised"
        )


def test_anon_bundle_has_metadata_preamble(anon_bundle):
    """Anonymised CSVs must retain the # query: preamble lines."""
    anon_dir = anon_bundle / "sample_bundle.anon"
    config_csv = anon_dir / "01_config.csv"
    if not config_csv.is_file():
        pytest.skip("01_config.csv not in anon bundle")
    content = config_csv.read_text()
    assert content.startswith("# query:"), "metadata preamble missing from anon CSV"
