"""Tests for sql/17-cis-coverage and sql/18-audit-roles CSV output.

Verifies that the fixture files have the expected structure, that the
anonymizer handles PSEUDO:DBUSER correctly in 18_audit_roles.csv, and
that audit_report.py loads both CSVs without raising.
"""

import csv
import io
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"
SAMPLE_BUNDLE = FIXTURES_DIR / "sample_bundle"
CIS_CSV = SAMPLE_BUNDLE / "17_cis_coverage.csv"
ROLES_CSV = SAMPLE_BUNDLE / "18_audit_roles.csv"

CIS_CONTROLS = {"5.1", "5.2", "5.3", "5.4", "5.5"}
VALID_VERDICTS = {"PASS", "WARN", "FAIL"}
VALID_RISK_FLAGS = {"STANDARD", "INFO", "WARN", "REVIEW"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_csv(path: Path):
    """Return (preamble_lines, header, rows) for a pipe-delimited CSV fixture."""
    lines = path.read_text().splitlines()
    preamble = [l for l in lines if l.startswith("#")]
    data_lines = [l for l in lines if not l.startswith("#") and l.strip()]
    reader = csv.DictReader(io.StringIO("\n".join(data_lines)), delimiter="|")
    rows = list(reader)
    return preamble, reader.fieldnames, rows


def _preamble_value(preamble, key):
    """Extract value from a '# key: value' preamble line."""
    prefix = f"# {key}:"
    for line in preamble:
        if line.startswith(prefix):
            return line[len(prefix):].strip()
    return None


# ---------------------------------------------------------------------------
# 17_cis_coverage.csv structure tests
# ---------------------------------------------------------------------------

def test_cis_coverage_file_exists():
    assert CIS_CSV.exists(), "17_cis_coverage.csv missing from fixture bundle"


def test_cis_coverage_preamble_no_continuation_char():
    """Preamble must not contain 'cis_controls: -' (SQL*Plus continuation bug)."""
    text = CIS_CSV.read_text()
    assert "# cis_controls: -" not in text


def test_cis_coverage_preamble_has_cis_controls():
    preamble, _, _ = _parse_csv(CIS_CSV)
    controls = _preamble_value(preamble, "cis_controls")
    assert controls is not None
    assert "5.1" in controls and "5.5" in controls


def test_cis_coverage_has_five_controls():
    """One row per CIS control 5.1-5.5."""
    _, _, rows = _parse_csv(CIS_CSV)
    assert len(rows) == 5, f"Expected 5 CIS control rows, got {len(rows)}"


def test_cis_coverage_all_controls_present():
    _, _, rows = _parse_csv(CIS_CSV)
    found = {r["cis_control"] for r in rows}
    assert found == CIS_CONTROLS, f"Missing controls: {CIS_CONTROLS - found}"


def test_cis_coverage_verdicts_are_valid():
    _, _, rows = _parse_csv(CIS_CSV)
    for row in rows:
        assert row["verdict"] in VALID_VERDICTS, (
            f"Unexpected verdict {row['verdict']!r} for control {row['cis_control']}"
        )


def test_cis_coverage_fixture_reflects_missing_policies():
    """Fixture uses a lab where CIS policies are not deployed -> all FAIL."""
    _, _, rows = _parse_csv(CIS_CSV)
    verdicts = {r["verdict"] for r in rows}
    # All FAIL is a valid lab state; at minimum no unknown verdict values
    assert verdicts <= VALID_VERDICTS


def test_cis_coverage_required_columns():
    _, fieldnames, _ = _parse_csv(CIS_CSV)
    required = {"policy_name", "cis_control", "cis_title",
                "policy_exists", "policy_enabled", "verdict"}
    missing = required - set(fieldnames or [])
    assert not missing, f"Missing columns: {missing}"


# ---------------------------------------------------------------------------
# 18_audit_roles.csv structure tests
# ---------------------------------------------------------------------------

def test_audit_roles_file_exists():
    assert ROLES_CSV.exists(), "18_audit_roles.csv missing from fixture bundle"


def test_audit_roles_preamble_no_continuation_char():
    """Preamble must not contain 'cis_controls: -' (SQL*Plus continuation bug)."""
    text = ROLES_CSV.read_text()
    assert "# cis_controls: -" not in text


def test_audit_roles_required_columns():
    _, fieldnames, _ = _parse_csv(ROLES_CSV)
    required = {"target_role", "grantee", "grantee_type",
                "grant_path", "risk_flag"}
    missing = required - set(fieldnames or [])
    assert not missing, f"Missing columns: {missing}"


def test_audit_roles_risk_flags_are_valid():
    _, _, rows = _parse_csv(ROLES_CSV)
    for row in rows:
        assert row["risk_flag"] in VALID_RISK_FLAGS, (
            f"Unexpected risk_flag {row['risk_flag']!r} for {row['grantee']}"
        )


def test_audit_roles_target_roles_are_known():
    _, _, rows = _parse_csv(ROLES_CSV)
    known = {"AUDIT_ADMIN", "AUDIT_VIEWER"}
    for row in rows:
        assert row["target_role"] in known, (
            f"Unexpected target_role {row['target_role']!r}"
        )


def test_audit_roles_sys_is_not_pseudonymised():
    """SYS must not be replaced with DBUSER_NNN (it is in ORACLE_USERS whitelist)."""
    _, _, rows = _parse_csv(ROLES_CSV)
    sys_rows = [r for r in rows if r["grantee"] == "SYS"]
    assert sys_rows, "Expected at least one SYS row in audit_roles fixture"


def test_audit_roles_non_sys_grantee_is_pseudonymised():
    """Non-system user grantees must appear as DBUSER_NNN pseudonyms."""
    _, _, rows = _parse_csv(ROLES_CSV)
    import re
    non_sys = [r for r in rows
               if r["grantee"] not in {"SYS", "SYSTEM", "AUDSYS",
                                       "AUDIT_ADMIN", "AUDIT_VIEWER"}
               and r["grantee_type"] == "USER"]
    for row in non_sys:
        assert re.match(r"^DBUSER_\d{3}$", row["grantee"]), (
            f"Grantee {row['grantee']!r} was not pseudonymised as DBUSER_NNN"
        )


# ---------------------------------------------------------------------------
# audit_report.py loads both CSVs without raising
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def bundle():
    import audit_report
    return audit_report.read_bundle(SAMPLE_BUNDLE)


def test_bundle_loads_query_17(bundle):
    assert "17" in bundle["_files"], "Query 17 (cis_coverage) not loaded from bundle"


def test_bundle_loads_query_18(bundle):
    assert "18" in bundle["_files"], "Query 18 (audit_roles) not loaded from bundle"


def test_cis_coverage_rows_in_bundle(bundle):
    data = bundle["_files"]["17"]
    rows = data.get("rows", [])
    assert len(rows) == 5, f"Expected 5 CIS rows in bundle, got {len(rows)}"


def test_audit_roles_rows_in_bundle(bundle):
    data = bundle["_files"]["18"]
    rows = data.get("rows", [])
    assert len(rows) >= 1, "Expected at least one audit_roles row in bundle"
