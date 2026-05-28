"""Smoke tests: audit_report.py renders on the sample bundle without raising."""

from pathlib import Path
import pytest

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"
SAMPLE_BUNDLE = FIXTURES_DIR / "sample_bundle"


@pytest.fixture(scope="module")
def bundle():
    import audit_report
    return audit_report.read_bundle(SAMPLE_BUNDLE)


@pytest.fixture(scope="module")
def report(bundle):
    import audit_report
    classifier = audit_report.HostClassifier({})
    policy_ddl_map = audit_report.load_policy_ddl(SAMPLE_BUNDLE)
    return audit_report.render_report(
        bundle,
        classifier=classifier,
        top_n=20,
        include_appendix=True,
        policy_ddl_map=policy_ddl_map,
    )


def test_bundle_loads_csv_files(bundle):
    """read_bundle must parse at least the core query CSVs."""
    files = bundle["_files"]
    # Queries 01-15 must all be present in the fixture
    for qid in ["01", "02", "03", "07", "08", "13", "14"]:
        assert qid in files, f"CSV for query {qid} missing from bundle"


def test_bundle_manifest_loaded(bundle):
    manifest = bundle["_manifest"]
    assert manifest.get("dbsid") == "free"
    assert manifest.get("bundle_version") == "0.2.0"


def test_report_is_non_empty_string(report):
    assert isinstance(report, str)
    assert len(report) > 500


def test_report_contains_audit_mode_section(report):
    """Section 1 must mention the audit mode."""
    assert "audit_mode" in report.lower() or "pure" in report.lower()


def test_report_contains_executive_summary(report):
    """Executive summary table header must appear."""
    assert "# " in report or "## " in report


def test_report_contains_policy_section(report):
    """Section 3 or appendix must reference policy names."""
    assert "ORA_SECURECONFIG" in report or "policy" in report.lower()


def test_report_contains_cis_section(report):
    """Section 9 must include the CIS coverage heading."""
    assert "CIS Benchmark" in report or "cis_coverage" in report.lower()


def test_report_contains_audit_roles_section(report):
    """Section 10 must include the audit roles heading."""
    assert "Audit-Rollen" in report or "audit_roles" in report.lower()


def test_report_cis_all_fail_fixture(report):
    """Fixture has all CIS controls as FAIL - report must show FAIL."""
    assert "FAIL" in report


def test_export_prompt_writes_file(tmp_path):
    """--export-prompt writes a non-empty file without requiring an API key."""
    import audit_report

    bundle = audit_report.read_bundle(SAMPLE_BUNDLE)
    classifier = audit_report.HostClassifier({})
    policy_ddl_map = audit_report.load_policy_ddl(SAMPLE_BUNDLE)
    report_text = audit_report.render_report(
        bundle, classifier=classifier, top_n=5,
        include_appendix=False, policy_ddl_map=policy_ddl_map,
    )

    dest = tmp_path / "prompt.txt"
    audit_report._write_export_prompt(report_text, "", dest)

    assert dest.is_file()
    content = dest.read_text(encoding="utf-8")
    assert len(content) > 200
    assert "claude.ai" in content
    assert "ChatGPT" in content


def test_export_prompt_contains_report(tmp_path):
    """Exported prompt must embed the report text."""
    import audit_report

    bundle = audit_report.read_bundle(SAMPLE_BUNDLE)
    classifier = audit_report.HostClassifier({})
    report_text = audit_report.render_report(
        bundle, classifier=classifier, top_n=5,
        include_appendix=False, policy_ddl_map={},
    )

    dest = tmp_path / "prompt.txt"
    audit_report._write_export_prompt(report_text, "TEST", dest)

    content = dest.read_text(encoding="utf-8")
    assert "TEST" in content or "Analyse" in content


def test_report_no_exception_on_missing_query(tmp_path):
    """Reporter must not crash when an optional CSV is missing."""
    import shutil
    import audit_report

    # Copy fixture but omit 15_noise_candidates.csv
    bundle_copy = tmp_path / "bundle"
    shutil.copytree(SAMPLE_BUNDLE, bundle_copy)
    (bundle_copy / "15_noise_candidates.csv").unlink(missing_ok=True)

    bundle = audit_report.read_bundle(bundle_copy)
    classifier = audit_report.HostClassifier({})
    result = audit_report.render_report(
        bundle,
        classifier=classifier,
        top_n=10,
        include_appendix=False,
        policy_ddl_map={},
    )
    assert isinstance(result, str)
    assert len(result) > 100
