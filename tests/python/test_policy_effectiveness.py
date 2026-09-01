"""Policy effectiveness (section 7.5) - the reverse view of the blind-spot
report.

Section 7.4 walks users and reports the uncovered ones. It structurally
cannot see a policy that is enabled, looks correct, and reaches nobody:
such a policy simply contributes no coverage, which is indistinguishable
from a policy that was never meant to cover those users. These tests pin
that the reverse view reports exactly the three "reaches nobody" verdicts
as findings, and treats EXCEPT drift as context rather than a gap.
"""

from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"
SAMPLE_BUNDLE = FIXTURES_DIR / "sample_bundle"

# Fixture (25_policy_effectiveness.csv), customer policies only:
#   findings   OUA_DEV_ALL (ENTITY_MISSING), OUA_STALE_ROLE (ENTITY_MISSING),
#              OUA_EMPTY_ROLE (ROLE_NO_GRANTEES)
#   context    EXCLUSION_DEAD, EXCLUSION, ALL_USERS, OK x2
#   excluded   ORA_SECURECONFIG (oracle_supplied = YES)
FINDING_POLICIES = ["OUA_DEV_ALL", "OUA_STALE_ROLE", "OUA_EMPTY_ROLE"]


@pytest.fixture(scope="module")
def bundle():
    import audit_report
    return audit_report.read_bundle(SAMPLE_BUNDLE)


@pytest.fixture(scope="module")
def section(bundle):
    import audit_report
    files = bundle["_files"]
    return audit_report.render_section_07_5_policy_effectiveness(
        files.get("25"), files.get("26"), top_n=20
    )


def test_finding_count(section):
    _md, n = section
    assert n == 3, "two ENTITY_MISSING plus one ROLE_NO_GRANTEES"


def test_findings_are_listed(section):
    md, _n = section
    for pol in FINDING_POLICIES:
        assert pol in md, f"{pol} reaches nobody and must be reported"


def test_healthy_policies_not_reported_as_findings(section):
    """OK / ALL_USERS / EXCLUSION rows belong in the summary counts, not in
    the findings table."""
    md, _n = section
    findings_part = md.split("ENTITY_MISSING")[0]
    assert "OUA_PRIV_DBA_ALL" not in findings_part


def test_oracle_supplied_excluded_by_default(section):
    """Counting Oracle-supplied policies here would drown the customer
    configuration, same rationale as section 7.4."""
    md, _n = section
    assert "ORA_SECURECONFIG" not in md


def test_exclusion_dead_is_context_not_finding(section):
    """A dead EXCEPT clause is drift, not a coverage gap - it must be
    mentioned but must not inflate the finding count."""
    md, n = section
    assert n == 3
    assert "EXCLUSION_DEAD" in md


def test_section_renders_without_csv(bundle):
    """A bundle from an older tool version has no 25/26 - the section must
    say so rather than raise."""
    import audit_report
    md, n = audit_report.render_section_07_5_policy_effectiveness(
        None, None, top_n=20
    )
    assert n == 0
    assert "25_policy_effectiveness.csv" in md
