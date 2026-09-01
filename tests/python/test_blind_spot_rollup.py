"""Blind-spot roll-up (section 7.4).

The point of this section is that it does NOT list every user. These tests
pin the two properties that make it useful and that regressed before:

  1. only actionable blind spots are listed (customer account, not locked)
  2. everything held back is named with a count - a silent filter would
     make suppressed findings look like absent findings
"""

from pathlib import Path
import pytest

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"
SAMPLE_BUNDLE = FIXTURES_DIR / "sample_bundle"

# Fixture layout (23_blind_spot_pdb.csv):
#   actionable blind spots  APP_ONE, APP_TWO, DEV_X
#   locked blind spots      OLD_ONE, OLD_TWO           (customer, not listed)
#   oracle blind spot       GSMADMIN_INTERNAL          (not listed)
#   deliberate exemptions   BATCH_A, BATCH_B
#   covered                 DBA_ONE, SYS
ACTIONABLE = ["APP_ONE", "APP_TWO", "DEV_X"]
NOT_LISTED = ["OLD_ONE", "OLD_TWO", "GSMADMIN_INTERNAL"]


@pytest.fixture(scope="module")
def bundle():
    import audit_report
    return audit_report.read_bundle(SAMPLE_BUNDLE)


@pytest.fixture(scope="module")
def section(bundle):
    import audit_report
    files = bundle["_files"]
    md, blind, actionable = audit_report.render_section_07_4_blind_spot(
        files.get("23"), files.get("24"), top_n=20
    )
    return md, blind, actionable


def test_counts(section):
    _md, blind, actionable = section
    assert blind == 6, "6 BLIND_SPOT rows in the fixture"
    assert actionable == 3, "3 of them are customer accounts able to log in"


def test_actionable_users_are_listed(section):
    md, _b, _a = section
    for name in ACTIONABLE:
        assert name in md, f"{name} is actionable and must be listed"


def test_non_actionable_users_are_not_listed(section):
    """Locked and Oracle-maintained blind spots are housekeeping. Listing
    them is what made the old section unreadable."""
    md, _b, _a = section
    for name in NOT_LISTED:
        assert name not in md, f"{name} must not be listed individually"


def test_suppressed_rows_are_counted_not_hidden(section):
    """A filter that holds rows back silently is a defect: the 3 suppressed
    blind spots must appear as a number."""
    md, _b, _a = section
    assert "3" in md
    assert "actionable = N" in md or "actionable = Y" in md, \
        "the note must say how to retrieve the suppressed rows"


def test_matrix_rows_sum_to_total(section):
    """The coverage matrix columns are disjoint (best path wins), so each
    row must add up. Guards against double counting a user."""
    md, _b, _a = section
    # Customer / yes row: 3 blind + 2 except + 1 covered_via_role = 6
    assert "| Customer | ja | 6 |" in md or "| Customer | yes | 6 |" in md


def test_except_grouped_by_policy(section):
    """EXCLUDED_EXCEPT is grouped by policy, not one row per user."""
    md, _b, _a = section
    assert "OUA_DDL_ALL" in md
    assert "BATCH_A" in md and "BATCH_B" in md


def test_derivation_fallback_without_new_columns(bundle):
    """Bundles collected before sql/23 gained account_class / login_enabled /
    actionable must still classify correctly - the rules are re-derived in
    Python from oracle_maintained + account_status."""
    import copy
    import audit_report

    fd = copy.deepcopy(bundle["_files"]["23"])
    drop = {"account_class", "login_enabled", "actionable"}
    keep = [i for i, h in enumerate(fd["headers"]) if h.lower() not in drop]
    fd["headers"] = [fd["headers"][i] for i in keep]
    fd["rows"] = [[r[i] for i in keep if i < len(r)] for r in fd["rows"]]

    md, blind, actionable = audit_report.render_section_07_4_blind_spot(
        fd, None, top_n=20
    )
    assert (blind, actionable) == (6, 3), \
        "fallback derivation must match the SQL-provided columns"
    for name in ACTIONABLE:
        assert name in md
    for name in NOT_LISTED:
        assert name not in md


# ---------------------------------------------------------------------------
# Block D: name-pattern grouping
# ---------------------------------------------------------------------------

def test_groups_collapse_numbered_accounts():
    """40 numbered dev accounts are one finding with one remedy, not 40
    rows. Totals must still add up to the input size."""
    import audit_report
    entries = [(f"ISC_DEV_{i:02d}", None) for i in range(1, 6)]
    entries += [(f"BATCH_LOAD_{i}", None) for i in range(1, 4)]
    entries += [("PAY_APP", None), ("X9", None), ("REPORT_2", None)]
    md = audit_report.render_blind_spot_groups(entries, grp_min=3)
    assert "ISC_DEV_*" in md
    assert "BATCH_LOAD_*" in md
    # PAY_APP has no digits, X9 has a stem shorter than 4, REPORT_2 is a
    # pattern below grp_min - all three fold into the ungrouped bucket.
    assert "| 3 |" in md


def test_groups_below_threshold_are_not_invented():
    import audit_report
    entries = [("APP_1", None), ("APP_2", None)]
    assert audit_report.render_blind_spot_groups(entries, grp_min=3) == ""


def test_groups_count_containers_when_present():
    import audit_report
    entries = [(f"C##DEV_{i:02d}", "CDB$ROOT") for i in range(1, 4)]
    entries += [(f"C##DEV_{i:02d}", "PDB1") for i in range(1, 4)]
    md = audit_report.render_blind_spot_groups(entries, grp_min=3)
    assert "C##DEV_*" in md
    assert "| 6 | 2 |" in md, "6 members across 2 containers"


def test_grouping_skipped_on_pseudonymised_bundle():
    """tools/anonymize_bundle.py replaces principals with DBUSER_nnn, which
    destroys every name pattern. Grouping them would produce one meaningless
    catch-all group - the section must say so instead."""
    import audit_report
    entries = [(f"DBUSER_{i:03d}", None) for i in range(1, 30)]
    md = audit_report.render_blind_spot_groups(entries, grp_min=3)
    assert "DBUSER_*" not in md
    assert "blind-spot-pdb.sql" in md, \
        "must point at the standalone script, where real names exist"


def test_pseudonym_detection_survives_a_small_actionable_subset():
    """Regression: detection must not depend on how many rows are actionable.

    The anonymiser whitelists Oracle-maintained schemas, so pseudonyms are a
    minority of the rows even in a fully anonymised bundle, and the actionable
    subset can be as small as three. A ratio- or sample-size-based check
    passes its own unit test and then fails on real data - a bogus DBUSER_*
    group needs only grp_min members to appear.
    """
    import audit_report
    # Only 4 actionable rows, all pseudonymised; the file also holds many
    # whitelisted real names.
    entries = [(f"DBUSER_{i:03d}", None) for i in range(1, 5)]
    all_names = [f"DBUSER_{i:03d}" for i in range(1, 5)] + \
                ["SYS", "SYSTEM", "DBSNMP", "OUTLN", "XDB", "GSMADMIN_INTERNAL",
                 "AUDSYS", "CTXSYS", "DVSYS", "LBACSYS", "MDSYS", "OLAPSYS"]
    md = audit_report.render_blind_spot_groups(
        entries, grp_min=3, all_names=all_names)
    assert "DBUSER_*" not in md, "must not invent a catch-all pseudonym group"
    assert "blind-spot-pdb.sql" in md


def test_real_names_still_group_when_mixed_with_oracle_schemas():
    """The counterpart: a raw bundle must still group."""
    import audit_report
    entries = [(f"ISC_DEV_{i:02d}", None) for i in range(1, 5)]
    all_names = [f"ISC_DEV_{i:02d}" for i in range(1, 5)] + ["SYS", "SYSTEM"]
    md = audit_report.render_blind_spot_groups(
        entries, grp_min=3, all_names=all_names)
    assert "ISC_DEV_*" in md


def test_name_pattern_is_conservative():
    """A pattern that merges unrelated accounts would hide a single finding
    inside a group - the exact failure block D exists to prevent."""
    import audit_report
    assert audit_report._name_pattern("ISC_DEV_01") == "ISC_DEV_*"
    assert audit_report._name_pattern("PAY_APP") is None      # no digits
    assert audit_report._name_pattern("X9") is None           # stem too short
