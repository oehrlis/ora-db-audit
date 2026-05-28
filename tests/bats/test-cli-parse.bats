#!/usr/bin/env bats
# SPDX-License-Identifier: Apache-2.0
# Test suite: bin/ora-db-audit.sh flag parsing and offline-mode validation.
# Does NOT require a live Oracle database; all tests exercise the script
# without executing SQL.

SCRIPT="${BATS_TEST_DIRNAME}/../../bin/ora-db-audit.sh"

HAVE_SQLPLUS=0
command -v sqlplus >/dev/null 2>&1 && HAVE_SQLPLUS=1

setup() {
    # Verify the script exists and is executable.
    if [[ ! -x "${SCRIPT}" ]]; then
        skip "ora-db-audit.sh not found or not executable at ${SCRIPT}"
    fi
}

# Helper: skip test if sqlplus is not in PATH (requires Oracle env).
require_sqlplus() {
    if [[ "${HAVE_SQLPLUS}" -eq 0 ]]; then
        skip "sqlplus not in PATH - source Oracle env to run this test"
    fi
}

# ---------------------------------------------------------------------------
# --help
# ---------------------------------------------------------------------------

@test "--help exits 0 and prints usage" {
    run "${SCRIPT}" --help
    [ "${status}" -eq 0 ]
    [[ "${output}" == *"Usage:"* ]]
}

@test "-h exits 0 and prints usage" {
    run "${SCRIPT}" -h
    [ "${status}" -eq 0 ]
    [[ "${output}" == *"Usage:"* ]]
}

# ---------------------------------------------------------------------------
# Unknown flag
# ---------------------------------------------------------------------------

@test "unknown flag exits non-zero" {
    run "${SCRIPT}" --totally-unknown-flag
    [ "${status}" -ne 0 ]
}

# ---------------------------------------------------------------------------
# --dry-run with valid flags
# ---------------------------------------------------------------------------

@test "--dry-run --days 7 exits 0 (requires sqlplus in PATH)" {
    require_sqlplus
    run "${SCRIPT}" --dry-run --days 7
    [ "${status}" -eq 0 ]
    [[ "${output}" == *"dry-run"* ]]
}

@test "--dry-run --days 14 --top-n 50 exits 0" {
    require_sqlplus
    run "${SCRIPT}" --dry-run --days 14 --top-n 50
    [ "${status}" -eq 0 ]
}

@test "--dry-run --connect '/ as sysdba' exits 0" {
    require_sqlplus
    run "${SCRIPT}" --dry-run --connect "/ as sysdba"
    [ "${status}" -eq 0 ]
}

# ---------------------------------------------------------------------------
# Flag validation
# ---------------------------------------------------------------------------

@test "--days with non-integer exits non-zero" {
    run "${SCRIPT}" --dry-run --days abc
    [ "${status}" -ne 0 ]
}

@test "--top-n with non-integer exits non-zero" {
    run "${SCRIPT}" --dry-run --top-n xyz
    [ "${status}" -ne 0 ]
}

# ---------------------------------------------------------------------------
# --from-bundle validation (file missing -> non-zero exit, no DB required)
# ---------------------------------------------------------------------------

@test "--from-bundle with non-existent file exits non-zero" {
    run "${SCRIPT}" --from-bundle /tmp/no-such-bundle-12345.tar.gz --report
    [ "${status}" -ne 0 ]
}

@test "--from-bundle --dry-run exits 0 even without real bundle" {
    run "${SCRIPT}" --from-bundle /tmp/hypothetical.tar.gz --dry-run
    [ "${status}" -eq 0 ]
    [[ "${output}" == *"dry-run"* ]]
}
