#!/usr/bin/env bats
# SPDX-License-Identifier: Apache-2.0
# Test suite: bin/ora-db-audit.sh --from-bundle offline mode.
# Uses tests/fixtures/sample_bundle.tar.gz - no live Oracle database required.
# Requires python3 in PATH for --report mode (tools/audit_report.py).

SCRIPT="${BATS_TEST_DIRNAME}/../../bin/ora-db-audit.sh"
FIXTURES="${BATS_TEST_DIRNAME}/../fixtures"
SAMPLE_BUNDLE_DIR="${FIXTURES}/sample_bundle"
SAMPLE_TAR="${FIXTURES}/sample_bundle.tar.gz"

setup() {
    if [[ ! -x "${SCRIPT}" ]]; then
        skip "ora-db-audit.sh not found or not executable"
    fi
    if [[ ! -d "${SAMPLE_BUNDLE_DIR}" ]]; then
        skip "sample_bundle/ fixture directory not found at ${FIXTURES}/"
    fi
    # Generate the tarball from the committed fixture directory if absent.
    if [[ ! -f "${SAMPLE_TAR}" ]]; then
        (cd "${FIXTURES}" && tar czf sample_bundle.tar.gz sample_bundle/) || {
            skip "failed to create sample_bundle.tar.gz from fixture"
        }
    fi
    # Use a per-test temp output dir so tests don't collide.
    TEST_OUT="$(mktemp -d)"
}

teardown() {
    [[ -n "${TEST_OUT:-}" && -d "${TEST_OUT}" ]] && rm -rf "${TEST_OUT}"
}

# ---------------------------------------------------------------------------
# Extraction-only (no --report)
# ---------------------------------------------------------------------------

@test "--from-bundle extracts bundle and exits 0" {
    run "${SCRIPT}" --from-bundle "${SAMPLE_TAR}" --output "${TEST_OUT}"
    [ "${status}" -eq 0 ]
}

@test "--from-bundle extracts bundle directory" {
    "${SCRIPT}" --from-bundle "${SAMPLE_TAR}" --output "${TEST_OUT}"
    local extracted_dir
    extracted_dir="$(find "${TEST_OUT}" -maxdepth 1 -type d -name "sample_bundle" | head -1)"
    [ -n "${extracted_dir}" ]
    [ -d "${extracted_dir}" ]
}

# ---------------------------------------------------------------------------
# --from-bundle --dry-run
# ---------------------------------------------------------------------------

@test "--from-bundle --dry-run exits 0 and prints dry-run message" {
    run "${SCRIPT}" --from-bundle "${SAMPLE_TAR}" --output "${TEST_OUT}" --dry-run
    [ "${status}" -eq 0 ]
    [[ "${output}" == *"dry-run"* ]]
}

# ---------------------------------------------------------------------------
# --from-bundle --report (requires python3)
# ---------------------------------------------------------------------------

@test "--from-bundle --report renders a Markdown report" {
    if ! command -v python3 >/dev/null 2>&1; then
        skip "python3 not available"
    fi
    "${SCRIPT}" --from-bundle "${SAMPLE_TAR}" \
                --output "${TEST_OUT}" \
                --report \
                --yes
    local bundle_dir
    bundle_dir="$(find "${TEST_OUT}" -maxdepth 1 -type d -name "sample_bundle" | head -1)"
    [ -f "${bundle_dir}/audit_report.md" ]
}

@test "--from-bundle --report output contains expected section headers" {
    if ! command -v python3 >/dev/null 2>&1; then
        skip "python3 not available"
    fi
    "${SCRIPT}" --from-bundle "${SAMPLE_TAR}" \
                --output "${TEST_OUT}" \
                --report \
                --yes
    local bundle_dir
    bundle_dir="$(find "${TEST_OUT}" -maxdepth 1 -type d -name "sample_bundle" | head -1)"
    local report="${bundle_dir}/audit_report.md"
    [ -f "${report}" ]
    grep -q "^#" "${report}"
}
