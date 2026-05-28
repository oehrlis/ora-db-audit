# tests/

Test suite for the toolkit.

## Layout

```text
tests/
├── bats/          - Shell tests using bats-core
│   ├── test_cli_parse.bats    - CLI argument parsing tests
│   └── test_from_bundle.bats  - Offline bundle mode tests
├── fixtures/
│   └── sample_bundle/         - Anonymised sample bundle (commit-safe, no real data)
└── python/
    └── test_*.py              - pytest tests (report render, anonymizer round-trip)
```

## Run Tests

```bash
make test           # run all tests (bats + pytest)
make test-bats      # bats shell tests only
make test-pytest    # pytest only
```

## Prerequisites

- bats-core for shell tests: `brew install bats-core` (macOS)
- Python 3.10+ for pytest
- No live Oracle database required - tests use the fixture bundle
