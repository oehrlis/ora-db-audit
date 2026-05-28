# ------------------------------------------------------------------------------
# OraDBA - Oracle Database Infrastructure and Security, 5630 Muri, Switzerland
# ------------------------------------------------------------------------------
# Name.......: Makefile
# Author.....: Stefan Oehrli (oes) stefan.oehrli@oradba.ch
# Editor.....: Stefan Oehrli
# Date.......: 2026.05.28
# Version....: 1.0.0
# Purpose....: Makefile for ora-db-audit
# Notes......: Config via environment overrides. Use 'make help' for targets.
# Reference..: https://github.com/oehrlis/ora-db-audit
# License....: Apache License Version 2.0, January 2004 as shown
#              at http://www.apache.org/licenses/
# ------------------------------------------------------------------------------

SHELL        := /bin/bash
.SHELLFLAGS  := -eu -o pipefail -c
.DEFAULT_GOAL := help
MAKEFLAGS    += --no-builtin-rules
.SUFFIXES:

PATH := /opt/homebrew/bin:/usr/local/bin:$(PATH)
export PATH

# -- Project -------------------------------------------------------------------
PROJECT_NAME := ora-db-audit
VERSION      := $(shell cat VERSION 2>/dev/null || echo "0.0.0")

# -- Directories ---------------------------------------------------------------
BIN_DIR    := bin
SQL_DIR    := sql
TOOLS_DIR  := tools
TESTS_DIR  := tests
SCRIPTS_DIR := scripts
DIST_DIR   := dist

# -- Colors --------------------------------------------------------------------
COLOR_RESET  := \033[0m
COLOR_BOLD   := \033[1m
COLOR_GREEN  := \033[32m
COLOR_YELLOW := \033[33m
COLOR_BLUE   := \033[34m
COLOR_RED    := \033[31m

# -- Tool detection ------------------------------------------------------------
SHELLCHECK   := $(shell PATH="$(PATH)" command -v shellcheck 2>/dev/null)
MARKDOWNLINT := $(shell PATH="$(PATH)" command -v markdownlint 2>/dev/null || \
                         PATH="$(PATH)" command -v markdownlint-cli 2>/dev/null)
YAMLLINT     := $(shell PATH="$(PATH)" command -v yamllint 2>/dev/null)
BATS         := $(shell PATH="$(PATH)" command -v bats 2>/dev/null)
PYTHON       := $(shell PATH="$(PATH)" command -v python3 2>/dev/null || \
                         PATH="$(PATH)" command -v python 2>/dev/null)
PYTEST       := $(shell PATH="$(PATH)" command -v pytest 2>/dev/null || \
                    { test -n "$(PYTHON)" && $(PYTHON) -m pytest --version >/dev/null 2>&1 && \
                      echo "$(PYTHON) -m pytest"; })
GIT          := $(shell PATH="$(PATH)" command -v git 2>/dev/null)

# -- Scripts -------------------------------------------------------------------
BUMP_SCRIPT := $(SCRIPTS_DIR)/bump_version.sh

# ==============================================================================
# Help
# ==============================================================================

.PHONY: help
help: ## Show this help message
	@echo -e "$(COLOR_BOLD)$(PROJECT_NAME) Makefile$(COLOR_RESET)"
	@echo "Version: $(VERSION)"
	@echo ""
	@echo "Release workflow:"
	@echo "  Patch : make release                  # bump patch -> commit -> tag"
	@echo "  Minor : make version-bump-minor && make tag"
	@echo "  Major : make version-bump-major && make tag"
	@echo "  After : git push origin main && git push origin v<VERSION>"
	@echo ""
	@echo -e "$(COLOR_BOLD)Lint:$(COLOR_RESET)"
	@grep -E '^lint[a-zA-Z_-]*:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(COLOR_GREEN)%-24s$(COLOR_RESET) %s\n", $$1, $$2}'
	@echo ""
	@echo -e "$(COLOR_BOLD)Test:$(COLOR_RESET)"
	@grep -E '^test[a-zA-Z_-]*:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(COLOR_GREEN)%-24s$(COLOR_RESET) %s\n", $$1, $$2}'
	@echo ""
	@echo -e "$(COLOR_BOLD)Build and Distribution:$(COLOR_RESET)"
	@grep -E '^(build|dist)[a-zA-Z_-]*:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(COLOR_GREEN)%-24s$(COLOR_RESET) %s\n", $$1, $$2}'
	@echo ""
	@echo -e "$(COLOR_BOLD)Cleanup:$(COLOR_RESET)"
	@grep -E '^clean[a-zA-Z_-]*:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(COLOR_GREEN)%-24s$(COLOR_RESET) %s\n", $$1, $$2}'
	@echo ""
	@echo -e "$(COLOR_BOLD)Version Management:$(COLOR_RESET)"
	@grep -E '^(version|check-version)[a-zA-Z_-]*:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(COLOR_GREEN)%-24s$(COLOR_RESET) %s\n", $$1, $$2}'
	@echo ""
	@echo -e "$(COLOR_BOLD)Release Management:$(COLOR_RESET)"
	@grep -E '^(tag|release):.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(COLOR_GREEN)%-24s$(COLOR_RESET) %s\n", $$1, $$2}'
	@echo ""
	@echo -e "$(COLOR_BOLD)Info:$(COLOR_RESET)"
	@grep -E '^status:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  $(COLOR_GREEN)%-24s$(COLOR_RESET) %s\n", $$1, $$2}'

# ==============================================================================
# Lint
# ==============================================================================

.PHONY: lint
lint: lint-shell lint-markdown ## Run all lint checks

.PHONY: lint-shell
lint-shell: ## Lint shell scripts with shellcheck
	@if [[ -z "$(SHELLCHECK)" ]]; then \
		echo "Error: shellcheck not found (install: brew install shellcheck)"; \
		exit 1; \
	fi
	@find "$(BIN_DIR)" "$(SCRIPTS_DIR)" -type f -name "*.sh" -print0 | \
		xargs -0 "$(SHELLCHECK)" -x -S warning

.PHONY: lint-markdown
lint-markdown: ## Lint markdown files with markdownlint
	@if [[ -z "$(MARKDOWNLINT)" ]]; then \
		echo "Error: markdownlint not found (install: npm install -g markdownlint-cli)"; \
		exit 1; \
	fi
	@find . -type f -name "*.md" \
		-not -path "./.git/*" \
		-not -path "./node_modules/*" -print0 | \
		xargs -0 "$(MARKDOWNLINT)"

.PHONY: lint-yaml
lint-yaml: ## Lint YAML files with yamllint
	@if [[ -z "$(YAMLLINT)" ]]; then \
		echo "Error: yamllint not found (install: pip install yamllint)"; \
		exit 1; \
	fi
	@find . -type f \( -name "*.yml" -o -name "*.yaml" \) \
		-not -path "./.git/*" \
		-not -path "./node_modules/*" -print0 | \
		xargs -0 "$(YAMLLINT)"

# ==============================================================================
# Test
# ==============================================================================

.PHONY: test
test: test-bats test-pytest ## Run all tests (bats + pytest)

.PHONY: test-bats
test-bats: ## Run bats shell tests (requires bats-core)
	@if [[ -z "$(BATS)" ]]; then \
		echo "Error: bats not found (install: brew install bats-core)"; \
		exit 1; \
	fi
	"$(BATS)" "$(TESTS_DIR)/bats/"

.PHONY: test-pytest
test-pytest: ## Run Python tests with pytest
	@if [[ -z "$(PYTHON)" ]]; then \
		echo "Error: python3 not found"; \
		exit 1; \
	fi
	@if [[ -z "$(PYTEST)" ]]; then \
		echo "Error: pytest not found (install: pip install pytest)"; \
		exit 1; \
	fi
	"$(PYTHON)" -m pytest "$(TESTS_DIR)/python/" -v

# ==============================================================================
# Build and Distribution
# ==============================================================================

DIST_PACK_NAME    := $(PROJECT_NAME)-$(VERSION)
DIST_PACK_TARBALL := $(DIST_DIR)/$(DIST_PACK_NAME).tar.gz

.PHONY: dist
dist: ## Build self-contained ora-db-audit-<VERSION>.tar.gz for deployment
	@mkdir -p "$(DIST_DIR)"
	@stage="$$(mktemp -d -t ora_db_audit.XXXXXX)/$(DIST_PACK_NAME)"; \
	mkdir -p "$$stage/$(TOOLS_DIR)" "$$stage/$(SQL_DIR)"; \
	cp "$(BIN_DIR)/ora-db-audit.sh"            "$$stage/"; \
	chmod +x "$$stage/ora-db-audit.sh"; \
	cp $(SQL_DIR)/*.sql                        "$$stage/$(SQL_DIR)/"; \
	cp $(TOOLS_DIR)/*.py                       "$$stage/$(TOOLS_DIR)/"; \
	chmod 0644 "$$stage/$(TOOLS_DIR)/"*.py; \
	cp README.md LICENSE DISCLAIMER.md        "$$stage/"; \
	printf '%s\n' "$(VERSION)"                 > "$$stage/VERSION"; \
	printf '{"pack_name":"%s","version":"%s","built_at":"%s","entrypoint":"ora-db-audit.sh"}\n' \
		"$(DIST_PACK_NAME)" "$(VERSION)" \
		"$$(date -u '+%Y-%m-%dT%H:%M:%SZ')" > "$$stage/dist_manifest.json"; \
	tar -C "$$(dirname "$$stage")" -czf "$(DIST_PACK_TARBALL)" "$(DIST_PACK_NAME)"; \
	rm -rf "$$(dirname "$$stage")"; \
	echo "Built $(DIST_PACK_TARBALL)"; \
	echo "  layout: $(DIST_PACK_NAME)/{ora-db-audit.sh, sql/*.sql, tools/*.py}"; \
	echo "  entrypoint: ./ora-db-audit.sh --help"

.PHONY: dist-verify
dist-verify: ## Verify the built distribution tarball
	@if [[ ! -f "$(DIST_PACK_TARBALL)" ]]; then \
		echo "ERROR: $(DIST_PACK_TARBALL) not found - run 'make dist' first" >&2; \
		exit 1; \
	fi
	@echo "tarball: $(DIST_PACK_TARBALL)"
	@tar -tzf "$(DIST_PACK_TARBALL)" | sort
	@for f in ora-db-audit.sh tools/audit_report.py tools/anonymize_bundle.py; do \
		if ! tar -tzf "$(DIST_PACK_TARBALL)" | grep -q "$(DIST_PACK_NAME)/$$f$$"; then \
			echo "ERROR: $$f missing from tarball" >&2; \
			exit 1; \
		fi; \
	done; \
	echo "All required files present in tarball"

# ==============================================================================
# Cleanup
# ==============================================================================

.PHONY: clean
clean: ## Remove build artefacts and temporary files (safe, no confirmation)
	@find . -type d -name "__pycache__" -not -path "./.git/*" -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -not -path "./.git/*" -delete 2>/dev/null || true
	@find . -type f -name "*.tmp" -not -path "./.git/*" -delete 2>/dev/null || true
	@rm -rf "$(DIST_DIR)" 2>/dev/null || true
	@rm -f "$(TESTS_DIR)/fixtures/sample_bundle.tar.gz" 2>/dev/null || true
	@echo "Clean complete"

# ==============================================================================
# Version Management
# ==============================================================================

.PHONY: version
version: ## Show current version from VERSION file
	@echo "$(VERSION)"

.PHONY: check-version
check-version: ## Validate semantic version format in VERSION file
	@grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$$' VERSION \
		&& echo "Version is valid: $(VERSION)" \
		|| (echo "Invalid version format in VERSION"; exit 1)

.PHONY: version-bump-patch
version-bump-patch: ## Bump patch (0.0.X), update CHANGELOG, commit
	@"$(BUMP_SCRIPT)" patch; \
	version="$$(cat VERSION)"; \
	$(GIT) add VERSION CHANGELOG.md; \
	$(GIT) commit -m "chore: bump version to v$$version"; \
	echo "Bumped and committed: v$$version"; \
	echo "  Next: make tag"

.PHONY: version-bump-minor
version-bump-minor: ## Bump minor (0.X.0), update CHANGELOG, commit
	@"$(BUMP_SCRIPT)" minor; \
	version="$$(cat VERSION)"; \
	$(GIT) add VERSION CHANGELOG.md; \
	$(GIT) commit -m "chore: bump version to v$$version"; \
	echo "Bumped and committed: v$$version"; \
	echo "  Next: make tag"

.PHONY: version-bump-major
version-bump-major: ## Bump major (X.0.0), update CHANGELOG, commit
	@"$(BUMP_SCRIPT)" major; \
	version="$$(cat VERSION)"; \
	$(GIT) add VERSION CHANGELOG.md; \
	$(GIT) commit -m "chore: bump version to v$$version"; \
	echo "Bumped and committed: v$$version"; \
	echo "  Next: make tag"

# ==============================================================================
# Release Management
# ==============================================================================

.PHONY: tag
tag: ## Create git tag from VERSION (guards: clean tree + VERSION committed)
	@if [[ -z "$(GIT)" ]]; then echo "Error: git not found in PATH"; exit 1; fi; \
	version="$$(cat VERSION)"; \
	tag="v$$version"; \
	if ! $(GIT) diff --quiet HEAD 2>/dev/null; then \
		echo "Working tree is dirty - commit all changes before tagging:"; \
		$(GIT) status -sb; \
		exit 1; \
	fi; \
	committed="$$($(GIT) show HEAD:VERSION 2>/dev/null | tr -d '[:space:]')"; \
	if [[ "$$committed" != "$$version" ]]; then \
		echo "VERSION ($$version) not yet committed (HEAD has: $$committed)"; \
		echo "  Run: git add VERSION CHANGELOG.md && git commit -m 'chore: bump version to v$$version'"; \
		exit 1; \
	fi; \
	if $(GIT) rev-parse "$$tag" >/dev/null 2>&1; then \
		echo "Tag $$tag already exists"; \
		exit 1; \
	fi; \
	$(GIT) tag -a "$$tag" -m "Release $$tag"; \
	echo "Created tag $$tag"; \
	echo ""; \
	echo "  Push manually:"; \
	echo "    git push origin main"; \
	echo "    git push origin $$tag"

.PHONY: release
release: ## Full patch release: bump patch -> commit -> tag
	@echo "Starting patch release..."
	@$(MAKE) --no-print-directory version-bump-patch
	@$(MAKE) --no-print-directory tag
	@version="$$(cat VERSION)"; \
	echo "Release v$$version complete!"; \
	echo ""; \
	echo "  Push manually:"; \
	echo "    git push origin main"; \
	echo "    git push origin v$$version"

# ==============================================================================
# Info
# ==============================================================================

.PHONY: status
status: ## Show git status and current version
	@echo -e "$(COLOR_BOLD)Project status$(COLOR_RESET)"
	@echo "Version: $(VERSION)"
	@if [[ -n "$(GIT)" ]]; then \
		echo ""; \
		$(GIT) status -sb; \
	fi

# EOF --------------------------------------------------------------------------
