# ---------------------------------------------------------------------------
# Makefile - ora-db-audit
#
# Slim scaffolding Makefile. Full release / packaging targets land in the
# follow-up development session (v0.2.0+).
#
# Conventions follow the OraDBA Makefile standard - see /makefile skill.
# ---------------------------------------------------------------------------

SHELL          := /bin/bash
.SHELLFLAGS    := -euo pipefail -c
.DEFAULT_GOAL  := help

# ---------------------------------------------------------------------------
# Variables
# ---------------------------------------------------------------------------

VERSION        := $(shell cat VERSION)
PROJECT_NAME   := ora-db-audit
DATE           := $(shell date +%Y-%m-%d)

# Tools (override on CLI if needed: e.g. make MARKDOWNLINT=mdl lint-md)
MARKDOWNLINT   ?= markdownlint
YAMLLINT       ?= yamllint
SHELLCHECK     ?= shellcheck

# ---------------------------------------------------------------------------
# Phony targets
# ---------------------------------------------------------------------------

.PHONY: help version lint lint-md lint-yaml lint-sh clean

# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------

help: ## Show this help
	@echo "$(PROJECT_NAME) $(VERSION) - available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

version: ## Print current version
	@echo "$(PROJECT_NAME) $(VERSION)"

lint: lint-md lint-yaml lint-sh ## Run all linters

lint-md: ## Lint markdown files
	@command -v $(MARKDOWNLINT) >/dev/null 2>&1 \
		|| { echo "markdownlint not installed - skipping"; exit 0; }
	$(MARKDOWNLINT) "**/*.md" --ignore node_modules

lint-yaml: ## Lint YAML files
	@command -v $(YAMLLINT) >/dev/null 2>&1 \
		|| { echo "yamllint not installed - skipping"; exit 0; }
	$(YAMLLINT) .

lint-sh: ## Lint shell scripts
	@command -v $(SHELLCHECK) >/dev/null 2>&1 \
		|| { echo "shellcheck not installed - skipping"; exit 0; }
	@find . -name "*.sh" -not -path "./.git/*" -print0 \
		| xargs -0 -r $(SHELLCHECK)

clean: ## Remove build artefacts and local workspace
	@rm -rf build/ dist/ workspace/* audit_bundle/ 2>/dev/null || true
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@echo "Cleaned."
