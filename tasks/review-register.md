# Review-Register - ora-db-audit

> Gepflegt von /repo-audit. IDs werden nie neu vergeben. Keine Task-Syntax.

- repo: ora-db-audit

## Befunde

### RA-ora-db-audit-001 - Kundendaten in der public Git-Historie (History-Scan, Orchestrator)

- status: offen
- schwere: kritisch
- rolle: security
- ort: docs/review-lens.md
- orte: tasks/prompt-concept-doc-blind-spot.md, docs/configuration.md, sql/19-offpath-candidates.sql,
  tools/audit_report.py, docs/use-cases/off-path-detection.md
- regel: inv-2
- gefunden: 2026-10-10
- beleg: b9e00ee tasks/prompt-concept-doc-blind-spot.md - Kundenname, Policy-Namen, EXCEPT-Ausnahmen, Pfad in
  Kundenablage (redigiert); 56af5e1 docs/configuration.md, sql/19-offpath-candidates.sql, tools/audit_report.py -
  Kunden-Host-Praefix; 56af5e1 docs/use-cases/off-path-detection.md - Kunden-Context-Name; Commit-Messages 29bc53a
  (Kundenname plus zwei DB-Namen) und 56af5e1 (Kunden-Host-Praefix)
- schwere-grund: ausnutzbar (Leser ordnet Kunde und Audit-Luecken einander zu, genau das Bedrohungsmodell der Linse),
  exponiert (Repo ist PUBLIC), keine kompensierende Kontrolle (Historie und Forks behalten die Werte) - alle drei Fragen
  ja

### RA-ora-db-audit-002 - Kein gitleaks-Config mit OCI-Regeln im Repo

- status: offen
- schwere: mittel
- rolle: security
- ort: .gitleaks.toml
- regel: ci-gate
- gefunden: 2026-10-10
- beleg: .gitleaks.toml fehlt - ls .gitleaks.toml: No such file or directory

### RA-ora-db-audit-003 - Kein Secret-Scan in der CI

- status: offen
- schwere: hoch
- rolle: security
- ort: .github/workflows/ci.yml
- regel: ci-gate
- gefunden: 2026-10-10
- beleg: .github/workflows/ci.yml - Jobs lint-markdown, lint-shell, test-bats, test-pytest, build-dist; grep -rl
  gitleaks .github/workflows liefert nichts

### RA-ora-db-audit-004 - Kein pre-commit-Hook fuer gitleaks

- status: offen
- schwere: mittel
- rolle: security
- ort: .pre-commit-config.yaml
- regel: ci-gate
- gefunden: 2026-10-10
- beleg: .pre-commit-config.yaml fehlt

### RA-ora-db-audit-005 - make lint und CI pruefen weder Python noch YAML

- status: offen
- schwere: mittel
- rolle: doku-tests
- ort: Makefile
- regel: lint-gate
- gefunden: 2026-10-10
- beleg: Makefile:120 - lint: lint-shell lint-markdown (ohne lint-yaml, kein Python-Linter); ruff check tools tests - 86
  Fehler; yamllint .yamllint - 1 Fehler; CLAUDE.md verlangt ruff- und mypy-sauberen Python-Code
