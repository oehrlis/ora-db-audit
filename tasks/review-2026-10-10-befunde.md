# Befunde 2026-10-10 (Init, Gate-Luecken und History-Scan)

- rollen: security, doku-tests
- commit: 630ff17

## Befunde

### F-01 - Kundendaten in der public Git-Historie (History-Scan, Orchestrator)

- schwere: kritisch
- rolle: security
- ort: docs/review-lens.md
- orte: tasks/prompt-concept-doc-blind-spot.md, docs/configuration.md, sql/19-offpath-candidates.sql,
  tools/audit_report.py, docs/use-cases/off-path-detection.md
- regel: INV-2
- beleg: b9e00ee tasks/prompt-concept-doc-blind-spot.md - Kundenname, Policy-Namen, EXCEPT-Ausnahmen,
  Pfad in Kundenablage (redigiert); 56af5e1 docs/configuration.md, sql/19-offpath-candidates.sql,
  tools/audit_report.py - Kunden-Host-Praefix; 56af5e1 docs/use-cases/off-path-detection.md -
  Kunden-Context-Name; Commit-Messages 29bc53a (Kundenname plus zwei DB-Namen) und 56af5e1
  (Kunden-Host-Praefix)
- schwere-grund: ausnutzbar (Leser ordnet Kunde und Audit-Luecken einander zu, genau das
  Bedrohungsmodell der Linse), exponiert (Repo ist PUBLIC), keine kompensierende Kontrolle
  (Historie und Forks behalten die Werte) - alle drei Fragen ja
- ausloeser: wenn jemand das public Repo klont oder die Commits auf GitHub liest, kann er den
  Kunden, seine DB-Namen, seine Policy-Namen und die bewussten Audit-Ausnahmen zuordnen
- aufwand: M
- fix: Owner-Entscheid - History-Umschreibung (filter-repo plus Force-Push, Forks pruefen) oder
  akzeptiert mit Begruendung; vorher Baum bereinigen

### F-02 - Kein gitleaks-Config mit OCI-Regeln im Repo

- schwere: mittel
- rolle: security
- ort: .gitleaks.toml
- regel: ci-gate
- beleg: .gitleaks.toml fehlt - ls .gitleaks.toml: No such file or directory
- ausloeser: wenn CI oder pre-commit gitleaks starten, laufen nur die Default-Regeln, die weder PARs
  noch OCIDs noch Kundennamen kennen
- aufwand: S
- fix: references/gitleaks-oci.toml als .gitleaks.toml uebernehmen

### F-03 - Kein Secret-Scan in der CI

- schwere: hoch
- rolle: security
- ort: .github/workflows/ci.yml
- regel: ci-gate
- beleg: .github/workflows/ci.yml - Jobs lint-markdown, lint-shell, test-bats, test-pytest, build-dist;
  grep -rl gitleaks .github/workflows liefert nichts
- ausloeser: wenn ein Commit ein Credential oder eine OCID enthaelt, geht er gruen durch die CI
  in ein public Repo
- aufwand: S
- fix: Job gitleaks (gepinnte Version, --config .gitleaks.toml, fetch-depth 0)

### F-04 - Kein pre-commit-Hook fuer gitleaks

- schwere: mittel
- rolle: security
- ort: .pre-commit-config.yaml
- regel: ci-gate
- beleg: .pre-commit-config.yaml fehlt
- ausloeser: wenn ein Secret oder Kundenname committet wird, faellt es erst nach dem Push in der
  CI auf - dann ist es in der public Historie
- aufwand: S
- fix: .pre-commit-config.yaml mit gitleaks-Hook (gepinnte rev)

### F-05 - make lint und CI pruefen weder Python noch YAML

- schwere: mittel
- rolle: doku-tests
- ort: Makefile
- regel: lint-gate
- beleg: Makefile:120 - lint: lint-shell lint-markdown (ohne lint-yaml, kein Python-Linter);
  ruff check tools tests - 86 Fehler; yamllint .yamllint - 1 Fehler; CLAUDE.md verlangt ruff- und
  mypy-sauberen Python-Code
- ausloeser: wenn Python-Code einen Fehler einfuehrt, den ruff faende, meldet make lint gruen
- aufwand: M
- fix: ruff-Befunde abbauen, dann lint-python (ruff) und lint-yaml in lint und CI aufnehmen
