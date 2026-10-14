# Review-Register - ora-db-audit

> Gepflegt von /repo-audit. IDs werden nie neu vergeben. Keine Task-Syntax.

- repo: ora-db-audit

## Befunde

### RA-ora-db-audit-001 - Kundendaten in der public Git-Historie (History-Scan, Orchestrator)

- status: behoben
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
- schwere-grund: ausnutzbar (Leser ordnet Kunde und Audit-Luecken einander zu, das Bedrohungsmodell der Linse),
  exponiert (Repo ist PUBLIC), keine kompensierende Kontrolle (Historie und Forks behalten die Werte) - alle drei Fragen
  ja
- gesehen: 2026-10-10
- erledigt: 2026-10-14
- massnahme: History mit git filter-repo bereinigt, Repo auf GitHub geloescht und neu angelegt (29 Tags,
  24 Releases mit neu gebauten Assets, v1.10.1 latest; Entwurf v1.0.3 ohne Tag nicht neu angelegt)
- nachweis: frischer Clone 2026-10-14 - Resttreffer 0 in `git log --all -p` und 0 in `--format=%B`, 110 Commits,
  29 Tags auf origin, 0 Treffer in 50 Release-Assets und in den Release-Notes, gitleaks volle History gruen
- ci: gitleaks-Job scannt seit diesem Befund die volle History statt nur die Commits des Events
- rest: zweites Kunden-Host-Praefix ist nicht in der Begriffsliste des Rewrites, steht weiter in Baum und
  History - unter RA-ora-db-audit-007 offen
- kunde: falls er geklont hat, neu klonen lassen

### RA-ora-db-audit-002 - Kein gitleaks-Config mit OCI-Regeln im Repo

- status: behoben
- schwere: mittel
- rolle: security
- ort: .gitleaks.toml
- regel: ci-gate
- gefunden: 2026-10-10
- beleg: .gitleaks.toml fehlt - ls .gitleaks.toml: No such file or directory
- erledigt: 2026-10-10
- commit: 5c3c97b

### RA-ora-db-audit-003 - Kein Secret-Scan in der CI

- status: behoben
- schwere: hoch
- rolle: security
- ort: .github/workflows/ci.yml
- regel: ci-gate
- gefunden: 2026-10-10
- beleg: .github/workflows/ci.yml - Jobs lint-markdown, lint-shell, test-bats, test-pytest, build-dist; grep -rl
  gitleaks .github/workflows liefert nichts
- gesehen: 2026-10-10
- erledigt: 2026-10-10
- commit: 527721f

### RA-ora-db-audit-004 - Kein pre-commit-Hook fuer gitleaks

- status: behoben
- schwere: mittel
- rolle: security
- ort: .pre-commit-config.yaml
- regel: ci-gate
- gefunden: 2026-10-10
- beleg: .pre-commit-config.yaml fehlt
- gesehen: 2026-10-10
- erledigt: 2026-10-10
- commit: 527721f

### RA-ora-db-audit-005 - make lint und CI pruefen weder Python noch YAML

- status: offen
- schwere: mittel
- rolle: doku-tests
- ort: Makefile
- regel: lint-gate
- gefunden: 2026-10-10
- beleg: Makefile:120 - lint: lint-shell lint-markdown; ruff check tools tests - 86 Fehler; yamllint .yamllint - 1
  Fehler; .github/workflows/ci.yml ohne ruff/mypy; CLAUDE.md verlangt ruff- und mypy-sauber
- orte: .github/workflows/ci.yml
- gesehen: 2026-10-10

### RA-ora-db-audit-006 - Kundenname, Kunden-Audit-Konfiguration und Kundenablage-Pfad im Baum

- status: behoben
- schwere: kritisch
- rolle: security
- ort: tasks/prompt-concept-doc-blind-spot.md
- regel: inv-1
- gefunden: 2026-10-10
- beleg: tasks/prompt-concept-doc-blind-spot.md:13,137,140,159,161,165,168,196,209,210,256 - <Kundenkuerzel>,
  <Kunden-Policy-Praefix>_*, EXCEPT-Ausnahmen, Pfad in die Kundenablage (redigiert)
- schwere-grund: ausnutzbar (Audit-Ausnahmen eines benannten Kunden), exponiert (PUBLIC auf main), keine kompensierende
  Kontrolle - drei Mal ja, von review-security belegt
- erledigt: 2026-10-10
- commit: ab33ed4

### RA-ora-db-audit-007 - Kunden-abgeleitete Praefixe als Beispiele in Doku, SQL, Tools und Tests

- status: offen
- schwere: hoch
- rolle: security
- ort: docs/review-lens.md
- orte: docs/configuration.md, sql/19-offpath-candidates.sql, tools/audit_report.py,
  docs/use-cases/off-path-detection.md, bin/ora-db-audit.sh, CHANGELOG.md, docs/usage.md, sql/standalone/README.md,
  sql/standalone/blind-spot-cdb.sql, sql/standalone/blind-spot-pdb.sql, tests/python/test_blind_spot_rollup.py,
  tools/audit_report_messages.py
- regel: inv-1
- gefunden: 2026-10-10
- beleg: docs/configuration.md:128, sql/19-offpath-candidates.sql:39, tools/audit_report.py:464 - <Kunden-Host-Praefix>;
  docs/use-cases/off-path-detection.md:58-87 - <Kunden-Context>_CTX; bin/ora-db-audit.sh:158 - Wallet-Alias
  /@<Kunden-Context>; <Kunden-Schema-Praefix>_DEV_nn in 8 weiteren Dateien
- schwere-grund: Praefixe allein nennen den Kunden nicht; erst zusammen mit der kritischen tasks-Datei und der Historie
  entsteht die Zuordnung - Frage 1 allein nicht belegt
- nachtrag: 2026-10-14 - zweites Kunden-Host-Praefix (<zweites Kunden-Host-Praefix>) zugeordnet, steht in
  docs/configuration.md, sql/19-offpath-candidates.sql, tools/audit_report.py; nicht von der Begriffsliste des
  Rewrites (RA-ora-db-audit-001) erfasst, daher auch weiter in der History - bleibt offen
- gesehen: 2026-10-14

### RA-ora-db-audit-008 - Feste /tmp-Dateien werden als SYSDBA-SQL ausgefuehrt

- status: offen
- schwere: hoch
- rolle: security
- ort: sql/00-setup.sql
- regel: injection
- gefunden: 2026-10-10
- beleg: sql/00-setup.sql:26,34-52 - HOST echo ... > /tmp/oradba_params.sql 2>/dev/null, danach
  @@/tmp/oradba_params.sql; WHENEVER OSERROR CONTINUE
- schwere-grund: braucht einen lokalen Account auf dem DB-Host - plausibler Zusatzfehler, deshalb hoch, nicht kritisch

### RA-ora-db-audit-009 - Connect-String mit Passwort in Log und argv

- status: offen
- schwere: hoch
- rolle: security
- ort: bin/ora-db-audit.sh
- orte: docs/installation.md
- regel: secret
- gefunden: 2026-10-10
- beleg: bin/ora-db-audit.sh:961 - log connect='${CONNECT}'; :357,1028,1035 - sqlplus -S -L "${CONNECT}"; :157 Hilfe
  nennt user/pw@tns; docs/installation.md:121 empfiehlt --connect mit <password>

### RA-ora-db-audit-010 - Vermutung: Beispiel-Hostnamen aus echtem Kundenlog

- status: offen
- schwere: mittel
- rolle: security
- ort: docs/use-cases/audit-log-anonymisation.md
- regel: inv-1
- gefunden: 2026-10-10
- beleg: docs/use-cases/audit-log-anonymisation.md:35 - 'xa-prefixed' passt zum Kunden-Host-Praefix; :321-322 -
  K8s-Pod-Name und Batch-Job mit Epoch-Suffix (2026-05-12) und echt wirkenden Login-Zahlen

### RA-ora-db-audit-011 - policy_ddl bleibt im .anon-Bundle Klartext (KEEP_MULTILINE unbekannt)

- status: offen
- schwere: hoch
- rolle: security
- ort: sql/16-policy-ddl.sql
- regel: inv-8
- gefunden: 2026-10-10
- beleg: sql/16-policy-ddl.sql - schema policy_ddl=KEEP_MULTILINE; tools/anonymize_bundle.py:97-100,137 - KEEP_MULTILINE
  fehlt in VALID_TYPES, wird KEEP; am Artefakt verifiziert (review-security, Fixture-Kopie): WHEN-Bedingung mit Host und
  App-User bleibt Klartext

### RA-ora-db-audit-012 - Anonymisierer ist fail-open

- status: offen
- schwere: hoch
- rolle: security
- ort: tools/anonymize_bundle.py
- orte: tools/anonymize_audit_log.py
- regel: inv-8
- gefunden: 2026-10-10
- beleg: tools/anonymize_bundle.py:137-144 - unbekannter Typ wird KEEP; :211-222,686-690 - CSV ohne Schema-Zeile wird
  roh kopiert; :393 - Preamble mit dbsid/pdb bleibt; tools/anonymize_audit_log.py:389-391 - --customer-prefix X laesst
  X_* im Klartext; Exit 0

### RA-ora-db-audit-013 - Persoenliche DBA-Accounts bleiben im .anon-Bundle Klartext

- status: offen
- schwere: hoch
- rolle: security
- ort: sql/14-privileged-activity.sql
- regel: inv-8
- gefunden: 2026-10-10
- beleg: sql/14-privileged-activity.sql:27 - dbusername=KEEP; :52-59 Grantees der Kunden-DBA-Rollen; am Artefakt
  verifiziert: synthetischer Personen-Account bleibt Klartext

### RA-ora-db-audit-014 - --ai ohne --anonymize schickt Rohdaten an die API

- status: offen
- schwere: mittel
- rolle: security
- ort: bin/ora-db-audit.sh
- regel: inv-8
- gefunden: 2026-10-10
- beleg: bin/ora-db-audit.sh:1067-1086 - --ai nutzt das Roh-Bundle, wenn --anonymize fehlt oder das .anon-Bundle fehlt;
  nur ein Log-Hinweis

### RA-ora-db-audit-015 - Keine umask fuer Bundle, Log und mapping.json

- status: offen
- schwere: mittel
- rolle: security
- ort: bin/ora-db-audit.sh
- regel: privilege
- gefunden: 2026-10-10
- beleg: bin/ora-db-audit.sh - kein umask; tools/anonymize_bundle.py:490 schreibt mapping.json mit geerbter umask
  (Testlauf: -rw-rw-r--)

### RA-ora-db-audit-016 - GRANT-Liste fuer den Least-Privilege-User unvollstaendig, Fehler werden verschluckt

- status: offen
- schwere: hoch
- rolle: doku-tests
- ort: docs/installation.md
- regel: inv-5
- gefunden: 2026-10-10
- beleg: docs/installation.md:99-116 - es fehlen u.a. V$OPTION (sql/01-config.sql:100), V$PARAMETER (:103), SYS.AUD$
  (:71), DBA_OBJECTS (sql/02-storage.sql:197), DBA_USERS (sql/21-uncovered-users.sql:86), DBA_ROLES
  (sql/18-audit-roles.sql:70), CDB_PDBS/CDB_ROLE_PRIVS/CDB_USERS (sql/24-blind-spot-cdb.sql:76,125,139), CDB_ROLES
  (sql/26-policy-effectiveness-cdb.sql:108), SET CONTAINER (sql/00-setup.sql:44); sql/00-setup.sql:27 WHENEVER SQLERROR
  CONTINUE

### RA-ora-db-audit-017 - README beantwortet die Privilegien-Frage nur fuer die Standalone-Skripte

- status: offen
- schwere: mittel
- rolle: doku-tests
- ort: README.md
- regel: inv-5
- gefunden: 2026-10-10
- beleg: README.md:94-95 - Privilegien nur fuer sql/standalone; Abschnitt How It Works (README.md:130-140) nennt keine
  Rechte des Tools
- schwere-grund: Invarianten-Bruch, aber docs/installation.md ist aus dem README verlinkt - kompensierende Kontrolle,
  deshalb mittel statt hoch

### RA-ora-db-audit-018 - DROP AUDIT POLICY ohne vorheriges NOAUDIT in den Fix-Beispielen

- status: offen
- schwere: mittel
- rolle: doku-tests
- ort: docs/false-positive-patterns.md
- regel: inv-6
- gefunden: 2026-10-10
- beleg: docs/false-positive-patterns.md:89,113,170,254,266,325 - DROP AUDIT POLICY als erster Schritt, kein NOAUDIT
  POLICY
- schwere-grund: review-docs schlug hoch vor; der Fehler ist laut und richtet keinen Schaden an - mittel

### RA-ora-db-audit-019 - README und Installation nennen veraltete Werte

- status: offen
- schwere: mittel
- rolle: doku-tests
- ort: README.md
- orte: docs/installation.md
- regel: doc-drift
- gefunden: 2026-10-10
- beleg: README.md:137,169 - 25 Queries 00-24, es gibt 27 (00-26); README.md:51 und docs/installation.md:65 - Tarball
  v1.9.1, VERSION ist v1.10.2

### RA-ora-db-audit-020 - SECURITY.md kennt nur Version 0.x

- status: offen
- schwere: mittel
- rolle: doku-tests
- ort: SECURITY.md
- regel: security-md
- gefunden: 2026-10-10
- beleg: SECURITY.md:4-6 - Tabelle nur 0.x Pre-release, Repo ist v1.10.2

### RA-ora-db-audit-021 - CLAUDE.md verweist auf fehlendes INITIAL_PROMPT.md

- status: offen
- schwere: niedrig
- rolle: doku-tests
- ort: CLAUDE.md
- regel: orphan-doc
- gefunden: 2026-10-10
- beleg: CLAUDE.md:148 - Follow-up session briefing: INITIAL_PROMPT.md; Datei existiert nicht

### RA-ora-db-audit-022 - CLAUDE.md beschreibt .github als spaeter und Python 3.10+

- status: offen
- schwere: niedrig
- rolle: doku-tests
- ort: CLAUDE.md
- regel: doc-drift
- gefunden: 2026-10-10
- beleg: CLAUDE.md:23 - .github/ GitHub workflows (later), ci.yml existiert; CLAUDE.md:100 Python 3.10+ gegen
  docs/installation.md:22 Python 3.6

### RA-ora-db-audit-023 - anonymize_audit_log.py ohne Tests

- status: offen
- schwere: hoch
- rolle: doku-tests
- ort: tools/anonymize_audit_log.py
- regel: test-gap
- gefunden: 2026-10-10
- beleg: grep -rln anonymize_audit_log tests/ - keine Treffer; tests/python/test_anonymizer_roundtrip.py:1 testet nur
  anonymize_bundle.py

### RA-ora-db-audit-024 - deanonymize_report.py ohne Tests

- status: offen
- schwere: mittel
- rolle: doku-tests
- ort: tools/deanonymize_report.py
- regel: test-gap
- gefunden: 2026-10-10
- beleg: grep -rln deanonymize_report tests/ - keine Treffer

### RA-ora-db-audit-025 - export_siem.py ohne Tests

- status: offen
- schwere: mittel
- rolle: doku-tests
- ort: tools/export_siem.py
- regel: test-gap
- gefunden: 2026-10-10
- beleg: grep -rln export_siem tests/ - keine Treffer

### RA-ora-db-audit-026 - Flag-Durchreichung zu audit_report.py ohne Regressionstest

- status: offen
- schwere: mittel
- rolle: doku-tests
- ort: tests/bats/test-cli-parse.bats
- regel: test-gap
- gefunden: 2026-10-10
- beleg: CLAUDE.md:91-93 - Known Trap, dreimal passiert (--lang, --export-prompt, --customer-prefix);
  tests/bats/test-cli-parse.bats - kein Test prueft die Weitergabe

### RA-ora-db-audit-027 - CI testet die dokumentierte Python-Baseline nicht

- status: offen
- schwere: mittel
- rolle: doku-tests
- ort: .github/workflows/ci.yml
- orte: docs/installation.md, CLAUDE.md
- regel: test-gap
- gefunden: 2026-10-10
- beleg: .github/workflows/ci.yml:55 - Matrix 3.10-3.12; docs/installation.md:22 - Python 3.6 or later; CHANGELOG
  v1.9.1 - Feld-Bug auf 3.6 beim ersten Kundeneinsatz

### RA-ora-db-audit-028 - Leere CSV nach SQL-Fehler wird nicht erkannt

- status: offen
- schwere: mittel
- rolle: doku-tests
- ort: tests/bats/test-from-bundle.bats
- regel: test-gap
- gefunden: 2026-10-10
- beleg: sql/00-setup.sql:27 - WHENEVER SQLERROR CONTINUE; tests/bats/test-from-bundle.bats - 5 Tests, alle mit
  vollstaendigem Fixture

### RA-ora-db-audit-029 - Whitelist-Bypass des Anonymisierers nicht negativ getestet

- status: offen
- schwere: mittel
- rolle: doku-tests
- ort: tests/python/test_anonymizer_roundtrip.py
- regel: test-gap
- gefunden: 2026-10-10
- beleg: tests/python/test_anonymizer_roundtrip.py:110 - prueft nur, dass Whitelist-Werte erhalten bleiben
