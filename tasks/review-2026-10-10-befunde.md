# Befunde 2026-10-10 (konsolidiert, quick)

- rollen: security, doku-tests
- commit: 44d06b2

## Befunde

### F-01 - Kundendaten in der public Git-Historie (History-Scan, Orchestrator)

- schwere: kritisch
- rolle: security
- ort: docs/review-lens.md
- orte: tasks/prompt-concept-doc-blind-spot.md, docs/configuration.md, sql/19-offpath-candidates.sql,
  tools/audit_report.py, docs/use-cases/off-path-detection.md
- regel: INV-2
- beleg: b9e00ee tasks/prompt-concept-doc-blind-spot.md - Kundenname, Policy-Namen, EXCEPT-Ausnahmen, Pfad in
  Kundenablage (redigiert); 56af5e1 docs/configuration.md, sql/19-offpath-candidates.sql, tools/audit_report.py -
  Kunden-Host-Praefix; 56af5e1 docs/use-cases/off-path-detection.md - Kunden-Context-Name; Commit-Messages 29bc53a
  (Kundenname plus zwei DB-Namen) und 56af5e1 (Kunden-Host-Praefix)
- schwere-grund: ausnutzbar (Leser ordnet Kunde und Audit-Luecken einander zu, das Bedrohungsmodell der Linse),
  exponiert (Repo ist PUBLIC), keine kompensierende Kontrolle (Historie und Forks behalten die Werte) - alle drei
  Fragen ja
- ausloeser: wenn jemand das public Repo klont oder die Commits auf GitHub liest, kann er den Kunden, seine DB-Namen,
  Policy-Namen und die bewussten Audit-Ausnahmen zuordnen
- aufwand: M
- fix: Owner-Entscheid - History-Umschreibung (filter-repo plus Force-Push, Forks pruefen) oder akzeptiert mit
  Begruendung; vorher Baum bereinigen

### F-02 - Kundenname, Kunden-Audit-Konfiguration und Kundenablage-Pfad im Baum

- schwere: kritisch
- rolle: security
- ort: tasks/prompt-concept-doc-blind-spot.md
- regel: INV-1
- beleg: tasks/prompt-concept-doc-blind-spot.md:13,137,140,159,161,165,168,196,209,210,256 - <Kundenkuerzel>,
  <Kunden-Policy-Praefix>_*, EXCEPT-Ausnahmen, Pfad in die Kundenablage (redigiert)
- schwere-grund: ausnutzbar (Audit-Ausnahmen eines benannten Kunden), exponiert (PUBLIC auf main), keine
  kompensierende Kontrolle - drei Mal ja, von review-security belegt
- ausloeser: wenn jemand die Datei auf main liest, erfaehrt er, welcher Kunde welche Policies deaktiviert hat und
  welche Accounts bewusst nicht auditiert werden
- aufwand: S
- fix: Datei aus dem Baum entfernen (Inhalt gehoert in die PKM-Projektnotiz); die Historie bleibt ein eigener
  Entscheid (F-01)

### F-03 - Kunden-abgeleitete Praefixe als Beispiele in Doku, SQL, Tools und Tests

- schwere: hoch
- rolle: security
- ort: docs/review-lens.md
- orte: docs/configuration.md, sql/19-offpath-candidates.sql, tools/audit_report.py,
  docs/use-cases/off-path-detection.md, bin/ora-db-audit.sh, CHANGELOG.md, docs/usage.md, sql/standalone/README.md,
  sql/standalone/blind-spot-cdb.sql, sql/standalone/blind-spot-pdb.sql, tests/python/test_blind_spot_rollup.py,
  tools/audit_report_messages.py
- regel: INV-1
- beleg: docs/configuration.md:128, sql/19-offpath-candidates.sql:39, tools/audit_report.py:464 -
  <Kunden-Host-Praefix>; docs/use-cases/off-path-detection.md:58-87 - <Kunden-Context>_CTX; bin/ora-db-audit.sh:158 -
  Wallet-Alias /@<Kunden-Context>; <Kunden-Schema-Praefix>_DEV_nn in 8 weiteren Dateien
- schwere-grund: Praefixe allein nennen den Kunden nicht; erst zusammen mit der kritischen tasks-Datei und der
  Historie entsteht die Zuordnung - Frage 1 allein nicht belegt
- ausloeser: wenn ein Leser das Kuerzel einem Unternehmen zuordnet, verraten die Beispiele dessen Host-, Context- und
  Account-Namensschema
- aufwand: M
- fix: ein Entscheid: generische Platzhalter (APP_DEV_nn, ^apphost, APP_AUDIT_CTX) in allen orte, Tests mit anpassen

### F-04 - Feste /tmp-Dateien werden als SYSDBA-SQL ausgefuehrt

- schwere: hoch
- rolle: security
- ort: sql/00-setup.sql
- regel: injection
- beleg: sql/00-setup.sql:26,34-52 - HOST echo ... > /tmp/oradba_params.sql 2>/dev/null, danach
  @@/tmp/oradba_params.sql; WHENEVER OSERROR CONTINUE
- schwere-grund: braucht einen lokalen Account auf dem DB-Host - plausibler Zusatzfehler, deshalb hoch, nicht kritisch
- ausloeser: wenn ein anderer lokaler Benutzer /tmp/oradba_*.sql vorher als eigene Datei anlegt, scheitert das
  Schreiben still und @@ fuehrt seine Datei in der SYSDBA-Session aus; parallele Laeufe uebernehmen die
  PDB-Umschaltung des anderen (falsch negativ)
- aufwand: S
- fix: Parameterdateien in ein per mktemp -d angelegtes, nur fuer den Aufrufer lesbares Verzeichnis schreiben, OSERROR
  dort auf EXIT

### F-05 - Connect-String mit Passwort in Log und argv

- schwere: hoch
- rolle: security
- ort: bin/ora-db-audit.sh
- orte: docs/installation.md
- regel: secret
- beleg: bin/ora-db-audit.sh:961 - log connect='${CONNECT}'; :357,1028,1035 - sqlplus -S -L "${CONNECT}"; :157 Hilfe
  nennt user/pw@tns; docs/installation.md:121 empfiehlt --connect mit <password>
- ausloeser: wenn der Operator user/passwort@db uebergibt, steht das Passwort im stderr-Log und fuer jeden lokalen
  Benutzer in ps
- aufwand: S
- fix: Connect-String vor dem Log maskieren, Passwort ueber /nolog plus CONNECT auf stdin, Doku auf Wallet als ersten
  Weg umstellen

### F-06 - Vermutung: Beispiel-Hostnamen aus echtem Kundenlog

- schwere: mittel
- rolle: security
- ort: docs/use-cases/audit-log-anonymisation.md
- regel: INV-1
- beleg: docs/use-cases/audit-log-anonymisation.md:35 - 'xa-prefixed' passt zum Kunden-Host-Praefix; :321-322 -
  K8s-Pod-Name und Batch-Job mit Epoch-Suffix (2026-05-12) und echt wirkenden Login-Zahlen
- ausloeser: wenn die Beispielzeilen aus dem Engagement-Log kopiert sind, liegen echte Kunden-Hostnamen im public Repo
- aufwand: S
- fix: Owner vergleicht mit dem Engagement-Log; bei Treffer durch synthetische Namen ersetzen

### F-07 - policy_ddl bleibt im .anon-Bundle Klartext (KEEP_MULTILINE unbekannt)

- schwere: hoch
- rolle: security
- ort: sql/16-policy-ddl.sql
- regel: INV-8
- beleg: sql/16-policy-ddl.sql - schema policy_ddl=KEEP_MULTILINE; tools/anonymize_bundle.py:97-100,137 -
  KEEP_MULTILINE fehlt in VALID_TYPES, wird KEEP; am Artefakt verifiziert (review-security, Fixture-Kopie):
  WHEN-Bedingung mit Host und App-User bleibt Klartext
- ausloeser: wenn ein Kunde das .anon-Bundle extern teilt, enthaelt die Policy-DDL Host-, User- und Schema-Namen im
  Klartext und hebt die Pseudonyme anderer Dateien auf
- aufwand: M
- fix: policy_ddl als REDACT oder mit PSEUDO-Parser behandeln; KEEP_MULTILINE implementieren oder entfernen

### F-08 - Anonymisierer ist fail-open

- schwere: hoch
- rolle: security
- ort: tools/anonymize_bundle.py
- orte: tools/anonymize_audit_log.py
- regel: INV-8
- beleg: tools/anonymize_bundle.py:137-144 - unbekannter Typ wird KEEP; :211-222,686-690 - CSV ohne Schema-Zeile wird
  roh kopiert; :393 - Preamble mit dbsid/pdb bleibt; tools/anonymize_audit_log.py:389-391 - --customer-prefix X laesst
  X_* im Klartext; Exit 0
- ausloeser: wenn eine neue Query ohne oder mit falscher Schema-Zeile hinzukommt, landen ihre Rohdaten unbemerkt im
  .anon-Bundle, und das Tool meldet Erfolg
- aufwand: M
- fix: fail-closed: unbekannter Typ und fehlende Schema-Zeile brechen mit Exit ungleich 0 ab; Preamble-Werte
  pseudonymisieren

### F-09 - Persoenliche DBA-Accounts bleiben im .anon-Bundle Klartext

- schwere: hoch
- rolle: security
- ort: sql/14-privileged-activity.sql
- regel: INV-8
- beleg: sql/14-privileged-activity.sql:27 - dbusername=KEEP; :52-59 Grantees der Kunden-DBA-Rollen; am Artefakt
  verifiziert: synthetischer Personen-Account bleibt Klartext
- ausloeser: wenn das .anon-Bundle geteilt wird, stehen persoenliche Accounts der Kunden-DBAs darin
- aufwand: S
- fix: dbusername als PSEUDO:DBUSER mit Whitelist fuer Oracle-Standardkonten

### F-10 - --ai ohne --anonymize schickt Rohdaten an die API

- schwere: mittel
- rolle: security
- ort: bin/ora-db-audit.sh
- regel: INV-8
- beleg: bin/ora-db-audit.sh:1067-1086 - --ai nutzt das Roh-Bundle, wenn --anonymize fehlt oder das .anon-Bundle
  fehlt; nur ein Log-Hinweis
- ausloeser: wenn der Operator --ai ohne --anonymize setzt, gehen Kundenwerte an einen externen Dienst
- aufwand: S
- fix: --ai erzwingt --anonymize oder verlangt ein explizites Opt-in; fehlendes .anon-Bundle bricht ab

### F-11 - Keine umask fuer Bundle, Log und mapping.json

- schwere: mittel
- rolle: security
- ort: bin/ora-db-audit.sh
- regel: privilege
- beleg: bin/ora-db-audit.sh - kein umask; tools/anonymize_bundle.py:490 schreibt mapping.json mit geerbter umask
  (Testlauf: -rw-rw-r--)
- ausloeser: wenn die umask des oracle-Benutzers 002 oder 022 ist, koennen andere lokale Benutzer Rohdaten und die
  Re-Identifikations-Tabelle lesen
- aufwand: S
- fix: umask 077 am Skriptanfang, mapping.json explizit 0600

### F-12 - Kein Secret-Scan in der CI

- schwere: hoch
- rolle: security
- ort: .github/workflows/ci.yml
- regel: ci-gate
- beleg: .github/workflows/ci.yml - Jobs lint-markdown, lint-shell, test-bats, test-pytest, build-dist; grep -rl
  gitleaks .github/workflows liefert nichts
- ausloeser: wenn ein Commit ein Credential, eine OCID oder einen Kundenablage-Pfad enthaelt, geht er gruen durch die
  CI in ein public Repo
- aufwand: S
- fix: Job gitleaks (gepinnte Version, --config .gitleaks.toml) - Vorschlag liegt als Patch vor

### F-13 - Kein pre-commit-Hook fuer gitleaks

- schwere: mittel
- rolle: security
- ort: .pre-commit-config.yaml
- regel: ci-gate
- beleg: .pre-commit-config.yaml fehlt
- ausloeser: wenn ein Secret oder Kundenname committet wird, faellt es erst nach dem Push auf - dann ist es in der
  public Historie
- aufwand: S
- fix: .pre-commit-config.yaml mit gitleaks-Hook (gepinnte rev) - Vorschlag liegt als Patch vor

### F-14 - make lint und CI pruefen weder Python noch YAML

- schwere: mittel
- rolle: doku-tests
- ort: Makefile
- orte: .github/workflows/ci.yml
- regel: lint-gate
- beleg: Makefile:120 - lint: lint-shell lint-markdown; ruff check tools tests - 86 Fehler; yamllint .yamllint - 1
  Fehler; .github/workflows/ci.yml ohne ruff/mypy; CLAUDE.md verlangt ruff- und mypy-sauber
- ausloeser: wenn Python-Code einen Fehler einfuehrt, den ruff faende, meldet make lint gruen
- aufwand: M
- fix: ruff-Befunde abbauen, dann lint-python und lint-yaml in lint und CI

### F-15 - GRANT-Liste fuer den Least-Privilege-User unvollstaendig, Fehler werden verschluckt

- schwere: hoch
- rolle: doku-tests
- ort: docs/installation.md
- regel: INV-5
- beleg: docs/installation.md:99-116 - es fehlen u.a. V$OPTION (sql/01-config.sql:100), V$PARAMETER (:103), SYS.AUD$
  (:71), DBA_OBJECTS (sql/02-storage.sql:197), DBA_USERS (sql/21-uncovered-users.sql:86), DBA_ROLES
  (sql/18-audit-roles.sql:70), CDB_PDBS/CDB_ROLE_PRIVS/CDB_USERS (sql/24-blind-spot-cdb.sql:76,125,139), CDB_ROLES
  (sql/26-policy-effectiveness-cdb.sql:108), SET CONTAINER (sql/00-setup.sql:44); sql/00-setup.sql:27 WHENEVER
  SQLERROR CONTINUE
- ausloeser: wenn ein Kunde genau die dokumentierten Rechte vergibt, liefern mehrere Queries still leer oder NULL, und
  der Report zeigt falsch negative Befunde
- aufwand: S
- fix: GRANT-Liste aus den sql/-Objekten neu ableiten, fehlende Rechte im Report sichtbar machen

### F-16 - README beantwortet die Privilegien-Frage nur fuer die Standalone-Skripte

- schwere: mittel
- rolle: doku-tests
- ort: README.md
- regel: INV-5
- beleg: README.md:94-95 - Privilegien nur fuer sql/standalone; Abschnitt How It Works (README.md:130-140) nennt keine
  Rechte des Tools
- schwere-grund: Invarianten-Bruch, aber docs/installation.md ist aus dem README verlinkt - kompensierende Kontrolle,
  deshalb mittel statt hoch
- ausloeser: wenn ein Reviewer beim Kunden die erste Frage stellt (welche DB-Rechte?), findet er im README keine
  Antwort
- aufwand: S
- fix: README-Abschnitt Required privileges: SYSDBA-Default, Least-Privilege-User mit Verweis auf docs/installation.md

### F-17 - DROP AUDIT POLICY ohne vorheriges NOAUDIT in den Fix-Beispielen

- schwere: mittel
- rolle: doku-tests
- ort: docs/false-positive-patterns.md
- regel: INV-6
- beleg: docs/false-positive-patterns.md:89,113,170,254,266,325 - DROP AUDIT POLICY als erster Schritt, kein NOAUDIT
  POLICY
- schwere-grund: review-docs schlug hoch vor; der Fehler ist laut und richtet keinen Schaden an - mittel
- ausloeser: wenn ein DBA das Beispiel auf einer aktivierten Policy ausfuehrt, bricht DROP mit ORA-46361 ab
- aufwand: S
- fix: vor jedes DROP ein NOAUDIT POLICY <policy_name> setzen

### F-18 - README und Installation nennen veraltete Werte

- schwere: mittel
- rolle: doku-tests
- ort: README.md
- orte: docs/installation.md
- regel: doc-drift
- beleg: README.md:137,169 - 25 Queries 00-24, es gibt 27 (00-26); README.md:51 und docs/installation.md:65 - Tarball
  v1.9.1, VERSION ist v1.10.2
- ausloeser: wenn ein Leser dem README folgt, entpackt er einen alten Tarball-Namen und kennt die
  Policy-Effectiveness-Queries nicht
- aufwand: S
- fix: Zahl und Version aus VERSION und sql/ ableiten oder generisch formulieren

### F-19 - SECURITY.md kennt nur Version 0.x

- schwere: mittel
- rolle: doku-tests
- ort: SECURITY.md
- regel: security-md
- beleg: SECURITY.md:4-6 - Tabelle nur 0.x Pre-release, Repo ist v1.10.2
- ausloeser: wenn ein Melder die unterstuetzte Version sucht, ist der Status von 1.x unbestimmt
- aufwand: S
- fix: Tabelle auf 1.10.x supported, aeltere nicht

### F-20 - CLAUDE.md verweist auf fehlendes INITIAL_PROMPT.md

- schwere: niedrig
- rolle: doku-tests
- ort: CLAUDE.md
- regel: orphan-doc
- beleg: CLAUDE.md:148 - Follow-up session briefing: INITIAL_PROMPT.md; Datei existiert nicht
- ausloeser: wenn eine Session dem Verweis folgt, findet sie nichts
- aufwand: S
- fix: Verweis entfernen

### F-21 - CLAUDE.md beschreibt .github als spaeter und Python 3.10+

- schwere: niedrig
- rolle: doku-tests
- ort: CLAUDE.md
- regel: doc-drift
- beleg: CLAUDE.md:23 - .github/ GitHub workflows (later), ci.yml existiert; CLAUDE.md:100 Python 3.10+ gegen
  docs/installation.md:22 Python 3.6
- ausloeser: wenn eine Session CLAUDE.md glaubt, plant sie an CI und Python-Baseline vorbei
- aufwand: S
- fix: Layout und Baseline nachziehen

### F-22 - anonymize_audit_log.py ohne Tests

- schwere: hoch
- rolle: doku-tests
- ort: tools/anonymize_audit_log.py
- regel: test-gap
- beleg: grep -rln anonymize_audit_log tests/ - keine Treffer; tests/python/test_anonymizer_roundtrip.py:1 testet nur
  anonymize_bundle.py
- ausloeser: wenn der Spool-Parser ein Muster nicht erkennt, gelangt der Wert unveraendert in die vermeintlich
  anonymisierte Ausgabe
- aufwand: M
- fix: Unit-Tests fuer FQDN, IPv4, Spalten-Extraktion, Whitelist und Wrap-Zeilen

### F-23 - deanonymize_report.py ohne Tests

- schwere: mittel
- rolle: doku-tests
- ort: tools/deanonymize_report.py
- regel: test-gap
- beleg: grep -rln deanonymize_report tests/ - keine Treffer
- ausloeser: wenn ein Mapping-Key fehlt oder kollidiert, stehen im Kundenreport falsche oder pseudonyme Namen
- aufwand: S
- fix: Roundtrip-Test anonymize, report, deanonymize

### F-24 - export_siem.py ohne Tests

- schwere: mittel
- rolle: doku-tests
- ort: tools/export_siem.py
- regel: test-gap
- beleg: grep -rln export_siem tests/ - keine Treffer
- ausloeser: wenn sich das Bundle-Schema aendert, liefert --export-siem still falsche Felder an das SIEM
- aufwand: S
- fix: Golden-File-Tests fuer ocsf und sentinel

### F-25 - Flag-Durchreichung zu audit_report.py ohne Regressionstest

- schwere: mittel
- rolle: doku-tests
- ort: tests/bats/test-cli-parse.bats
- regel: test-gap
- beleg: CLAUDE.md:91-93 - Known Trap, dreimal passiert (--lang, --export-prompt, --customer-prefix);
  tests/bats/test-cli-parse.bats - kein Test prueft die Weitergabe
- ausloeser: wenn ein neues Flag nicht durchgereicht wird, ignoriert der Report es still
- aufwand: S
- fix: bats-Test je Flag, der den audit_report.py-Aufruf im --dry-run prueft

### F-26 - CI testet die dokumentierte Python-Baseline nicht

- schwere: mittel
- rolle: doku-tests
- ort: .github/workflows/ci.yml
- orte: docs/installation.md, CLAUDE.md
- regel: test-gap
- beleg: .github/workflows/ci.yml:55 - Matrix 3.10-3.12; docs/installation.md:22 - Python 3.6 or later; CHANGELOG
  v1.9.1 - Feld-Bug auf 3.6 beim ersten Kundeneinsatz
- ausloeser: wenn Code eine neuere Syntax einfuehrt, faellt es erst auf dem Kunden-DB-Host auf - wie bei v1.9.0
- aufwand: S
- fix: Baseline entscheiden; bei 3.6 einen Syntax-Check in CI

### F-27 - Leere CSV nach SQL-Fehler wird nicht erkannt

- schwere: mittel
- rolle: doku-tests
- ort: tests/bats/test-from-bundle.bats
- regel: test-gap
- beleg: sql/00-setup.sql:27 - WHENEVER SQLERROR CONTINUE; tests/bats/test-from-bundle.bats - 5 Tests, alle mit
  vollstaendigem Fixture
- ausloeser: wenn ein Privileg fehlt, entsteht eine leere CSV und der Report meldet keine Events statt eines Fehlers -
  falsch negativ
- aufwand: M
- fix: Fixture mit leerer CSV, Report muss warnen

### F-28 - Whitelist-Bypass des Anonymisierers nicht negativ getestet

- schwere: mittel
- rolle: doku-tests
- ort: tests/python/test_anonymizer_roundtrip.py
- regel: test-gap
- beleg: tests/python/test_anonymizer_roundtrip.py:110 - prueft nur, dass Whitelist-Werte erhalten bleiben
- ausloeser: wenn ein Kundenname einem Whitelist-Muster aehnelt, bleibt er unbemerkt Klartext
- aufwand: S
- fix: Negativtest mit aehnlichen Nicht-System-Namen
