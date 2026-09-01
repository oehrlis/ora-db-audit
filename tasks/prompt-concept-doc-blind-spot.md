# Prompt: Konzeptdoku auf den Blind-Spot-Zusammenzug nachziehen

> Erzeugt am 2026-09-01 aus der Session, die `sql/standalone/blind-spot-*.sql`
> von einer Zeile-pro-User-Liste auf einen Zusammenzug umgebaut und die
> Policy-Wirksamkeit ergänzt hat. Zielversion: `ora-db-audit` **1.10.0**.
> In einer Session im Repo `ora-db-audit-eng` verwenden.

---

## Kontext

Im Tool-Repo `~/Repos/own/oehrlis/ora-db-audit` wurde der Blind-Spot-Report
umgebaut. Die Doku in `ora-db-audit-eng` und beim Kunden EJPD beschreibt noch
den alten Stand - und an einer Stelle sachlich falsch, was der Report
überhaupt tut.

### Was sich geändert hat

1. **`sql/23-blind-spot-pdb.sql` / `sql/24-blind-spot-cdb.sql`** (CSV-Sammlung)
   sind inhaltlich unverändert, haben aber **drei neue abgeleitete Spalten**
   am Ende:

   <!-- markdownlint-disable MD013 MD060 -->

   | Spalte | Werte | Regel |
   | --- | --- | --- |
   | `account_class` | `CUSTOMER`, `ORACLE` | `ORACLE` wenn `oracle_maintained = 'Y'` |
   | `login_enabled` | `Y`, `N` | `N` wenn `account_status` `LOCKED` enthält |
   | `actionable` | `Y`, `N` | `Y` wenn `BLIND_SPOT` **und** `CUSTOMER` **und** `login_enabled = Y` |

   <!-- markdownlint-restore -->

   `actionable = Y` ist der Befund. Alles andere ist Kontext.
   Der `# schema:`-Preamble ist entsprechend erweitert (additiv, bestehende
   Spalten und ihre Reihenfolge unverändert).

2. **`sql/standalone/blind-spot-pdb.sql` / `blind-spot-cdb.sql`** sind keine
   Kopie der CSV-Query mehr, sondern ein read-only PL/SQL-Block mit vier
   Ausgabeblöcken:

   - **A Scorecard** - Policy-Anzahl, User-Anzahl, Coverage-Prozent, Blind
     Spots, davon handlungsrelevant
   - **F Container-Matrix** (nur CDB-Script) - eine Zeile pro offenem Container
     mit Spalte `POL` (aktive Customer-Policies in diesem Container)
   - **B Abdeckungsmatrix** - Accountklasse x Anmeldefähigkeit x Coverage-Status
   - **C Blind Spots** - nur die handlungsrelevanten Accounts

   Steuerung über `DEFINE bs_scope` (`ACTIONABLE` / `CUSTOMER` / `ALL`) und
   `DEFINE bs_max_rows`. Jede unterdrückte Zeile wird mit Anzahl und dem
   Schalter benannt, der sie sichtbar macht.

3. **`tools/audit_report.py` Sektion 7.4** nutzt exakt dasselbe Layout, damit
   ein Screen-Run und ein ausgelieferter Report nicht auseinanderlaufen
   können. `EXCLUDED_EXCEPT` wird nach der Policy gruppiert, aus der
   ausgenommen wird, statt eine Zeile pro User.

4. **Executive-Summary-Metrik** lautet jetzt `40 (davon handlungsrelevant: 4)`
   statt nur `40`.

### Warum

Auf einer Datenbank mit ~250 Accounts produzierte die alte Standalone-Variante
~250 Zeilen (CDB-weit ~1000). Die Mehrheit davon sind gesperrte Alt-Accounts
und Oracle-Schemas, die von `ORA_SECURECONFIG` abgedeckt sind. Die Handvoll
Accounts, die eine Entscheidung braucht, war darin nicht zu finden.

### Verifiziert gegen

Lab `auditlab-db` (Oracle FREE, CDB mit `AUDITPDB1`). Standalone-Ausgabe,
CSV-Query und Python-Report liefern identische Zahlen:
88 User-Container-Zeilen, 18 Customer, 14 abgedeckt, 40 Blind Spots, davon
4 handlungsrelevant. Der Befund im Lab ist eine einzige Zeile in Block F:
`CDB$ROOT` hat `POL = 0` - keine einzige Customer-Policy - und vier
Common-Accounts, die sich anmelden können, sind unauditiert.

---

## Aufgabe 1: `ora-db-audit-eng`

Datei: `doc/09_implementation_steps.md`, Abschnitt **7.4 Blind-Spot-Analyse**
(ca. Zeile 417-450).

### 1a. Sachfehler korrigieren

Der Abschnitt behauptet aktuell:

> Der Report vergleicht die aktiven Policies gegen einen Katalog
> sicherheitsrelevanter Aktionen und weist die nicht abgedeckten Bereiche aus.

**Das ist falsch.** Der Blind-Spot-Report vergleicht **Datenbankbenutzer**
gegen die **Entity-Zuweisung** der aktiven Policies (`BY USER`,
`BY GRANTED ROLE` inkl. transitiver Rollenauflösung und `PUBLIC`,
`EXCEPT USER`). Er beantwortet "wer wird auditiert und wer nicht", nicht
"welche Aktionen sind abgedeckt".

Der Aktions-/Kontrollkatalog-Vergleich ist ein **anderer** Report:
`sql/17-cis-coverage.sql`. Beide Abschnitte sollten sich gegenseitig
referenzieren und die Abgrenzung benennen - das ist die Verwechslung, die
zum Fehler geführt hat.

### 1b. Abschnitt inhaltlich erweitern

- Die vier Ausgabeblöcke A/F/B/C beschreiben, inklusive einem echten
  Beispiel-Output (aus `sql/standalone/README.md`, Abschnitt "Example Output"
  übernehmen - das ist verifizierte Lab-Ausgabe, keine erfundene).
- Die Triage-Regel `actionable` als Tabelle aufnehmen (siehe oben). Kernsatz:
  ein Blind Spot auf einem gesperrten Account ist Housekeeping, kein Risiko -
  aber er muss trotzdem gezählt und benannt werden, nicht weggefiltert.
- Die Abgrenzung CSV vs. Standalone klarstellen: `sql/23`/`24` sind für die
  Datensammlung und die Report-Pipeline, `sql/standalone/*` für das Lesen in
  einer laufenden Session. Beide liefern dieselben Zahlen.
- `bs_scope` / `bs_max_rows` dokumentieren.
- Bei den "erwarteten bekannten Lücken" ergänzen: `POL = 0` in einem
  Container ist kein User-Befund, sondern ein Konfigurationsbefund - dort
  kann per Konstruktion niemand abgedeckt sein. Das ist ein typischer Fund in
  `CDB$ROOT`, wenn alle Policies lokal in den PDBs angelegt wurden.
- Die Versionsangabe "ab Version 1.9.0" auf **1.10.0** anheben. Zusammenzug,
  Block D und Block E sind alle in `ora-db-audit` 1.10.0 enthalten (siehe
  dortiges `CHANGELOG.md`).

### 1c. Querverweise prüfen

`grep -rn -i "blind" doc/` und in jeder Trefferstelle prüfen, ob die
Beschreibung noch stimmt. Bekannte Kandidaten:

- `doc/11_audit_process.md:54` - P1-Ergebnis "Blind-Spot-Liste". Passt, aber
  präzisieren: das Ergebnis ist die handlungsrelevante Liste, nicht alle.
- `doc/11_audit_process.md:120,128,133` - Prüfen, ob "Blind Spots suchen" und
  "GAP-nn"-Liste die neue Triage widerspiegeln.
- `doc/01_management_summary.md:43,49` - D-05 / D-11 nutzen "blind" /
  "Blindspot" in anderer Bedeutung (fachliche Lücke, nicht Report-Status).
  Nicht anfassen, aber prüfen, ob eine Begriffsklärung nötig ist, damit
  "Blind Spot" im Dokument nicht zwei Dinge bedeutet.

---

## Aufgabe 2: EJPD-Kundendoku

Verzeichnis:
`~/Library/CloudStorage/OneDrive-Accenture/20_Customers/Active/EJPD/10_Arbeitsresultate/ejpd_audit`

Zuerst `grep -rn -i "blind" .` über `analysis/` und die Doku-Verzeichnisse,
dann gezielt anpassen. Erwartete Kandidaten:

- `analysis/sql_script_inventory.md` und `analysis/audit_script_status.md` -
  Beschreibung von Query 23/24 und der Standalone-Varianten auf den neuen
  Stand bringen, neue Spalten aufnehmen, und die **neuen Queries 25/26**
  (Policy-Wirksamkeit) als Einträge ergänzen.
- `analysis/phase-1-output.md` / `phase-2-output.md` / `phase-3-output.md` -
  falls dort Blind-Spot-Ergebnisse als Volllisten stehen: auf die
  handlungsrelevante Teilmenge umstellen und die Gesamtzahl daneben nennen.
  **Nicht** stillschweigend Zeilen entfernen - die Zahl der nicht
  aufgelisteten muss dastehen.
- `analysis/implementation-plan.md` - falls ein Schritt "Blind-Spot-Report
  ausführen" enthält, um `bs_scope` und die Interpretation ergänzen.
- `analysis/project_handover.md` - der Handover muss erklären, wie der Report
  zu lesen ist, sonst liest der Kunde 250 Zeilen als 250 Probleme.

Wichtig für EJPD-spezifisch:

- EJPD hat `ISC_*`-Policies, `ORA_*` sind alle deaktiviert. Das heisst
  `ora_supplied_cover` ist dort meist `NO` - ein `BLIND_SPOT` ist dort also
  wirklich unbeobachtet, nicht durch eine Oracle-Baseline abgefedert. Diesen
  Unterschied zur Default-Annahme explizit benennen.
- Die `ISC_DEV_*`- und `%_APPUSER%`-Accountklassen aus
  `analysis/audit-scope-overview-2026-07-02.md` sind genau der Fall, für den
  eine Gruppierung nach Namensmuster gedacht ist (siehe offener Punkt unten).
- Die `EXCEPT`-Ausnahmen (ATTUNITY, DBSNMP/SYSMAN, On-Path-App-User) müssen
  als `EXCLUDED_EXCEPT` erscheinen, nicht als Blind Spot. Gegenprüfen, dass
  das im letzten Bundle so ist.

---

## Randbedingungen

- Markdown nach `markdownlint` MD013 `line_length: 120`.
- Lange Tabellen mit einem `markdownlint-disable MD013 MD060`-Kommentar
  öffnen und mit einem `markdownlint-restore`-Kommentar schliessen.
  **Niemals** mit `enable` schliessen - `enable` reaktiviert Regeln mit
  Default-Parametern und setzt `line_length` auf 80 zurück.
- Nur Bindestrich, keine Halbgeviert-/Geviertstriche.
- Deutsch mit Schweizer Konvention: immer "ss", nie "ß".
- Keine erfundenen Zahlen. Beispielausgaben aus
  `ora-db-audit/sql/standalone/README.md` übernehmen (verifizierte
  Lab-Ausgabe) oder den Report neu gegen `auditlab-db` laufen lassen.
- `CHANGELOG.md` in `ora-db-audit-eng` nachziehen.

## Zusätzlich in 1.10.0: Block D und E

Beide zunächst zurückgestellten Blöcke sind implementiert und müssen in der
Doku auftauchen.

### Block D - Namensmuster-Gruppierung

Fasst die handlungsrelevanten Blind Spots nach Namensmuster zusammen:
`ISC_DEV_01` .. `ISC_DEV_40` ist ein Befund mit einer Massnahme, nicht 40
Zeilen. Im CDB-Script zeigt eine Spalte `PDBS`, in wie vielen Containern das
Muster auftritt.

Regel bewusst konservativ - ein zu grobes Muster würde einen Einzelbefund in
einer Gruppe verstecken:

- nur eine **abschliessende** Ziffernfolge wird zu `*`
- Stamm mindestens 4 Zeichen (`X9` bleibt ungruppiert)
- Muster unter `grp_min` (Default 3) ist keine Gruppe; seine Mitglieder fallen
  in `(ungruppiert)` zurück, damit Mitglieder + ungruppiert immer der
  handlungsrelevanten Gesamtzahl entsprechen

**Für EJPD relevant:** genau die Klassen aus
`analysis/audit-scope-overview-2026-07-02.md` (`ISC_DEV_*`, `%_APPUSER`,
`%_APPUSER_PAAS`, `%_APPBATCH`, `%_BATCH_%`, `%_IMPORT`). Bei der Doku darauf
achten: die Gruppierung braucht **echte** Kontonamen. Im anonymisierten Bundle
ist jeder Principal `DBUSER_nnn` und alle Muster sind zerstört - der Report
erkennt das und meldet, dass nicht gruppiert wurde, statt eine sinnlose
Sammelgruppe zu drucken. Praktisch heisst das: Gruppierung nur über die
Standalone-Scripte auf dem DB-System.

### Block E - Policy-Wirksamkeit

Neue Queries `sql/25-policy-effectiveness.sql` und
`sql/26-policy-effectiveness-cdb.sql`, Block E im Standalone, Abschnitt 7.5 im
Report.

Beantwortet die Umkehrfrage: nicht "wer ist unauditiert", sondern "welche
aktivierte Policy erreicht niemanden". Eine Policy auf einen gelöschten
Benutzer oder eine Rolle ohne Grantees ist aktiv, sieht in
`AUDIT_UNIFIED_ENABLED_POLICIES` korrekt aus und auditiert nichts. Query 23/24
kann das strukturell nicht zeigen.

<!-- markdownlint-disable MD013 MD060 -->

| Verdict | Bedeutung | Befund? |
| --- | --- | --- |
| `ENTITY_MISSING` | benannter User/Rolle existiert nicht | **ja** |
| `ROLE_NO_GRANTEES` | Rolle existiert, kein Konto hält sie (transitiv, PUBLIC eingerechnet) | **ja** |
| `NO_USERS` | löst auf, erreicht kein Konto | **ja** |
| `EXCLUSION_DEAD` | `EXCEPT` auf nicht existierenden User - Drift-Marker | nein |
| `EXCLUSION` | `EXCEPT`, Entity existiert | nein |
| `ALL_USERS` | unbeschränkte Aktivierung | nein |
| `OK` | löst auf, erreicht mindestens ein Konto | nein |

<!-- markdownlint-restore -->

Zwei Punkte, die in der Doku stehen müssen:

1. **Granularität**: eine Zeile pro Policy x Aktivierungsform x Entity - die
   Granularität, die Oracle selbst verwendet. Eine Policy hat regelmässig
   mehrere Zeilen; `BY GRANTED ROLE <rolle>` **plus** zusätzlich
   `BY USER SYS` ist das empfohlene Muster für Privileged-Activity-Policies.
   "Der Scope einer Policy" ist deshalb kein Einzelwert.
2. **Kein Logon-Filter**: anders als 23/24 filtert E logon-only Policies nicht
   heraus. Ob eine Aktivierung auflöst, ist unabhängig davon, welche Aktionen
   die Policy auditiert - eine tote LOGON-Policy ist genauso kaputt wie eine
   tote DDL-Policy.

**Für EJPD besonders relevant:** `ISC_LOC_DEV_ALL_V1` ist `BY USER` auf eine
Entwicklerliste aktiviert, und laut Scope-Dokument ist diese Liste als offener
Punkt **OP-13 noch unbestätigt**. Genau der Fall, den E prüft - im Bericht als
konkreten Prüfauftrag formulieren, nicht als allgemeinen Hinweis.

**Im CDB:** dieselbe Policy kann in einem Container gesund und im nächsten tot
sein - eine Common Policy `BY GRANTED ROLE`, deren Rolle nur in manchen PDBs
Grantees hat. Diese Asymmetrie als typische Ursache benennen.
