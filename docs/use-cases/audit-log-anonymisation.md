# Use Case: Anonymisierung von Audit-Trail-Spool-Files
<!-- SPDX-License-Identifier: Apache-2.0 -->

<!-- markdownlint-disable MD013 MD060 -->

> **Status: Legacy / Ad-hoc-Tool.** Für den wiederkehrenden Phase-2-Workflow
> empfehlen wir das CSV-Bundle-Pipeline-Toolset, dokumentiert in
> [`audit-analysis.md`](audit-analysis.md). Das hier
> beschriebene `tools/anonymize_audit_log.py` bleibt für die Ad-hoc-Anonymisierung
> existierender SQL\*Plus-Spool-Files erhalten - sinnvoll wenn das
> `analysis_pack/` nicht (mehr) ausgeführt werden kann oder wenn ein älterer
> Spool-Bericht nachträglich geteilt werden soll. Beide Tools koexistieren -
> keine Migration nötig.

## Übersicht

| Eigenschaft   | Wert                                                          |
|---------------|---------------------------------------------------------------|
| Use Case ID   | UC-07                                                         |
| Tool          | `tools/anonymize_audit_log.py`                                |
| Phase         | Ad-hoc (Legacy - bevorzugt UC-08 `audit-analysis.md`)         |
| Zielgruppe    | DBA, Security Engineer, Auditor                               |
| Dauer         | < 10 Sekunden für 7.5 MB / 34k Zeilen                         |
| Voraussetzung | Python 3.9+ (Standardbibliothek, keine Dependencies)          |

---

## Problem

Audit-Trail-Reports, die mit `sql/aud_report_full_aud.sql` (oder einem der
Sub-Scripts wie `aud_trail_userhost_analysis_aud.sql`) erzeugt werden,
enthalten produktive Kundendaten:

- DB-Usernamen, OS-Usernamen
- Hostnamen (xa-prefixed, K8s-Pod-Namen, FQDNs)
- IP-Adressen
- Client-Programme inkl. `tool@hostname`-Strings
- Schemata und Objektnamen
- E-Mail-Adressen in Free-Text-Feldern

Für die gemeinsame Analyse mit externen Beratern, ai-gestützte
Auswertung oder das Beilegen als Anhang in einer Dokumentation müssen
diese Werte maskiert werden, ohne die Analyse-Substanz zu verlieren.

---

## Lösung

`tools/anonymize_audit_log.py` ersetzt sensitive Werte deterministisch
durch Pseudonyme (`HOST_001`, `DBUSER_042`, `IP_007`, ...) und schreibt
das Mapping in ein separates JSON-File, das lokal bleibt.

### Eigenschaften

- **Deterministisch**: gleicher Input -> gleiches Pseudonym (alphabetisch sortiert, durchnummeriert)
- **Inkrementell**: `--load-mapping` erlaubt, mehrere Logs mit demselben Mapping zu anonymisieren - ein `HOST_001` bleibt in allen Files derselbe reale Host
- **Korrelations-erhaltend**: ein User, der als DBUSER und OSUSER auftaucht, bekommt **ein** Pseudonym (`DBUSER_042`) - dadurch bleibt die Aussage "selber Identifier in beiden Kontexten" lesbar
- **Whitelist-basiert**: Oracle-supplied User/Schemas (`SYS`, `SYSTEM`, `APEX_*`, `DBA_*`, `V$*`, ...), Customer-Prefix und Policy-Namen bleiben unverändert lesbar
- **Ambiguous Detection**: Werte, die rein numerisch oder zu kurz sind (`30`, `001`, `-10`) werden **nicht** anonymisiert, weil sie sonst Login-Counts oder Strings wie `(last 30 days)` zerstören würden

---

## Verwendung

### Standard-Aufruf

```bash
python3 tools/anonymize_audit_log.py logs/aud_report_full_aud_<DBSID>_<TS>.log
```

Outputs landen neben dem Input:

- `<input>.anon.log` - anonymisierter Spool, kann geteilt werden
- `<input>.mapping.json` - Reverse-Lookup, bleibt **lokal** (per `.gitignore` ausgeschlossen)

### Dry-Run vor dem ersten Lauf

```bash
python3 tools/anonymize_audit_log.py logs/<file>.log --dry-run --verbose
```

Zeigt nur die Statistik plus Beispiel-Mappings pro Kategorie. Keine
Files werden geschrieben. Empfohlen für die erste Überprüfung der
Klassifizierung.

### Inkrementelle Anonymisierung mehrerer Files

```bash
# Erstes File - erzeugt Mapping
python3 tools/anonymize_audit_log.py logs/audit_jan.log --yes

# Zweites File - verwendet bestehendes Mapping weiter
python3 tools/anonymize_audit_log.py logs/audit_feb.log \
  --load-mapping logs/audit_jan.mapping.json --yes
```

Hosts, die in beiden Files vorkommen, behalten identische Pseudonyme.
Neue Werte bekommen die nächsten freien Indices.

### CLI-Optionen

| Option                     | Beschreibung                                                   |
|----------------------------|----------------------------------------------------------------|
| `--output FILE`            | Output-Pfad überschreiben                                      |
| `--mapping FILE`           | Mapping-Pfad überschreiben                                     |
| `--load-mapping FILE`      | Bestehendes Mapping vorladen (inkrementell)                    |
| `--whitelist FILE`         | JSON mit zusätzlichen `"whitelist"`-Werten zum Sichtbar-Halten |
| `--customer-prefix PREFIX` | Customer-Prefix. Leer-String deaktiviert die Prefix-Whitelist  |
| `--dry-run`                | Nur Statistik, keine Files                                     |
| `--yes` / `-y`             | Existierende Outputs ohne Rückfrage überschreiben              |
| `--verbose` / `-v`         | Beispiel-Mappings + ambigue Werte pro Kategorie                |

---

## Analyse-Methode

### 1. Anonymisierung lokal ausführen

```bash
python3 tools/anonymize_audit_log.py logs/<file>.log --dry-run --verbose
python3 tools/anonymize_audit_log.py logs/<file>.log --yes
```

### 2. Statistik überprüfen

```text
Category       kept   anonymised   ambiguous
---------- -------- ------------ -----------
HOST              0        14983        2075
IP                0            0           0
DBUSER            3           54           5
OSUSER            1           15           1
CLIENT            3            5           0
SCHEMA            0            0           0
OBJECT            0            0           0
EMAIL             0            0           0
```

- `kept` = sichtbar gehalten (Oracle-defaults, Customer-Prefix, Generic-Client-Names)
- `anonymised` = ersetzt durch Pseudonym
- `ambiguous` = Werte zu kurz / rein numerisch - nicht ersetzbar ohne Risk auf Counts

### 3. Spot-Check im `.anon.log`

Stichprobe lesen - Section-Header und Zahlenwerte müssen unverändert sein,
sensitive Spalten enthalten nur Pseudonyme.

```bash
head -50 logs/<file>.anon.log
grep -c "HOST_" logs/<file>.anon.log   # Anzahl Ersetzungen
```

### 4. Mapping-File sichten (optional)

```bash
python3 -c "
import json
with open('logs/<file>.mapping.json') as f:
    m = json.load(f)['mapping']
print(f'Total: {len(m)}')
for k, v in list(m.items())[:10]:
    print(f'  {k!r:50}  ->  {v}')
"
```

### 5. Geteiltes File zur Analyse geben

Nur das `.anon.log` weitergeben. Das `.mapping.json` bleibt lokal -
es enthält die Realwerte und ist in `.gitignore` ausgeschlossen.

### 6. Findings zurück-übersetzen

Nach der Analyse hat man Findings wie `HOST_4711 hatte 5'000 Failed Logons`.
Die Realwerte via Mapping nachschlagen:

```bash
python3 -c "
import json
with open('logs/<file>.mapping.json') as f:
    m = json.load(f)['mapping']
inv = {v: k for k, v in m.items()}
print(inv.get('HOST_4711'))
"
```

---

## Architektur

### Zwei-Pass-Extraktion

1. **Section-aware**: parst jede `dashes-line` (`-----`) im Spool und
   nimmt die direkt darüber liegende Zeile als Column-Heading.
   Heading-Text wird auf eine Kategorie gemappt:

    | Heading                                                       | Kategorie |
    |---------------------------------------------------------------|-----------|
    | `Host`, `Machine`, `User Host`, `Host (distinct)`, `userhost` | HOST      |
    | `DB User`, `User`, `Username`, `dbusername`                   | DBUSER    |
    | `OS User`, `OSUser`, `os_username`                            | OSUSER    |
    | `Client Program`, `Program`, `Client Program Name`            | CLIENT    |
    | `Schema`, `object_schema`                                     | SCHEMA    |
    | `Objects`, `object_name`, `Object`                            | OBJECT    |

    Werte aus diesen Spalten werden gesammelt. Multi-Column-Tabellen
    (z.B. Host + DB User + OS User + Client Program in einer Zeile)
    werden vollständig erfasst.

2. **Pattern-based** (global über das ganze File): zusätzliche
   IPv4-Adressen, FQDNs und E-Mail-Adressen werden via Regex erkannt,
   damit auch eingebettete Werte in Narrativ-Text gemasht werden.

### Cross-Category-Dedup

Ein Wert, der in mehreren Kategorien auftaucht (z.B. derselbe Identifier
als DBUSER und OSUSER), bekommt das Pseudonym der **zuerst gesehenen**
Kategorie - das gilt dann global im File. So bleibt die Korrelation
"selber Identifier" lesbar.

### Substitution (zwei Pässe)

- **Plain-Token-Scan** (O(N)): für Werte ohne Spaces/Sonderzeichen
  (Hostnamen, Usernamen, IPs). Ein einzelner Scan über das File mit
  Dict-Lookup. Skaliert auf 18k+ Werte ohne Performance-Verlust.
- **Batched Regex** (für `multi-token` Werte wie E-Mails, Multi-Word
  Client-Programme): Token-Boundary-Guards verhindern Inside-Match
  (`db01` matcht nicht in `db01.acme.com`).

### Whitelist

Standardmässig nicht anonymisiert:

- Oracle-supplied Users: `SYS`, `SYSTEM`, `DBSNMP`, `AUDSYS`,
  `GSMADMIN_INTERNAL`, `XS$NULL`, ... (vollständige Liste im Script)
- Oracle-Schema-Prefixes: `APEX_*`, `ORDS_*`, `OJVM*`, `FLOWS_*`
- Dictionary-Views: `V$*`, `GV$*`, `DBA_*`, `ALL_*`, `USER_*`, `CDB_*`, `X$*`, `ORA_*`
- Customer-Prefix: `<CUSTOMER-PREFIX>`, `<CUSTOMER-PREFIX>_*` (in DBUSER, OSUSER, SCHEMA, OBJECT)
- Generic-Client-Programme: `JDBC Thin Client`, `SQL Developer`,
  `sqlplus`, `SQL*Plus`, `sqlcl`, ...
- `localhost`, `oracle.com`, `oradba.ch`
- NVL-Placeholders: `n/a`, `UNKNOWN`, `(null)`

Erweiterbar via `--whitelist whitelist.json`:

```json
{
  "whitelist": ["additional_value_1", "additional_value_2"]
}
```

### Ambiguous Filter

Werte mit < 3 Zeichen ODER rein numerisch (`30`, `001`, `-10`) werden
**nicht** ersetzt, sondern als "ambiguous" gezählt. Begründung: solche
Werte tauchen auch in Login-Counts, Page-Numbers oder freien
Text-Fragmenten wie `(last 30 days)` auf. Eine globale Substitution
würde diese korrumpieren. Im echten K8s-Setup tauchen "001", "0-m"
etc. als Pod-Ordinals auf - diese bleiben unmasked sichtbar.

---

## Bekannte Limitationen

- **SQL\*Plus WRAP-Continuation**: Werte länger als die Spaltenbreite
  (z.B. > A60 für `userhost`) werden von SQL\*Plus über zwei Zeilen
  umbrochen. Der Parser erkennt Wrap-Continuations (Content nur in
  Column 1) und überspringt sie. Folge: extrem lange Hostnamen werden
  nur teilweise (die ersten 60 chars) als Wert erfasst. Der Pattern-Scan
  fängt vollständige FQDNs auf der Original-Zeile, aber wrappte Werte
  ohne Pattern-Match bleiben unmasked.
- **Numeric Hostnames**: Pod-Ordinals wie `001` oder `-10` werden als
  "ambiguous" markiert und bleiben lesbar. Bei sensitiven numerischen
  Hostnames muss manuell maskiert werden.
- **Column-Boundary-Spillover**: in seltenen Fällen kann Padding zwischen
  Spalten zu falscher Klassifikation führen. Whitelist und Ambiguous-Filter
  fangen das in den meisten Fällen ab. Bei Unstimmigkeiten: `--verbose`
  und Sample-Mappings prüfen, ggf. Whitelist erweitern.

---

## Test

Sample-Fixture mit allen Sections (Full Report Format) liegt in
`tools/tests/sample_input.log` und kann jederzeit als Regression
verwendet werden:

```bash
python3 tools/anonymize_audit_log.py tools/tests/sample_input.log --dry-run --verbose
```

Erwartete Statistik:

```text
Category       kept   anonymised   ambiguous
---------- -------- ------------ -----------
HOST              0            5           0
IP                0            1           0
DBUSER            5            2           0
OSUSER            0            4           0
CLIENT            2            0           0
SCHEMA            4            2           0
OBJECT            4            2           0
EMAIL             0            1           0
```

---

## Beispiel: Vorher / Nachher

### Input (Auszug aus `aud_trail_userhost_analysis_aud_*.log`)

```text
================================================================================
= 1. HOST SUMMARY - Distinct hosts mit Login-Anzahl und User-Anzahl (last 30 days)
================================================================================

Host                                                               Logins User (distinct)
------------------------------------------------------------ ------------ ---------------
dbhost-prod-01                                                     91,565               2
dbhost-prod-01.intranet.example.com                                 1,765               3
refdata-read-service-cdf8d757b-s86fx.svc.cluster.local                605               1
batch-scheduled-job-1778550300-main-841282096                         152               1
```

### Output (`*.anon.log`)

```text
================================================================================
= 1. HOST SUMMARY - Distinct hosts mit Login-Anzahl und User-Anzahl (last 30 days)
================================================================================

Host                                                               Logins User (distinct)
------------------------------------------------------------ ------------ ---------------
HOST_11295                                                         91,565               2
HOST_11297                                                          1,765               3
HOST_14697                                                            605               1
HOST_11295                                                            152               1
```

Header, Counts und Strukturelemente unverändert. Hostnamen
deterministisch pseudonymisiert.

---

## Wann was? - Entscheidungs-Hilfe

| Situation                                                                 | Empfehlung                                    |
|---------------------------------------------------------------------------|-----------------------------------------------|
| Phase-2-Analyse, monatliche Re-Runs, Tuning-Empfehlungen                  | UC-08 `audit-analysis.md` (CSV-Bundle-Pipeline) |
| Bestehendes Spool-File (`*_aud_*.log`) nachträglich anonymisieren         | UC-07 (dieses Dokument)                       |
| Customer kann SQL\*Plus aufrufen, aber kein zusätzliches Tooling laufen   | UC-07 (dieses Dokument)                       |
| Customer hat `$ORACLE_HOME/python` und kann `ora-db-audit.sh` laufen      | UC-08 `audit-analysis.md`                     |
| Off-line Bericht, der nicht reproduzierbar/parameterisierbar sein muss    | UC-07 (dieses Dokument)                       |
| Maschinen-Auswertbares Bundle für Trend-Analysen oder Reporter-Tooling    | UC-08 `audit-analysis.md`                     |

Beide Tools nutzen dieselbe Whitelist-Logik (`ORACLE_USERS`, Customer-Prefix,
Generic-Client-Programme) - Pseudonyme aus dem Spool-Workflow sind
**nicht** kompatibel mit denen aus dem CSV-Bundle-Workflow (unterschiedlicher
Numerierungs-Counter pro Datei-Set). Kein Cross-Use von `mapping.json`-Files
zwischen den beiden Use Cases.
