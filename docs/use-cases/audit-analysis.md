# Use Case: ora-db-audit - CSV-Bundle-Pipeline
<!-- SPDX-License-Identifier: Apache-2.0 -->

<!-- markdownlint-disable MD013 MD060 -->

## Übersicht

| Eigenschaft     | Wert                                                                            |
|-----------------|---------------------------------------------------------------------------------|
| Use Case ID     | UC-08                                                                           |
| Tools           | `sql/analysis_pack/`, `tools/anonymize_bundle.py`, `tools/audit_report.py`, `tools/deanonymize_report.py` |
| Phase           | Analyse (Phase 2 - Datengetriebene Anforderungs- und Policy-Diskussion)         |
| Zielgruppe      | Customer-DBA (Bundle-Erzeugung), Analyst (Auswertung)                           |
| Dauer DB-seitig | ~1-3 min für 30 Tage / Top 100 (eine SQL\*Plus-Session)                         |
| Dauer Analyst   | ~5 min (Anonymisierung + Report) für ein Standard-Bundle                        |
| Voraussetzung   | `sqlplus` mit Audit-Lese-Recht; Python 3.9+ (Stdlib, keine Dependencies)        |

---

## Problem

Der Legacy-Workflow `tools/anonymize_audit_log.py` arbeitet auf
SQL\*Plus-Spool-Files (`aud_report_full_aud_<DBSID>_*.log`). Das funktioniert
für Ad-hoc-Reports, hat aber drei Schwächen für eine wiederholbare
Phase-2-Analyse:

1. **Spool-Format ist human-readable, nicht maschinenlesbar.** Tabellen-Wraps,
   Page-Breaks, Spaltenpadding - der Anonymizer muss heuristisch parsen
   (Section-Header + Pattern-Scan). Bei jeder Reportänderung muss das Parsing
   nachgezogen werden.
2. **Keine Trennung von Datentyp und Klassifikation.** Der Spool sagt nicht,
   ob `userhost` ein Hostname oder ein Counter ist - der Anonymizer muss
   raten. Folge: Whitelist und Ambiguous-Filter fangen Fehl-Klassifizierungen
   ab, aber sicher ist nur das Bekannte.
3. **Aggregations-Logik liegt im Spool-File.** Volumen-Verteilung, Top-N,
   Off-Path-Detection - alles muss aus dem Bericht zurück-extrahiert werden.
   Das macht parameterisierte Analyse (verschiedene Zeitfenster,
   Customer-Patterns) aufwendig.

Für die wiederkehrende Customer-Phase-2 (Datenstand sichten, Policies
diskutieren, Tuning-Empfehlungen formulieren) brauchen wir ein
maschinell verarbeitbares Bundle mit explizitem Schema.

---

## Lösung

Drei-stufige Pipeline mit klarer Trennung zwischen
DB-Auszug, Anonymisierung und Report-Erzeugung:

```text
Customer-DBA                          Analyst (extern)
─────────────────────────────         ─────────────────────────────

P1  ./ora-db-audit.sh
       │
       ▼
    audit_analysis_<DBSID>_<TS>/      (rohes Bundle, lokal beim Customer)
    audit_analysis_<DBSID>_<TS>.tar.gz
       │
       ▼ (optional, Customer-Side)
P2  anonymize_bundle.py
       │                                  audit_analysis_*.anon/
       │      ───────  send  ───────►     audit_analysis_*.anon.tar.gz
       │                                       │
    (mapping.json bleibt lokal)                ▼
                                          P3  audit_report.py
                                                │
                                                ▼
                                              audit_report.md
                                              audit_ai_findings.md
                                              (--ai optional)
                                                │
                                                │ send back to Customer
                                                ▼
P3b ./ora-db-audit.sh --deanonymize ◄──── reports (anonymisiert)
       │  (mapping.json + reports)
       ▼
    audit_report.deanon.md             (Klartextwerte wiederhergestellt)
    audit_ai_findings.deanon.md
```

Jede Stufe ist einzeln lauffähig - das anonymisierte Bundle ist eine
selbsterklärende Eingabe für den Report-Generator, der wiederum reine
Markdown-Ausgabe liefert (analyse-fähig, versionierbar, anhängbar an
Phase-2-Dokumentation).

### Eigenschaften

- **Schema-Hint pro CSV-Spalte** - Anonymizer und Reporter klassifizieren
  Spalten anhand der `# schema:` Zeile, nicht via Heuristik.
- **Shared Mapping über das ganze Bundle** - `HOST_001` ist in allen
  15 CSVs derselbe reale Host. Cross-Category-Dedup (z.B. ein Identifier
  in `db_username` UND `os_username`) liefert ein einziges Pseudonym.
- **Deterministisch** - identischer Input erzeugt identische Pseudonyme.
  Mit `--load-mapping` lässt sich ein monatlicher Re-Run gegen ein
  bestehendes Mapping konsolidieren.
- **Whitelist-Wiederverwendung** - Oracle-User, Schema-Prefixes,
  Customer-Prefix und Generic-Clients werden aus dem Legacy-Anonymizer
  importiert. Erweiterbar via `--whitelist`.
- **Customer-Patterns für die Host-Klassifizierung** - die Report-Logik
  klassifiziert Hosts als `INFRA > APP > DBA > OFF-PATH` und akzeptiert
  pro Engagement eine `--patterns config.json`.

---

## Verwendung

### Customer-Auslieferung (Distribution)

An den Customer-DBA wird **nicht das ganze Repo** geschickt, sondern ein
versions-getaggtes, selbstkonsistentes Tarball:

```bash
# Engagement-Lead intern, einmal pro Engagement / Release:
make dist-ora-db-audit
# -> artefacts/ora-db-audit-<VERSION>.tar.gz
make dist-ora-db-audit-verify
```

Tarball-Layout (alles in einem Verzeichnis, Tools enthalten):

```text
ora-db-audit-<VERSION>/
├── ora-db-audit.sh              ← Entry-Point
├── 00_setup.sql .. 15_noise_candidates.sql
├── README.md                    ← Customer-DBA-Quickstart
├── VERSION
├── dist_manifest.json
└── tools/
    ├── anonymize_bundle.py
    ├── anonymize_audit_log.py
    ├── audit_report.py
    └── deanonymize_report.py
```

Der Customer-DBA entpackt das Tarball einmalig, `ora-db-audit.sh` findet
die Tools automatisch unter `./tools/` und kann sofort mit `--anonymize` und
`--report` aufgerufen werden - keine zusätzlichen Installations- oder
Pfad-Konfigurations-Schritte.

### End-to-End-Beispiel

Der gesamte Pipeline-Lauf - DB-Auszug, Anonymisierung, Markdown-Report -
in einer Wrapper-Invocation:

```bash
# Customer-DBA-Maschine (Source):
cd /home/oracle/ora-db-audit-<VERSION>/
./ora-db-audit.sh \
    --days 30 --top-n 100 \
    --connect "/ as sysdba" \
    --pdb AUDITPDB1 \
    --anonymize \
    --customer-prefix <CUSTOMER-PREFIX> \
    --report \
    --patterns ./acme_patterns.json
```

Output - alles unter `./audit_bundle/`:

```text
audit_bundle/
├── audit_analysis_<DBSID>_<TS>/             ← rohes Bundle, lokal
├── audit_analysis_<DBSID>_<TS>.tar.gz       ← lokal
├── audit_analysis_<DBSID>_<TS>.anon/        ← versandfertig
│   ├── audit_report.md                      ← anonymisierter Report
│   └── audit_ai_findings.md                 ← AI-Analyse (mit --ai)
├── audit_analysis_<DBSID>_<TS>.anon.tar.gz  ← an Analyst senden
└── audit_analysis_<DBSID>_<TS>.mapping.json ← LOKAL beim Customer
```

Nach Rücksendung der Reports vom Analyst - De-Anonymisierung lokal:

```bash
# Customer-DBA-Maschine (P3b):
./ora-db-audit.sh \
    --from-bundle audit_bundle/audit_analysis_<DBSID>_<TS>.anon.tar.gz \
    --deanonymize
# -> audit_report.deanon.md, audit_ai_findings.deanon.md
```

### Schritt 1 - DB-Bundle erzeugen (Customer-DBA)

```bash
./ora-db-audit.sh --days 30 --top-n 100 --connect "/ as sysdba"
```

Erzeugt 15 CSV-Files plus `manifest.json` und `README.md` in
`audit_bundle/audit_analysis_<DBSID>_<TS>/`. Jede CSV hat einen
Metadata-Preamble:

```text
# query: distinct_hosts
# query_id: 12
# dbsid: free
# pdb: AUDITPDB1
# generated: 2026-05-12T10:00:00+02:00
# date_range_days: 30
# top_n: 100
# schema: userhost=PSEUDO:HOST|logins=COUNT|distinct_users=COUNT|...
userhost|logins|distinct_users|distinct_programs|first_seen|last_seen
auditlab-db.example.com|6200|2|2|2026-04-12 09:00:00|2026-05-12 09:30:00
auditlab-app-classic.example.com|800|1|1|2026-04-15 08:30:00|2026-05-12 09:25:00
```

Erwartete Grösse: < 5 MB für 30 Tage / Top 100. Lab-Validierung
(`auditlab-db` / `AUDITPDB1`): 12 KB komprimiert.

### Schritt 2 - Anonymisierung (Customer-Side oder Analyst-Side)

```bash
$ORACLE_HOME/python/bin/python tools/anonymize_bundle.py \
    audit_bundle/audit_analysis_<DBSID>_<TS>/ \
    --customer-prefix <CUSTOMER-PREFIX> \
    --yes
```

Erzeugt drei Artefakte neben dem Input-Bundle:

| Datei                           | Zweck                                           |
|---------------------------------|-------------------------------------------------|
| `audit_analysis_*.anon/`        | Anonymisierte CSV-Files, Schema-Header erhalten |
| `audit_analysis_*.anon.tar.gz`  | Versandbares Tarball                            |
| `audit_analysis_*.mapping.json` | Reverse-Lookup - **bleibt immer beim Customer** |

Bei monatlichem Re-Run dasselbe Mapping wiederverwenden:

```bash
$ORACLE_HOME/python/bin/python tools/anonymize_bundle.py \
    audit_bundle/audit_analysis_<DBSID>_<TS+30d>/ \
    --load-mapping audit_bundle/audit_analysis_<DBSID>_<TS>.mapping.json \
    --customer-prefix <CUSTOMER-PREFIX> --yes
```

Hosts/User, die in beiden Bundles vorkommen, behalten identische Pseudonyme.
Nur neue Werte bekommen die nächsten freien Indices.

### Schritt 3 - Markdown-Report rendern (Analyst)

```bash
python3 tools/audit_report.py \
    audit_analysis_<DBSID>_<TS>.anon/ \
    --patterns acme_patterns.json \
    --include-appendix
```

Output: `audit_analysis_*.anon/audit_report.md`. Struktur:

- **Executive Summary**: DBSID/PDB/Zeitfenster, Top-3 Volume-Treiber,
  Host-Klassifizierung (App / Infra / DBA / Off-Path), Storage-Status
- **Section 1-8**:
  1. Audit-Konfiguration (Mixed/Pure, Retention, Init-Params)
  2. Trail-Storage (Tablespace, Partitionen, Volumen)
  3. Policy-Inventar (Top 20 + Vollliste als Appendix)
  4. Volumen-Verteilung (Policies, User, Actions, Objects)
  5. Connect-Profil (Hosts, Host-Pattern-Analyse, Matrix)
  6. Privileged Activity (SYS/SYSDBA/AUDIT_ADMIN)
  7. Security Signals (Failed Logins, Off-Path-Kandidaten)
  8. Tuning-Empfehlungen (WHEN-Klausel-Vorschläge für Top-N-Noise-Combos)
- **Appendix** (optional): Manifest + vollständige Tabellen 03/04/05

Der Report ist deutschsprachig (Konsistenz mit `docs/use-cases/`),
markdownlint-clean und kann direkt an die Phase-2-Auswertung angehängt
werden.

### Schritt 3b - De-Anonymisierung (Customer-Side)

Sobald der Analyst den Report zurückschickt, können die Pseudonyme
(`HOST_003`, `DBUSER_001`) mit dem lokalen `mapping.json` zurück in
Klartextwerte übersetzt werden:

```bash
# Customer-DBA-Maschine:
./ora-db-audit.sh \
    --from-bundle audit_bundle/audit_analysis_<DBSID>_<TS>.anon.tar.gz \
    --deanonymize
```

`--mapping FILE` erlaubt ein explizites Mapping-File, falls das automatisch
erkannte (`.anon/`-Sibling) nicht zutrifft:

```bash
./ora-db-audit.sh \
    --from-bundle audit_bundle/audit_analysis_<DBSID>_<TS>.anon.tar.gz \
    --deanonymize \
    --mapping audit_bundle/audit_analysis_<DBSID>_<TS>.mapping.json
```

Output: `audit_report.deanon.md` und (falls vorhanden)
`audit_ai_findings.deanon.md` im Bundle-Verzeichnis. Die Originale bleiben
unverändert.

> **Voraussetzung:** `mapping.json` muss beim Customer lokal vorliegen und
> darf nie das Netz verlassen. Das `.deanon.md`-Output enthält echte
> Werte und ist analog zum Rohbundle zu behandeln.

Das Tool `tools/deanonymize_report.py` kann auch direkt aufgerufen werden,
wenn der Report manuell übergeben wird:

```bash
python3 tools/deanonymize_report.py \
    audit_analysis_<DBSID>_<TS>.anon/ \
    --mapping audit_analysis_<DBSID>_<TS>.mapping.json \
    --dry-run
```

---

## CLI-Optionen

### `ora-db-audit.sh`

| Option                | Default              | Beschreibung                                       |
|-----------------------|----------------------|----------------------------------------------------|
| `--days N`            | 30                   | Zeitfenster in Tagen                               |
| `--top-n N`           | 100                  | Top N Zeilen pro Query                             |
| `--connect "CONN"`    | `/ as sysdba`        | sqlplus connect string                             |
| `--pdb NAME`          | -                    | `ALTER SESSION SET CONTAINER` nach Connect         |
| `--output DIR`        | `./audit_bundle`     | Output-Verzeichnis                                 |
| `--anonymize`         | off                  | `anonymize_bundle.py` nach Generierung aufrufen    |
| `--customer-prefix P` | `<CUSTOMER-PREFIX>`  | Customer-Namespace bei `--anonymize`               |
| `--report`            | off                  | Markdown-Report rendern (anon-Bundle bevorzugt)    |
| `--patterns FILE`     | -                    | JSON mit App/Infra/DBA-Host-Pattern für den Report |
| `--tools-dir DIR`     | (auto)               | Override für die Python-Tools-Auto-Erkennung       |
| `--deanonymize`       | off                  | `deanonymize_report.py` auf Reports anwenden (P3b) |
| `--mapping FILE`      | (auto)               | Explizites `mapping.json` für `--deanonymize`      |
| `--dry-run`           | -                    | Nur Aktionen anzeigen                              |
| `--yes / -y`          | -                    | Existierende Outputs überschreiben                 |

> Tools-Auto-Erkennung (`--anonymize`, `--report`, `--deanonymize`): `--tools-dir` >
> `$ORA_DB_AUDIT_TOOLS` > `<script-dir>/tools/` (Default im Dist-Tarball) >
> `<repo-root>/tools/` (Repo-Layout). Customer-Auslieferung via `make
> dist-ora-db-audit` erfüllt Punkt 3 ohne Zutun.

### `tools/anonymize_bundle.py`

| Option                     | Beschreibung                                                        |
|----------------------------|---------------------------------------------------------------------|
| `INPUT`                    | Bundle-Verzeichnis oder `.tar.gz`                                   |
| `--load-mapping FILE`      | Bestehende `mapping.json` inkrementell weiterverwenden              |
| `--customer-prefix PREFIX` | Customer-Prefix. Leer-String deaktiviert die Prefix-Whitelist       |
| `--whitelist FILE`         | JSON mit zusätzlichen Werten, die KEEP bleiben sollen               |
| `--no-tar`                 | Tarball-Erzeugung unterdrücken                                      |
| `--dry-run`                | Statistik anzeigen, keine Files schreiben                           |
| `--yes / -y`               | Existierende Outputs überschreiben                                  |
| `--verbose / -v`           | Sample-Mappings pro Kategorie ausgeben                              |

### `tools/deanonymize_report.py`

| Option            | Beschreibung                                                         |
|-------------------|----------------------------------------------------------------------|
| `BUNDLE_DIR`      | Bundle-Verzeichnis mit `audit_report.md` / `audit_ai_findings.md`   |
| `--mapping FILE`  | Explizites `mapping.json` (Default: auto-detect aus `.anon/`-Sibling)|
| `--output DIR`    | Output-Verzeichnis (Default: neben den Originalen)                   |
| `--dry-run`       | Zeigt Ersetzungs-Statistik, schreibt nichts                          |
| `--yes / -y`      | Existierende `.deanon.md`-Files überschreiben                        |

### `tools/audit_report.py`

| Option                | Beschreibung                                                  |
|-----------------------|---------------------------------------------------------------|
| `BUNDLE`              | Pfad zum Bundle (anon oder roh)                               |
| `--output / -o FILE`  | Output-Markdown (Default `<bundle>/audit_report.md`)          |
| `--patterns FILE`     | JSON mit Customer-Host-Pattern (App/Infra/DBA)                |
| `--top-n N`           | Top-N pro Tabelle im Report (Default eigener Cap)             |
| `--customer-prefix P` | Prefix in Narrativ-Texten                                     |
| `--include-appendix`  | Manifest + vollständige Tabellen 03/04/05 anhängen            |
| `--dry-run`           | Report rendern, aber nicht schreiben                          |
| `--yes / -y`          | Existierende Outputs überschreiben                            |
| `--verbose / -v`      | Welche CSV-Files verwendet/übersprungen wurden                |

---

## Bundle-Format

### Layout

```text
audit_analysis_<DBSID>_<TS>/
├── manifest.json              ← Bundle-Metadaten (Version, Queries, Zeit)
├── README.md                  ← Schema-Erklärung, Sicherheitshinweise
├── _sqlplus.log               ← SQL*Plus-Session-Log
├── 01_config.csv              ← Audit-Konfiguration
├── 02_storage.csv             ← Trail-Storage, Partitionen
├── 03_policy_inventory.csv    ← Aktive Policies (QUOTE ON)
├── 04_policy_volume.csv       ← Events pro Policy
├── 05_policy_user_action.csv  ← Policy x User x Action
├── 06_policy_client_program.csv ← Policy x Client
├── 07_policy_host.csv         ← Policy x Host
├── 08_top_users.csv           ← User x Events
├── 09_top_actions.csv         ← Action x Events
├── 10_top_objects.csv         ← Sensitive Objects
├── 11_host_user_program.csv   ← Connect-Profil-Matrix
├── 12_distinct_hosts.csv      ← Distinct Hosts mit Volume
├── 13_failed_logins.csv       ← LOGON returncode != 0
├── 14_privileged_activity.csv ← SYS/SYSDBA/AUDIT_ADMIN
└── 15_noise_candidates.csv    ← High-Volume-Combos -> WHEN-Kandidaten
```

### Schema-Hint-Spezifikation

Jede CSV hat eine `# schema:`-Zeile mit Pipe-separierten
`column=TYPE_HINT`-Paaren. Diese steuern den Anonymizer:

| Type-Hint       | Bedeutung                                               |
|-----------------|---------------------------------------------------------|
| `KEEP`          | Wert sichtbar lassen (Policy/Action/Default-Namen)      |
| `PSEUDO:HOST`   | als `HOST_NNN` ersetzen (shared dict im Bundle)         |
| `PSEUDO:DBUSER` | als `DBUSER_NNN`                                        |
| `PSEUDO:OSUSER` | als `OSUSER_NNN`                                        |
| `PSEUDO:CLIENT` | als `CLIENT_NNN` (mit Generic-Client-Whitelist)         |
| `PSEUDO:SCHEMA` | als `SCHEMA_NNN` (mit Oracle-Schema-Prefixes-Whitelist) |
| `PSEUDO:OBJECT` | als `OBJECT_NNN` (mit Oracle-Object-Prefixes-Whitelist) |
| `COUNT`         | numerisch, unverändert                                  |
| `TIMESTAMP`     | Zeitstempel, unverändert                                |
| `BYTES`         | numerisch, unverändert                                  |
| `REDACT`        | komplett mit `[REDACTED]` ersetzen (Freitext-Felder)    |

### Patterns-Config-Format

JSON, vom Reporter via `--patterns` geladen, drei optionale Listen mit
regulären Ausdrücken:

```json
{
  "app_host_patterns":   ["^wls-", "^app-srv-"],
  "infra_host_patterns": ["^oem-", "^db-"],
  "dba_host_patterns":   ["^jumphost-"]
}
```

Priorität bei Mehrfach-Match: `INFRA > APP > DBA > OFF-PATH`. Hosts ohne
Match landen in `OFF-PATH` und tauchen in Section 7 "Security Signals"
als Kandidaten auf.

---

## Compliance-Hinweise

- **Rohes Bundle enthält echte Werte.** Niemals per E-Mail oder
  Cloud-Upload versenden, ohne vorher `anonymize_bundle.py` zu laufen.
- **Mapping-File (`*.mapping.json`) bleibt immer beim Customer.** Es
  enthält die Reverse-Lookup-Tabelle und ist via `.gitignore` aus dem
  Repo ausgeschlossen (`**/*.mapping.json`).
- **Anonymisierung am Customer-Standort.** Wenn die Customer-Policy es
  zulässt, kann der Analyst die Anonymisierung übernehmen - dann wandert
  das rohe Bundle aber inkl. echter Werte über das Netz. Default-Empfehlung:
  Anonymisierung lokal auf der DB-Maschine via `--anonymize`.
- **`_sqlplus.log` mit anschauen.** Dieses File kann sensitive Werte
  (Connect-Strings, Fehlermeldungen mit User-Kontext) enthalten. Vor
  Versand prüfen und ggf. löschen.
- **Findings zurück-übersetzen.** Der Analyst arbeitet auf Pseudonymen
  (`HOST_4711 hatte 5'000 Failed Logons`). Die Realwerte werden via
  `mapping.json` zurück gemappt - dieser Schritt findet beim Customer
  statt. Bevorzugte Methode: `--deanonymize` (P3b) oder direkt via
  `tools/deanonymize_report.py` - ersetzt alle Pseudonyme im Report
  automatisch. Für Einzelwert-Lookup:

```bash
python3 -c "
import json
m = json.load(open('audit_analysis_*.mapping.json'))['mapping']
inv = {v: k for k, v in m.items()}
print(inv.get('HOST_4711'))
"
```

- **`.deanon.md`-Output enthält echte Werte.** Diese Dateien sind mit
  demselben Schutzbedarf wie das Rohbundle zu behandeln und nicht per
  E-Mail oder unverschlüsselten Cloud-Upload weiterzugeben.

---

## Workflow im Phase-2-Prozess

1. **Initial-Run** zum Engagement-Start (`--days 30 --top-n 100`).
   Output dient als Grundlage für den ersten Phase-2-Workshop.
2. **Monatlicher Re-Run** mit `--load-mapping` der initialen Mapping-Datei.
   Stabile Pseudonyme erlauben einen Trend-Vergleich über mehrere Reports.
3. **Pro Use Case** ein gezielter `--days 7 --top-n 50`-Run nach
   Policy-Deployment - schnelles Feedback, ob das Tuning gegriffen hat.
4. **Phase-2-Auswertung** mit `audit_report.md` als Beilage zur
   Findings-Dokumentation in `docs/analysis/`.
5. **P3b-De-Anonymisierung** nach Analyst-Rücksendung: Analyst schickt
   anonymisierten Report (Pseudonyme), Customer-DBA führt `--deanonymize`
   lokal aus und erhält lesbaren Report in Klartextwerten für die interne
   Dokumentation.

---

## Bekannte Limitationen

- **Kein per-policy Split** bei komma-separierten `unified_audit_policies`-
  Werten (wenn ein Event mehreren Policies matcht). Aktuelle Aggregate
  gruppieren auf den raw-String. Per-Policy-Split bleibt Post-Processing.
- **`audit_condition` als Freitext.** Die WHEN-Klausel einer Policy kann
  Hostnamen, User-Listen, Programm-Namen enthalten. Im Bundle als
  `PSEUDO:OBJECT` markiert - das ist konservativ, aber nicht semantisch
  exakt. Inhaltliche Diskussion erfolgt auf der `mapping.json`-Seite.
- **Lab-validiert, nicht PROD-validiert.** Der initiale Lauf gegen
  `auditlab-db` / `AUDITPDB1` deckt das Schema und alle 15 Queries ab.
  Ein erster PROD-Run gegen einen 10+ GB Audit-Trail steht noch aus -
  Top-N und Zeitfenster ggf. anpassen.
- **WHEN-Klausel-Templates sind Vorschläge, kein Apply.** Section 8 des
  Reports liefert drei Varianten pro Noise-Kandidat (User-Suppression,
  Program-Suppression, kombiniert). Diese sind als Diskussionsgrundlage
  gedacht - der DBA verifiziert sie gegen den `<PREFIX>_AUDIT_CTX`-Kontext
  und das CIS-Mapping.

---

## Beispiel - vorher / nachher

### Vor Anonymisierung (`12_distinct_hosts.csv`)

```text
# schema: userhost=PSEUDO:HOST|logins=COUNT|distinct_users=COUNT|distinct_programs=COUNT|first_seen=TIMESTAMP|last_seen=TIMESTAMP
userhost|logins|distinct_users|distinct_programs|first_seen|last_seen
auditlab-db.example.com|6200|2|2|2026-04-12 09:00:00|2026-05-12 09:30:00
auditlab-app-classic.example.com|800|1|1|2026-04-15 08:30:00|2026-05-12 09:25:00
auditlab-app-paas.example.com|410|1|1|2026-04-16 08:30:00|2026-05-12 09:20:00
laptop-001.example.com|55|1|1|2026-04-20 14:00:00|2026-05-11 18:00:00
```

### Nach Anonymisierung

```text
# schema: userhost=PSEUDO:HOST|logins=COUNT|distinct_users=COUNT|distinct_programs=COUNT|first_seen=TIMESTAMP|last_seen=TIMESTAMP
userhost|logins|distinct_users|distinct_programs|first_seen|last_seen
HOST_003|6200|2|2|2026-04-12 09:00:00|2026-05-12 09:30:00
HOST_001|800|1|1|2026-04-15 08:30:00|2026-05-12 09:25:00
HOST_002|410|1|1|2026-04-16 08:30:00|2026-05-12 09:20:00
HOST_004|55|1|1|2026-04-20 14:00:00|2026-05-11 18:00:00
```

Schema-Header, Counts und Timestamps unverändert. Hostnamen
deterministisch pseudonymisiert, in allen 15 CSVs identisch.

### Auszug aus `audit_report.md` (Auszug aus dem Tuning-Abschnitt)

```markdown
### 8.2 Vorschlag - <PREFIX>_LOC_LOGON_EVENTS_V1

**Beobachtung:** 89'558 Events in 30 Tagen, davon 71'200 (~80%) von
HOST_003 als DBUSER_001 mit CLIENT_001 (`sqlplus`-Heartbeat).

**WHEN-Klausel-Vorschlag (kombiniert):**

    CREATE AUDIT POLICY <PREFIX>_LOC_LOGON_EVENTS_V2
      ACTIONS LOGON, LOGOFF
      WHEN 'SYS_CONTEXT(''USERENV'',''CURRENT_USER'') != ''<DBUSER_001-real>''
         OR SYS_CONTEXT(''USERENV'',''CLIENT_PROGRAM_NAME'')
                NOT LIKE ''<CLIENT_001-real>%'''
      EVALUATE PER SESSION;

**Anti-Pattern:** WHEN-Klausel-Werte müssen vor Apply gegen `mapping.json`
zurück übersetzt werden.
```

---

## Referenzen

- Bundle-SQL: `sql/analysis_pack/00_setup.sql` ... `15_noise_candidates.sql`
- Wrapper: `src/ora-db-audit.sh`
- Anonymizer: `tools/anonymize_bundle.py`
- Reporter: `tools/audit_report.py`
- De-Anonymizer: `tools/deanonymize_report.py`
- Customer-DBA-Quickstart: `sql/analysis_pack/README.md`
- Customer-Handover-Template: `templates/customer-handover.md`
- Roadmap und Architekturkontext: `docs/roadmap.md`
- Legacy-Ad-hoc-Anonymisierung: `docs/use-cases/audit-log-anonymisation.md`

<!-- EOF -->
