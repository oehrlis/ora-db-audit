# Use Case: Off-Path Detection

<!-- SPDX-License-Identifier: Apache-2.0 -->

<!-- markdownlint-disable MD013 MD060 -->

## Uebersicht

| Eigenschaft | Wert |
| --- | --- |
| Use Case ID | UC-19 |
| SQL | `sql/19-offpath-candidates.sql` |
| Report-Section | 7.2 Off-Path Candidates (automatisch) |
| Phase | Analyse (Host-Klassifizierung) |
| Zielgruppe | Security Engineer, DBA |
| Voraussetzung | `AUDIT_VIEWER` oder `AUDIT_ADMIN`; kein `ODB_AUDIT_CTX` erforderlich |

<!-- markdownlint-enable MD013 MD060 -->

---

## Problem

Oracle Unified Auditing protokolliert fuer jedes Datenbank-Event den `USERHOST` -
den Hostnamen oder die IP-Adresse des Clients, der die Verbindung aufgebaut hat.
In einer ordentlich strukturierten Umgebung kommen Datenbankverbindungen
ausschliesslich von bekannten Tier-Hosts:

- **APP-Tier**: Applikationsserver, Web-Tier, Middleware (z.B. `wls-prod-01`)
- **INFRA**: Datenbankserver selbst, OEM-Agent, Backup-Client (z.B. `db-prod-01`)
- **DBA**: Jump-Hosts, DBA-Laptops (z.B. `jumphost-01`, `laptop-stefan`)

Verbindungen von **unbekannten Hosts** - solchen, die keinem dieser Pattern
entsprechen - sind ein starkes Indikator-Signal fuer:

- Direktzugriffe auf die Datenbank ohne Applikations-Layer (Bypassing)
- Laterale Bewegung nach einer Kompromittierung
- Fehlkonfigurierte Clients / neue, noch nicht registrierte Tier-Hosts
- Entwickler-Notebooks in Produktion

Diese Hosts werden als **OFF-PATH** klassifiziert.

---

## Ansatz ohne Application-Kontext

Die bevorzugte Variante fuer Off-Path-Detection ist der Oracle Application
Context `ODB_AUDIT_CTX` (oder Kunden-Aequivalent), der pro Session ein
strukturiertes Feld `APP_MODULE` setzt und so die Herkunft der Verbindung
eindeutig identifiziert. Diese Variante erfordert jedoch, dass das Context-
Paket auf der Zieldatenbank deployt ist.

`sql/19-offpath-candidates.sql` implementiert die **Pattern-basierte Variante**
ohne Application-Context-Abhaengigkeit. Sie funktioniert auf jeder Datenbank
mit Unified Auditing und LOGON-Events - auch ohne Code-Deployment.

**Mechanismus:**

```sql
NOT REGEXP_LIKE(userhost, '&APP_PATTERN',   'i')
AND NOT REGEXP_LIKE(userhost, '&INFRA_PATTERN', 'i')
AND NOT REGEXP_LIKE(userhost, '&DBA_PATTERN',   'i')
```

Jeder Host, der keinem der drei Muster entspricht, landet im Result-Set.

**Einschraenkung:** USERHOST ist ein Client-supplied Wert. Er kann gefaelscht
werden (hoher Aufwand) und ist bei einigen JDBC-Treibern ohne explizite
Konfiguration leer oder ein generischer Wert (`localhost`). Leere USERHOST-
Werte werden in diesem Query gefiltert (`userhost IS NOT NULL`).

---

## Pattern-Konfiguration

Die drei Pattern-Variablen folgen denselben Namenskonventionen wie
`audit_report.py` (`DEFAULT_PATTERNS`) und koennen auf drei Wegen gesetzt werden:

### Option A: DEFINE im SQL vor dem Run

```sql
DEFINE APP_PATTERN   = '^wls-|^app-prod-|^tomcat-'
DEFINE INFRA_PATTERN = '^db-prod-|^oem-|^rman-'
DEFINE DBA_PATTERN   = '^jumphost-|^laptop-'
```

### Option B: Per `--patterns config.json` in audit_report.py

Die JSON-Datei mit `app_host_patterns`, `infra_host_patterns`,
`dba_host_patterns` wird auch fuer die automatische Report-Klassifizierung
(Section 5.2, 7.2) verwendet. Muster hier synchron halten.

### Option C: Einfache Einzel-Pattern-Anpassung im Bundle-Script

In `bin/ora-db-audit.sh` koennen die DEFINE-Defaults fuer alle Queries
ueberschrieben werden (geplant fuer v1.2, R3-Scope).

---

## Ablauf

```text
1. bin/ora-db-audit.sh ausfuehren (schliesst 12-distinct-hosts und
   19-offpath-candidates ein)
        |
2. tools/anonymize_bundle.py ausfuehren
   -> PSEUDO:HOST und PSEUDO:DBUSER ersetzen USERHOST und DBUSERNAME
   -> classification-Spalte (Wert 'OFF-PATH') bleibt KEEP
        |
3. tools/audit_report.py ausfuehren
   -> Section 7.2 listet OFF-PATH-Hosts aus 12-distinct-hosts (automatisch)
   -> 19-offpath-candidates.csv ist ergaenzende Detailtabelle (Appendix)
        |
4. Triage anhand action_count und distinct_actions:
   - Hohe action_count + unbekannter Host -> Prioritaet 1 (Incident-Check)
   - Niedrige action_count, bekanntes Programm -> moeglicherweise
     fehlkonfigurierter Monitoring-Job (P2)
   - Einzelner Connect, alter Timestamp -> historische Verbindung / nicht
     mehr aktiv (P3)
```

---

## Output-Schema

<!-- markdownlint-disable MD013 -->
| Spalte | Anonymisierung | Bedeutung |
| --- | --- | --- |
| `userhost` | `PSEUDO:HOST` | Quell-Hostname (CLIENT-supplied) |
| `dbusername` | `PSEUDO:DBUSER` | DB-Benutzerkonto |
| `os_username` | `PSEUDO:DBUSER` | OS-Benutzername des Clients |
| `client_program_name` | `PSEUDO:OBJECT` | Client-Programm (z.B. `sqlplus`, `jdbc`) |
| `action_count` | `COUNT` | Gesamt-Events dieses Hosts/User-Paares |
| `distinct_actions` | `COUNT` | Unterschiedliche Action-Typen |
| `first_seen` | `TIMESTAMP` | Erste Verbindung im Zeitfenster |
| `last_seen` | `TIMESTAMP` | Letzte Verbindung im Zeitfenster |
| `classification` | `KEEP` | Immer `OFF-PATH` (Filter-Ausgabe) |
<!-- markdownlint-enable MD013 -->

---

## Triage-Heuristik

```text
action_count >= 1000 AND distinct_actions >= 5
    -> HIGH: regelmassige Verbindung mit breitem Action-Profil
       Sofortiger Incident-Check empfohlen

action_count >= 100 AND client_program_name LIKE '%jdbc%'
    -> MEDIUM: Applikation direkt via JDBC ohne App-Tier-Host
       Pattern pruefen: moeglicherweise neuer App-Server

action_count < 10 AND first_seen = last_seen
    -> LOW: Einzelner Connect, kein Follow-up
       Oft DBA-Test oder fehlgeschlagener Deploy-Check

action_count < 10 AND os_username = dbusername
    -> INFO: Wahrscheinlich Entwickler mit lokalem SQL-Client
       Policy-Diskussion: soll Entwicklerzugriff auf Produktion erlaubt sein?
```

---

## Abgrenzung zu Application-Context-basierter Detection

<!-- markdownlint-disable MD013 -->
| Kriterium | Pattern-basiert (UC-19) | Application-Context (`ODB_AUDIT_CTX`) |
| --- | --- | --- |
| Deployment-Aufwand | Keiner - laeuft out-of-the-box | Context-Package deployen + App-Integration |
| Genauigkeit | Mittel - USERHOST ist client-supplied | Hoch - App setzt Kontext serverseitig |
| Faelschbarkeit | Ja (Client-Kontrolle ueber USERHOST) | Nein (DB-serverseitig gesetzt) |
| Off-Path-Granularitaet | Host-Level | Session-Level (App-Modul, Transaktion) |
| Empfehlung | Einstiegspunkt / keine Context-Infra | Produktiv-Umgebungen mit hoher Anforderung |
<!-- markdownlint-enable MD013 -->

---

## Verwandte Dokumente

- `docs/use-cases/audit-analysis.md` - Standard-Bundle-Pipeline
- `sql/12-distinct-hosts.sql` - Alle Hosts mit Volumen (Klassifizierungs-Basis)
- `sql/11-host-user-program.sql` - Connect-Matrix Host x User x Programm
- `docs/ai-analysis-rules.md` - Off-Path-Findings in AI-Analyse (Section 3)
- `docs/compliance-mapping.md` - CIS-Kontrollen mit Off-Path-Relevanz

---

Apache License 2.0 - ora-db-audit
