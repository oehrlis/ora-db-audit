# Use Case: Off-Path Detection

<!-- SPDX-License-Identifier: Apache-2.0 -->

<!-- markdownlint-disable MD013 MD060 -->

## Uebersicht

| Eigenschaft | Wert |
| --- | --- |
| Use Case ID | UC-19 |
| SQL | `sql/19-offpath-candidates.sql` |
| Report-Sections | 7.2.1 Application Context (Szenario A), 7.2.2 Pattern-basiert (Szenario B) |
| Phase | Analyse (Host-Klassifizierung) |
| Zielgruppe | Security Engineer, DBA |
| Voraussetzung | `AUDIT_VIEWER` oder `AUDIT_ADMIN` |

<!-- markdownlint-enable MD013 MD060 -->

---

## Problem

Oracle Unified Auditing protokolliert fuer jedes Datenbank-Event den `USERHOST` -
den Hostnamen oder die IP-Adresse des Clients, der die Verbindung aufgebaut hat.
In einer ordentlich strukturierten Umgebung kommen Datenbankverbindungen
ausschliesslich von bekannten Tier-Hosts:

- **APP-Tier**: Applikationsserver, Web-Tier, Middleware, PaaS/K8s-Pods
- **INFRA**: Datenbankserver selbst, OEM-Agent, Backup-Client
- **DBA**: Jump-Hosts, DBA-Laptops

Verbindungen von **unbekannten Hosts** - solchen, die keinem dieser Kategorien
entsprechen - sind ein starkes Indikator-Signal fuer:

- Direktzugriffe auf die Datenbank ohne Applikations-Layer (Bypassing)
- Laterale Bewegung nach einer Kompromittierung
- Fehlkonfigurierte Clients / neue, noch nicht registrierte Tier-Hosts
- Entwickler-Notebooks in Produktion

Diese Hosts werden als **OFF-PATH** klassifiziert.

---

## Zwei Erkennungs-Szenarien

Das Tool unterstuetzt zwei Szenarien - in der Praxis kommen beide gleichzeitig vor.

### Wie man das aktive Szenario erkennt

Im Report Section 3 (Policy Inventory) oder direkt in `03_policy_inventory.csv`:
Wenn eine Audit-Policy in der Spalte `audit_condition` einen `SYS_CONTEXT(...)`-Ausdruck
enthaelt (der nicht auf den Oracle-eigenen `USERENV`-Context verweist), ist
Szenario A aktiv.

```sql
-- Beispiel-Bedingung in einer Off-Path-Policy (jeder Context-Name moeglich):
SYS_CONTEXT('ISC_AUDIT_CTX','IS_APP_ACCESS') != 'TRUE'
OR SYS_CONTEXT('ISC_AUDIT_CTX','IS_APP_ACCESS') IS NULL
```

---

### Szenario A - Application Context deployed

Ein Oracle Application Context (kundenspezifischer Name) ist auf der Zieldatenbank
deployed. Ein LOGON-Trigger setzt pro Session boolean Attribute:

| Attribut | TRUE = ... | Verwendung |
| --- | --- | --- |
| `IS_APP_ACCESS` | Host matcht App-Server-Pattern im Package | Off-Path-Policy |
| `IS_OEM_ACCESS` | OEM-Monitoring-Verbindung (Host oder User) | INFRA-Exclusion |
| `IS_KNOWN_CLIENT` | Explizit registrierter Client-Host oder IP | DBA-Exclusion |
| `IS_DEV_TOOL` | SQL Developer, Toad oder aequivalentes Tool | Dev-Exclusion |

Die Audit-Policies feuern **nur wenn das Flag FALSE oder NULL ist** - d.h. alle
Records aus einer Context-bedingten Policy sind per Definition Off-Path-Zugriffe.

**Audit-Policy WHEN-Klausel - NULL-Fallback-Muster:**

```sql
-- Korrekt: NULL wird wie FALSE behandelt (konservative Fallback-Auditierung)
CONDITION: SYS_CONTEXT('ISC_AUDIT_CTX','IS_APP_ACCESS') != 'TRUE'
           OR SYS_CONTEXT('ISC_AUDIT_CTX','IS_APP_ACCESS') IS NULL

-- Falsch: NULL-Sessions (Trigger-Fehler) werden nicht auditiert
CONDITION: SYS_CONTEXT('ISC_AUDIT_CTX','IS_APP_ACCESS') = 'FALSE'
```

**Context-Package Konfiguration (kundenspezifisch anpassen):**

```sql
-- App-Server Host-Pattern (WLS Classic + generische K8s-Patterns)
C_APP_HOST_PATTERN CONSTANT VARCHAR2(400) :=
    '^customer-app-|^wls-|-[a-z0-9]{10}-[a-z0-9]{5}$|-[0-9]{10}-';
-- K8s ReplicaSet-Pod: -<10hex>-<5hex> am Hostnamen-Ende
-- K8s CronJob-Pod:    -<10digits>- im Hostnamen (Unix-Timestamp)

-- OEM-Server und Standard-Agent-User
C_OEM_HOST_PATTERN CONSTANT VARCHAR2(400) := '^oem-mgmt-';
C_OEM_USERS        CONSTANT VARCHAR2(200) := 'DBSNMP|SYSMAN';

-- Explizit registrierte DBA-Workstations (NULL = deaktiviert)
C_KNOWN_HOST_PATTERN CONSTANT VARCHAR2(400) := '^jumphost-|^dba-ws-';

-- Developer-Tool Pattern (SQL Developer, Toad)
C_DEV_TOOL_PATTERN CONSTANT VARCHAR2(200) := 'sql[[:space:]_.-]*developer|toad(\.exe)?';
```

**Finding-Severity (Szenario A):**

| Zustand | Severity |
| --- | --- |
| Context in `dba_context`, Trigger ENABLED, nur historische Events | INFO / LOW |
| Context in `dba_context`, Trigger ENABLED, laufende Events | MEDIUM (Host nicht registriert) |
| Context registriert, Trigger DISABLED | HIGH (Infra unvollstaendig) |
| Context nicht in `dba_context` | HIGH (nicht deployed) |

---

### Szenario B - Pattern-basiert (kein Application Context)

Kein Application Context auf der Datenbank deployed oder unbekannt.
Das Tool klassifiziert Hosts aus `UNIFIED_AUDIT_TRAIL.userhost` anhand
von Pattern-Listen ohne Datenbank-seitiges Deployment:

```sql
-- 19-offpath-candidates.sql: negative Pattern-Filter
NOT REGEXP_LIKE(userhost, '&APP_PATTERN',   'i')
AND NOT REGEXP_LIKE(userhost, '&INFRA_PATTERN', 'i')
AND NOT REGEXP_LIKE(userhost, '&DBA_PATTERN',   'i')
```

**Default-Pattern-Konfiguration** (`DEFAULT_PATTERNS` in `audit_report.py`):

```json
{
  "app_host_patterns": [
    "^auditlab-app-",
    "^app-",
    "^wls-",
    "-[a-z0-9]{10}-[a-z0-9]{5}$",
    "-[0-9]{10}-"
  ],
  "infra_host_patterns": ["^auditlab-db", "^oem-"],
  "dba_host_patterns":   ["^laptop-", "^jumphost-"]
}
```

Die K8s-Patterns (`-[a-z0-9]{10}-[a-z0-9]{5}$` und `-[0-9]{10}-`) sind
generisch und greifen fuer Standard-Kubernetes-Pod-Namen ohne
kundenspezifische Prefix-Konfiguration:

- **ReplicaSet-Pod**: `my-service-6c4d8bbdfd-jdbsd` (10-char + 5-char Hash)
- **CronJob-Pod**: `healthcheck-batch-scheduled-1774600200-main-xyz` (10-digit Unix-Timestamp)

**Kunden-spezifische Pattern** (via `--patterns config.json`):

```json
{
  "app_host_patterns": [
    "^prod-app-",
    "^wls-prod-",
    "-[a-z0-9]{10}-[a-z0-9]{5}$",
    "-[0-9]{10}-"
  ],
  "infra_host_patterns": ["^db-prod-", "^oem-", "^rman-"],
  "dba_host_patterns":   ["^jumphost-", "^laptop-stefan"]
}
```

**Finding-Severity (Szenario B):**

| Heuristik | Severity |
| --- | --- |
| `action_count >= 1000` UND `distinct_actions >= 5` | HIGH |
| JDBC-Client auf unbekanntem Host | MEDIUM (moeglicherweise neuer App-Server) |
| Einzelner Login, alter Timestamp | LOW |
| `os_username = dbusername` | INFO (wahrscheinlich Entwickler) |

**Wichtig vor dem Raising:** Ein Host in Section 7.2.2 kann ein legitimer Server sein,
der noch nicht in der Pattern-Konfiguration registriert ist. Login-Volumen, Distinct
Users und Client-Programm pruefen. Falls bekannt: zur `--patterns`-Datei hinzufuegen.

---

## Ablauf

```text
1. bin/ora-db-audit.sh ausfuehren (12-distinct-hosts + 19-offpath-candidates)
        |
2. tools/anonymize_bundle.py (optional)
   -> PSEUDO:HOST und PSEUDO:DBUSER ersetzen USERHOST und DBUSERNAME
        |
3. tools/audit_report.py ausfuehren
   -> Section 7.2.1: Context-Variablen aus Policy-Conditions (Szenario A)
   -> Section 7.2.2: Pattern-basierte OFF-PATH-Host-Liste (Szenario B)
   -> 19-offpath-candidates.csv: ergaenzende Detailtabelle (Appendix)
        |
4. Triage anhand action_count und distinct_actions (Heuristik oben)
```

---

## Output-Schema (19-offpath-candidates.csv)

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

## Einschraenkungen

- **USERHOST ist client-supplied** und kann theoretisch gefaelscht werden.
  JDBC-Treiber ohne explizite Konfiguration liefern manchmal `localhost` oder
  eine leere Zeichenkette (wird im Query gefiltert).
- **Szenario B erkennt keine Schema-Zugriffs-Kontext**: ob ein App-Server
  auf das "falsche" Schema zugreift, ist ohne Application Context nicht
  erkennbar. Szenario A (Context mit IS_APP_ACCESS) loest dies durch
  schema-spezifische Policy-Conditions.

---

## Verwandte Dokumente

- `docs/use-cases/audit-analysis.md` - Standard-Bundle-Pipeline
- `sql/12-distinct-hosts.sql` - Alle Hosts mit Volumen (Klassifizierungs-Basis)
- `sql/11-host-user-program.sql` - Connect-Matrix Host x User x Programm
- `docs/ai-analysis-rules.md` - Off-Path-Findings Szenario A/B (Section 2.6)
- `docs/configuration.md` - Pattern-Konfiguration (`--patterns`)

---

Apache License 2.0 - ora-db-audit
