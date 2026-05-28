# Audit Analysis Pack - Customer Handover
<!-- SPDX-License-Identifier: Apache-2.0 -->

<!-- markdownlint-disable MD013 -->

> Einseitiges Handover-Sheet pro Customer-Engagement.
> Vom Engagement-Lead ausgefüllt, vor dem ersten `ora-db-audit.sh`-Lauf
> an den Customer-DBA übergeben. Kopie zum Engagement-Ordner unter
> `doc/analysis/handover_customer_<NAME>.md` ablegen (mit ausgefüllten Werten,
> nicht das Template selbst).

---

## 1. Engagement-Header

| Feld                         | Wert                                        |
|------------------------------|---------------------------------------------|
| Customer                     | `<CUSTOMER-NAME>`                           |
| Engagement-ID                | `<ENG-ID>`                                  |
| Customer-Prefix (Policies)   | `<CUSTOMER-PREFIX>`                         |
| Engagement-Lead intern       | `<NAME>` `<E-Mail>`                         |
| Customer-DBA-Ansprechpartner | `<NAME>` `<E-Mail>`                         |
| Datum Handover               | `<YYYY-MM-DD>`                              |
| Pack-Version                 | `0.1.0` (bundle_version in `manifest.json`) |

---

## 2. Connect & Scope

| Feld                      | Wert / Default                                                                   |
|---------------------------|----------------------------------------------------------------------------------|
| DBSID                     | `<DBSID>` (CDB-Instance-Name)                                                    |
| PDB-Name                  | `<PDB>`                                                                          |
| Connect-String            | z.B. `"/ as sysdba"` oder `"auditadmin/secret@TNS"` oder Wallet `"/@AUDIT_PROD"` |
| Audit-Lese-Rolle          | `AUDIT_VIEWER` reicht; `SYSDBA` ist ebenfalls OK                                 |
| Zeitfenster (Initial-Run) | `30` Tage                                                                        |
| Zeitfenster (monatlich)   | `30` Tage mit `--load-mapping`                                                   |
| Top-N pro Query           | `100` (bei sehr breiten Trails ggf. `50`)                                        |
| Output-Verzeichnis        | `<absoluter Pfad>` (Default `./audit_bundle`)                                    |

> **Hinweis:** Bei SYSDBA-Connects auf eine PDB muss `--pdb <NAME>` mitgegeben
> werden - das Script setzt dann `ALTER SESSION SET CONTAINER`.

---

## 3. Anonymisierung

| Feld                                  | Wert / Default                             |
|---------------------------------------|--------------------------------------------|
| Anonymisierung Customer-Side?         | `ja` (empfohlen) / `nein`                  |
| Customer-Prefix (`--customer-prefix`) | `<CUSTOMER-PREFIX>`                        |
| Zusätzliche Whitelist (`--whitelist`) | `<Pfad zu JSON oder "n/a">`                |
| Python-Interpreter                    | `$ORACLE_HOME/python/bin/python` (Default) |

### Custom-Whitelist-Vorlage

Werte, die customer-side sichtbar bleiben sollen (Standard-Tools, generische
Service-Account-Namen, eigene App-Hostnames die für die Analyse hilfreich sind):

```json
{
  "whitelist": [
    "MY_BATCH_USER",
    "MY_MONITORING_AGENT",
    "wls-monitor.intra.example.com"
  ]
}
```

---

## 4. Versand-Empfänger

| Feld                      | Wert                                             |
|---------------------------|--------------------------------------------------|
| Empfänger Bundle          | `<ANALYST-E-Mail>`                               |
| Versand-Kanal             | E-Mail / SharePoint / SFTP - bitte spezifizieren |
| Maximale Bundle-Grösse    | `<MB>` (E-Mail-Anhang oft auf 25 MB limitiert)   |
| Verschlüsselung Transport | TLS-Mail (Default) / S/MIME / PGP                |
| Aufbewahrung beim Analyst | `<N>` Tage nach Engagement-Ende, dann Löschung   |

> **Sicherheitspflicht:** Nur die `*.anon.tar.gz` versenden. Die
> `*.mapping.json` und das rohe Bundle bleiben **immer** beim Customer.

---

## 5. Host-Pattern-Konfiguration

Für die Report-Klassifizierung (`tools/audit_report.py --patterns`)
werden engagement-spezifische Regex-Pattern verwendet. Priorität:
`INFRA > APP > DBA > OFF-PATH`.

```json
{
  "app_host_patterns":   ["^wls-", "^app-srv-"],
  "infra_host_patterns": ["^oem-", "^db-"],
  "dba_host_patterns":   ["^jumphost-"]
}
```

Bitte folgende Listen vom Customer einholen (vor erstem Report-Run):

| Kategorie  | Erwartete Pattern | Beispiele                |
|------------|-------------------|--------------------------|
| App-Server | `^...`            | `^wls-`, `^app-srv-`     |
| Infra      | `^...`            | `^oem-`, `^backup-`      |
| DBA        | `^...`            | `^jumphost-`, `^laptop-` |

Diese Datei wird als `<engagement>_patterns.json` neben dem Bundle abgelegt.

---

## 6. Run-Kadenz

| Phase                         | Frequenz        | Befehl-Skizze                                             |
|-------------------------------|-----------------|-----------------------------------------------------------|
| Initial-Baseline              | einmalig        | `./ora-db-audit.sh --days 30 --anonymize`                 |
| Phase-2-Workshop-Vorbereitung | 1x pro Workshop | `--days 30 --anonymize --report --patterns ...`           |
| Monatlicher Trend-Vergleich   | 1x pro Monat    | `--load-mapping <initial>.mapping.json --anonymize`       |
| Nach Policy-Deployment        | 1x nach 7 Tagen | `--days 7 --top-n 50 --anonymize --report`                |

---

## 7. Checkliste Customer-DBA (vor erstem Lauf)

- [ ] `sqlplus` im PATH (`. oraenv` ausgeführt)
- [ ] Connect-User hat Lese-Recht auf `UNIFIED_AUDIT_TRAIL` und `DBA_*`-Views
- [ ] `$ORACLE_HOME/python/bin/python --version` -> Python 3.x verfügbar
  *(nur falls `--anonymize` oder `--report` verwendet wird)*
- [ ] Output-Verzeichnis hat Schreibrechte und genug Platz (< 100 MB sind realistisch)
- [ ] `_sqlplus.log` darf erzeugt werden (kann sensitive Werte enthalten)
- [ ] Versandweg für `*.anon.tar.gz` definiert
- [ ] `*.mapping.json` als "stay local" markiert (nicht in Cloud-Sync, nicht im Repo)

---

## 8. Eskalationspfad

| Symptom                                   | Erste Massnahme                                |
|-------------------------------------------|------------------------------------------------|
| `ORA-01017: invalid username/password`    | Connect-String prüfen, ggf. Wallet/`op read`   |
| `missing or empty output: <NN_query>.csv` | `_sqlplus.log` prüfen, ggf. Privileg fehlt     |
| Bundle deutlich > 50 MB                   | `--top-n 50` oder kürzeres Zeitfenster         |
| `anonymize_bundle.py: python not found`   | `ORACLE_HOME/python/bin/python` setzen         |
| `[FATAL] Bundle has no manifest.json`     | Falsches Input-Verzeichnis - .tar.gz entpacken |

Bei sonstigen Fragen: Engagement-Lead intern kontaktieren (siehe Header).

<!-- EOF -->
