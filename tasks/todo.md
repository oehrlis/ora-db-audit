# ora-db-audit - Task Backlog

## Completed

### v1.6.0 - False Positive Detection Framework

- [x] Create `sql/20-fp-role-grantees.sql`
- [x] Create `tools/fp_patterns.json` with FP-001 to FP-004 patterns
- [x] Add FP detection engine to `tools/audit_report.py`
  - [x] `load_fp_patterns()`, `detect_false_positives()`, `render_fp_context_for_ai()`, `render_fp_section()`
  - [x] `--fp-patterns` CLI argument
  - [x] Wire into `_run_ai_analysis`
- [x] Extend AI system prompts (de/en) with Oracle engine behavior notes
- [x] Create `docs/false-positive-patterns.md`
- [x] Update `docs/ai-analysis-rules.md` - add §2.8 FP rule contract
- [x] CHANGELOG [1.6.0] + VERSION 1.5.0 → 1.6.0

### v1.7.0 - Report Improvements (F1-F7)

- [x] F1: Section 7.2.1 - event list for context-conditioned policies
- [x] F2: Section 7.2.2 - user list column in off-path host table
- [x] F3: Language-aware AI section header (de/en) via `t()`
- [x] F4: Executive summary AI sentinel + search-replace after `--ai` run
- [x] F5: Section 7.3 - uncovered users/roles + `sql/21-uncovered-users.sql`
- [x] F6a: Section 11 - custom policy DDL (oracle-supplied excluded)
- [x] F6b: `sql/20-fp-role-grantees.sql` + queries 19/21 added to `QUERIES` array
- [x] F7: Per-query sqlplus progress output `[N/M] filename ... done (Xs)`
- [x] CHANGELOG [1.7.0] + VERSION 1.6.0 → 1.7.0

---

## Open

### v1.8.0 - V2 Policy Alignment

**Kontext:** `ora-db-audit-eng` wurde auf V2-Policies umgestellt (Präfix `ODB_LOC_*_V2`).
Folgende strukturelle Änderungen haben direkten Impact auf das Reporting-Tool:

| Policy | V1 → V2 Änderung |
| --- | --- |
| `ODB_LOC_LOGON_EVENTS_V2` | LOGON+LOGOFF in einer Policy (war getrennt) |
| `ODB_LOC_DDL_ALL_V2` | Explizite Action-Liste (~80 Aktionen, kein ACTION ALL); 26ai-Actions hinzu |
| `ODB_LOC_CRIT_PKG_V2` | **Neu**: 19 kritische SYS-Packages (CIS 5.1.3), Object-Level EXECUTE |
| `ODB_LOC_APP_OFFPATH_V2` | **Massiv erweitert**: DDL+SELECT+DML+EXECUTE für ALL USERS + IS_KNOWN_CLIENT |
| `ODB_LOC_PRIV_DBA_ALL_V2` | Explicit-List statt ACTIONS ALL; Role-based via C##ODB_ROLE_DBA; kein WHEN |
| `ODB_LOC_DEV_ALL_V2` | **Neu**: Developer DDL+DML Audit via BY user-list |
| `ODB_LOC_ADHOC_ALL_V2` | **Neu**: ACTIONS ALL Reserve-Policy (default nicht enabled) |

---

#### Kritische Bugs (falsches Reporting)

- [x] **G-01** `17-cis-coverage.sql` CIS 5.5 FULL-Kriterium korrigieren [P1]
  - Aktuell: `audit_option = 'ALL'` - matcht V2 DBA-Policy nicht (explizite Liste)
  - Fix: FULL auch für explizite DDL+DML-Listen akzeptieren wenn BY ROLE oder BY SYS

- [x] **G-02** `17-cis-coverage.sql` CIS 5.3 audit_option_type korrigieren [P1]
  - Aktuell: prüft nur `STANDARD ACTION` für EXECUTE - matcht `ODB_LOC_CRIT_PKG_V2` nicht
  - Ursache: Package-level EXECUTE hat `audit_option_type = 'OBJECT ACTION'` in `AUDIT_UNIFIED_POLICIES`
  - Fix: CIS 5.3 CTE auch auf `OBJECT ACTION` mit `EXECUTE` erweitern

- [x] **G-03** `14-privileged-activity.sql` für C##ODB_ROLE_DBA-Holder erweitern [P1]
  - Aktuell: Hardcoded IN-Liste (SYS, SYSTEM, AUDIT_ADMIN etc.) - DBA-Role-Holder fehlen
  - Fix: Subquery auf `DBA_ROLE_PRIVS WHERE granted_role = 'C##ODB_ROLE_DBA'` zusätzlich

---

#### Fehlende Queries / Sections (High)

- [x] **G-04** Neue SQL-Query `22-crit-pkg-executions.sql` [P1]
  - Policy `ODB_LOC_CRIT_PKG_V2` hat keine dedizierte Analyse-Query
  - Inhalt: Top-Executions nach Package, User, Host aus UAT gefiltert auf OBJECT_NAME IN (19 Packages)
  - Pendant zu `14-privileged-activity.sql` aber für kritische Package-EXECUTE-Events

- [x] **G-05** Adhoc-Policy-Detection in `audit_report.py` [P2]
  - `ODB_LOC_ADHOC_ALL_V2` (ACTIONS ALL) sollte WARN triggern wenn enabled
  - Erkennung: in `render_section_03_policy_inventory()` prüfen ob Policy mit ACTIONS ALL enabled ist
  - Meldung: "WARN: Ad-hoc ACTIONS-ALL-Policy aktiv - nach Incident-Investigation deaktivieren?"

- [x] **G-06** AI-Prompt: IS_KNOWN_CLIENT ergänzen [P2]
  - FP-003 und AI-Context nennen nur `IS_APP_ACCESS`, nicht `IS_KNOWN_CLIENT`
  - V2 OFFPATH-Policy nutzt beide: WHEN `IS_APP_ACCESS != TRUE AND IS_KNOWN_CLIENT != TRUE`
  - Fix: beide Attribute in FP-003 Beschreibung und Kontext-Text ergänzen

---

#### Partielle / Unvollständige Coverage (Medium)

- [x] **G-07** Double-Coverage-Note in `04-policy-volume.sql` Kommentar + Report [P2]
  - V2-Design: Off-Path-DDL erscheint in BEIDEN Policies (ODB_LOC_DDL_ALL_V2 + ODB_LOC_APP_OFFPATH_V2)
  - Report Section 4.1 (Policy Volume) braucht Hinweis auf Doppelzählung
  - Ggf. `QUERY_FILES`-Eintrag "04" mit Kontext-Fussnote in `render_section_04_07_volumes()`

- [x] **G-08** 26ai-spezifische DDL-Actions dokumentieren [P3]
  - `ODB_LOC_DDL_ALL_V2` enthält MLE MODULE, MLE ENV, DOMAIN, PROPERTY GRAPH (nur 26ai)
  - Diese Actions erscheinen in UAT wenn auf 26ai deployed; Report/CIS-Check sollte Hinweis zeigen
  - Fix: Note in CIS 5.1 Abschnitt des Reports: "26ai-Actions: MLE MODULE/ENV, DOMAIN, PROPERTY GRAPH"

- [x] **G-09** Off-Path Cross-Reference verbessern [P2]
  - `19-offpath-candidates.sql` nutzt Hostname-Pattern (context-unabhängig, Fallback)
  - Zusätzlich: Filter auf `UNIFIED_AUDIT_POLICIES LIKE '%ODB_LOC_APP_OFFPATH_V2%'` in einem CTE
  - Abgleich: policy-tagged Off-Path-Records vs. pattern-basierte Kandidaten zeigen
  - Kann als Note in Report Section 7.2 eingefügt werden (kein neues SQL nötig)

- [x] **G-10** Developer-Activity-Section für `ODB_LOC_DEV_ALL_V2` [P3]
  - Keine dedizierte Analyse für Developer-Audit-Events
  - Minimal: in `render_section_06_privileged()` Subsektion für BY-USER policies hinzufügen
  - Alternativ: eigene Query `sql/23-developer-activity.sql` (analog zu 14-privileged)

---

#### Dokumentation (Low)

- [x] **G-11** Report-Section-Intros auf V2 Nomenclature updaten [P3]
  - Section 3 (Policy Inventory), Section 6 (Privileged), Section 7.2 (Offpath) erwähnen
    keine V2-spezifischen Policies; generische Formulierungen sind OK, aber Referenz-Listen updaten
  - Betrifft: `audit_report_messages.py` (oder direkte String-Literale in `audit_report.py`)

- [x] **G-12** `docs/` V2 Architecture Reference [P3]
  - Kein Dokument in `ora-db-audit/docs/` beschreibt die V2 Policy-Architektur
  - Verweis auf `ora-db-audit-eng/doc/04_policies.md` reicht als Cross-Ref im README
