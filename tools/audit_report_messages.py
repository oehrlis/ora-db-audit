#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# ------------------------------------------------------------------------------
# OraDBA - Oracle Database Infrastructure and Security, 5630 Muri, Switzerland
# ------------------------------------------------------------------------------
# Name.......: audit_report_messages.py
# Author.....: Stefan Oehrli (oes) stefan.oehrli@oradba.ch
# Editor.....: Stefan Oehrli
# Date.......: 2026.05.29
# Version....: 1.3.0
# Purpose....: Centralised user-facing message dictionary for audit_report.py.
#              Keeps every German string in one place so v1.1 can add an EN
#              translation by extending the dict; no code changes required.
# Notes......: Per tasks/rework-plan.md Phase D + Stefan's amendment of
#              2026-05-28: v1.0.0 ships German-only. Architecture supports
#              additional languages by extending MESSAGES with a new lang
#              key. Lightweight dict-based design - intentionally NOT gettext
#              (overkill for the ~50-100 strings expected).
#              docs/ai-analysis-rules.md is the rules contract referenced by
#              the AI prompt; it stays English (technical reference, not
#              user-facing report content).
# License....: Apache License Version 2.0
# ------------------------------------------------------------------------------
# CHANGE LOG:
# 2026.05.29  oes  v1.3.0: F1-F6a keys for v1.7.0 report features.        1.3.0
# 2026.05.28  oes  R3: add exec.sampling_note key (DE+EN); align version   1.2.0
#                  to repo SemVer.
# 2026.05.28  oes  R5: populate MESSAGES["en"] with full EN translations;  1.1.1
#                  add message keys for sections 3-10, executive summary,
#                  storage verdicts, and all remaining inline strings.
# 2026.05.28  oes  v1.1.0 initial: MESSAGES["de"] complete; architecture  1.1.0
#                  ready for EN via SUPPORTED_LANGUAGES extension.
# ------------------------------------------------------------------------------
"""Centralised message dictionary for audit_report.py.

Usage:

    from audit_report_messages import t, SUPPORTED_LANGUAGES

    title = t("report.title")
    intro = t("report.intro", dbsid="ORCLCDB", days=30)
"""

from __future__ import annotations

from typing import Any


SUPPORTED_LANGUAGES = ("de", "en")
"""Languages with a complete MESSAGES population."""

DEFAULT_LANGUAGE = "de"


MESSAGES: dict[str, dict[str, str]] = {
    "de": {
        # --- Report header / page title ---
        "report.page_title": "Audit-Trail Analyse - {dbsid} / {pdb}",
        "report.title": "Oracle Audit Trail Analyse",
        "report.subtitle": "Unified Auditing Pure Mode - DBSID: {dbsid}",
        "report.generated_at": "Generiert: `{ts}` | Bundle: `{bundle_name}`",
        "report.window": "Zeitfenster: {days} Tage | Top-N: {top_n}",
        "report.audit_mode": "Audit-Modus: **{audit_mode}**",

        # --- Executive summary labels ---
        "exec.dbsid": "**DBSID:** `{dbsid}`",
        "exec.pdb": "**PDB:** `{pdb}`",
        "exec.window": "**Zeitfenster:** letzte {days} Tage",
        "exec.top_n": "**Bundle Top-N:** {top_n}",
        "exec.generated": "**Bundle erzeugt:** {ts}",
        "exec.version": "**Bundle-Version:** {version}",
        "exec.sampling_note": (
            "> **Hinweis:** Sampling aktiv - Abfragen 08-12, 15 wurden auf "
            "{n} Zeilen begrenzt (`ROWNUM <= {n}`). Absolute Zaehler sind "
            "Schaetzwerte; relative Rangfolgen bleiben repraesentativ."
        ),

        # --- Section titles ---
        "section.executive_summary": "Executive Summary",
        "section.metrics": "Kennzahlen",
        "section.top3_volume": "Top 3 Volume-Treiber (Policy)",
        "section.host_summary": "Host-Klassifizierung (Zusammenfassung)",
        "section.01_config": "1. Audit-Konfiguration",
        "section.02_storage": "2. Trail Storage",
        "section.03_policy_inventory": "3. Policy-Inventar",
        "section.04_07_volumes": "4. Volumen-Verteilung",
        "section.04_1": "4.1 Policies",
        "section.04_2": "4.2 User",
        "section.04_3": "4.3 Actions",
        "section.04_4": "4.4 Objekte",
        "section.04_5": "4.5 Client-Programme",
        "section.04_6": "4.6 Policies x Hosts",
        "section.04_7": "4.7 Policies x User x Action",
        "section.05_connect_profile": "5. Connect-Profil",
        "section.05_1_hosts": "5.1 Hosts",
        "section.05_2_pattern": "5.2 Host-Pattern-Analyse",
        "section.05_3_matrix": "5.3 Connect-Matrix (Host x User x Programm)",
        "section.06_privileged": "6. Privileged Activity",
        "section.07_security_signals": "7. Security Signals",
        "section.07_1_failed": "7.1 Failed Logins",
        "section.07_2_offpath": "7.2 Off-Path Candidates",
        "section.07_2a_ctx": "7.2.1 Application Context (Szenario A)",
        "section.07_2b_pattern": "7.2.2 Pattern-basierte Klassifizierung (Szenario B)",
        "section.08_tuning": "8. Tuning-Empfehlungen",
        "section.08_1_when_clauses": "8.1 WHEN-Klausel-Vorschlaege",
        "section.09_cis_coverage": "9. CIS Benchmark 5.1-5.5 - Policy-Abdeckung",
        "section.10_audit_roles": "10. Audit-Rollen - Mitglieder und Risiko-Flags",
        "section.appendix": "Anhang",
        "section.appendix_manifest": "Manifest",
        "section.appendix_full_data": "Vollstaendige Daten - {name}",

        # --- Table column labels ---
        "label.metric": "Metrik",
        "label.value": "Wert",
        "label.class": "Klasse",
        "label.host": "Host",
        "label.logins": "Logins",
        "label.host_count": "Anzahl Hosts",
        "label.distinct_users": "Distinct Users",
        "label.policy": "Policy",
        "label.events": "Events",
        "label.manifest": "Manifest",

        # --- Executive summary metric row labels ---
        "metric.pol_events": "Events (Policy-getrieben, Summe Top-N)",
        "metric.user_events": "Events (User-Summe Top-N)",
        "metric.failed_logins": "Failed Logins (Summe Top-N)",
        "metric.mandatory_events": "Events (ORA$MANDATORY)",
        "metric.active_policies": "Aktive Audit-Policies (Inventar)",
        "metric.storage_partitions": "Storage-Partitionen",

        "label.cis_control": "CIS Control",
        "label.cis_title": "Titel",
        "label.cis_policy": "Policy",
        "label.cis_exists": "Exists",
        "label.cis_enabled": "Enabled",
        "label.cis_verdict": "Verdict",
        "label.cis_custom": "Abgedeckt durch (Custom)",
        "label.cis_oracle": "Oracle-Policies",
        "label.role_target": "Ziel-Rolle",
        "label.role_grantee": "Grantee",
        "label.role_type": "Typ",
        "label.role_path": "Grant-Pfad",
        "label.role_admin": "Admin-Option",
        "label.role_flag": "Risk-Flag",

        # --- Audit-mode interpretation labels ---
        "audit_mode.pure": "Pure Mode (sauber)",
        "audit_mode.pure_intent": "Pure Mode (Legacy-Parameter gesetzt, ohne Effekt)",
        "audit_mode.pure_contaminated": "Pure Mode (alte AUD$-Daten vorhanden, kein Schreibverkehr)",
        "audit_mode.mixed": "Mixed Mode (Bericht ausserhalb des Scopes)",
        "audit_mode.unsupported": "Unified Auditing nicht aktiv (nicht unterstuetzt)",

        # --- Section 1 - mode blockquotes ---
        "mode.mixed_note": (
            "> **Mixed Mode erkannt** - dieser Bericht-Scope ist Pure Mode. "
            "Findings unterhalb sind unter dieser Annahme zu lesen; eine "
            "vollstaendige Analyse erfordert vorher die Migration auf "
            "Pure Mode (siehe /oracle-audit skill, Mixed-to-Pure)."
        ),
        "mode.pure_contaminated_note": (
            "> **Pure Mode mit Alt-Daten** - keine neuen Legacy-Schreibvorgaenge, "
            "aber `SYS.AUD$` enthaelt noch alte Zeilen. Optional purgen mit "
            "`DBMS_AUDIT_MGMT.CLEAN_AUDIT_TRAIL(AUDIT_TRAIL_AUD_STD,...)`."
        ),
        "mode.pure_intent_note": (
            "> **Pure Mode, Legacy-Parameter gesetzt** - `audit_trail` Wert "
            "ist nicht `NONE`, hat in Pure Mode aber keine Wirkung. "
            "Empfehlung: beim naechsten Bounce `audit_trail = NONE` setzen."
        ),
        "mode.unsupported_note": (
            "> **Unified Auditing nicht aktiv** - dieser Tool-Scope ist nicht "
            "anwendbar. Vor weiterer Analyse Unified Auditing aktivieren."
        ),
        "mode.unknown_note": (
            "> _(audit_mode-Metadata fehlt - 01-config.sql wurde "
            "moeglicherweise vor Phase C generiert. Pure-Mode-Annahmen "
            "gelten implizit; legacy-Parameter-Findings bitte selbst pruefen.)_"
        ),
        "mode.aud_recent_rows": (
            "> **Hinweis:** `SYS.AUD$` enthaelt {n} Zeilen aus "
            "den letzten 7 Tagen - aktive Mixed-Mode-Schreibvorgaenge? "
            "Quelle pruefen (Traditional-AUDIT-Statements aktiv?)."
        ),
        "mode.legacy_params_footer": (
            "_Parameter mit `_(legacy)_` Markierung sind Mixed-Mode-Artefakte. "
            "Sie haben in Pure Mode keinen Effekt - Findings darauf sind "
            "False-Positive (siehe `docs/ai-analysis-rules.md` Section 2)._"
        ),

        # --- Section 2 - storage verdicts ---
        "storage.verdict_fmt": "**Verdict:** `{label}` - {note}",
        "storage.verdict_misconfig": (
            "AUD$UNIFIED Default-Tablespace ist `SYSAUX`. Audit-Daten "
            "und Data-Dictionary teilen sich denselben Tablespace - "
            "Empfehlung: `ALTER TABLE AUDSYS.AUD$UNIFIED MODIFY DEFAULT "
            "ATTRIBUTES TABLESPACE AUDIT_DATA;` (Tablespace `AUDIT_DATA` "
            "ggf. zuerst anlegen)."
        ),
        "storage.verdict_ok": (
            "Default- und alle Partitions-Tablespaces stehen auf "
            "`{tbs}`. Keine Massnahme erforderlich."
        ),
        "storage.verdict_transient_older": (
            "Default-Tablespace ist `{tbs_default}` (korrekt), aber "
            "aeltere Partitionen liegen noch in: "
            "`{tbs_older}`. Optional: pro Partition "
            "`ALTER TABLE AUDSYS.AUD$UNIFIED MOVE PARTITION <name> "
            "TABLESPACE {tbs_default};` - keine Pflicht (kein Finding)."
        ),
        "storage.verdict_transient_current": (
            "Default-Tablespace wurde auf `{tbs_default}` umgestellt, "
            "aktuelle Partition liegt aber noch in `{tbs_current}`. "
            "Naechste Range-Partition wird in `{tbs_default}` angelegt "
            "(Auto-Partitionierung). Kein Finding."
        ),
        "storage.verdict_empty": (
            "AUD$UNIFIED hat noch keine Partition - das erste Event "
            "erzeugt eine Partition in `{tbs_default}`. Kein Finding."
        ),
        "storage.row_default": "Default fuer neue Partitionen",
        "storage.row_current": "Aktuelle Partition",
        "storage.row_older": "Aeltere Partitionen",
        "storage.none": "_(keine)_",
        "storage.partitions_summary": (
            "Partitionen: {n} - Gesamt {rows} Zeilen / {mb} MB."
        ),
        "storage.verdict_unknown": (
            "> _(Tablespace-Metadata fehlt - 02-storage.sql wurde "
            "moeglicherweise vor Phase C generiert. Manuelle Pruefung "
            "der Tablespace-Zuordnung erforderlich.)_"
        ),
        "storage.trail_mgmt": "**Trail-Management (Purge)**",
        "storage.purge_job_row": "Purge-Job (Unified Audit Trail)",
        "storage.last_arch_row": "Letzter Archivierungs-Zeitstempel",
        "storage.part_interval_row": "Partitions-Intervall",
        "storage.purge_warn_no_job": (
            "> ⚠️ **Kein Purge-Job konfiguriert** - "
            "`AUD$UNIFIED` waechst unbegrenzt."
        ),
        "storage.purge_warn_no_ts": (
            "> ⚠️ **Kein `LAST_ARCHIVE_TIMESTAMP` gesetzt** - "
            "der Purge-Job loescht keine Zeilen."
        ),
        "vol.ghost_events_note": (
            "> ℹ️ **Historische Events aus inaktiven Policies ({n}):** "
            "{total} Events insgesamt. Diese Policies waren aktiv, als "
            "die Events aufgezeichnet wurden, sind aber aktuell nicht "
            "aktiviert. Kein Handlungsbedarf."
        ),

        # --- Section 3 - policy inventory ---
        "policy.count": "Policies erfasst: **{n}**.",
        "policy.unique_count": (
            "**{n}** eindeutige Policies ({n_custom} Custom, "
            "{n_oracle} Oracle-supplied)."
        ),
        "policy.ora_count": "- Oracle-supplied (`ORA_*`): {n}",
        "policy.cust_count": "- Kunden-/Custom-Policies: {n}",
        "policy.see_appendix": "_Vollstaendige Aktionsliste verfuegbar mit `--include-appendix`._",
        "section.03_detail": "3.1 Policy-Inventar - Vollstaendige Aktionsliste",
        "section.09_detail": "9.1 Abdeckende Policies - Detail",
        "label.ora": "ORA",
        "label.policy_option": "Option",
        "label.entity": "Entity",
        "label.entity_type": "Typ",
        "label.success_short": "S",
        "label.failure_short": "F",
        "label.condition": "Bedingung",
        "label.cis_controls": "CIS",
        "cis.detail_intro": (
            "Policies die mindestens eine CIS-Anforderung abdecken "
            "(gefiltert aus Policy-Inventar, ohne Duplikate pro Entity):"
        ),

        # --- Section 6 - privileged activity ---
        "section.06_intro": (
            "Aktivitaet privilegierter User (SYS, SYSTEM, "
            "Customer-DBA-Accounts)."
        ),

        # --- Section 7 - security signals / off-path ---
        "offpath.ctx_intro": (
            "Audit-Policies mit `SYS_CONTEXT`-Bedingung erkannt (Szenario A). "
            "Alle Records dieser Policies sind per Definition Off-Path-Zugriffe "
            "(die Policy feuert nur, wenn das Context-Flag FALSE oder NULL ist). "
            "Sicherheitsbewertung nach `docs/ai-analysis-rules.md` Abschnitt 2.6."
        ),
        "offpath.ctx_found": (
            "**{n} Context-Attribut(e)** in Policy-Bedingungen erkannt:"
        ),
        "offpath.ctx_none": (
            "_Kein Application Context (SYS_CONTEXT) in Audit-Policy-Bedingungen "
            "gefunden. Off-Path-Detection basiert ausschliesslich auf "
            "Pattern-Matching (Szenario B, Abschnitt 7.2.2)._"
        ),
        "offpath.ctx_hint_null": (
            "> **Hinweis NULL-Fallback:** Policy-Bedingungen sollten "
            "`!= 'TRUE' OR IS NULL` verwenden (nicht `= 'FALSE'`), damit "
            "Sessions ohne gesetzten Context (Trigger-Fehler) konservativ "
            "auditiert werden."
        ),
        "offpath.ctx_label_ctx": "Context",
        "offpath.ctx_label_attr": "Attribut",
        "offpath.ctx_label_policies": "Policies",
        "offpath.pattern_intro": (
            "Host-Klassifizierung aus `12_distinct_hosts.csv` anhand der "
            "konfigurierten Pattern-Listen (app / infra / dba). "
            "Hosts ohne Treffer = **OFF-PATH**."
        ),
        "offpath.none": (
            "_Keine OFF-PATH-Hosts identifiziert - alle Quell-Hosts "
            "matchen App/Infra/DBA-Pattern._"
        ),
        "offpath.found": (
            "**{n} Off-Path-Host(s)** - Hosts die "
            "weder dem App-, Infra- noch DBA-Pattern entsprechen:"
        ),
        "offpath.hint": (
            "> **Hinweis:** OFF-PATH-Hosts identifiziert. "
            "Detail in Kapitel 7 (Security Signals)."
        ),

        # --- Section 9 - CIS coverage ---
        "cis.fail_count": (
            "> **{n} von {total} CIS-Anforderungen nicht abgedeckt** "
            "(FAIL). Keine aktive Custom-Policy deckt diese Anforderungen ab."
        ),
        "cis.partial_count": (
            "> **{n} CIS-Anforderung(en) nur teilweise abgedeckt** "
            "(PARTIAL). Abdeckung besteht, aber mit WHEN-Bedingung oder "
            "eingeschraenktem User-Scope."
        ),
        "cis.warn_count": (
            "> **{n} CIS-Policy/ies vorhanden aber deaktiviert** "
            "(WARN). Policies existieren, sind aber nicht aktiv."
        ),
        "cis.all_pass": "> Alle CIS 5.1-5.5 Anforderungen vollstaendig abgedeckt (PASS).",
        "cis.coverage_note": (
            "_Abdeckung wird durch Aktions-Vergleich ermittelt (nicht durch Policy-Namen). "
            "PARTIAL = Policy mit WHEN-Bedingung oder eingeschraenktem User-Scope. "
            "Oracle-supplied Policies werden informativ gezeigt, beeinflussen das Verdict nicht._"
        ),
        "cis.source": "Quelle: `17_cis_coverage.csv`",

        # --- Section 10 - audit roles ---
        "roles.review_count": (
            "> **{n} Eintrag/Eintraege mit erhoehtem Risiko** "
            "(WARN/REVIEW) - manuelle Pruefung der Grantees empfohlen."
        ),
        "roles.source": "Quelle: `18_audit_roles.csv`",

        # --- Source / data-origin notes ---
        "note.source_01": "Quelle: `01-config.csv` (DBMS_AUDIT_MGMT, init-Parameter, Instanz)",
        "note.source_02": "Quelle: `02-storage.csv` (AUD$UNIFIED Partitionen, Tablespace-Zuordnung)",
        "note.no_data": "_(keine Daten verfuegbar)_",
        "note.ai_generated": "> Automatisch generierte Analyse - Findings sind zu verifizieren.",
        "note.policy_ddl_unavailable": (
            "_(Policy-DDL nicht verfuegbar - `sql/16-policy-ddl.csv` fehlt im Bundle "
            "oder ohne `AUDIT_ADMIN`-Privileg generiert. Vorschlag uebersprungen.)_"
        ),
        "note.tuning_disclaimer": (
            "> **Hinweis:** Templates sind als Diskussionsgrundlage gedacht. "
            "WHEN-Klauseln sind policy-spezifisch - vor dem Einsatz manuell "
            "review-en und gegen Compliance-Anforderungen pruefen."
        ),
        "note.csv_missing": "_({fname} nicht im Bundle)_",
        "note.offpath_skipped": (
            "_(Off-Path-Analyse uebersprungen - 12_distinct_hosts fehlt)_"
        ),
        "note.hosts_unclassifiable": (
            "_(Hosts nicht klassifizierbar - 12_distinct_hosts fehlt)_"
        ),
        "note.csv_missing_cis": (
            "> _(17_cis_coverage.csv fehlt im Bundle - "
            "SQL/17-cis-coverage.sql wurde nicht ausgefuehrt oder ist "
            "nicht in diesem Bundle enthalten.)_"
        ),
        "note.cis_no_data": "> _(Keine CIS-Coverage-Daten vorhanden.)_",
        "note.csv_missing_roles": (
            "> _(18_audit_roles.csv fehlt im Bundle - "
            "SQL/18-audit-roles.sql wurde nicht ausgefuehrt oder ist "
            "nicht in diesem Bundle enthalten.)_"
        ),
        "note.roles_no_data": "> _(Keine Audit-Rollen-Daten vorhanden.)_",

        # --- Section 8.1 specific ---
        "tuning.intro": (
            "Top Noise-Kandidaten (High-Volume Kombinationen aus Policy / User / "
            "Action / Programm). Pro Kandidat folgt die aktuelle Policy-DDL plus "
            "vorgeschlagene WHEN-Klausel-Erweiterungen. Vorschlaege sind "
            "Bedingungs-Ausdruecke - die Anwendung erfolgt manuell via "
            "`DROP AUDIT POLICY ...; CREATE AUDIT POLICY ... WHEN '...';` "
            "(per ai-analysis-rules.md Section 4)."
        ),
        "tuning.csv_missing": "_(15-noise-candidates.csv nicht im Bundle)_",
        "tuning.no_candidates": "_Keine Noise-Kandidaten - keine Tuning-Empfehlung._",
        "tuning.candidate_header": "Kandidat {n}",
        "tuning.observed_combo": "Beobachtete Kombination",
        "tuning.current_ddl_label": "Aktuelle Policy-DDL (DBMS_METADATA.GET_DDL)",
        "tuning.existing_when": "Bestehende WHEN-Klausel",
        "tuning.no_existing_when": "_(keine bestehende WHEN-Klausel)_",
        "tuning.suggestion_header": "Kandidat {n} - Variante {v}: {label}",
        "tuning.suppress_user": "Benutzer {user} in {policy} ausschliessen",
        "tuning.suppress_program": "Programm {program} in {policy} ausschliessen",
        "tuning.suppress_combo": "Kombination {user}/{program} in {policy} ausschliessen",
        "tuning.no_template": "Kein automatisches Template ableitbar fuer {policy}",
        "tuning.apply_instructions": "Anwendung (manuell)",
        "tuning.apply_template": (
            "Erweitere die WHEN-Klausel von `{policy}` um den oben gezeigten Ausdruck. "
            "Verfahren: bestehende DDL behalten, WHEN-Klausel auf "
            "`(bestehend) AND ({new})` setzen "
            "(ohne `(bestehend) AND` falls noch keine WHEN-Klausel existiert). "
            "Sequenz: `DROP AUDIT POLICY {policy};` gefolgt von einem neuen "
            "`CREATE AUDIT POLICY {policy} ...` mit der angepassten WHEN-Klausel."
        ),
        "tuning.rationale_user": (
            "Filtere Events vom Benutzer `{user}` aus. Anwendbar "
            "wenn `{user}` ein deterministischer Service-Account "
            "ist und seine Aktionen aus dem Audit-Scope ausgeschlossen "
            "werden duerfen (Compliance-Pruefung erforderlich)."
        ),
        "tuning.rationale_program": (
            "Filtere Events vom Client-Programm `{program}` aus. "
            "Sinnvoll bei automatisierten Monitoring- oder "
            "Backup-Tools mit hohem Aktivitaets-Volumen."
        ),
        "tuning.rationale_combo": (
            "Engste Suppression: nur die exakte Kombination "
            "`{user}` / `{program}` wird ausgeblendet. Andere "
            "Benutzer mit dem gleichen Programm und `{user}` mit "
            "anderen Programmen bleiben weiterhin auditiert."
        ),
        "tuning.rationale_no_template": (
            "Weder `dbusername` noch `client_program_name` liefern "
            "eine eindeutige Suppression-Heuristik. Manuelle Analyse "
            "der Action `{action}` erforderlich."
        ),

        # --- F1: 7.2.1 Context-Policy event list ---
        "offpath.ctx_events_header": "Events unter diesen Context-Policies (Top-N, aus 05_policy_user_action.csv)",
        "offpath.ctx_events_none": "_(keine Events unter diesen Policies im Zeitfenster)_",
        "label.user": "User",
        "label.action": "Action",
        "label.return_code_short": "RC",

        # --- F2: 7.2.2 user column ---
        "label.users": "Users",

        # --- F3: AI section headers (language-aware) ---
        "ai.section_title": "12. AI-Findings (Claude)",
        "ai.generated_line": "> Generiert: `{ts}` | Modell: `{model}`  ",
        "ai.disclaimer": "> Automatisch generierte Analyse - Findings sind zu verifizieren.",
        "ai.standalone_title": "# AI-Findings - Audit Trail Analyse",
        "ai.standalone_generated": "Generiert",
        "ai.standalone_model": "Modell",
        "ai.standalone_dbsid": "DBSID",
        "ai.footer": "_Generiert von `audit_report.py` v{version} via Claude API_",
        "ai.fp_section_note": "  incl. {n} FP-Verdacht(e) in Abschnitt 13",

        # --- F4: Exec summary AI placeholder ---
        "metric.ai_findings": "AI-Analyse",
        "metric.ai_pending": "ausstehend (--ai Flag)",
        "metric.ai_done": "Section 12 - {n} Finding(s)",

        # --- F5: Uncovered users ---
        "section.07_3_uncovered": "7.3 Benutzer ohne Non-Logon Policy-Abdeckung",
        "metric.uncovered_users": "Principals ohne Policy-Abdeckung",
        "uncovered.all_users_note": (
            "_ALL USERS Policy mit Non-Logon-Aktionen aktiv - "
            "alle Principals gelten als abgedeckt._"
        ),
        "uncovered.none": "_Alle Principals durch Non-Logon Policies abgedeckt._",
        "uncovered.found": "**{n} Principal(s)** ohne Non-Logon Policy-Abdeckung (P1=direkt, P2=via Rolle):",
        "uncovered.intro": (
            "Principals (User-Accounts und Rollen aus `DBA_USERS` / `DBA_ROLES`, "
            "nicht Oracle-supplied, Account-Status OPEN) ohne Abdeckung durch eine "
            "aktuell aktive Non-Logon Audit-Policy. "
            "P1 = direkte BY USER Bindung; "
            "P2 = via BY GRANTED ROLE (Tiefe 1, direkte Grants)."
        ),
        "uncovered.depth_note": (
            "_Hinweis: Indirekte Rollen-Ketten (Rolle -> Rolle -> User) "
            "werden nicht traversiert. Fuer vollstaendige Pruefung "
            "`SESSION_ROLES` im Kontext des jeweiligen Users pruefen._"
        ),
        "uncovered.source": "Quelle: `21_uncovered_users.csv`",
        "uncovered.csv_missing": "_(21_uncovered_users.csv nicht im Bundle)_",
        "label.principal": "Principal",
        "label.principal_type": "Typ",
        "label.covered_direct": "P1 (Direkt)",
        "label.covered_role": "P2 (Via Rolle)",

        # --- F6a: Policy DDL section (custom only) ---
        "section.11_policy_ddl": "11. Policy-Definitionen (Custom)",
        "policy_ddl.section_intro": (
            "DDL-Definitionen aller Custom Audit-Policies aus "
            "`DBMS_METADATA.GET_DDL`. Oracle-supplied Policies werden ausgeblendet. "
            "Dient als Referenz fuer Policy-Analyse und Anpassungsvorschlaege."
        ),
        "policy_ddl.none": (
            "_Keine Custom Policy-DDL verfuegbar - "
            "`16_policy_ddl.csv` fehlt oder wurde ohne `AUDIT_ADMIN`-Privileg erzeugt._"
        ),
        "policy_ddl.source": "Quelle: `16_policy_ddl.csv` (DBMS_METADATA.GET_DDL)",
    },
    "en": {
        # --- Report header / page title ---
        "report.page_title": "Audit Trail Analysis - {dbsid} / {pdb}",
        "report.title": "Oracle Audit Trail Analysis",
        "report.subtitle": "Unified Auditing Pure Mode - DBSID: {dbsid}",
        "report.generated_at": "Generated: `{ts}` | Bundle: `{bundle_name}`",
        "report.window": "Time window: {days} days | Top-N: {top_n}",
        "report.audit_mode": "Audit mode: **{audit_mode}**",

        # --- Executive summary labels ---
        "exec.dbsid": "**DBSID:** `{dbsid}`",
        "exec.pdb": "**PDB:** `{pdb}`",
        "exec.window": "**Time window:** last {days} days",
        "exec.top_n": "**Bundle Top-N:** {top_n}",
        "exec.generated": "**Bundle generated:** {ts}",
        "exec.version": "**Bundle version:** {version}",
        "exec.sampling_note": (
            "> **Note:** Sampling active - queries 08-12, 15 were limited to "
            "{n} rows (`ROWNUM <= {n}`). Absolute counts are estimates; "
            "relative rankings remain representative."
        ),

        # --- Section titles ---
        "section.executive_summary": "Executive Summary",
        "section.metrics": "Key Metrics",
        "section.top3_volume": "Top 3 Volume Drivers (Policy)",
        "section.host_summary": "Host Classification (Summary)",
        "section.01_config": "1. Audit Configuration",
        "section.02_storage": "2. Trail Storage",
        "section.03_policy_inventory": "3. Policy Inventory",
        "section.04_07_volumes": "4. Volume Distribution",
        "section.04_1": "4.1 Policies",
        "section.04_2": "4.2 Users",
        "section.04_3": "4.3 Actions",
        "section.04_4": "4.4 Objects",
        "section.04_5": "4.5 Client Programs",
        "section.04_6": "4.6 Policies x Hosts",
        "section.04_7": "4.7 Policies x User x Action",
        "section.05_connect_profile": "5. Connect Profile",
        "section.05_1_hosts": "5.1 Hosts",
        "section.05_2_pattern": "5.2 Host Pattern Analysis",
        "section.05_3_matrix": "5.3 Connect Matrix (Host x User x Program)",
        "section.06_privileged": "6. Privileged Activity",
        "section.07_security_signals": "7. Security Signals",
        "section.07_1_failed": "7.1 Failed Logins",
        "section.07_2_offpath": "7.2 Off-Path Candidates",
        "section.07_2a_ctx": "7.2.1 Application Context (Scenario A)",
        "section.07_2b_pattern": "7.2.2 Pattern-based Classification (Scenario B)",
        "section.08_tuning": "8. Tuning Recommendations",
        "section.08_1_when_clauses": "8.1 WHEN Clause Suggestions",
        "section.09_cis_coverage": "9. CIS Benchmark 5.1-5.5 - Policy Coverage",
        "section.10_audit_roles": "10. Audit Roles - Members and Risk Flags",
        "section.appendix": "Appendix",
        "section.appendix_manifest": "Manifest",
        "section.appendix_full_data": "Full Data - {name}",

        # --- Table column labels ---
        "label.metric": "Metric",
        "label.value": "Value",
        "label.class": "Class",
        "label.host": "Host",
        "label.logins": "Logins",
        "label.host_count": "Host Count",
        "label.distinct_users": "Distinct Users",
        "label.policy": "Policy",
        "label.events": "Events",
        "label.manifest": "Manifest",

        # --- Executive summary metric row labels ---
        "metric.pol_events": "Events (policy-driven, Top-N sum)",
        "metric.user_events": "Events (user Top-N sum)",
        "metric.failed_logins": "Failed logins (Top-N sum)",
        "metric.mandatory_events": "Events (ORA$MANDATORY)",
        "metric.active_policies": "Active audit policies (inventory)",
        "metric.storage_partitions": "Storage partitions",

        "label.cis_control": "CIS Control",
        "label.cis_title": "Title",
        "label.cis_policy": "Policy",
        "label.cis_exists": "Exists",
        "label.cis_enabled": "Enabled",
        "label.cis_verdict": "Verdict",
        "label.cis_custom": "Covered by (Custom)",
        "label.cis_oracle": "Oracle Policies",
        "label.role_target": "Target Role",
        "label.role_grantee": "Grantee",
        "label.role_type": "Type",
        "label.role_path": "Grant Path",
        "label.role_admin": "Admin Option",
        "label.role_flag": "Risk Flag",

        # --- Audit-mode interpretation labels ---
        "audit_mode.pure": "Pure Mode (clean)",
        "audit_mode.pure_intent": "Pure Mode (legacy parameter set, no effect)",
        "audit_mode.pure_contaminated": "Pure Mode (old AUD$ rows present, no active writes)",
        "audit_mode.mixed": "Mixed Mode (report outside tool scope)",
        "audit_mode.unsupported": "Unified Auditing inactive (not supported)",

        # --- Section 1 - mode blockquotes ---
        "mode.mixed_note": (
            "> **Mixed Mode detected** - this report scope is Pure Mode. "
            "Findings below should be read under this assumption; a "
            "complete analysis requires migration to Pure Mode first "
            "(see /oracle-audit skill, Mixed-to-Pure)."
        ),
        "mode.pure_contaminated_note": (
            "> **Pure Mode with legacy data** - no new legacy writes, "
            "but `SYS.AUD$` still contains old rows. Optionally purge with "
            "`DBMS_AUDIT_MGMT.CLEAN_AUDIT_TRAIL(AUDIT_TRAIL_AUD_STD,...)`."
        ),
        "mode.pure_intent_note": (
            "> **Pure Mode, legacy parameter set** - `audit_trail` value "
            "is not `NONE`, but has no effect in Pure Mode. "
            "Recommendation: set `audit_trail = NONE` at next bounce."
        ),
        "mode.unsupported_note": (
            "> **Unified Auditing not active** - this tool scope is not "
            "applicable. Enable Unified Auditing before further analysis."
        ),
        "mode.unknown_note": (
            "> _(audit_mode metadata missing - 01-config.sql may have been "
            "generated before Phase C. Pure Mode assumptions apply implicitly; "
            "verify legacy parameter findings manually.)_"
        ),
        "mode.aud_recent_rows": (
            "> **Note:** `SYS.AUD$` contains {n} rows from "
            "the last 7 days - active Mixed Mode writes? "
            "Check source (Traditional AUDIT statements active?)."
        ),
        "mode.legacy_params_footer": (
            "_Parameters marked `_(legacy)_` are Mixed Mode artefacts. "
            "They have no effect in Pure Mode - findings against them are "
            "false positives (see `docs/ai-analysis-rules.md` Section 2)._"
        ),

        # --- Section 2 - storage verdicts ---
        "storage.verdict_fmt": "**Verdict:** `{label}` - {note}",
        "storage.verdict_misconfig": (
            "AUD$UNIFIED default tablespace is `SYSAUX`. Audit data "
            "and the data dictionary share the same tablespace - "
            "Recommendation: `ALTER TABLE AUDSYS.AUD$UNIFIED MODIFY DEFAULT "
            "ATTRIBUTES TABLESPACE AUDIT_DATA;` (create tablespace `AUDIT_DATA` "
            "first if it does not exist)."
        ),
        "storage.verdict_ok": (
            "Default and all partition tablespaces are set to "
            "`{tbs}`. No action required."
        ),
        "storage.verdict_transient_older": (
            "Default tablespace is `{tbs_default}` (correct), but "
            "older partitions are still in: "
            "`{tbs_older}`. Optional: per partition "
            "`ALTER TABLE AUDSYS.AUD$UNIFIED MOVE PARTITION <name> "
            "TABLESPACE {tbs_default};` - not mandatory (not a finding)."
        ),
        "storage.verdict_transient_current": (
            "Default tablespace was changed to `{tbs_default}`, "
            "but current partition is still in `{tbs_current}`. "
            "Next range partition will be created in `{tbs_default}` "
            "(auto-partitioning). Not a finding."
        ),
        "storage.verdict_empty": (
            "AUD$UNIFIED has no partition yet - the first event "
            "will create a partition in `{tbs_default}`. Not a finding."
        ),
        "storage.row_default": "Default for new partitions",
        "storage.row_current": "Current partition",
        "storage.row_older": "Older partitions",
        "storage.none": "_(none)_",
        "storage.partitions_summary": (
            "Partitions: {n} - Total {rows} rows / {mb} MB."
        ),
        "storage.verdict_unknown": (
            "> _(Tablespace metadata missing - 02-storage.sql may have been "
            "generated before Phase C. Manual verification of tablespace "
            "assignments required.)_"
        ),
        "storage.trail_mgmt": "**Trail Management (Purge)**",
        "storage.purge_job_row": "Purge job (Unified Audit Trail)",
        "storage.last_arch_row": "Last archive timestamp",
        "storage.part_interval_row": "Partition interval",
        "storage.purge_warn_no_job": (
            "> ⚠️ **No purge job configured** - "
            "`AUD$UNIFIED` grows without bound."
        ),
        "storage.purge_warn_no_ts": (
            "> ⚠️ **No `LAST_ARCHIVE_TIMESTAMP` set** - "
            "the purge job will not delete any rows."
        ),
        "vol.ghost_events_note": (
            "> ℹ️ **Historical events from inactive policies ({n}):** "
            "{total} events total. These policies were active when the "
            "events were recorded but are currently not enabled. "
            "No action required."
        ),

        # --- Section 3 - policy inventory ---
        "policy.count": "Policies found: **{n}**.",
        "policy.unique_count": (
            "**{n}** unique policies ({n_custom} custom, "
            "{n_oracle} Oracle-supplied)."
        ),
        "policy.ora_count": "- Oracle-supplied (`ORA_*`): {n}",
        "policy.cust_count": "- Custom policies: {n}",
        "policy.see_appendix": "_Full action list available with `--include-appendix`._",
        "section.03_detail": "3.1 Policy Inventory - Full Action List",
        "section.09_detail": "9.1 Covering Policies - Detail",
        "label.ora": "ORA",
        "label.policy_option": "Option",
        "label.entity": "Entity",
        "label.entity_type": "Type",
        "label.success_short": "S",
        "label.failure_short": "F",
        "label.condition": "Condition",
        "label.cis_controls": "CIS",
        "cis.detail_intro": (
            "Policies covering at least one CIS requirement "
            "(filtered from policy inventory, deduplicated per entity):"
        ),

        # --- Section 6 - privileged activity ---
        "section.06_intro": (
            "Activity of privileged users (SYS, SYSTEM, "
            "customer DBA accounts)."
        ),

        # --- Section 7 - security signals / off-path ---
        "offpath.ctx_intro": (
            "Audit policies with `SYS_CONTEXT` conditions detected (Scenario A). "
            "All records from these policies are off-path accesses by definition "
            "(the policy fires only when the context flag is FALSE or NULL). "
            "Severity assessment per `docs/ai-analysis-rules.md` Section 2.6."
        ),
        "offpath.ctx_found": (
            "**{n} context attribute(s)** detected in policy conditions:"
        ),
        "offpath.ctx_none": (
            "_No Application Context (SYS_CONTEXT) found in audit policy conditions. "
            "Off-path detection relies exclusively on pattern matching "
            "(Scenario B, Section 7.2.2)._"
        ),
        "offpath.ctx_hint_null": (
            "> **NULL fallback note:** Policy conditions should use "
            "`!= 'TRUE' OR IS NULL` (not `= 'FALSE'`) so that sessions "
            "where the context was not set (trigger failure) are audited "
            "conservatively."
        ),
        "offpath.ctx_label_ctx": "Context",
        "offpath.ctx_label_attr": "Attribute",
        "offpath.ctx_label_policies": "Policies",
        "offpath.pattern_intro": (
            "Host classification from `12_distinct_hosts.csv` using the "
            "configured pattern lists (app / infra / dba). "
            "Hosts with no match = **OFF-PATH**."
        ),
        "offpath.none": (
            "_No OFF-PATH hosts identified - all source hosts "
            "match App/Infra/DBA patterns._"
        ),
        "offpath.found": (
            "**{n} off-path host(s)** - hosts that do not match "
            "any App, Infra, or DBA pattern:"
        ),
        "offpath.hint": (
            "> **Note:** OFF-PATH hosts identified. "
            "Details in Section 7 (Security Signals)."
        ),

        # --- Section 9 - CIS coverage ---
        "cis.fail_count": (
            "> **{n} of {total} CIS requirements not covered** "
            "(FAIL). No active custom policy covers these requirements."
        ),
        "cis.partial_count": (
            "> **{n} CIS requirement(s) only partially covered** "
            "(PARTIAL). Coverage exists but with WHEN condition or "
            "restricted user scope."
        ),
        "cis.warn_count": (
            "> **{n} CIS policy/ies present but disabled** "
            "(WARN). Policies exist but are not active."
        ),
        "cis.all_pass": "> All CIS 5.1-5.5 requirements fully covered (PASS).",
        "cis.coverage_note": (
            "_Coverage determined by action comparison (not policy names). "
            "PARTIAL = policy has WHEN condition or restricted user scope. "
            "Oracle-supplied policies shown for information, do not affect verdict._"
        ),
        "cis.source": "Source: `17_cis_coverage.csv`",

        # --- Section 10 - audit roles ---
        "roles.review_count": (
            "> **{n} entry/entries with elevated risk** "
            "(WARN/REVIEW) - manual review of grantees recommended."
        ),
        "roles.source": "Source: `18_audit_roles.csv`",

        # --- Source / data-origin notes ---
        "note.source_01": "Source: `01-config.csv` (DBMS_AUDIT_MGMT, init parameters, instance)",
        "note.source_02": "Source: `02-storage.csv` (AUD$UNIFIED partitions, tablespace assignments)",
        "note.no_data": "_(no data available)_",
        "note.ai_generated": "> Automatically generated analysis - findings must be verified.",
        "note.policy_ddl_unavailable": (
            "_(Policy DDL unavailable - `sql/16-policy-ddl.csv` missing from bundle "
            "or generated without `AUDIT_ADMIN` privilege. Suggestion skipped.)_"
        ),
        "note.tuning_disclaimer": (
            "> **Note:** Templates are intended as a starting point. "
            "WHEN clauses are policy-specific - review manually and verify "
            "against compliance requirements before applying."
        ),
        "note.csv_missing": "_({fname} not in bundle)_",
        "note.offpath_skipped": (
            "_(Off-path analysis skipped - 12_distinct_hosts missing)_"
        ),
        "note.hosts_unclassifiable": (
            "_(Hosts cannot be classified - 12_distinct_hosts missing)_"
        ),
        "note.csv_missing_cis": (
            "> _(17_cis_coverage.csv missing from bundle - "
            "SQL/17-cis-coverage.sql was not executed or is "
            "not included in this bundle.)_"
        ),
        "note.cis_no_data": "> _(No CIS coverage data available.)_",
        "note.csv_missing_roles": (
            "> _(18_audit_roles.csv missing from bundle - "
            "SQL/18-audit-roles.sql was not executed or is "
            "not included in this bundle.)_"
        ),
        "note.roles_no_data": "> _(No audit roles data available.)_",

        # --- Section 8.1 specific ---
        "tuning.intro": (
            "Top noise candidates (high-volume combinations of Policy / User / "
            "Action / Program). Each candidate is followed by the current policy DDL "
            "and suggested WHEN clause extensions. Suggestions are condition "
            "expressions - apply manually via "
            "`DROP AUDIT POLICY ...; CREATE AUDIT POLICY ... WHEN '...';` "
            "(per ai-analysis-rules.md Section 4)."
        ),
        "tuning.csv_missing": "_(15-noise-candidates.csv not in bundle)_",
        "tuning.no_candidates": "_No noise candidates - no tuning recommendation._",
        "tuning.candidate_header": "Candidate {n}",
        "tuning.observed_combo": "Observed combination",
        "tuning.current_ddl_label": "Current policy DDL (DBMS_METADATA.GET_DDL)",
        "tuning.existing_when": "Existing WHEN clause",
        "tuning.no_existing_when": "_(no existing WHEN clause)_",
        "tuning.suggestion_header": "Candidate {n} - Option {v}: {label}",
        "tuning.suppress_user": "Exclude user {user} from {policy}",
        "tuning.suppress_program": "Exclude program {program} from {policy}",
        "tuning.suppress_combo": "Exclude combination {user}/{program} from {policy}",
        "tuning.no_template": "No automatic template derivable for {policy}",
        "tuning.apply_instructions": "How to apply (manual)",
        "tuning.apply_template": (
            "Extend the WHEN clause of `{policy}` with the expression shown above. "
            "Procedure: keep existing DDL, set WHEN clause to "
            "`(existing) AND ({new})` "
            "(omit `(existing) AND` if no WHEN clause exists yet). "
            "Sequence: `DROP AUDIT POLICY {policy};` followed by a new "
            "`CREATE AUDIT POLICY {policy} ...` with the updated WHEN clause."
        ),
        "tuning.rationale_user": (
            "Filter events from user `{user}`. Applicable when "
            "`{user}` is a deterministic service account and its "
            "actions may be excluded from the audit scope "
            "(compliance review required)."
        ),
        "tuning.rationale_program": (
            "Filter events from client program `{program}`. "
            "Useful for automated monitoring or backup tools "
            "with high activity volume."
        ),
        "tuning.rationale_combo": (
            "Tightest suppression: only the exact combination "
            "`{user}` / `{program}` is excluded. Other users with "
            "the same program, and `{user}` with other programs, "
            "continue to be audited."
        ),
        "tuning.rationale_no_template": (
            "Neither `dbusername` nor `client_program_name` provide "
            "an unambiguous suppression heuristic. Manual analysis "
            "of action `{action}` required."
        ),

        # --- F1: 7.2.1 Context-Policy event list ---
        "offpath.ctx_events_header": "Events under these Context Policies (Top-N, from 05_policy_user_action.csv)",
        "offpath.ctx_events_none": "_(no events under these policies in the time window)_",
        "label.user": "User",
        "label.action": "Action",
        "label.return_code_short": "RC",

        # --- F2: 7.2.2 user column ---
        "label.users": "Users",

        # --- F3: AI section headers (language-aware) ---
        "ai.section_title": "12. AI-Findings (Claude)",
        "ai.generated_line": "> Generated: `{ts}` | Model: `{model}`  ",
        "ai.disclaimer": "> Automatically generated analysis - findings require verification.",
        "ai.standalone_title": "# AI-Findings - Audit Trail Analysis",
        "ai.standalone_generated": "Generated",
        "ai.standalone_model": "Model",
        "ai.standalone_dbsid": "DBSID",
        "ai.footer": "_Generated by `audit_report.py` v{version} via Claude API_",
        "ai.fp_section_note": "  incl. {n} FP suspect(s) in Section 13",

        # --- F4: Exec summary AI placeholder ---
        "metric.ai_findings": "AI Analysis",
        "metric.ai_pending": "pending (use --ai flag)",
        "metric.ai_done": "Section 12 - {n} finding(s)",

        # --- F5: Uncovered users ---
        "section.07_3_uncovered": "7.3 Principals without Non-Logon Policy Coverage",
        "metric.uncovered_users": "Principals without policy coverage",
        "uncovered.all_users_note": (
            "_ALL USERS policy with non-logon actions is active - "
            "all principals are considered covered._"
        ),
        "uncovered.none": "_All principals are covered by non-logon audit policies._",
        "uncovered.found": "**{n} principal(s)** without non-logon policy coverage (P1=direct, P2=via role):",
        "uncovered.intro": (
            "Principals (user accounts and roles from `DBA_USERS` / `DBA_ROLES`, "
            "non-Oracle-supplied, account status OPEN) not covered by any "
            "currently active non-logon audit policy. "
            "P1 = direct BY USER binding; "
            "P2 = via BY GRANTED ROLE (depth 1, direct grants only)."
        ),
        "uncovered.depth_note": (
            "_Note: indirect role chains (role -> role -> user) are not traversed. "
            "For full coverage verification, check `SESSION_ROLES` "
            "in the context of each specific user._"
        ),
        "uncovered.source": "Source: `21_uncovered_users.csv`",
        "uncovered.csv_missing": "_(21_uncovered_users.csv not in bundle)_",
        "label.principal": "Principal",
        "label.principal_type": "Type",
        "label.covered_direct": "P1 (Direct)",
        "label.covered_role": "P2 (Via Role)",

        # --- F6a: Policy DDL section (custom only) ---
        "section.11_policy_ddl": "11. Policy Definitions (Custom)",
        "policy_ddl.section_intro": (
            "DDL definitions of all custom audit policies from "
            "`DBMS_METADATA.GET_DDL`. Oracle-supplied policies are excluded. "
            "Serves as reference for policy analysis and modification suggestions."
        ),
        "policy_ddl.none": (
            "_No custom policy DDL available - "
            "`16_policy_ddl.csv` missing or generated without `AUDIT_ADMIN` privilege._"
        ),
        "policy_ddl.source": "Source: `16_policy_ddl.csv` (DBMS_METADATA.GET_DDL)",
    },
}


def t(key: str, lang: str = DEFAULT_LANGUAGE, **kwargs: Any) -> str:
    """Look up a message by key and language; apply str.format(**kwargs).

    Returns the looked-up message after str.format substitution. If the key
    is missing in the target language, falls back to DEFAULT_LANGUAGE. If
    still missing, returns the key itself in angle brackets (so missing
    keys are visible at runtime rather than crashing the report).
    """
    if lang not in MESSAGES:
        lang = DEFAULT_LANGUAGE
    catalog = MESSAGES[lang]
    if key not in catalog and lang != DEFAULT_LANGUAGE:
        catalog = MESSAGES[DEFAULT_LANGUAGE]
    value = catalog.get(key, f"<missing:{key}>")
    if kwargs:
        try:
            return value.format(**kwargs)
        except (KeyError, IndexError) as exc:
            return f"{value} <format-error:{exc}>"
    return value


def validate_catalog(lang: str = DEFAULT_LANGUAGE) -> list[str]:
    """Return a list of message keys that are missing in `lang` compared to
    DEFAULT_LANGUAGE. Used by tests + CI to detect translation drift once
    a second language is added.
    """
    if lang == DEFAULT_LANGUAGE:
        return []
    if lang not in MESSAGES:
        return list(MESSAGES[DEFAULT_LANGUAGE].keys())
    target = set(MESSAGES[lang].keys())
    source = set(MESSAGES[DEFAULT_LANGUAGE].keys())
    return sorted(source - target)
