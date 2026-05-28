#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# ------------------------------------------------------------------------------
# OraDBA - Oracle Database Infrastructure and Security, 5630 Muri, Switzerland
# ------------------------------------------------------------------------------
# Name.......: audit_report_messages.py
# Author.....: Stefan Oehrli (oes) stefan.oehrli@oradba.ch
# Editor.....: Stefan Oehrli
# Date.......: 2026.05.28
# Version....: 0.2.0
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
"""Centralised message dictionary for audit_report.py.

Usage:

    from audit_report_messages import t, SUPPORTED_LANGUAGES

    title = t("report.title")
    intro = t("report.intro", dbsid="ORCLCDB", days=30)
"""

from __future__ import annotations

from typing import Any


SUPPORTED_LANGUAGES = ("de",)
"""Languages with a complete MESSAGES population.

v1.0.0 ships German-only. Add "en" here (and populate MESSAGES["en"])
in v1.1 - no other code change required.
"""

DEFAULT_LANGUAGE = "de"


MESSAGES: dict[str, dict[str, str]] = {
    "de": {
        # --- Report header / banner ---
        "report.title": "Oracle Audit Trail Analyse",
        "report.subtitle": "Unified Auditing Pure Mode - DBSID: {dbsid}",
        "report.generated_at": "Generiert: `{ts}` | Bundle: `{bundle_name}`",
        "report.window": "Zeitfenster: {days} Tage | Top-N: {top_n}",
        "report.audit_mode": "Audit-Modus: **{audit_mode}**",

        # --- Section titles ---
        "section.executive_summary": "Executive Summary",
        "section.01_config": "1. Audit-Konfiguration",
        "section.02_storage": "2. Trail Storage",
        "section.03_policy_inventory": "3. Policy-Inventar",
        "section.04_07_volumes": "4. Volumen-Verteilung",
        "section.05_connect_profile": "5. Connect-Profil-Matrix",
        "section.06_privileged": "6. Privilegierte Aktivitaet",
        "section.07_security_signals": "7. Security-Signale",
        "section.08_tuning": "8. Tuning-Empfehlungen",
        "section.08_1_when_clauses": "8.1 WHEN-Klausel-Vorschlaege",
        "section.09_ai_findings": "9. AI-Findings (Claude)",
        "section.appendix": "Anhang",

        # --- Audit-mode interpretation labels ---
        "audit_mode.pure": "Pure Mode (sauber)",
        "audit_mode.pure_intent": "Pure Mode (Legacy-Parameter gesetzt, ohne Effekt)",
        "audit_mode.pure_contaminated": "Pure Mode (alte AUD$-Daten vorhanden, kein Schreibverkehr)",
        "audit_mode.mixed": "Mixed Mode (Bericht ausserhalb des Scopes)",
        "audit_mode.unsupported": "Unified Auditing nicht aktiv (nicht unterstuetzt)",

        # --- Common labels / notes ---
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
