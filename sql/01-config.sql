-- SPDX-License-Identifier: Apache-2.0
-- -----------------------------------------------------------------------------
-- OraDBA - Oracle Database Infrastructure and Security, 5630 Muri, Switzerland
-- -----------------------------------------------------------------------------
-- Name......: 01-config.sql
-- Author....: Stefan Oehrli (oes) stefan.oehrli@oradba.ch
-- Date......: 2026.05.12
-- Revision..: 0.2.0
-- Purpose...: Audit configuration snapshot with audit-mode classification.
--             Captures DBMS_AUDIT_MGMT config params, audit-related init params,
--             instance metadata, and unified_audit_* parameters. Classifies the
--             instance as pure | pure-intent | pure-contaminated | mixed |
--             unsupported per docs/ai-analysis-rules.md Section 6.2 and emits
--             the result as a metadata preamble line.
-- Pattern...: Unified key-value table from four sources. Audit-mode and
--             AUD$ row-count captured via PL/SQL (privilege-safe EXECUTE
--             IMMEDIATE) and forwarded to SQL*Plus DEFINE variables through
--             a helper single-row query.
-- Notes.....: Interpretation contract: docs/ai-analysis-rules.md Sections 5+6.
--             The # audit_mode: metadata line gates Section 2 suppressions in
--             the reporter and AI prompt.
--             Legacy parameters (audit_trail, audit_sys_operations,
--             audit_syslog_level, audit_file_dest) are captured for
--             completeness but tagged legacy_param=1 in the schema-hint so
--             the reporter suppresses findings against them when audit_mode
--             is pure, pure-intent, or pure-contaminated.
--             The # recent_aud_legacy_rows: metadata exposes the AUD$ count
--             used in classification. The value is NULL when the running user
--             lacks SELECT on SYS.AUD$; the reporter treats NULL as unknown
--             and does not flag it as Mixed-Mode contamination.
-- License...: Apache License Version 2.0
-- -----------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- Phase 1: Privilege-safe AUD$ row count via a temporary helper table.
--
-- SQL*Plus cannot capture DBMS_OUTPUT values into DEFINE variables directly.
-- Strategy: write the computed values into a global temporary table
-- (created inline if needed), then SELECT from it.
--
-- Simpler alternative used here: PL/SQL writes values into a package-level
-- context, then a SQL SELECT reads from the context.
--
-- Simplest approach that avoids DDL or package state: run two scalar SELECTs.
--   - First SELECT derives audit_mode from V$OPTION + V$PARAMETER only
--     (no AUD$ needed for the NONE-branch of the decision matrix).
--   - Second SELECT uses EXECUTE IMMEDIATE inside PL/SQL to try AUD$;
--     writes result to a one-row pipelined wrapper.
-- Because this adds complexity with limited portability, we follow the
-- constraint in the task brief: if a clean privilege-safe path is not
-- available in a single SQL*Plus run, emit NULL and document the gap.
--
-- Implementation:
--   Step 1a - capture signals via SQL (V$OPTION, V$PARAMETER).
--   Step 1b - attempt AUD$ count via WHENEVER SQLERROR CONTINUE; if the
--             SELECT fails the DEFINE keeps its default value of 'NULL'.
--   Step 1c - compute audit_mode via CASE in SQL (no PL/SQL required).
-- ---------------------------------------------------------------------------

-- Safe defaults in case subsequent SELECTs fail (no privilege).
DEFINE AUD_LEGACY_ROWS = 'NULL'

COLUMN x_aud_legacy_rows  NEW_VALUE AUD_LEGACY_ROWS  NOPRINT

-- Step 1b: try to read AUD$ recent row count.
-- WHENEVER SQLERROR CONTINUE (inherited from 00-setup.sql) means that if
-- this SELECT raises ORA-00942 (table or view does not exist) or
-- ORA-01031 (insufficient privileges), SQL*Plus continues and
-- AUD_LEGACY_ROWS keeps its default value of 'NULL'.
SELECT TO_CHAR(COUNT(*)) AS x_aud_legacy_rows
FROM   sys.aud$
WHERE  ntimestamp# > SYSTIMESTAMP - INTERVAL '7' DAY;

-- Step 1c: derive audit_mode from V$OPTION + V$PARAMETER + AUD_LEGACY_ROWS.
-- The DEFINE &AUD_LEGACY_ROWS is a VARCHAR2; compare as number via TO_NUMBER
-- with NVL so NULL (unknown) maps to the zero-rows branch (conservative).
COLUMN x_audit_mode  NEW_VALUE AUDIT_MODE  NOPRINT

-- AUD_LEGACY_ROWS is either a numeric string ('42') or the literal 'NULL'.
-- TO_NUMBER(NULLIF(...,'NULL')) converts the literal 'NULL' to SQL NULL safely.
SELECT
    CASE
        WHEN opt.uopt != 'TRUE'  THEN 'unsupported'
        WHEN opt.uopt  = 'TRUE'
         AND atr.aval  = 'NONE'
         AND NVL(TO_NUMBER(NULLIF('&AUD_LEGACY_ROWS','NULL')), 0) = 0  THEN 'pure'
        WHEN opt.uopt  = 'TRUE'
         AND atr.aval  = 'NONE'
         AND TO_NUMBER(NULLIF('&AUD_LEGACY_ROWS','NULL')) > 0           THEN 'pure-contaminated'
        WHEN opt.uopt  = 'TRUE'
         AND atr.aval != 'NONE'
         AND NVL(TO_NUMBER(NULLIF('&AUD_LEGACY_ROWS','NULL')), 0) = 0  THEN 'pure-intent'
        ELSE 'mixed'
    END AS x_audit_mode
FROM
    (SELECT NVL(MAX(UPPER(value)), 'FALSE') AS uopt
     FROM   v$option
     WHERE  parameter = 'Unified Auditing') opt,
    (SELECT NVL(UPPER(MAX(value)), 'NONE')  AS aval
     FROM   v$parameter
     WHERE  name = 'audit_trail') atr;

-- ---------------------------------------------------------------------------
-- Phase 2: Spool the config CSV with full metadata preamble.
-- ---------------------------------------------------------------------------
SPOOL &LOGDIR./01_config.csv

PROMPT # query: config
PROMPT # query_id: 01
PROMPT # dbsid: &DBSID
PROMPT # pdb: &PDB_NAME
PROMPT # generated: &GENERATED_ISO
PROMPT # cis_controls: -
PROMPT # audit_mode: &AUDIT_MODE
PROMPT # recent_aud_legacy_rows: &AUD_LEGACY_ROWS
PROMPT # schema: source=KEEP|name=KEEP|value=KEEP|trail=KEEP|legacy_param=COUNT

SET MARKUP CSV ON DELIMITER '|' QUOTE OFF

-- DBMS_AUDIT_MGMT configuration parameters
SELECT
    'audit_mgmt'                                    AS "source",
    parameter_name                                  AS "name",
    parameter_value                                 AS "value",
    audit_trail                                     AS "trail",
    0                                               AS "legacy_param"
FROM dba_audit_mgmt_config_params
UNION ALL
-- Audit-related init parameters.
-- legacy_param=1 flags parameters that have no effect in Pure Mode
-- per ai-analysis-rules.md Section 2.1. The reporter suppresses
-- findings against these when audit_mode is pure / pure-intent /
-- pure-contaminated.
SELECT
    'init_param'                                    AS "source",
    name                                            AS "name",
    value                                           AS "value",
    NULL                                            AS "trail",
    CASE LOWER(name)
        WHEN 'audit_trail'          THEN 1
        WHEN 'audit_sys_operations' THEN 1
        WHEN 'audit_syslog_level'   THEN 1
        WHEN 'audit_file_dest'      THEN 1
        ELSE 0
    END                                             AS "legacy_param"
FROM v$parameter
WHERE LOWER(name) LIKE '%audit%'
UNION ALL
-- Instance identity metadata
SELECT
    'instance'                                      AS "source",
    'instance_name'                                 AS "name",
    instance_name                                   AS "value",
    NULL                                            AS "trail",
    0                                               AS "legacy_param"
FROM v$instance
UNION ALL
SELECT
    'instance'                                      AS "source",
    'version'                                       AS "name",
    version                                         AS "value",
    NULL                                            AS "trail",
    0                                               AS "legacy_param"
FROM v$instance
UNION ALL
SELECT
    'instance'                                      AS "source",
    'host_name'                                     AS "name",
    host_name                                       AS "value",
    NULL                                            AS "trail",
    0                                               AS "legacy_param"
FROM v$instance
UNION ALL
-- Unified Auditing option flag (V$OPTION signal 1 per Section 6.1)
SELECT
    'unified_audit'                                 AS "source",
    'pure_mode'                                     AS "name",
    value                                           AS "value",
    NULL                                            AS "trail",
    0                                               AS "legacy_param"
FROM v$option
WHERE parameter = 'Unified Auditing'
ORDER BY 1, 2;

SET MARKUP CSV OFF
SPOOL OFF
