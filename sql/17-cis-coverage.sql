-- SPDX-License-Identifier: Apache-2.0
-- -----------------------------------------------------------------------------
-- OraDBA - Oracle Database Infrastructure and Security, 5630 Muri, Switzerland
-- -----------------------------------------------------------------------------
-- Name......: 17-cis-coverage.sql
-- Author....: Stefan Oehrli (oes) stefan.oehrli@oradba.ch
-- Date......: 2026.05.28
-- Revision..: 0.1.0
-- Purpose...: CIS Oracle DB Benchmark v2.0 (19c) policy presence and
--             completeness check. Verifies that all five CIS Level 1 audit
--             policies (CIS 5.1-5.5) exist, are enabled, and are configured
--             with SUCCESS=YES and FAILURE=YES. Detects EXCEPT USER exclusions
--             which may weaken coverage.
-- Pattern...: Static reference list (WITH cis_policies) LEFT JOINed against
--             AUDIT_UNIFIED_POLICIES and AUDIT_UNIFIED_ENABLED_POLICIES.
--             Emits one row per CIS control with PASS/WARN/FAIL verdict.
-- Notes.....: CIS policy names are customer-created (not predefined by Oracle).
--             Verdict logic:
--               FAIL - policy does not exist, OR exists but not enabled
--               WARN - enabled but SUCCESS/FAILURE != YES, OR EXCEPT USER
--                      exclusions detected (partial coverage)
--               PASS - enabled, SUCCESS=YES, FAILURE=YES, no EXCEPT USER rows
--             Run in the CDB root (CONTAINER=ALL) for full coverage view.
--             CIS reference: CIS Oracle DB Benchmark 19c v2.0.0 Section 5.
-- License...: Apache License Version 2.0
-- -----------------------------------------------------------------------------

SPOOL &LOGDIR./17_cis_coverage.csv

PROMPT # query: cis_coverage
PROMPT # query_id: 17
PROMPT # dbsid: &DBSID
PROMPT # pdb: &PDB_NAME
PROMPT # generated: &GENERATED_ISO
PROMPT # cis_controls: 5.1,5.2,5.3,5.4,5.5
PROMPT # schema: policy_name=KEEP|cis_control=KEEP|cis_title=KEEP|policy_exists=KEEP|policy_enabled=KEEP|success_enabled=KEEP|failure_enabled=KEEP|except_user_count=COUNT|verdict=KEEP

SET MARKUP CSV ON DELIMITER '|' QUOTE OFF

-- CIS 5.1-5.5 coverage check.
-- Left-joins the expected policy names against the data dictionary.
-- A missing policy produces policy_exists=NO and verdict=FAIL.
WITH cis_policies AS (
    SELECT 'CIS_CDB_DDL_ACTIONS'                    AS policy_name,
           '5.1'                                    AS cis_control,
           'DDL Actions'                            AS cis_title
    FROM dual
    UNION ALL
    SELECT 'CIS_CDB_LOGON_LOGOFF',
           '5.2',
           'Logon and Logoff'
    FROM dual
    UNION ALL
    SELECT 'CIS_CDB_CRITICAL_PACKAGES',
           '5.3',
           'Critical Packages'
    FROM dual
    UNION ALL
    SELECT 'CIS_CDB_EXPORT',
           '5.4',
           'Export Activities'
    FROM dual
    UNION ALL
    SELECT 'CIS_CDB_ALL_ACTIONS_BY_PRIVILEGED_USERS',
           '5.5',
           'SYS Privileged Users'
    FROM dual
),
policy_check AS (
    SELECT
        c.policy_name,
        c.cis_control,
        c.cis_title,
        CASE WHEN p.policy_name IS NOT NULL THEN 'YES' ELSE 'NO' END
                                                                    AS policy_exists,
        NVL(MAX(CASE WHEN e.enabled_option != 'EXCEPT USER'
                     THEN 'YES' END), 'NO')                         AS policy_enabled,
        NVL(MAX(CASE WHEN e.enabled_option != 'EXCEPT USER'
                     THEN e.success END), 'N/A')                    AS success_enabled,
        NVL(MAX(CASE WHEN e.enabled_option != 'EXCEPT USER'
                     THEN e.failure END), 'N/A')                    AS failure_enabled,
        COUNT(CASE WHEN e.enabled_option = 'EXCEPT USER' THEN 1 END)
                                                                    AS except_user_count
    FROM cis_policies c
    LEFT JOIN audit_unified_policies p
        ON p.policy_name = c.policy_name
    LEFT JOIN audit_unified_enabled_policies e
        ON e.policy_name = c.policy_name
    GROUP BY c.policy_name, c.cis_control, c.cis_title, p.policy_name
)
SELECT
    policy_name                                                     AS "policy_name",
    cis_control                                                     AS "cis_control",
    cis_title                                                       AS "cis_title",
    policy_exists                                                   AS "policy_exists",
    policy_enabled                                                  AS "policy_enabled",
    success_enabled                                                 AS "success_enabled",
    failure_enabled                                                 AS "failure_enabled",
    TO_CHAR(except_user_count)                                      AS "except_user_count",
    CASE
        WHEN policy_exists  = 'NO'                                  THEN 'FAIL'
        WHEN policy_enabled = 'NO'                                  THEN 'FAIL'
        WHEN success_enabled != 'YES' OR failure_enabled != 'YES'   THEN 'WARN'
        WHEN except_user_count > 0                                  THEN 'WARN'
        ELSE 'PASS'
    END                                                             AS "verdict"
FROM policy_check
ORDER BY cis_control;

SET MARKUP CSV OFF
SPOOL OFF
