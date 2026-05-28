-- SPDX-License-Identifier: Apache-2.0
-- -----------------------------------------------------------------------------
-- OraDBA - Oracle Database Infrastructure and Security, 5630 Muri, Switzerland
-- -----------------------------------------------------------------------------
-- Name......: 17-cis-coverage.sql
-- Author....: Stefan Oehrli (oes) stefan.oehrli@oradba.ch
-- Date......: 2026.05.28
-- Revision..: 1.3.0
-- Purpose...: CIS Oracle DB Benchmark v2.0 (19c/23ai) coverage check via
--             action comparison. Instead of checking for hard-coded policy
--             names (CIS_CDB_*), this query inspects all enabled policies and
--             classifies whether each CIS 5.1-5.5 requirement is met by the
--             existing policy set.
-- Pattern...: Per-CIS-control CTEs define indicator actions. A policy matches
--             a control when it audits those actions (or audits ALL, which
--             covers everything). Coverage quality:
--               FULL    - policy targets ALL USERS with no WHEN condition
--                         (or for 5.5: targets SYS/DBA role specifically)
--               PARTIAL - policy has a WHEN condition or limited user scope
--             Verdict:
--               PASS    - at least one custom (non-ORA_*) policy gives FULL
--                         coverage for the control
--               PARTIAL - only PARTIAL coverage from custom policies (no FULL)
--               FAIL    - no custom policy covers the control at all
-- Notes.....: Oracle-supplied policies (oracle_supplied='YES') are shown in a
--             separate column for informational purposes; they do not affect
--             the verdict because they are outside customer control.
--             CIS 5.3 (Critical Packages) checks for EXECUTE action; full
--             package-level specificity requires object-level audit which is
--             not captured in this query.
-- License...: Apache License Version 2.0
-- -----------------------------------------------------------------------------

SPOOL &LOGDIR./17_cis_coverage.csv

PROMPT # query: cis_coverage
PROMPT # query_id: 17
PROMPT # dbsid: &DBSID
PROMPT # pdb: &PDB_NAME
PROMPT # generated: &GENERATED_ISO
PROMPT # cis_controls: 5.1,5.2,5.3,5.4,5.5
PROMPT # schema: cis_control=KEEP|cis_title=KEEP|verdict=KEEP|custom_policies=KEEP|oracle_policies=KEEP

SET MARKUP CSV ON DELIMITER '|' QUOTE OFF

WITH
-- CIS 5.1-5.5 control reference
cis_controls AS (
    SELECT '5.1' AS cis_control, 'DDL Actions'         AS cis_title FROM dual UNION ALL
    SELECT '5.2',                 'Logon and Logoff'                  FROM dual UNION ALL
    SELECT '5.3',                 'Critical Packages'                 FROM dual UNION ALL
    SELECT '5.4',                 'Export Activities'                 FROM dual UNION ALL
    SELECT '5.5',                 'SYS Privileged Users'              FROM dual
),
-- All enabled policy action rows (excluding EXCEPT USER exclusion rows)
active_policies AS (
    SELECT DISTINCT
        p.policy_name,
        p.audit_option_type,
        p.audit_option,
        e.entity_name,
        e.entity_type,
        p.oracle_supplied,
        p.audit_condition
    FROM audit_unified_policies p
    JOIN audit_unified_enabled_policies e
        ON  e.policy_name     = p.policy_name
        AND e.enabled_option != 'EXCEPT USER'
),
-- ---------------------------------------------------------------------------
-- CIS 5.1 DDL Actions
-- Full  : STANDARD ACTION (GRANT|REVOKE|CREATE/ALTER/DROP TABLE|user|role|ALL)
--         for ALL USERS with no WHEN condition
-- Partial: same actions but user-limited or has a WHEN condition
-- ---------------------------------------------------------------------------
cis51_full AS (
    SELECT DISTINCT policy_name, oracle_supplied
    FROM   active_policies
    WHERE  audit_option_type = 'STANDARD ACTION'
      AND  (   audit_option = 'ALL'
            OR audit_option IN ('GRANT','REVOKE',
                                'CREATE TABLE','ALTER TABLE','DROP TABLE',
                                'CREATE USER','ALTER USER','DROP USER',
                                'CREATE ROLE','ALTER ROLE','DROP ROLE',
                                'CREATE SEQUENCE','ALTER SEQUENCE'))
      AND  entity_name = 'ALL USERS'
      AND  (audit_condition = 'NONE' OR audit_condition IS NULL)
),
cis51_partial AS (
    SELECT DISTINCT policy_name, oracle_supplied
    FROM   active_policies
    WHERE  audit_option_type = 'STANDARD ACTION'
      AND  (   audit_option = 'ALL'
            OR audit_option IN ('GRANT','REVOKE',
                                'CREATE TABLE','ALTER TABLE','DROP TABLE',
                                'CREATE USER','ALTER USER','DROP USER',
                                'CREATE ROLE','ALTER ROLE','DROP ROLE',
                                'CREATE SEQUENCE','ALTER SEQUENCE'))
    MINUS
    SELECT policy_name, oracle_supplied FROM cis51_full
),
-- ---------------------------------------------------------------------------
-- CIS 5.2 Logon and Logoff
-- ---------------------------------------------------------------------------
cis52_full AS (
    SELECT DISTINCT policy_name, oracle_supplied
    FROM   active_policies
    WHERE  audit_option_type = 'STANDARD ACTION'
      AND  (audit_option = 'ALL' OR audit_option IN ('LOGON','LOGOFF'))
      AND  entity_name = 'ALL USERS'
      AND  (audit_condition = 'NONE' OR audit_condition IS NULL)
),
cis52_partial AS (
    SELECT DISTINCT policy_name, oracle_supplied
    FROM   active_policies
    WHERE  audit_option_type = 'STANDARD ACTION'
      AND  (audit_option = 'ALL' OR audit_option IN ('LOGON','LOGOFF'))
    MINUS
    SELECT policy_name, oracle_supplied FROM cis52_full
),
-- ---------------------------------------------------------------------------
-- CIS 5.3 Critical Packages (EXECUTE on DBMS_SYS_SQL, UTL_*, etc.)
-- Full  : STANDARD ACTION EXECUTE (or ALL) for ALL USERS, no condition
-- Partial: EXECUTE with conditions or user-scoped, or ALL with conditions
-- ---------------------------------------------------------------------------
cis53_full AS (
    SELECT DISTINCT policy_name, oracle_supplied
    FROM   active_policies
    WHERE  audit_option_type = 'STANDARD ACTION'
      AND  (audit_option = 'ALL' OR audit_option = 'EXECUTE')
      AND  entity_name = 'ALL USERS'
      AND  (audit_condition = 'NONE' OR audit_condition IS NULL)
),
cis53_partial AS (
    SELECT DISTINCT policy_name, oracle_supplied
    FROM   active_policies
    WHERE  audit_option_type = 'STANDARD ACTION'
      AND  (audit_option = 'ALL' OR audit_option = 'EXECUTE')
    MINUS
    SELECT policy_name, oracle_supplied FROM cis53_full
),
-- ---------------------------------------------------------------------------
-- CIS 5.4 Export Activities (DataPump EXPORT)
-- ---------------------------------------------------------------------------
cis54_full AS (
    SELECT DISTINCT policy_name, oracle_supplied
    FROM   active_policies
    WHERE  audit_option_type = 'DATAPUMP ACTION'
      AND  audit_option = 'EXPORT'
      AND  entity_name = 'ALL USERS'
      AND  (audit_condition = 'NONE' OR audit_condition IS NULL)
),
cis54_partial AS (
    SELECT DISTINCT policy_name, oracle_supplied
    FROM   active_policies
    WHERE  audit_option_type = 'DATAPUMP ACTION'
      AND  audit_option = 'EXPORT'
    MINUS
    SELECT policy_name, oracle_supplied FROM cis54_full
),
-- ---------------------------------------------------------------------------
-- CIS 5.5 SYS Privileged Users - all actions by privileged accounts
-- Full  : policy audits ALL for SYS/SYSTEM user or a DBA-type role
--         (targeting privileged users IS the expected scope for 5.5)
-- Partial: policy audits ALL for ALL USERS with a condition (partial scope)
-- ---------------------------------------------------------------------------
cis55_full AS (
    SELECT DISTINCT policy_name, oracle_supplied
    FROM   active_policies
    WHERE  audit_option_type = 'STANDARD ACTION'
      AND  audit_option = 'ALL'
      AND  (entity_name IN ('SYS','SYSTEM') OR entity_type = 'ROLE')
),
cis55_partial AS (
    SELECT DISTINCT policy_name, oracle_supplied
    FROM   active_policies
    WHERE  audit_option_type = 'STANDARD ACTION'
      AND  audit_option = 'ALL'
      AND  entity_name = 'ALL USERS'
    MINUS
    SELECT policy_name, oracle_supplied FROM cis55_full
),
-- ---------------------------------------------------------------------------
-- Combine all coverage into one labelled set
-- ---------------------------------------------------------------------------
all_coverage AS (
    SELECT '5.1' AS cis_control, 'FULL'    AS quality, policy_name, oracle_supplied FROM cis51_full    UNION ALL
    SELECT '5.1',                'PARTIAL',             policy_name, oracle_supplied FROM cis51_partial UNION ALL
    SELECT '5.2',                'FULL',                policy_name, oracle_supplied FROM cis52_full    UNION ALL
    SELECT '5.2',                'PARTIAL',             policy_name, oracle_supplied FROM cis52_partial UNION ALL
    SELECT '5.3',                'FULL',                policy_name, oracle_supplied FROM cis53_full    UNION ALL
    SELECT '5.3',                'PARTIAL',             policy_name, oracle_supplied FROM cis53_partial UNION ALL
    SELECT '5.4',                'FULL',                policy_name, oracle_supplied FROM cis54_full    UNION ALL
    SELECT '5.4',                'PARTIAL',             policy_name, oracle_supplied FROM cis54_partial UNION ALL
    SELECT '5.5',                'FULL',                policy_name, oracle_supplied FROM cis55_full    UNION ALL
    SELECT '5.5',                'PARTIAL',             policy_name, oracle_supplied FROM cis55_partial
),
-- ---------------------------------------------------------------------------
-- Aggregate: one row per CIS control
-- ---------------------------------------------------------------------------
coverage_agg AS (
    SELECT
        cis_control,
        LISTAGG(CASE WHEN quality = 'FULL'    AND oracle_supplied = 'NO'  THEN policy_name END, ', ')
            WITHIN GROUP (ORDER BY policy_name)   AS custom_full,
        LISTAGG(CASE WHEN quality = 'PARTIAL' AND oracle_supplied = 'NO'  THEN policy_name END, ', ')
            WITHIN GROUP (ORDER BY policy_name)   AS custom_partial,
        LISTAGG(CASE WHEN                          oracle_supplied = 'YES' THEN policy_name END, ', ')
            WITHIN GROUP (ORDER BY policy_name)   AS oracle_policies,
        COUNT(CASE WHEN quality = 'FULL'    AND oracle_supplied = 'NO'  THEN 1 END)
                                                  AS custom_full_cnt,
        COUNT(CASE WHEN quality = 'PARTIAL' AND oracle_supplied = 'NO'  THEN 1 END)
                                                  AS custom_partial_cnt
    FROM all_coverage
    GROUP BY cis_control
)
SELECT
    c.cis_control                                                    AS "cis_control",
    c.cis_title                                                      AS "cis_title",
    CASE
        WHEN a.custom_full_cnt    > 0             THEN 'PASS'
        WHEN a.custom_partial_cnt > 0             THEN 'PARTIAL'
        ELSE                                           'FAIL'
    END                                                              AS "verdict",
    CASE
        WHEN a.custom_full_cnt > 0 AND a.custom_partial_cnt > 0
            THEN a.custom_full || ' (+partial: ' || a.custom_partial || ')'
        WHEN a.custom_full_cnt    > 0             THEN a.custom_full
        WHEN a.custom_partial_cnt > 0             THEN '(partial) ' || a.custom_partial
        ELSE                                           '(none)'
    END                                                              AS "custom_policies",
    NVL(a.oracle_policies, '(none)')                                 AS "oracle_policies"
FROM cis_controls c
LEFT JOIN coverage_agg a ON a.cis_control = c.cis_control
ORDER BY c.cis_control;

SET MARKUP CSV OFF
SPOOL OFF
