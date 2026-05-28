-- SPDX-License-Identifier: Apache-2.0
-- -----------------------------------------------------------------------------
-- Name......: 06-policy-client-program.sql
-- Purpose...: Policy x client_program_name. Shows which client tools
--             trigger which audit policies - input for tool-based
--             WHEN-clause tuning ("welche Programme erzeugen die meiste
--             Last unter dieser Policy?").
--             Per-policy aggregation via UAP-concat split CTE (see below).
-- Pattern...: Split CTE + two-dimension aggregate, one row per individual
--             (policy_name, client_program_name).
-- -----------------------------------------------------------------------------

-- UAP-concat split: unified_audit_policies is comma-separated when
-- multiple policies match an event. Per ai-analysis-rules.md Section 3,
-- aggregating on the raw column gives wrong per-policy counts. The
-- split CTE below tokenises the column into one row per (event, policy).

SPOOL &LOGDIR./06_policy_client_program.csv

PROMPT # query: policy_client_program
PROMPT # query_id: 06
PROMPT # dbsid: &DBSID
PROMPT # pdb: &PDB_NAME
PROMPT # generated: &GENERATED_ISO
PROMPT # cis_controls: -
PROMPT # date_range_days: &days
PROMPT # top_n: &top_n
PROMPT # schema: policy_name=KEEP|client_program_name=PSEUDO:CLIENT|events=COUNT|distinct_users=COUNT|distinct_hosts=COUNT

SET MARKUP CSV ON DELIMITER '|' QUOTE OFF

WITH split_uap AS (
    SELECT
        TRIM(REGEXP_SUBSTR(t.unified_audit_policies, '[^,]+', 1, lvl.col_pos)) AS policy_name,
        t.event_timestamp_utc,
        t.dbusername,
        t.userhost,
        t.client_program_name
    FROM unified_audit_trail t
    CROSS JOIN (
        SELECT LEVEL AS col_pos FROM dual CONNECT BY LEVEL <= 20
    ) lvl
    WHERE t.unified_audit_policies IS NOT NULL
      AND lvl.col_pos <= REGEXP_COUNT(t.unified_audit_policies, ',') + 1
      AND t.event_timestamp_utc >= SYSTIMESTAMP - NUMTODSINTERVAL(TO_NUMBER('&days'), 'DAY')
      AND t.dbid = con_id_to_dbid(SYS_CONTEXT('USERENV','CON_ID'))
)
SELECT
    policy_name                                                  AS "policy_name",
    NVL(client_program_name, '(null)')                           AS "client_program_name",
    COUNT(*)                                                     AS "events",
    COUNT(DISTINCT dbusername)                                   AS "distinct_users",
    COUNT(DISTINCT userhost)                                     AS "distinct_hosts"
FROM split_uap
GROUP BY policy_name, client_program_name
ORDER BY 3 DESC
FETCH FIRST TO_NUMBER('&top_n') ROWS ONLY;

SET MARKUP CSV OFF
SPOOL OFF
