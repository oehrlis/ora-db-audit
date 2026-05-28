-- SPDX-License-Identifier: Apache-2.0
-- -----------------------------------------------------------------------------
-- Name......: 05-policy-user-action.sql
-- Purpose...: Detailed breakdown: policy x dbusername x action_name.
--             Identifies which (policy, user, action) combinations
--             generate volume - the actionable input for WHEN-clause
--             tuning ("muss User X via Policy Y fuer Action Z auditiert
--             werden?").
--             Per-policy aggregation via UAP-concat split CTE (see below).
-- Pattern...: Split CTE + multi-dimension aggregate, one row per
--             individual (policy_name, dbusername, action_name, return_code).
-- -----------------------------------------------------------------------------

-- UAP-concat split: unified_audit_policies is comma-separated when
-- multiple policies match an event. Per ai-analysis-rules.md Section 3,
-- aggregating on the raw column gives wrong per-policy counts. The
-- split CTE below tokenises the column into one row per (event, policy).

SPOOL &LOGDIR./05_policy_user_action.csv

PROMPT # query: policy_user_action
PROMPT # query_id: 05
PROMPT # dbsid: &DBSID
PROMPT # pdb: &PDB_NAME
PROMPT # generated: &GENERATED_ISO
PROMPT # date_range_days: &days
PROMPT # top_n: &top_n
PROMPT # schema: policy_name=KEEP|dbusername=PSEUDO:DBUSER|action_name=KEEP|return_code=KEEP|events=COUNT|distinct_hosts=COUNT|first_seen=TIMESTAMP|last_seen=TIMESTAMP

SET MARKUP CSV ON DELIMITER '|' QUOTE OFF

WITH split_uap AS (
    SELECT
        TRIM(REGEXP_SUBSTR(t.unified_audit_policies, '[^,]+', 1, lvl.col_pos)) AS policy_name,
        t.event_timestamp_utc,
        t.dbusername,
        t.userhost,
        t.action_name,
        t.return_code
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
    NVL(dbusername, '(null)')                                    AS "dbusername",
    NVL(action_name, '(null)')                                   AS "action_name",
    return_code                                                  AS "return_code",
    COUNT(*)                                                     AS "events",
    COUNT(DISTINCT userhost)                                     AS "distinct_hosts",
    TO_CHAR(MIN(event_timestamp_utc), 'YYYY-MM-DD HH24:MI:SS')   AS "first_seen",
    TO_CHAR(MAX(event_timestamp_utc), 'YYYY-MM-DD HH24:MI:SS')   AS "last_seen"
FROM split_uap
GROUP BY policy_name, dbusername, action_name, return_code
ORDER BY 5 DESC
FETCH FIRST TO_NUMBER('&top_n') ROWS ONLY;

SET MARKUP CSV OFF
SPOOL OFF
