-- SPDX-License-Identifier: Apache-2.0
-- -----------------------------------------------------------------------------
-- Name......: 07-policy-host.sql
-- Purpose...: Policy x userhost. Maps audit-policy volume to source
--             hosts - critical for distinguishing app-server traffic
--             (whitelist via C_APP_HOST_PATTERN) from off-path.
--             Per-policy aggregation via UAP-concat split CTE (see below).
-- Pattern...: Split CTE + two-dimension aggregate with first/last seen,
--             one row per individual (policy_name, userhost).
-- -----------------------------------------------------------------------------

-- UAP-concat split: unified_audit_policies is comma-separated when
-- multiple policies match an event. Per ai-analysis-rules.md Section 3,
-- aggregating on the raw column gives wrong per-policy counts. The
-- split CTE below tokenises the column into one row per (event, policy).

SPOOL &LOGDIR./07_policy_host.csv

PROMPT # query: policy_host
PROMPT # query_id: 07
PROMPT # dbsid: &DBSID
PROMPT # pdb: &PDB_NAME
PROMPT # generated: &GENERATED_ISO
PROMPT # date_range_days: &days
PROMPT # top_n: &top_n
PROMPT # schema: policy_name=KEEP|userhost=PSEUDO:HOST|events=COUNT|distinct_users=COUNT|first_seen=TIMESTAMP|last_seen=TIMESTAMP

SET MARKUP CSV ON DELIMITER '|' QUOTE OFF

WITH split_uap AS (
    SELECT
        TRIM(REGEXP_SUBSTR(t.unified_audit_policies, '[^,]+', 1, lvl.col_pos)) AS policy_name,
        t.event_timestamp_utc,
        t.dbusername,
        t.userhost
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
    NVL(userhost, '(null)')                                      AS "userhost",
    COUNT(*)                                                     AS "events",
    COUNT(DISTINCT dbusername)                                   AS "distinct_users",
    TO_CHAR(MIN(event_timestamp_utc), 'YYYY-MM-DD HH24:MI:SS')   AS "first_seen",
    TO_CHAR(MAX(event_timestamp_utc), 'YYYY-MM-DD HH24:MI:SS')   AS "last_seen"
FROM split_uap
GROUP BY policy_name, userhost
ORDER BY 3 DESC
FETCH FIRST TO_NUMBER('&top_n') ROWS ONLY;

SET MARKUP CSV OFF
SPOOL OFF
