-- SPDX-License-Identifier: Apache-2.0
-- -----------------------------------------------------------------------------
-- Name......: 04-policy-volume.sql
-- Purpose...: Event count per unified audit policy (last &days days).
--             Volume distribution across enabled policies - the core data
--             point for policy tuning ("welche Policy generiert viel?").
--             Per-policy aggregation via UAP-concat split CTE (see below).
-- Pattern...: Split CTE + aggregate, one row per individual policy_name.
-- Notes.....: unified_audit_policies is comma-separated when multiple
--             policies match the same event. Aggregating on the raw string
--             is incorrect for per-policy semantics; the split CTE below
--             tokenises the column into one row per (event, policy).
-- -----------------------------------------------------------------------------

-- UAP-concat split: unified_audit_policies is comma-separated when
-- multiple policies match an event. Per ai-analysis-rules.md Section 3,
-- aggregating on the raw column gives wrong per-policy counts. The
-- split CTE below tokenises the column into one row per (event, policy).

SPOOL &LOGDIR./04_policy_volume.csv

PROMPT # query: policy_volume
PROMPT # query_id: 04
PROMPT # dbsid: &DBSID
PROMPT # pdb: &PDB_NAME
PROMPT # generated: &GENERATED_ISO
PROMPT # cis_controls: -
PROMPT # date_range_days: &days
PROMPT # top_n: &top_n
PROMPT # schema: policy_name=KEEP|events=COUNT|distinct_users=COUNT|distinct_hosts=COUNT|first_seen=TIMESTAMP|last_seen=TIMESTAMP

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
    COUNT(*)                                                     AS "events",
    COUNT(DISTINCT dbusername)                                   AS "distinct_users",
    COUNT(DISTINCT userhost)                                     AS "distinct_hosts",
    TO_CHAR(MIN(event_timestamp_utc), 'YYYY-MM-DD HH24:MI:SS')   AS "first_seen",
    TO_CHAR(MAX(event_timestamp_utc), 'YYYY-MM-DD HH24:MI:SS')   AS "last_seen"
FROM split_uap
GROUP BY policy_name
ORDER BY 2 DESC
FETCH FIRST TO_NUMBER('&top_n') ROWS ONLY;

SET MARKUP CSV OFF
SPOOL OFF
