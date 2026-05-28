-- SPDX-License-Identifier: Apache-2.0
-- -----------------------------------------------------------------------------
-- Name......: 04-policy-volume.sql
-- Purpose...: Event count per unified audit policy (last &days days).
--             Volume distribution across enabled policies - the core data
--             point for policy tuning ("welche Policy generiert viel?").
-- Pattern...: Simple aggregate, one row per policy_name string.
-- Notes.....: unified_audit_policies is comma-separated when multiple
--             policies match the same event. We GROUP BY the raw string;
--             post-processing (Python) can split if per-policy attribution
--             is needed.
-- -----------------------------------------------------------------------------

SPOOL &LOGDIR./04_policy_volume.csv

PROMPT # query: policy_volume
PROMPT # query_id: 04
PROMPT # dbsid: &DBSID
PROMPT # pdb: &PDB_NAME
PROMPT # generated: &GENERATED_ISO
PROMPT # date_range_days: &days
PROMPT # top_n: &top_n
PROMPT # schema: policy_name=KEEP|events=COUNT|distinct_users=COUNT|distinct_hosts=COUNT|first_seen=TIMESTAMP|last_seen=TIMESTAMP

SET MARKUP CSV ON DELIMITER '|' QUOTE OFF

SELECT
    unified_audit_policies                                       AS "policy_name",
    COUNT(*)                                                     AS "events",
    COUNT(DISTINCT dbusername)                                   AS "distinct_users",
    COUNT(DISTINCT userhost)                                     AS "distinct_hosts",
    TO_CHAR(MIN(event_timestamp_utc), 'YYYY-MM-DD HH24:MI:SS')   AS "first_seen",
    TO_CHAR(MAX(event_timestamp_utc), 'YYYY-MM-DD HH24:MI:SS')   AS "last_seen"
FROM unified_audit_trail
WHERE event_timestamp_utc >= SYSTIMESTAMP - NUMTODSINTERVAL(TO_NUMBER('&days'), 'DAY')
  AND dbid = con_id_to_dbid(SYS_CONTEXT('USERENV','CON_ID'))
  AND unified_audit_policies IS NOT NULL
GROUP BY unified_audit_policies
ORDER BY 2 DESC
FETCH FIRST TO_NUMBER('&top_n') ROWS ONLY;

SET MARKUP CSV OFF
SPOOL OFF
