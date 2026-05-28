-- SPDX-License-Identifier: Apache-2.0
-- -----------------------------------------------------------------------------
-- Name......: 08-top-users.sql
-- Purpose...: Top DB users by event count. Volume-driver identification
--             ("wer macht am meisten?").
-- Pattern...: Single-dimension aggregate with first/last seen.
-- -----------------------------------------------------------------------------

SPOOL &LOGDIR./08_top_users.csv

PROMPT # query: top_users
PROMPT # query_id: 08
PROMPT # dbsid: &DBSID
PROMPT # pdb: &PDB_NAME
PROMPT # generated: &GENERATED_ISO
PROMPT # cis_controls:
PROMPT # date_range_days: &days
PROMPT # top_n: &top_n
PROMPT # sampled: &sampled
PROMPT # schema: dbusername=PSEUDO:DBUSER|events=COUNT|distinct_actions=COUNT|distinct_policies=COUNT|distinct_hosts=COUNT|first_seen=TIMESTAMP|last_seen=TIMESTAMP

SET MARKUP CSV ON DELIMITER '|' QUOTE OFF

SELECT
    NVL(dbusername, '(null)')                                    AS "dbusername",
    COUNT(*)                                                     AS "events",
    COUNT(DISTINCT action_name)                                  AS "distinct_actions",
    COUNT(DISTINCT unified_audit_policies)                       AS "distinct_policies",
    COUNT(DISTINCT userhost)                                     AS "distinct_hosts",
    TO_CHAR(MIN(event_timestamp_utc), 'YYYY-MM-DD HH24:MI:SS')   AS "first_seen",
    TO_CHAR(MAX(event_timestamp_utc), 'YYYY-MM-DD HH24:MI:SS')   AS "last_seen"
FROM unified_audit_trail
WHERE event_timestamp_utc >= SYSTIMESTAMP - NUMTODSINTERVAL(TO_NUMBER('&days'), 'DAY')
  AND dbid = con_id_to_dbid(SYS_CONTEXT('USERENV','CON_ID'))
  &SAMPLE_WHERE
GROUP BY dbusername
ORDER BY 2 DESC
FETCH FIRST TO_NUMBER('&top_n') ROWS ONLY;

SET MARKUP CSV OFF
SPOOL OFF
