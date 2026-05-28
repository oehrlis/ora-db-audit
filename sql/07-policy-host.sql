-- SPDX-License-Identifier: Apache-2.0
-- -----------------------------------------------------------------------------
-- Name......: 07-policy-host.sql
-- Purpose...: Policy x userhost. Maps audit-policy volume to source
--             hosts - critical for distinguishing app-server traffic
--             (whitelist via C_APP_HOST_PATTERN) from off-path.
-- Pattern...: Two-dimension aggregate with first/last seen.
-- -----------------------------------------------------------------------------

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

SELECT
    unified_audit_policies                                       AS "policy_name",
    NVL(userhost, '(null)')                                      AS "userhost",
    COUNT(*)                                                     AS "events",
    COUNT(DISTINCT dbusername)                                   AS "distinct_users",
    TO_CHAR(MIN(event_timestamp_utc), 'YYYY-MM-DD HH24:MI:SS')   AS "first_seen",
    TO_CHAR(MAX(event_timestamp_utc), 'YYYY-MM-DD HH24:MI:SS')   AS "last_seen"
FROM unified_audit_trail
WHERE event_timestamp_utc >= SYSTIMESTAMP - NUMTODSINTERVAL(TO_NUMBER('&days'), 'DAY')
  AND dbid = con_id_to_dbid(SYS_CONTEXT('USERENV','CON_ID'))
  AND unified_audit_policies IS NOT NULL
GROUP BY unified_audit_policies, userhost
ORDER BY 3 DESC
FETCH FIRST TO_NUMBER('&top_n') ROWS ONLY;

SET MARKUP CSV OFF
SPOOL OFF
