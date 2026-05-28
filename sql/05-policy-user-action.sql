-- SPDX-License-Identifier: Apache-2.0
-- -----------------------------------------------------------------------------
-- Name......: 05-policy-user-action.sql
-- Purpose...: Detailed breakdown: policy x dbusername x action_name.
--             Identifies which (policy, user, action) combinations
--             generate volume - the actionable input for WHEN-clause
--             tuning ("muss User X via Policy Y fuer Action Z auditiert
--             werden?").
-- Pattern...: Multi-dimension aggregate, optimised for tuning decisions.
-- -----------------------------------------------------------------------------

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

SELECT
    unified_audit_policies                                       AS "policy_name",
    NVL(dbusername, '(null)')                                    AS "dbusername",
    NVL(action_name, '(null)')                                   AS "action_name",
    return_code                                                  AS "return_code",
    COUNT(*)                                                     AS "events",
    COUNT(DISTINCT userhost)                                     AS "distinct_hosts",
    TO_CHAR(MIN(event_timestamp_utc), 'YYYY-MM-DD HH24:MI:SS')   AS "first_seen",
    TO_CHAR(MAX(event_timestamp_utc), 'YYYY-MM-DD HH24:MI:SS')   AS "last_seen"
FROM unified_audit_trail
WHERE event_timestamp_utc >= SYSTIMESTAMP - NUMTODSINTERVAL(TO_NUMBER('&days'), 'DAY')
  AND dbid = con_id_to_dbid(SYS_CONTEXT('USERENV','CON_ID'))
  AND unified_audit_policies IS NOT NULL
GROUP BY unified_audit_policies, dbusername, action_name, return_code
ORDER BY 5 DESC
FETCH FIRST TO_NUMBER('&top_n') ROWS ONLY;

SET MARKUP CSV OFF
SPOOL OFF
