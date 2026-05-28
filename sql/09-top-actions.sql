-- SPDX-License-Identifier: Apache-2.0
-- -----------------------------------------------------------------------------
-- Name......: 09-top-actions.sql
-- Purpose...: Top action_name (DDL/DML/DCL/LOGON/...) by event count.
--             Action-profile-overview.
-- Pattern...: Single-dimension aggregate.
-- -----------------------------------------------------------------------------

SPOOL &LOGDIR./09_top_actions.csv

PROMPT # query: top_actions
PROMPT # query_id: 09
PROMPT # dbsid: &DBSID
PROMPT # pdb: &PDB_NAME
PROMPT # generated: &GENERATED_ISO
PROMPT # date_range_days: &days
PROMPT # top_n: &top_n
PROMPT # schema: action_name=KEEP|events=COUNT|distinct_users=COUNT|distinct_objects=COUNT|distinct_policies=COUNT

SET MARKUP CSV ON DELIMITER '|' QUOTE OFF

SELECT
    NVL(action_name, '(null)')                                   AS "action_name",
    COUNT(*)                                                     AS "events",
    COUNT(DISTINCT dbusername)                                   AS "distinct_users",
    COUNT(DISTINCT object_schema || '.' || object_name)          AS "distinct_objects",
    COUNT(DISTINCT unified_audit_policies)                       AS "distinct_policies"
FROM unified_audit_trail
WHERE event_timestamp_utc >= SYSTIMESTAMP - NUMTODSINTERVAL(TO_NUMBER('&days'), 'DAY')
  AND dbid = con_id_to_dbid(SYS_CONTEXT('USERENV','CON_ID'))
GROUP BY action_name
ORDER BY 2 DESC
FETCH FIRST TO_NUMBER('&top_n') ROWS ONLY;

SET MARKUP CSV OFF
SPOOL OFF
