-- SPDX-License-Identifier: Apache-2.0
-- -----------------------------------------------------------------------------
-- Name......: 06-policy-client-program.sql
-- Purpose...: Policy x client_program_name. Shows which client tools
--             trigger which audit policies - input for tool-based
--             WHEN-clause tuning ("welche Programme erzeugen die meiste
--             Last unter dieser Policy?").
-- Pattern...: Two-dimension aggregate.
-- -----------------------------------------------------------------------------

SPOOL &LOGDIR./06_policy_client_program.csv

PROMPT # query: policy_client_program
PROMPT # query_id: 06
PROMPT # dbsid: &DBSID
PROMPT # pdb: &PDB_NAME
PROMPT # generated: &GENERATED_ISO
PROMPT # date_range_days: &days
PROMPT # top_n: &top_n
PROMPT # schema: policy_name=KEEP|client_program_name=PSEUDO:CLIENT|events=COUNT|distinct_users=COUNT|distinct_hosts=COUNT

SET MARKUP CSV ON DELIMITER '|' QUOTE OFF

SELECT
    unified_audit_policies                                       AS "policy_name",
    NVL(client_program_name, '(null)')                           AS "client_program_name",
    COUNT(*)                                                     AS "events",
    COUNT(DISTINCT dbusername)                                   AS "distinct_users",
    COUNT(DISTINCT userhost)                                     AS "distinct_hosts"
FROM unified_audit_trail
WHERE event_timestamp_utc >= SYSTIMESTAMP - NUMTODSINTERVAL(TO_NUMBER('&days'), 'DAY')
  AND dbid = con_id_to_dbid(SYS_CONTEXT('USERENV','CON_ID'))
  AND unified_audit_policies IS NOT NULL
GROUP BY unified_audit_policies, client_program_name
ORDER BY 3 DESC
FETCH FIRST TO_NUMBER('&top_n') ROWS ONLY;

SET MARKUP CSV OFF
SPOOL OFF
