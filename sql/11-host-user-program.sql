-- SPDX-License-Identifier: Apache-2.0
-- -----------------------------------------------------------------------------
-- Name......: 11-host-user-program.sql
-- Purpose...: Connect-profile matrix: host x dbuser x os_user x client.
--             The richest dimension table for off-path detection - every
--             unique connection signature plus its volume.
-- Pattern...: Multi-dimension aggregate.
-- -----------------------------------------------------------------------------

SPOOL &LOGDIR./11_host_user_program.csv

PROMPT # query: host_user_program
PROMPT # query_id: 11
PROMPT # dbsid: &DBSID
PROMPT # pdb: &PDB_NAME
PROMPT # generated: &GENERATED_ISO
PROMPT # cis_controls:
PROMPT # date_range_days: &days
PROMPT # top_n: &top_n
PROMPT # sampled: &sampled
PROMPT # schema: userhost=PSEUDO:HOST|dbusername=PSEUDO:DBUSER|os_username=PSEUDO:OSUSER|client_program_name=PSEUDO:CLIENT|events=COUNT|first_seen=TIMESTAMP|last_seen=TIMESTAMP

SET MARKUP CSV ON DELIMITER '|' QUOTE OFF

SELECT
    NVL(userhost, '(null)')                                      AS "userhost",
    NVL(dbusername, '(null)')                                    AS "dbusername",
    NVL(os_username, '(null)')                                   AS "os_username",
    NVL(client_program_name, '(null)')                           AS "client_program_name",
    COUNT(*)                                                     AS "events",
    TO_CHAR(MIN(event_timestamp_utc), 'YYYY-MM-DD HH24:MI:SS')   AS "first_seen",
    TO_CHAR(MAX(event_timestamp_utc), 'YYYY-MM-DD HH24:MI:SS')   AS "last_seen"
FROM unified_audit_trail
WHERE event_timestamp_utc >= SYSTIMESTAMP - NUMTODSINTERVAL(TO_NUMBER('&days'), 'DAY')
  AND dbid = con_id_to_dbid(SYS_CONTEXT('USERENV','CON_ID'))
  &SAMPLE_WHERE
GROUP BY userhost, dbusername, os_username, client_program_name
ORDER BY 5 DESC
FETCH FIRST TO_NUMBER('&top_n') ROWS ONLY;

SET MARKUP CSV OFF
SPOOL OFF
