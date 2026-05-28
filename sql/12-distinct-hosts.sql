-- SPDX-License-Identifier: Apache-2.0
-- -----------------------------------------------------------------------------
-- Name......: 12-distinct-hosts.sql
-- Purpose...: Distinct userhost values with first/last seen and login count.
--             Primary data source for hostname regex pattern definition
--             (Engineering Task E-05, C_APP_HOST_PATTERN) and off-path
--             detection.
-- Pattern...: Distinct enumeration with time bounds, sorted by host for
--             pattern review.
-- Notes.....: Filters to LOGON events only - the connection-establishment
--             event is what the off-path detection has to classify.
-- -----------------------------------------------------------------------------

SPOOL &LOGDIR./12_distinct_hosts.csv

PROMPT # query: distinct_hosts
PROMPT # query_id: 12
PROMPT # dbsid: &DBSID
PROMPT # pdb: &PDB_NAME
PROMPT # generated: &GENERATED_ISO
PROMPT # cis_controls:
PROMPT # date_range_days: &days
PROMPT # top_n: &top_n
PROMPT # schema: userhost=PSEUDO:HOST|logins=COUNT|distinct_users=COUNT|distinct_programs=COUNT|first_seen=TIMESTAMP|last_seen=TIMESTAMP

SET MARKUP CSV ON DELIMITER '|' QUOTE OFF

SELECT
    NVL(userhost, '(null)')                                      AS "userhost",
    COUNT(*)                                                     AS "logins",
    COUNT(DISTINCT dbusername)                                   AS "distinct_users",
    COUNT(DISTINCT client_program_name)                          AS "distinct_programs",
    TO_CHAR(MIN(event_timestamp_utc), 'YYYY-MM-DD HH24:MI:SS')   AS "first_seen",
    TO_CHAR(MAX(event_timestamp_utc), 'YYYY-MM-DD HH24:MI:SS')   AS "last_seen"
FROM unified_audit_trail
WHERE event_timestamp_utc >= SYSTIMESTAMP - NUMTODSINTERVAL(TO_NUMBER('&days'), 'DAY')
  AND dbid = con_id_to_dbid(SYS_CONTEXT('USERENV','CON_ID'))
  AND action_name = 'LOGON'
GROUP BY userhost
ORDER BY 1 ASC
FETCH FIRST TO_NUMBER('&top_n') ROWS ONLY;

SET MARKUP CSV OFF
SPOOL OFF
