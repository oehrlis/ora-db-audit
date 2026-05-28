-- SPDX-License-Identifier: Apache-2.0
-- -----------------------------------------------------------------------------
-- Name......: 13-failed-logins.sql
-- Purpose...: Failed login attempts (action_name=LOGON, return_code != 0).
--             Security signal - identifies brute-force, misconfigured app
--             credentials, expired passwords.
-- Pattern...: Multi-dimension aggregate filtered to failures.
-- Notes.....: return_code 1017 = invalid credentials, 1045 = insufficient
--             privilege, 28000 = account locked, 28001 = password expired.
-- -----------------------------------------------------------------------------

SPOOL &LOGDIR./13_failed_logins.csv

PROMPT # query: failed_logins
PROMPT # query_id: 13
PROMPT # dbsid: &DBSID
PROMPT # pdb: &PDB_NAME
PROMPT # generated: &GENERATED_ISO
PROMPT # cis_controls: 5.2
PROMPT # date_range_days: &days
PROMPT # top_n: &top_n
PROMPT # schema: dbusername=PSEUDO:DBUSER|userhost=PSEUDO:HOST|client_program_name=PSEUDO:CLIENT|return_code=KEEP|failed_attempts=COUNT|distinct_programs=COUNT|first_seen=TIMESTAMP|last_seen=TIMESTAMP

SET MARKUP CSV ON DELIMITER '|' QUOTE OFF

SELECT
    NVL(dbusername, '(null)')                                    AS "dbusername",
    NVL(userhost, '(null)')                                      AS "userhost",
    NVL(client_program_name, '(null)')                           AS "client_program_name",
    return_code                                                  AS "return_code",
    COUNT(*)                                                     AS "failed_attempts",
    COUNT(DISTINCT client_program_name)                          AS "distinct_programs",
    TO_CHAR(MIN(event_timestamp_utc), 'YYYY-MM-DD HH24:MI:SS')   AS "first_seen",
    TO_CHAR(MAX(event_timestamp_utc), 'YYYY-MM-DD HH24:MI:SS')   AS "last_seen"
FROM unified_audit_trail
WHERE event_timestamp_utc >= SYSTIMESTAMP - NUMTODSINTERVAL(TO_NUMBER('&days'), 'DAY')
  AND dbid = con_id_to_dbid(SYS_CONTEXT('USERENV','CON_ID'))
  AND action_name = 'LOGON'
  AND return_code != 0
GROUP BY dbusername, userhost, client_program_name, return_code
ORDER BY 5 DESC
FETCH FIRST TO_NUMBER('&top_n') ROWS ONLY;

SET MARKUP CSV OFF
SPOOL OFF
