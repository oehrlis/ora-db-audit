-- SPDX-License-Identifier: Apache-2.0
-- -----------------------------------------------------------------------------
-- Name......: 15-noise-candidates.sql
-- Purpose...: Identify high-volume (policy, user, action, client, rc)
--             combinations that fire >= 10 events/day on average.
--             Primary actionable output for WHEN-clause tuning ("muss
--             das so sein?").
-- Pattern...: Multi-dimension aggregate with rate calculation and
--             HAVING-threshold filter.
-- Notes.....: Threshold (10/day) is hard-coded. Adjust if your trail
--             needs tighter filtering.
-- -----------------------------------------------------------------------------

SPOOL &LOGDIR./15_noise_candidates.csv

PROMPT # query: noise_candidates
PROMPT # query_id: 15
PROMPT # dbsid: &DBSID
PROMPT # pdb: &PDB_NAME
PROMPT # generated: &GENERATED_ISO
PROMPT # date_range_days: &days
PROMPT # top_n: &top_n
PROMPT # threshold: 10_events_per_day_average
PROMPT # schema: policy_name=KEEP|dbusername=PSEUDO:DBUSER|action_name=KEEP|client_program_name=PSEUDO:CLIENT|return_code=KEEP|events=COUNT|events_per_day=COUNT|distinct_hosts=COUNT|first_seen=TIMESTAMP|last_seen=TIMESTAMP

SET MARKUP CSV ON DELIMITER '|' QUOTE OFF

SELECT
    unified_audit_policies                                       AS "policy_name",
    NVL(dbusername, '(null)')                                    AS "dbusername",
    NVL(action_name, '(null)')                                   AS "action_name",
    NVL(client_program_name, '(null)')                           AS "client_program_name",
    return_code                                                  AS "return_code",
    COUNT(*)                                                     AS "events",
    ROUND(COUNT(*) / GREATEST(TO_NUMBER('&days'), 1), 1)         AS "events_per_day",
    COUNT(DISTINCT userhost)                                     AS "distinct_hosts",
    TO_CHAR(MIN(event_timestamp_utc), 'YYYY-MM-DD HH24:MI:SS')   AS "first_seen",
    TO_CHAR(MAX(event_timestamp_utc), 'YYYY-MM-DD HH24:MI:SS')   AS "last_seen"
FROM unified_audit_trail
WHERE event_timestamp_utc >= SYSTIMESTAMP - NUMTODSINTERVAL(TO_NUMBER('&days'), 'DAY')
  AND dbid = con_id_to_dbid(SYS_CONTEXT('USERENV','CON_ID'))
  AND unified_audit_policies IS NOT NULL
GROUP BY unified_audit_policies, dbusername, action_name, client_program_name, return_code
HAVING COUNT(*) >= GREATEST(TO_NUMBER('&days'), 1) * 10
ORDER BY 6 DESC
FETCH FIRST TO_NUMBER('&top_n') ROWS ONLY;

SET MARKUP CSV OFF
SPOOL OFF
