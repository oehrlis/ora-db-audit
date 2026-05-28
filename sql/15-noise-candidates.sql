-- SPDX-License-Identifier: Apache-2.0
-- -----------------------------------------------------------------------------
-- Name......: 15-noise-candidates.sql
-- Purpose...: Identify high-volume (policy, user, action, client, rc)
--             combinations that fire >= 10 events/day on average.
--             Primary actionable output for WHEN-clause tuning ("muss
--             das so sein?"). Feeds Section 8.1 of the audit report -
--             per-policy correctness here is critical (finding F2).
--             Per-policy aggregation via UAP-concat split CTE (see below).
-- Pattern...: Split CTE + multi-dimension aggregate with rate calculation
--             and HAVING-threshold filter, one row per individual
--             (policy_name, dbusername, action_name, client_program_name,
--             return_code).
-- Notes.....: Threshold (10/day) is hard-coded. Adjust if your trail
--             needs tighter filtering.
-- -----------------------------------------------------------------------------

-- UAP-concat split: unified_audit_policies is comma-separated when
-- multiple policies match an event. Per ai-analysis-rules.md Section 3,
-- aggregating on the raw column gives wrong per-policy counts. The
-- split CTE below tokenises the column into one row per (event, policy).
-- CRITICAL: Section 8.1 of audit_report.py uses this output to generate
-- ALTER AUDIT POLICY DDL. Incorrect policy_name values here cause
-- functionally wrong DDL (finding F2). Split is mandatory.

SPOOL &LOGDIR./15_noise_candidates.csv

PROMPT # query: noise_candidates
PROMPT # query_id: 15
PROMPT # dbsid: &DBSID
PROMPT # pdb: &PDB_NAME
PROMPT # generated: &GENERATED_ISO
PROMPT # cis_controls: -
PROMPT # date_range_days: &days
PROMPT # top_n: &top_n
PROMPT # threshold: 10_events_per_day_average
PROMPT # schema: policy_name=KEEP|dbusername=PSEUDO:DBUSER|action_name=KEEP|client_program_name=PSEUDO:CLIENT|return_code=KEEP|events=COUNT|events_per_day=COUNT|distinct_hosts=COUNT|first_seen=TIMESTAMP|last_seen=TIMESTAMP

SET MARKUP CSV ON DELIMITER '|' QUOTE OFF

WITH split_uap AS (
    SELECT
        TRIM(REGEXP_SUBSTR(t.unified_audit_policies, '[^,]+', 1, lvl.col_pos)) AS policy_name,
        t.event_timestamp_utc,
        t.dbusername,
        t.userhost,
        t.action_name,
        t.client_program_name,
        t.return_code
    FROM unified_audit_trail t
    CROSS JOIN (
        SELECT LEVEL AS col_pos FROM dual CONNECT BY LEVEL <= 20
    ) lvl
    WHERE t.unified_audit_policies IS NOT NULL
      AND lvl.col_pos <= REGEXP_COUNT(t.unified_audit_policies, ',') + 1
      AND t.event_timestamp_utc >= SYSTIMESTAMP - NUMTODSINTERVAL(TO_NUMBER('&days'), 'DAY')
      AND t.dbid = con_id_to_dbid(SYS_CONTEXT('USERENV','CON_ID'))
)
SELECT
    policy_name                                                  AS "policy_name",
    NVL(dbusername, '(null)')                                    AS "dbusername",
    NVL(action_name, '(null)')                                   AS "action_name",
    NVL(client_program_name, '(null)')                           AS "client_program_name",
    return_code                                                  AS "return_code",
    COUNT(*)                                                     AS "events",
    ROUND(COUNT(*) / GREATEST(TO_NUMBER('&days'), 1), 1)         AS "events_per_day",
    COUNT(DISTINCT userhost)                                     AS "distinct_hosts",
    TO_CHAR(MIN(event_timestamp_utc), 'YYYY-MM-DD HH24:MI:SS')   AS "first_seen",
    TO_CHAR(MAX(event_timestamp_utc), 'YYYY-MM-DD HH24:MI:SS')   AS "last_seen"
FROM split_uap
GROUP BY policy_name, dbusername, action_name, client_program_name, return_code
HAVING COUNT(*) >= GREATEST(TO_NUMBER('&days'), 1) * 10
ORDER BY 6 DESC
FETCH FIRST TO_NUMBER('&top_n') ROWS ONLY;

SET MARKUP CSV OFF
SPOOL OFF
