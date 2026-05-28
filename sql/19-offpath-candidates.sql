-- SPDX-License-Identifier: Apache-2.0
-- -----------------------------------------------------------------------------
-- Name......: 19-offpath-candidates.sql
-- Purpose...: Surface host + user combinations whose userhost does not match
--             the expected application-tier or infrastructure pattern.
--             Off-path connections originating from unknown / unclassified
--             hosts are a key indicator for lateral movement, direct-DB
--             access bypassing application controls, or misconfigured clients.
--
--             This query does NOT require the ODB_AUDIT_CTX application
--             context package to be deployed. It derives the classification
--             entirely from the USERHOST value in UNIFIED_AUDIT_TRAIL.
--
--             The pattern variables below follow the same naming convention
--             as bin/ora-db-audit.sh and 12-distinct-hosts.sql:
--
--               APP_PATTERN    - REGEXP_LIKE pattern for application-tier hosts
--               INFRA_PATTERN  - REGEXP_LIKE pattern for DB / OEM / infra hosts
--               DBA_PATTERN    - REGEXP_LIKE pattern for DBA jump / laptop hosts
--
--             All three patterns are OR-combined. Any host NOT matching
--             any of the three is classified as OFF-PATH.
--
--             Output contains one row per unique (userhost, dbusername) pair
--             that is off-path, together with action volume and time range
--             to help triage priority.
--
-- Pattern...: Outer filter via NOT REGEXP_LIKE; aggregate per host+user.
-- Notes.....: Adjust the three &*_PATTERN substitution variables to the
--             actual deployment patterns before running. The defaults match
--             the built-in community patterns in audit_report.py.
--             Requires SELECT on UNIFIED_AUDIT_TRAIL (AUDIT_VIEWER or
--             AUDIT_ADMIN).
-- -----------------------------------------------------------------------------

-- APP_PATTERN: lab prefixes + generic WebLogic + K8s ReplicaSet/CronJob pods.
-- K8s ReplicaSet pod: <name>-<10hex>-<5hex>   e.g. my-service-6c4d8bbdfd-jdbsd
-- K8s CronJob pod:    <name>-<10digits>-<...>  e.g. batch-job-1774600200-main-xyz
-- Customer-specific prefixes (^ejpdxa, ^eap etc.) set via SQL*Plus DEFINE override.
DEFINE APP_PATTERN   = '^auditlab-app-|^app-|^wls-|-[a-z0-9]{10}-[a-z0-9]{5}$|-[0-9]{10}-'
DEFINE INFRA_PATTERN = '^auditlab-db|^oem-'
DEFINE DBA_PATTERN   = '^laptop-|^jumphost-'

SPOOL &LOGDIR./19_offpath_candidates.csv

PROMPT # query: offpath_candidates
PROMPT # query_id: 19
PROMPT # dbsid: &DBSID
PROMPT # pdb: &PDB_NAME
PROMPT # generated: &GENERATED_ISO
PROMPT # cis_controls:
PROMPT # date_range_days: &days
PROMPT # top_n: &top_n
PROMPT # schema: userhost=PSEUDO:HOST|dbusername=PSEUDO:DBUSER|os_username=PSEUDO:DBUSER|client_program_name=PSEUDO:OBJECT|action_count=COUNT|distinct_actions=COUNT|first_seen=TIMESTAMP|last_seen=TIMESTAMP|classification=KEEP

SET MARKUP CSV ON DELIMITER '|' QUOTE OFF

SELECT
    NVL(userhost, '(null)')                                         AS "userhost",
    NVL(dbusername, '(null)')                                       AS "dbusername",
    NVL(os_username, '(null)')                                      AS "os_username",
    NVL(client_program_name, '(null)')                              AS "client_program_name",
    COUNT(*)                                                        AS "action_count",
    COUNT(DISTINCT action_name)                                     AS "distinct_actions",
    TO_CHAR(MIN(event_timestamp_utc), 'YYYY-MM-DD HH24:MI:SS')     AS "first_seen",
    TO_CHAR(MAX(event_timestamp_utc), 'YYYY-MM-DD HH24:MI:SS')     AS "last_seen",
    'OFF-PATH'                                                      AS "classification"
FROM unified_audit_trail
WHERE event_timestamp_utc >= SYSTIMESTAMP - NUMTODSINTERVAL(TO_NUMBER('&days'), 'DAY')
  AND dbid = con_id_to_dbid(SYS_CONTEXT('USERENV','CON_ID'))
  AND userhost IS NOT NULL
  AND NOT REGEXP_LIKE(userhost, '&APP_PATTERN',   'i')
  AND NOT REGEXP_LIKE(userhost, '&INFRA_PATTERN', 'i')
  AND NOT REGEXP_LIKE(userhost, '&DBA_PATTERN',   'i')
GROUP BY
    NVL(userhost, '(null)'),
    NVL(dbusername, '(null)'),
    NVL(os_username, '(null)'),
    NVL(client_program_name, '(null)')
ORDER BY action_count DESC
FETCH FIRST &top_n ROWS ONLY;

SET MARKUP CSV OFF
SPOOL OFF
