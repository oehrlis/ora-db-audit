-- SPDX-License-Identifier: Apache-2.0
-- -----------------------------------------------------------------------------
-- Name......: 14-privileged-activity.sql
-- Purpose...: Privileged-user activity (SYS, SYSTEM, SYSDBA, AUDIT_ADMIN
--             etc). Compliance requirement (CIS, PCI-DSS) - privileged
--             actions must be fully traceable and visible.
-- Pattern...: Filtered multi-dimension aggregate.
-- Notes.....: Privileged USERNAMES stay KEEP (visible) per compliance.
--             Object schema/name still PSEUDO (customer data).
-- -----------------------------------------------------------------------------

SPOOL &LOGDIR./14_privileged_activity.csv

PROMPT # query: privileged_activity
PROMPT # query_id: 14
PROMPT # dbsid: &DBSID
PROMPT # pdb: &PDB_NAME
PROMPT # generated: &GENERATED_ISO
PROMPT # cis_controls: 5.5
PROMPT # date_range_days: &days
PROMPT # top_n: &top_n
PROMPT # schema: dbusername=KEEP|action_name=KEEP|object_schema=PSEUDO:SCHEMA|object_name=PSEUDO:OBJECT|return_code=KEEP|events=COUNT|distinct_hosts=COUNT|first_seen=TIMESTAMP|last_seen=TIMESTAMP

SET MARKUP CSV ON DELIMITER '|' QUOTE OFF

SELECT
    dbusername                                                   AS "dbusername",
    NVL(action_name, '(null)')                                   AS "action_name",
    NVL(object_schema, '')                                       AS "object_schema",
    NVL(object_name, '')                                         AS "object_name",
    return_code                                                  AS "return_code",
    COUNT(*)                                                     AS "events",
    COUNT(DISTINCT userhost)                                     AS "distinct_hosts",
    TO_CHAR(MIN(event_timestamp_utc), 'YYYY-MM-DD HH24:MI:SS')   AS "first_seen",
    TO_CHAR(MAX(event_timestamp_utc), 'YYYY-MM-DD HH24:MI:SS')   AS "last_seen"
FROM unified_audit_trail
WHERE event_timestamp_utc >= SYSTIMESTAMP - NUMTODSINTERVAL(TO_NUMBER('&days'), 'DAY')
  AND dbid = con_id_to_dbid(SYS_CONTEXT('USERENV','CON_ID'))
  AND dbusername IN ('SYS', 'SYSTEM', 'AUDIT_VIEWER', 'AUDIT_ADMIN',
                     'SYSBACKUP', 'SYSDG', 'SYSKM', 'SYSRAC',
                     'DBSNMP', 'AUDSYS')
GROUP BY dbusername, action_name, object_schema, object_name, return_code
ORDER BY 6 DESC
FETCH FIRST TO_NUMBER('&top_n') ROWS ONLY;

SET MARKUP CSV OFF
SPOOL OFF
