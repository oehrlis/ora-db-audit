-- SPDX-License-Identifier: Apache-2.0
-- -----------------------------------------------------------------------------
-- Name......: 10-top-objects.sql
-- Purpose...: Top accessed objects (schema.object). Identifies which
--             customer objects generate the most audit volume - often
--             pointing to noisy app tables that may need WHEN-clause
--             tuning or Fine-Grained Auditing instead of full audit.
-- Pattern...: Two-dimension aggregate (schema + object), filtered to
--             rows with a non-null object_name.
-- -----------------------------------------------------------------------------

SPOOL &LOGDIR./10_top_objects.csv

PROMPT # query: top_objects
PROMPT # query_id: 10
PROMPT # dbsid: &DBSID
PROMPT # pdb: &PDB_NAME
PROMPT # generated: &GENERATED_ISO
PROMPT # cis_controls:
PROMPT # date_range_days: &days
PROMPT # top_n: &top_n
PROMPT # sampled: &sampled
PROMPT # schema: object_schema=PSEUDO:SCHEMA|object_name=PSEUDO:OBJECT|object_type=KEEP|events=COUNT|distinct_users=COUNT|distinct_actions=COUNT

SET MARKUP CSV ON DELIMITER '|' QUOTE OFF

SELECT
    NVL(object_schema, '(null)')                                 AS "object_schema",
    NVL(object_name, '(null)')                                   AS "object_name",
    NVL(object_type, '(null)')                                   AS "object_type",
    COUNT(*)                                                     AS "events",
    COUNT(DISTINCT dbusername)                                   AS "distinct_users",
    COUNT(DISTINCT action_name)                                  AS "distinct_actions"
FROM unified_audit_trail
WHERE event_timestamp_utc >= SYSTIMESTAMP - NUMTODSINTERVAL(TO_NUMBER('&days'), 'DAY')
  AND dbid = con_id_to_dbid(SYS_CONTEXT('USERENV','CON_ID'))
  AND object_name IS NOT NULL
  &SAMPLE_WHERE
GROUP BY object_schema, object_name, object_type
ORDER BY 4 DESC
FETCH FIRST TO_NUMBER('&top_n') ROWS ONLY;

SET MARKUP CSV OFF
SPOOL OFF
