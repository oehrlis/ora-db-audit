-- SPDX-License-Identifier: Apache-2.0
-- -----------------------------------------------------------------------------
-- Name......: 01-config.sql
-- Purpose...: Audit configuration snapshot. DBMS_AUDIT_MGMT config params
--             plus audit-related init parameters and instance metadata.
-- Pattern...: Unified key-value table from three sources.
-- -----------------------------------------------------------------------------

SPOOL &LOGDIR./01_config.csv

PROMPT # query: config
PROMPT # query_id: 01
PROMPT # dbsid: &DBSID
PROMPT # pdb: &PDB_NAME
PROMPT # generated: &GENERATED_ISO
PROMPT # schema: source=KEEP|name=KEEP|value=KEEP|trail=KEEP

SET MARKUP CSV ON DELIMITER '|' QUOTE OFF

SELECT
    'audit_mgmt'                                    AS "source",
    parameter_name                                  AS "name",
    parameter_value                                 AS "value",
    audit_trail                                     AS "trail"
FROM dba_audit_mgmt_config_params
UNION ALL
SELECT
    'init_param'                                    AS "source",
    name                                            AS "name",
    value                                           AS "value",
    NULL                                            AS "trail"
FROM v$parameter
WHERE LOWER(name) LIKE '%audit%'
UNION ALL
SELECT
    'instance'                                      AS "source",
    'instance_name'                                 AS "name",
    instance_name                                   AS "value",
    NULL                                            AS "trail"
FROM v$instance
UNION ALL
SELECT
    'instance'                                      AS "source",
    'version'                                       AS "name",
    version                                         AS "value",
    NULL                                            AS "trail"
FROM v$instance
UNION ALL
SELECT
    'instance'                                      AS "source",
    'host_name'                                     AS "name",
    host_name                                       AS "value",
    NULL                                            AS "trail"
FROM v$instance
UNION ALL
SELECT
    'unified_audit'                                 AS "source",
    'pure_mode'                                     AS "name",
    value                                           AS "value",
    NULL                                            AS "trail"
FROM v$option
WHERE parameter = 'Unified Auditing'
ORDER BY 1, 2;

SET MARKUP CSV OFF
SPOOL OFF
