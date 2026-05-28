-- SPDX-License-Identifier: Apache-2.0
-- -----------------------------------------------------------------------------
-- Name......: 02-storage.sql
-- Purpose...: Audit-trail storage usage. Partition-level info for
--             AUDSYS.AUD$UNIFIED (the unified audit trail table).
-- Pattern...: Per-partition aggregate plus a summary row.
-- -----------------------------------------------------------------------------

SPOOL &LOGDIR./02_storage.csv

PROMPT # query: storage
PROMPT # query_id: 02
PROMPT # dbsid: &DBSID
PROMPT # pdb: &PDB_NAME
PROMPT # generated: &GENERATED_ISO
PROMPT # schema: partition_name=KEEP|num_rows=COUNT|size_mb=COUNT|last_analyzed=TIMESTAMP|tablespace_name=KEEP

SET MARKUP CSV ON DELIMITER '|' QUOTE OFF

SELECT
    p.partition_name                                            AS "partition_name",
    NVL(p.num_rows, 0)                                          AS "num_rows",
    NVL(ROUND(s.bytes / 1024 / 1024, 2), 0)                     AS "size_mb",
    TO_CHAR(p.last_analyzed, 'YYYY-MM-DD HH24:MI:SS')           AS "last_analyzed",
    NVL(p.tablespace_name, '(none)')                            AS "tablespace_name"
FROM dba_tab_partitions p
LEFT JOIN dba_segments s
    ON s.owner        = p.table_owner
   AND s.segment_name = p.table_name
   AND s.partition_name = p.partition_name
WHERE p.table_owner = 'AUDSYS'
  AND p.table_name  = 'AUD$UNIFIED'
ORDER BY p.partition_position;

SET MARKUP CSV OFF
SPOOL OFF
