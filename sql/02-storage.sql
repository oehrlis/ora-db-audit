-- SPDX-License-Identifier: Apache-2.0
-- -----------------------------------------------------------------------------
-- OraDBA - Oracle Database Infrastructure and Security, 5630 Muri, Switzerland
-- -----------------------------------------------------------------------------
-- Name......: 02-storage.sql
-- Author....: Stefan Oehrli (oes) stefan.oehrli@oradba.ch
-- Date......: 2026.05.12
-- Revision..: 0.2.0
-- Purpose...: Audit-trail storage analysis with partition tablespace
--             disambiguation. Captures per-partition details for
--             AUDSYS.AUD$UNIFIED and emits three distinct metadata values:
--             D = DEF_TABLESPACE_NAME (target for new partitions),
--             C = tablespace of the most recent (current write) partition,
--             O = comma-joined unique tablespaces of older retained partitions.
--             Enables the reporter to apply the D/C/O decision matrix from
--             docs/ai-analysis-rules.md Section 5.2 and distinguish
--             MISCONFIGURATION from TRANSIENT state after ALTER TABLE
--             MODIFY DEFAULT ATTRIBUTES TABLESPACE.
-- Pattern...: Metadata preamble via PL/SQL + per-partition detail rows.
-- Notes.....: Interpretation contract: docs/ai-analysis-rules.md Sections 5+6.
--             Schema-hint tag TABLESPACE_STATE marks the per-partition
--             tablespace_name column so the reporter compares it against D
--             to derive the decision matrix verdict.
--             Column creation_time reflects DBA_OBJECTS.CREATED for the
--             partition object; may be NULL if statistics are stale or the
--             object is not yet analysed.
-- License...: Apache License Version 2.0
-- -----------------------------------------------------------------------------

-- ---------------------------------------------------------------------------
-- Phase 1: Derive D, C, O via PL/SQL and capture into SQL*Plus DEFINEs.
-- ---------------------------------------------------------------------------
SET SERVEROUTPUT ON SIZE UNLIMITED

COLUMN x_tbs_default  NEW_VALUE TBS_DEFAULT  NOPRINT
COLUMN x_tbs_current  NEW_VALUE TBS_CURRENT  NOPRINT
COLUMN x_tbs_older    NEW_VALUE TBS_OLDER    NOPRINT

-- Scalar SELECT to derive D, C, O in a single pass using analytic functions.
-- D: DEF_TABLESPACE_NAME from DBA_PART_TABLES.
-- C: tablespace of the partition with the highest partition_position (most recent).
-- O: LISTAGG of distinct tablespaces from all partitions except the highest one.
SELECT
    NVL(d.def_tbs,    'UNKNOWN')    AS x_tbs_default,
    NVL(c.curr_tbs,   '(none)')     AS x_tbs_current,
    NVL(o.older_tbs,  '(none)')     AS x_tbs_older
FROM
    -- D: default tablespace for new partitions
    (SELECT def_tablespace_name AS def_tbs
     FROM   dba_part_tables
     WHERE  owner      = 'AUDSYS'
       AND  table_name = 'AUD$UNIFIED') d,
    -- C: tablespace of the highest-positioned (most recent) partition
    (SELECT tablespace_name AS curr_tbs
     FROM   dba_tab_partitions
     WHERE  table_owner = 'AUDSYS'
       AND  table_name  = 'AUD$UNIFIED'
       AND  partition_position = (
                SELECT MAX(partition_position)
                FROM   dba_tab_partitions
                WHERE  table_owner = 'AUDSYS'
                  AND  table_name  = 'AUD$UNIFIED')) c,
    -- O: distinct tablespaces from all non-latest partitions (comma-joined)
    (SELECT LISTAGG(DISTINCT NVL(tablespace_name, '(none)'), ',')
                WITHIN GROUP (ORDER BY NVL(tablespace_name, '(none)')) AS older_tbs
     FROM   dba_tab_partitions
     WHERE  table_owner = 'AUDSYS'
       AND  table_name  = 'AUD$UNIFIED'
       AND  partition_position < (
                SELECT MAX(partition_position)
                FROM   dba_tab_partitions
                WHERE  table_owner = 'AUDSYS'
                  AND  table_name  = 'AUD$UNIFIED')) o;

SET SERVEROUTPUT OFF

-- ---------------------------------------------------------------------------
-- Phase 2: Spool the storage CSV with full metadata preamble.
-- ---------------------------------------------------------------------------
SPOOL &LOGDIR./02_storage.csv

PROMPT # query: storage
PROMPT # query_id: 02
PROMPT # dbsid: &DBSID
PROMPT # pdb: &PDB_NAME
PROMPT # generated: &GENERATED_ISO
PROMPT # audit_data_tablespace_default: &TBS_DEFAULT
PROMPT # audit_data_tablespace_current: &TBS_CURRENT
PROMPT # audit_data_tablespace_older_partitions: &TBS_OLDER
PROMPT # schema: partition_name=KEEP|num_rows=COUNT|size_mb=COUNT|last_analyzed=TIMESTAMP|tablespace_name=TABLESPACE_STATE|partition_position=KEEP|creation_time=TIMESTAMP

SET MARKUP CSV ON DELIMITER '|' QUOTE OFF

-- Per-partition detail rows.
-- tablespace_name is tagged TABLESPACE_STATE in the schema-hint.
-- The reporter compares this column against TBS_DEFAULT (D) for each row
-- to apply the decision matrix from docs/ai-analysis-rules.md Section 5.2.
-- partition_position: integer sort order; highest position = most recent
--   write-target partition. HIGH_VALUE is a LONG column in DBA_TAB_PARTITIONS
--   and cannot be safely projected in a JOIN context; partition_position
--   provides the relative ordering needed for the D/C/O classification.
-- creation_time: sourced from DBA_OBJECTS.CREATED for the partition object.
SELECT
    p.partition_name                                                AS "partition_name",
    NVL(p.num_rows, 0)                                              AS "num_rows",
    NVL(ROUND(s.bytes / 1024 / 1024, 2), 0)                        AS "size_mb",
    TO_CHAR(p.last_analyzed, 'YYYY-MM-DD HH24:MI:SS')              AS "last_analyzed",
    NVL(p.tablespace_name, '(none)')                               AS "tablespace_name",
    TO_CHAR(p.partition_position)                                  AS "partition_position",
    TO_CHAR(o.created, 'YYYY-MM-DD HH24:MI:SS')                    AS "creation_time"
FROM dba_tab_partitions p
LEFT JOIN dba_segments s
    ON  s.owner          = p.table_owner
    AND s.segment_name   = p.table_name
    AND s.partition_name = p.partition_name
LEFT JOIN dba_objects o
    ON  o.owner          = p.table_owner
    AND o.object_name    = p.table_name
    AND o.subobject_name = p.partition_name
    AND o.object_type    = 'TABLE PARTITION'
WHERE p.table_owner = 'AUDSYS'
  AND p.table_name  = 'AUD$UNIFIED'
ORDER BY p.partition_position;

SET MARKUP CSV OFF
SPOOL OFF
