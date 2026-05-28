-- SPDX-License-Identifier: Apache-2.0
-- -----------------------------------------------------------------------------
-- OraDBA - Oracle Database Infrastructure and Security, 5630 Muri, Switzerland
-- -----------------------------------------------------------------------------
-- Name......: 00-setup.sql
-- Author....: Stefan Oehrli (oes) stefan.oehrli@oradba.ch
-- Date......: 2026.05.12
-- Revision..: 0.1.0
-- Purpose...: Shared setup for the audit analysis_pack. Reads parameters
--             from the environment (ORADBA_LOG, ORADBA_DAYS, ORADBA_TOP_N)
--             and captures runtime metadata (DBSID, PDB, ISO timestamp).
-- Usage.....: Must be sourced once at the start of every sqlplus session
--             that runs analysis_pack queries. The wrapper script
--             run_analysis_pack.sh does this automatically.
-- Notes.....: Output format = CSV with '|' delimiter, QUOTE OFF for compact
--             rows. Each query produces one .csv file with a metadata
--             preamble (# key: value lines incl. a `# schema:` line that
--             lists per-column type hints for the column-aware anonymiser).
-- License...: Apache License Version 2.0
-- -----------------------------------------------------------------------------

SET ECHO OFF
SET VERIFY OFF
SET SERVEROUTPUT OFF
SET TIMING OFF
WHENEVER OSERROR CONTINUE
WHENEVER SQLERROR CONTINUE

-- Read parameters from environment with safe defaults.
-- Allows running scripts standalone (defaults) or via wrapper (env vars).
-- The HOST command runs via the OS shell; SQL*Plus does NOT expand
-- shell-style ${var}. We therefore use a fixed temp-file name (no
-- ${USER} suffix, which would not survive the @@-include).
HOST echo "DEFINE LOGDIR = '${ORADBA_LOG:-.}'"      >  /tmp/oradba_params.sql 2>/dev/null
HOST echo "DEFINE days   = '${ORADBA_DAYS:-30}'"    >> /tmp/oradba_params.sql 2>/dev/null
HOST echo "DEFINE top_n  = '${ORADBA_TOP_N:-100}'"  >> /tmp/oradba_params.sql 2>/dev/null
@@/tmp/oradba_params.sql
HOST rm -f /tmp/oradba_params.sql

-- Optional: switch to target PDB if ORADBA_PDB is set. The conditional
-- is built in bash (single-line - sqlplus HOST does not support line
-- continuation) and included as a separate file - either an ALTER
-- SESSION statement or a no-op comment.
HOST if [ -n "${ORADBA_PDB:-}" ]; then echo "ALTER SESSION SET CONTAINER = \"${ORADBA_PDB}\";" > /tmp/oradba_container.sql; else echo "-- no PDB switch (ORADBA_PDB not set)" > /tmp/oradba_container.sql; fi
@@/tmp/oradba_container.sql
HOST rm -f /tmp/oradba_container.sql

-- Predictable NLS for CSV consumers.
ALTER SESSION SET NLS_NUMERIC_CHARACTERS    = '.,';
ALTER SESSION SET NLS_DATE_FORMAT           = 'YYYY-MM-DD HH24:MI:SS';
ALTER SESSION SET NLS_TIMESTAMP_FORMAT      = 'YYYY-MM-DD HH24:MI:SS';
ALTER SESSION SET NLS_TIMESTAMP_TZ_FORMAT   = 'YYYY-MM-DD"T"HH24:MI:SSTZH:TZM';

-- Capture run metadata into SQL*Plus DEFINEs.
COLUMN x_ts  NEW_VALUE GENERATED_TS  NOPRINT
COLUMN x_iso NEW_VALUE GENERATED_ISO NOPRINT
COLUMN x_sid NEW_VALUE DBSID         NOPRINT
COLUMN x_pdb NEW_VALUE PDB_NAME      NOPRINT
COLUMN x_ver NEW_VALUE DB_VERSION    NOPRINT

SELECT
    TO_CHAR(SYSDATE,     'YYYYMMDD_HH24MISS')                AS x_ts,
    TO_CHAR(SYSTIMESTAMP, 'YYYY-MM-DD"T"HH24:MI:SSTZH:TZM')  AS x_iso,
    LOWER(SYS_CONTEXT('USERENV','INSTANCE_NAME'))            AS x_sid,
    NVL(SYS_CONTEXT('USERENV','CON_NAME'), 'CDB$ROOT')       AS x_pdb,
    (SELECT version FROM v$instance)                         AS x_ver
FROM DUAL;

-- SQL*Plus settings for clean CSV output.
SET LINESIZE 32767
SET PAGESIZE 50000
SET TRIMSPOOL ON
SET TRIMOUT ON
SET HEADING ON
SET FEEDBACK OFF
SET TERMOUT OFF
SET NULL ""

-- Confirm setup once on the terminal (will appear in wrapper log).
SET TERMOUT ON
PROMPT
PROMPT analysis_pack setup: DBSID=&DBSID PDB=&PDB_NAME days=&days top_n=&top_n
PROMPT analysis_pack setup: LOGDIR=&LOGDIR DB_VERSION=&DB_VERSION
PROMPT
SET TERMOUT OFF
