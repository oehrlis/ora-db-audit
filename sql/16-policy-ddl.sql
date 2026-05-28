-- SPDX-License-Identifier: Apache-2.0
-- -----------------------------------------------------------------------------
-- Name......: 16-policy-ddl.sql
-- Purpose...: Retrieve current DDL for every enabled audit policy via
--             DBMS_METADATA.GET_DDL. Canonical DDL source for Section 8.1
--             of the audit report (WHEN-clause tuning suggestions).
--             Per ai-analysis-rules.md Section 4 - suggested policy
--             modifications MUST be based on actual DDL, never synthesised
--             from UNIFIED_AUDIT_POLICIES concat strings (finding F2).
-- Pattern...: One row per policy_name, DDL as CLOB column.
-- Notes.....: Requires AUDIT_ADMIN or SELECT_CATALOG_ROLE privilege.
--             If privilege is missing the query returns no rows; Phase D
--             reporter falls back to "DDL unavailable - suggestion
--             suppressed" rather than fabricating DDL from concat strings.
--             policy_ddl is a CLOB with embedded newlines. Phase D
--             audit_report.py CSV parser needs multi-line cell handling
--             for this column (flagged for Phase D scope, not fixed here).
-- -----------------------------------------------------------------------------

-- DDL source rule: per ai-analysis-rules.md Section 4, every suggested
-- ALTER AUDIT POLICY statement must reference the actual policy DDL via
-- DBMS_METADATA.GET_DDL, not be assembled from observed UAP concat strings.
-- This file is the canonical Phase B data source for that requirement.

SPOOL &LOGDIR./16_policy_ddl.csv

PROMPT # query: policy_ddl
PROMPT # query_id: 16
PROMPT # dbsid: &DBSID
PROMPT # pdb: &PDB_NAME
PROMPT # generated: &GENERATED_ISO
PROMPT # date_range_days: &days
PROMPT # top_n: &top_n
PROMPT # schema: policy_name=KEEP|policy_ddl=KEEP_MULTILINE

SET MARKUP CSV ON DELIMITER '|' QUOTE OFF
SET LONG 100000
SET LONGCHUNKSIZE 100000

BEGIN
  DBMS_METADATA.SET_TRANSFORM_PARAM(DBMS_METADATA.SESSION_TRANSFORM, 'SQLTERMINATOR', TRUE);
  DBMS_METADATA.SET_TRANSFORM_PARAM(DBMS_METADATA.SESSION_TRANSFORM, 'PRETTY', TRUE);
END;
/

SELECT DISTINCT
    p.policy_name,
    DBMS_METADATA.GET_DDL('AUDIT_POLICY', p.policy_name) AS policy_ddl
FROM audit_unified_policies p
ORDER BY p.policy_name;

SET MARKUP CSV OFF
SPOOL OFF
