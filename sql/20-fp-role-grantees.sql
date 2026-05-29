-- SPDX-License-Identifier: Apache-2.0
-- -----------------------------------------------------------------------------
-- OraDBA - Oracle Database Infrastructure and Security, 5630 Muri, Switzerland
-- -----------------------------------------------------------------------------
-- Name......: 20-fp-role-grantees.sql
-- Author....: Stefan Oehrli (oes) stefan.oehrli@oradba.ch
-- Date......: 2026.05.29
-- Revision..: 0.1.0
-- Purpose...: Cross-reference BY GRANTED ROLE audit policy bindings with the
--             actual role grants in DBA_ROLE_PRIVS. Used by audit_report.py
--             to detect FP-001 false positives: failed LOGON events appearing
--             under a BY GRANTED ROLE policy even though the user does not
--             actually hold the role.
--
--             Background (Oracle engine behavior):
--             Oracle Unified Auditing does NOT evaluate BY GRANTED ROLE
--             membership for unauthenticated sessions. When a LOGON attempt
--             fails (ORA-01017, ORA-01045), the session is never established,
--             so the role-check against DBA_ROLE_PRIVS is skipped. The audit
--             record is written with the attempted username regardless of
--             whether that user holds the role. Without cross-referencing the
--             actual grants, an AI analyser will incorrectly conclude that
--             high LOGON-failure volume proves the user has the role.
--
-- Pattern...: LEFT JOIN so policies whose role has no grantees still appear
--             (one row with NULL grantee). This lets audit_report.py flag
--             policies with zero role members as an additional anomaly.
--             Only custom (non-Oracle-supplied) policies are included because
--             Oracle-supplied policy role bindings are not customer-managed.
-- Notes.....: Run in the target PDB (or CDB root for CDB-scope policies).
--             Direct role grants only (depth=1). Role-to-role chains (e.g.
--             C##ROLE_DBA granted to INTERMEDIATE_ROLE granted to USER) are
--             not traversed; the audit engine evaluates the full effective
--             role set, so deep chains may produce FP-001 indicators that are
--             actually correct - verify with SESSION_PRIVS / SESSION_ROLES for
--             the specific user if unsure.
-- License...: Apache License Version 2.0
-- -----------------------------------------------------------------------------

SPOOL &LOGDIR./20_fp_role_grantees.csv

PROMPT # query: fp_role_grantees
PROMPT # query_id: 20
PROMPT # dbsid: &DBSID
PROMPT # pdb: &PDB_NAME
PROMPT # generated: &GENERATED_ISO
PROMPT # cis_controls:
PROMPT # schema: policy_name=KEEP|role_name=KEEP|grantee=PSEUDO:DBUSER|grantee_type=KEEP|admin_option=KEEP

SET MARKUP CSV ON DELIMITER '|' QUOTE OFF

-- BY GRANTED ROLE policy bindings cross-referenced with actual role grants.
-- LEFT JOIN on dba_role_privs: rows where grantee IS NULL indicate a role that
-- exists in audit policy bindings but has no direct grantees in this container.
SELECT
    p.policy_name                                                           AS "policy_name",
    p.entity_name                                                           AS "role_name",
    r.grantee                                                               AS "grantee",
    CASE
        WHEN r.grantee IS NULL                     THEN 'NONE'
        WHEN dr.role   IS NOT NULL                 THEN 'ROLE'
        ELSE                                            'USER'
    END                                                                     AS "grantee_type",
    NVL(r.admin_option, 'N/A')                                              AS "admin_option"
FROM (
    SELECT DISTINCT policy_name, entity_name
    FROM   audit_unified_policies
    WHERE  entity_type    = 'ROLE'
    AND    oracle_supplied = 'NO'
) p
LEFT JOIN dba_role_privs r  ON  r.granted_role = p.entity_name
LEFT JOIN dba_roles      dr ON  dr.role        = r.grantee
ORDER BY p.policy_name, p.entity_name, r.grantee;

SET MARKUP CSV OFF
SPOOL OFF
