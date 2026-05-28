-- SPDX-License-Identifier: Apache-2.0
-- -----------------------------------------------------------------------------
-- OraDBA - Oracle Database Infrastructure and Security, 5630 Muri, Switzerland
-- -----------------------------------------------------------------------------
-- Name......: 18-audit-roles.sql
-- Author....: Stefan Oehrli (oes) stefan.oehrli@oradba.ch
-- Date......: 2026.05.28
-- Revision..: 0.1.0
-- Purpose...: AUDIT_ADMIN and AUDIT_VIEWER role membership check.
--             Identifies who can modify (AUDIT_ADMIN) or read (AUDIT_VIEWER)
--             audit policies and the unified audit trail. Flags accounts that
--             warrant review - particularly those with ADMIN_OPTION (can
--             re-grant the role) or non-standard grantees.
-- Pattern...: Two-level role chain: direct grantees, then grantees of
--             intermediate roles that hold the target role. Uses LEFT JOIN
--             against DBA_ROLES to classify each grantee as USER or ROLE.
-- Notes.....: Traversal depth is limited to 2 levels (direct + one hop).
--             Deeper role chains are unusual in practice for audit roles.
--             Risk-flag values:
--               STANDARD - SYS, AUDSYS, or SYSTEM (expected)
--               INFO     - grantee is itself a role (intermediate, not a user)
--               WARN     - user grantee with ADMIN_OPTION (can re-grant)
--               REVIEW   - user grantee without ADMIN_OPTION (verify justified)
--             Run in the CDB root for CDB-wide membership; run in each PDB
--             for PDB-local role grants.
--             Oracle BP v2.0 reference: privileged-user audit recommendations.
-- License...: Apache License Version 2.0
-- -----------------------------------------------------------------------------

SPOOL &LOGDIR./18_audit_roles.csv

PROMPT # query: audit_roles
PROMPT # query_id: 18
PROMPT # dbsid: &DBSID
PROMPT # pdb: &PDB_NAME
PROMPT # generated: &GENERATED_ISO
PROMPT # cis_controls: -
PROMPT # schema: target_role=KEEP|grantee=PSEUDO:DBUSER|grantee_type=KEEP|grant_path=KEEP|admin_option=KEEP|default_role=KEEP|grant_depth=COUNT|risk_flag=KEEP

SET MARKUP CSV ON DELIMITER '|' QUOTE OFF

-- Two-level role chain for AUDIT_ADMIN and AUDIT_VIEWER.
-- Level 1: direct grantees (users and intermediate roles).
-- Level 2: grantees of roles that directly hold the target role.
WITH target_roles AS (
    SELECT 'AUDIT_ADMIN'  AS role_name FROM dual
    UNION ALL
    SELECT 'AUDIT_VIEWER'             FROM dual
),
direct_grantees AS (
    SELECT
        r.role_name                     AS target_role,
        g.grantee                       AS grantee,
        'DIRECT'                        AS grant_path,
        g.admin_option,
        g.default_role,
        1                               AS grant_depth
    FROM target_roles r
    JOIN dba_role_privs g ON g.granted_role = r.role_name
),
role_holders AS (
    SELECT DISTINCT
        d.target_role,
        rp.grantee                      AS grantee,
        'VIA ' || d.grantee             AS grant_path,
        rp.admin_option,
        rp.default_role,
        2                               AS grant_depth
    FROM direct_grantees d
    JOIN dba_roles dr ON dr.role = d.grantee
    JOIN dba_role_privs rp ON rp.granted_role = d.grantee
),
all_grantees AS (
    SELECT target_role, grantee, grant_path, admin_option, default_role, grant_depth
    FROM direct_grantees
    UNION ALL
    SELECT target_role, grantee, grant_path, admin_option, default_role, grant_depth
    FROM role_holders
)
SELECT
    ag.target_role                                                          AS "target_role",
    ag.grantee                                                              AS "grantee",
    CASE WHEN dr.role IS NOT NULL THEN 'ROLE' ELSE 'USER' END               AS "grantee_type",
    ag.grant_path                                                           AS "grant_path",
    ag.admin_option                                                         AS "admin_option",
    ag.default_role                                                         AS "default_role",
    TO_CHAR(ag.grant_depth)                                                 AS "grant_depth",
    CASE
        WHEN dr.role IS NOT NULL                                            THEN 'INFO'
        WHEN ag.grantee IN ('SYS', 'AUDSYS', 'SYSTEM')                     THEN 'STANDARD'
        WHEN ag.admin_option = 'YES'                                        THEN 'WARN'
        ELSE 'REVIEW'
    END                                                                     AS "risk_flag"
FROM all_grantees ag
LEFT JOIN dba_roles dr ON dr.role = ag.grantee
ORDER BY ag.target_role, ag.grant_depth, ag.grantee;

SET MARKUP CSV OFF
SPOOL OFF
