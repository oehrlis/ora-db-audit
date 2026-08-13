-- SPDX-License-Identifier: Apache-2.0
-- -----------------------------------------------------------------------------
-- OraDBA - Oracle Database Infrastructure and Security, 5630 Muri, Switzerland
-- -----------------------------------------------------------------------------
-- Name......: blind-spot-cdb.sql
-- Author....: Stefan Oehrli (oes) stefan.oehrli@oradba.ch
-- Date......: 2026.08.13
-- Revision..: 0.1.0
-- Purpose...: Unified Audit blind-spot report, CDB scope (all open containers).
--             Standalone version - no tool, no setup, no spool file.
--             Copy the whole file into SQL*Plus or SQL Developer and run it.
--
-- Run as....: SYSDBA, or any account with SELECT on the data dictionary
--             (SELECT ANY DICTIONARY / SELECT_CATALOG_ROLE).
-- Run where.: In CDB$ROOT of a CDB. Not usable in a Non-CDB -
--             use blind-spot-pdb.sql there. Run from a PDB it degrades to
--             that one container.
--
-- Question..: Who is actually audited by the currently enabled Unified Audit
--             policies - and who is not.
--
-- Assignment forms evaluated (all three Oracle variants):
--   BY USER <name>          -> direct assignment          -> COVERED_DIRECT
--   BY USER 'ALL USERS'     -> unrestricted policy        -> COVERED_ALL_USERS
--   BY GRANTED ROLE <role>  -> via role membership,       -> COVERED_VIA_ROLE
--                              resolved transitively and
--                              including roles granted to PUBLIC
--   EXCEPT <name>           -> explicit exclusion. Oracle stores no extra
--                              ALL USERS row for such a policy, so an EXCEPT
--                              list is treated as "all users minus this list".
--
-- coverage_status:
--   COVERED_DIRECT     named explicitly in at least one enabled policy
--   COVERED_VIA_ROLE   covered through a granted role - NOT a blind spot
--   COVERED_ALL_USERS  covered by an unrestricted policy
--   EXCLUDED_EXCEPT    not covered, and the only reason is an EXCEPT clause.
--                      This is a deliberate exemption, not an accidental gap.
--   BLIND_SPOT         no customer-controlled policy audits this user
--
-- Important.: coverage_status counts customer-controlled policies only
--             (oracle_supplied = 'NO'). Oracle ships ORA_SECURECONFIG enabled
--             BY ALL USERS on virtually every database - counting it would
--             mark every user as covered and make the report meaningless.
--             Oracle-supplied coverage is still reported, in the column
--             ora_supplied_cover. A row with BLIND_SPOT + ora_supplied_cover
--             = YES means: the Oracle baseline still catches dictionary and
--             privilege events, but no customer policy audits this user.
--
-- Note......: Only policies with at least one non-logon action are counted.
--             LOGON/LOGOFF/SESSION* alone is session accounting, not
--             activity auditing.
--
-- Oracle does NOT provide CDB_AUDIT_UNIFIED_POLICIES or
-- CDB_AUDIT_UNIFIED_ENABLED_POLICIES. The Unified Audit catalog views exist
-- without a DBA_/CDB_ prefix and are always container-local. The CDB-wide
-- view is therefore built with the CONTAINERS() clause, which fans the local
-- view out over all OPEN containers and adds CON_ID. The user and role side
-- does have real catalog views and uses CDB_USERS / CDB_ROLE_PRIVS /
-- CDB_PDBS, joined back on CON_ID.
--
-- CONTAINERS() returns OPEN containers only. A PDB in MOUNTED state is
-- silently absent - cross-check CDB_PDBS / V$PDBS before declaring a PDB
-- clean. Common users appear once per container; that is intentional, their
-- policy assignment can differ per PDB.
-- License...: Apache License Version 2.0
-- -----------------------------------------------------------------------------

SET LINESIZE 300
SET PAGESIZE 200
SET FEEDBACK ON
SET NULL "-"

COLUMN principal          FORMAT A30
COLUMN oracle_maintained  FORMAT A3   HEADING "ORA"
COLUMN account_status     FORMAT A18
COLUMN coverage_status    FORMAT A18
COLUMN cover_paths        FORMAT A22
COLUMN policy_count       FORMAT 9999 HEADING "POL#"
COLUMN ora_supplied_cover FORMAT A3   HEADING "OCOV"
COLUMN via_roles          FORMAT A30
COLUMN excepted_policies  FORMAT A30
COLUMN covering_policies  FORMAT A40
COLUMN con_id            FORMAT 9999
COLUMN pdb_name          FORMAT A20

WITH
-- Container name lookup - CDB$ROOT is con_id 1 and not in cdb_pdbs.
containers_map AS (
    SELECT 1 AS con_id, 'CDB$ROOT' AS pdb_name FROM dual
    UNION ALL
    SELECT con_id, pdb_name FROM cdb_pdbs
),
-- Enabled policies with at least one non-logon action, per container.
scope_pol AS (
    SELECT DISTINCT
           e.con_id,
           e.policy_name,
           UPPER(e.enabled_option) AS enabled_option,
           UPPER(e.entity_name)    AS entity_name,
           UPPER(e.entity_type)    AS entity_type,
           p.oracle_supplied
    FROM   containers(audit_unified_enabled_policies) e
    JOIN   containers(audit_unified_policies) p
           ON  p.policy_name = e.policy_name
           AND p.con_id      = e.con_id
    WHERE  UPPER(p.audit_option) NOT IN (
               'LOGON', 'LOGOFF',
               'SESSION REC', 'SESSION CON', 'SESSION EX'
           )
),
by_user AS (
    SELECT con_id, policy_name, entity_name, oracle_supplied
    FROM   scope_pol
    WHERE  enabled_option = 'BY USER'
    AND    entity_name   <> 'ALL USERS'
),
by_role AS (
    SELECT con_id, policy_name, entity_name AS role_name, oracle_supplied
    FROM   scope_pol
    WHERE  enabled_option = 'BY GRANTED ROLE'
),
excepted AS (
    SELECT con_id, policy_name, entity_name, oracle_supplied
    FROM   scope_pol
    WHERE  enabled_option = 'EXCEPT USER'
),
-- Explicit ALL USERS plus every policy carrying an EXCEPT list.
universal AS (
    SELECT DISTINCT con_id, policy_name, oracle_supplied
    FROM   scope_pol
    WHERE  (enabled_option = 'BY USER' AND entity_name = 'ALL USERS')
    OR      enabled_option = 'EXCEPT USER'
),
-- Transitive role closure per container.
role_closure AS (
    SELECT DISTINCT
           con_id,
           UPPER(CONNECT_BY_ROOT grantee) AS grantee,
           UPPER(granted_role)            AS granted_role
    FROM   cdb_role_privs
    CONNECT BY NOCYCLE PRIOR UPPER(granted_role) = UPPER(grantee)
           AND PRIOR con_id = con_id
),
public_roles AS (
    SELECT con_id, granted_role
    FROM   role_closure
    WHERE  grantee = 'PUBLIC'
),
principals AS (
    SELECT con_id,
           username AS principal,
           oracle_maintained,
           account_status
    FROM   cdb_users
),
cov_direct AS (
    SELECT pr.con_id, pr.principal, b.policy_name, b.oracle_supplied,
           'DIRECT' AS cover_path, CAST(NULL AS VARCHAR2(128)) AS via_role
    FROM   principals pr
    JOIN   by_user b
           ON  b.con_id      = pr.con_id
           AND b.entity_name = UPPER(pr.principal)
),
cov_role AS (
    SELECT pr.con_id, pr.principal, r.policy_name, r.oracle_supplied,
           'ROLE' AS cover_path, r.role_name AS via_role
    FROM   principals pr
    JOIN   role_closure rc
           ON  rc.con_id  = pr.con_id
           AND rc.grantee = UPPER(pr.principal)
    JOIN   by_role r
           ON  r.con_id    = pr.con_id
           AND r.role_name = rc.granted_role
    UNION
    SELECT pr.con_id, pr.principal, r.policy_name, r.oracle_supplied,
           'ROLE' AS cover_path, r.role_name AS via_role
    FROM   principals pr
    JOIN   by_role r ON r.con_id = pr.con_id
    WHERE  EXISTS (
               SELECT 1 FROM public_roles pu
               WHERE  pu.con_id       = r.con_id
               AND    pu.granted_role = r.role_name
           )
),
cov_all AS (
    SELECT pr.con_id, pr.principal, u.policy_name, u.oracle_supplied,
           'ALL_USERS' AS cover_path, CAST(NULL AS VARCHAR2(128)) AS via_role
    FROM   principals pr
    JOIN   universal u ON u.con_id = pr.con_id
    WHERE  NOT EXISTS (
               SELECT 1 FROM excepted e
               WHERE  e.con_id      = u.con_id
               AND    e.policy_name = u.policy_name
               AND    e.entity_name = UPPER(pr.principal)
           )
),
coverage AS (
    SELECT * FROM cov_direct
    UNION
    SELECT * FROM cov_role
    UNION
    SELECT * FROM cov_all
),
agg AS (
    SELECT c.con_id, c.principal,
           COUNT(DISTINCT CASE WHEN c.oracle_supplied = 'NO'
                               THEN c.policy_name END) AS policy_count,
           MAX(CASE WHEN c.oracle_supplied = 'NO'
                     AND c.cover_path = 'DIRECT'    THEN 1 ELSE 0 END) AS has_direct,
           MAX(CASE WHEN c.oracle_supplied = 'NO'
                     AND c.cover_path = 'ROLE'      THEN 1 ELSE 0 END) AS has_role,
           MAX(CASE WHEN c.oracle_supplied = 'NO'
                     AND c.cover_path = 'ALL_USERS' THEN 1 ELSE 0 END) AS has_all,
           MAX(CASE WHEN c.oracle_supplied = 'YES'  THEN 1 ELSE 0 END) AS has_ora,
           LISTAGG(DISTINCT CASE WHEN c.oracle_supplied = 'NO' THEN c.via_role END, ',')
               WITHIN GROUP (ORDER BY CASE WHEN c.oracle_supplied = 'NO'
                                           THEN c.via_role END) AS via_roles,
           LISTAGG(DISTINCT CASE WHEN c.oracle_supplied = 'NO' THEN c.policy_name END, ',')
               WITHIN GROUP (ORDER BY CASE WHEN c.oracle_supplied = 'NO'
                                           THEN c.policy_name END) AS covering_policies
    FROM   coverage c
    GROUP  BY c.con_id, c.principal
),
exc AS (
    SELECT pr.con_id, pr.principal,
           LISTAGG(DISTINCT e.policy_name, ',')
               WITHIN GROUP (ORDER BY e.policy_name) AS excepted_policies
    FROM   principals pr
    JOIN   excepted e
           ON  e.con_id      = pr.con_id
           AND e.entity_name = UPPER(pr.principal)
    WHERE  e.oracle_supplied = 'NO'
    GROUP  BY pr.con_id, pr.principal
),
final AS (
    SELECT
        pr.con_id,
        NVL(cm.pdb_name, 'CON_' || pr.con_id) AS pdb_name,
        pr.principal,
        pr.oracle_maintained,
        pr.account_status,
        CASE
            WHEN a.has_direct = 1 THEN 'COVERED_DIRECT'
            WHEN a.has_role   = 1 THEN 'COVERED_VIA_ROLE'
            WHEN a.has_all    = 1 THEN 'COVERED_ALL_USERS'
            WHEN x.principal IS NOT NULL THEN 'EXCLUDED_EXCEPT'
            ELSE 'BLIND_SPOT'
        END AS coverage_status,
        NVL(
            TRIM(BOTH '+' FROM
                CASE WHEN a.has_direct = 1 THEN 'DIRECT+' END ||
                CASE WHEN a.has_role   = 1 THEN 'ROLE+'   END ||
                CASE WHEN a.has_all    = 1 THEN 'ALL_USERS' END
            ), '-') AS cover_paths,
        NVL(a.policy_count, 0) AS policy_count,
        CASE WHEN NVL(a.has_ora, 0) = 1 THEN 'YES' ELSE 'NO' END AS ora_supplied_cover,
        NVL(a.via_roles, '-')         AS via_roles,
        NVL(x.excepted_policies, '-') AS excepted_policies,
        NVL(a.covering_policies, '-') AS covering_policies
    FROM   principals pr
    LEFT   JOIN containers_map cm ON cm.con_id = pr.con_id
    LEFT   JOIN agg a ON a.con_id = pr.con_id AND a.principal = pr.principal
    LEFT   JOIN exc x ON x.con_id = pr.con_id AND x.principal = pr.principal
)
SELECT
    con_id,
    pdb_name,
    principal,
    oracle_maintained,
    account_status,
    coverage_status,
    cover_paths,
    policy_count,
    ora_supplied_cover,
    via_roles,
    excepted_policies,
    covering_policies
FROM   final
ORDER  BY
    CASE coverage_status
        WHEN 'BLIND_SPOT'        THEN 1
        WHEN 'EXCLUDED_EXCEPT'   THEN 2
        WHEN 'COVERED_ALL_USERS' THEN 3
        WHEN 'COVERED_VIA_ROLE'  THEN 4
        ELSE 5
    END,
    con_id,
    oracle_maintained,
    principal;

-- -----------------------------------------------------------------------------
-- Optional: restrict to customer accounts only. Uncomment the WHERE line
-- inside the final SELECT above, or simply run:
--
--   ... FROM final WHERE oracle_maintained = 'N' ORDER BY ...
--
-- Optional: only the gaps.
--
--   ... FROM final WHERE coverage_status IN ('BLIND_SPOT','EXCLUDED_EXCEPT') ...
-- -----------------------------------------------------------------------------
