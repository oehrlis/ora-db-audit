-- SPDX-License-Identifier: Apache-2.0
-- -----------------------------------------------------------------------------
-- OraDBA - Oracle Database Infrastructure and Security, 5630 Muri, Switzerland
-- -----------------------------------------------------------------------------
-- Name......: blind-spot-pdb.sql
-- Author....: Stefan Oehrli (oes) stefan.oehrli@oradba.ch
-- Date......: 2026.08.13
-- Revision..: 0.1.0
-- Purpose...: Unified Audit blind-spot report, PDB scope (dba_* views, current container).
--             Standalone version - no tool, no setup, no spool file.
--             Copy the whole file into SQL*Plus or SQL Developer and run it.
--
-- Run as....: SYSDBA, or any account with SELECT on the data dictionary
--             (SELECT ANY DICTIONARY / SELECT_CATALOG_ROLE).
-- Run where.: In a PDB, or in a Non-CDB. When run in CDB$ROOT it
--             reports the root container only. For all containers of a CDB
--             in one pass use blind-spot-cdb.sql.
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

WITH
-- Enabled policies that audit real activity (>= 1 non-logon audit_option),
-- flattened together with their entity assignment rows.
scope_pol AS (
    SELECT DISTINCT
           e.policy_name,
           UPPER(e.enabled_option) AS enabled_option,
           UPPER(e.entity_name)    AS entity_name,
           UPPER(e.entity_type)    AS entity_type,
           p.oracle_supplied
    FROM   audit_unified_enabled_policies e
    JOIN   audit_unified_policies p
           ON  p.policy_name = e.policy_name
    WHERE  UPPER(p.audit_option) NOT IN (
               'LOGON', 'LOGOFF',
               'SESSION REC', 'SESSION CON', 'SESSION EX'
           )
),
-- BY USER with a named user - direct assignment
by_user AS (
    SELECT policy_name, entity_name, oracle_supplied
    FROM   scope_pol
    WHERE  enabled_option = 'BY USER'
    AND    entity_name   <> 'ALL USERS'
),
-- BY GRANTED ROLE - assignment through role membership
by_role AS (
    SELECT policy_name, entity_name AS role_name, oracle_supplied
    FROM   scope_pol
    WHERE  enabled_option = 'BY GRANTED ROLE'
),
-- EXCEPT USER - explicit exclusion list
excepted AS (
    SELECT policy_name, entity_name, oracle_supplied
    FROM   scope_pol
    WHERE  enabled_option = 'EXCEPT USER'
),
-- Policies that apply to every user: explicit ALL USERS, plus every policy
-- that carries an EXCEPT list (Oracle stores those without an ALL USERS row).
universal AS (
    SELECT DISTINCT policy_name, oracle_supplied
    FROM   scope_pol
    WHERE  (enabled_option = 'BY USER' AND entity_name = 'ALL USERS')
    OR      enabled_option = 'EXCEPT USER'
),
-- Transitive role closure: every role a grantee holds, at any depth.
role_closure AS (
    SELECT DISTINCT
           UPPER(CONNECT_BY_ROOT grantee) AS grantee,
           UPPER(granted_role)            AS granted_role
    FROM   dba_role_privs
    CONNECT BY NOCYCLE PRIOR UPPER(granted_role) = UPPER(grantee)
),
-- Roles reachable by every user because they are granted to PUBLIC.
public_roles AS (
    SELECT granted_role
    FROM   role_closure
    WHERE  grantee = 'PUBLIC'
),
-- Principals under review: database user accounts (roles are coverage
-- vehicles here, not subjects - see 21-uncovered-users.sql for roles).
principals AS (
    SELECT username         AS principal,
           oracle_maintained,
           account_status
    FROM   dba_users
),
-- Coverage path 1: named directly in the policy
cov_direct AS (
    SELECT pr.principal, b.policy_name, b.oracle_supplied,
           'DIRECT' AS cover_path, CAST(NULL AS VARCHAR2(128)) AS via_role
    FROM   principals pr
    JOIN   by_user b ON b.entity_name = UPPER(pr.principal)
),
-- Coverage path 2: holds a role the policy is enabled for
cov_role AS (
    SELECT pr.principal, r.policy_name, r.oracle_supplied,
           'ROLE' AS cover_path, r.role_name AS via_role
    FROM   principals pr
    JOIN   role_closure rc ON rc.grantee     = UPPER(pr.principal)
    JOIN   by_role      r  ON r.role_name    = rc.granted_role
    UNION
    SELECT pr.principal, r.policy_name, r.oracle_supplied,
           'ROLE' AS cover_path, r.role_name AS via_role
    FROM   principals pr
    CROSS  JOIN by_role r
    WHERE  r.role_name IN (SELECT granted_role FROM public_roles)
),
-- Coverage path 3: unrestricted policy, unless this user is excepted from it
cov_all AS (
    SELECT pr.principal, u.policy_name, u.oracle_supplied,
           'ALL_USERS' AS cover_path, CAST(NULL AS VARCHAR2(128)) AS via_role
    FROM   principals pr
    CROSS  JOIN universal u
    WHERE  NOT EXISTS (
               SELECT 1 FROM excepted e
               WHERE  e.policy_name = u.policy_name
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
-- One aggregated row per principal. has_* flags count customer-controlled
-- policies only; Oracle-supplied coverage is tracked separately in has_ora.
agg AS (
    SELECT c.principal,
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
    GROUP  BY c.principal
),
-- Customer-controlled policies this principal is explicitly excepted from
exc AS (
    SELECT pr.principal,
           LISTAGG(DISTINCT e.policy_name, ',')
               WITHIN GROUP (ORDER BY e.policy_name) AS excepted_policies
    FROM   principals pr
    JOIN   excepted e ON e.entity_name = UPPER(pr.principal)
    WHERE  e.oracle_supplied = 'NO'
    GROUP  BY pr.principal
),
final AS (
    SELECT
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
    LEFT   JOIN agg a ON a.principal = pr.principal
    LEFT   JOIN exc x ON x.principal = pr.principal
)
SELECT
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
