-- SPDX-License-Identifier: Apache-2.0
-- -----------------------------------------------------------------------------
-- OraDBA - Oracle Database Infrastructure and Security, 5630 Muri, Switzerland
-- -----------------------------------------------------------------------------
-- Name......: 23-blind-spot-pdb.sql
-- Author....: Stefan Oehrli (oes) stefan.oehrli@oradba.ch
-- Date......: 2026.08.13
-- Revision..: 0.1.0
-- Purpose...: Blind-spot report, PDB scope (dba_* views, current container).
--             Answers "who is audited and who is not" by cross-checking every
--             database user against the entity assignment of all currently
--             enabled Unified Audit policies.
--
-- Scope.....: Current container only. Run in a PDB or in a Non-CDB. When run
--             in CDB$ROOT it reports the root container.
--             For a CDB-wide view use 24-blind-spot-cdb.sql.
--
-- Model.....: All three Oracle entity assignment forms are evaluated:
--
--               BY USER (entity_name <> 'ALL USERS')
--                 -> direct assignment, coverage path DIRECT
--               BY USER (entity_name  = 'ALL USERS')
--                 -> policy covers every user, coverage path ALL_USERS
--               BY GRANTED ROLE
--                 -> user holding that role is covered, path ROLE
--                    Role chains are resolved transitively (CONNECT BY),
--                    roles granted to PUBLIC count for every user.
--               EXCEPT USER
--                 -> policy is implicitly enabled for all users minus the
--                    listed ones. Oracle does NOT emit an extra ALL USERS
--                    row for such policies, so EXCEPT rows are themselves
--                    treated as a universal enablement with an exclusion list.
--
--             Resulting coverage_status per user (best path wins):
--
--               COVERED_DIRECT    - named explicitly in >=1 enabled policy
--               COVERED_VIA_ROLE  - covered through a granted role
--               COVERED_ALL_USERS - covered by an unrestricted policy
--               EXCLUDED_EXCEPT   - not covered, and the only reason is an
--                                   EXCEPT clause -> deliberate exemption,
--                                   NOT an accidental gap
--               BLIND_SPOT        - not covered by any enabled policy
--
-- Notes.....: Only policies with at least one non-logon audit_option are
--             counted. LOGON/LOGOFF/SESSION REC/SESSION CON/SESSION EX alone
--             is session accounting, not activity auditing.
--             coverage_status is derived from customer-controlled policies
--             only (oracle_supplied = 'NO'). Oracle ships ORA_SECURECONFIG
--             enabled BY ALL USERS on virtually every database, so counting
--             Oracle-supplied policies towards coverage would mark every user
--             as covered and make the report meaningless.
--             Oracle-supplied coverage is not discarded - it is reported
--             separately in ora_supplied_cover, so a user flagged BLIND_SPOT
--             with ora_supplied_cover = YES is understood correctly: the
--             Oracle baseline still catches dictionary/privilege events, but
--             no customer policy audits this user.
--             This complements 21-uncovered-users.sql (open non-Oracle
--             accounts and roles, no EXCEPT handling, role depth 1).
-- License...: Apache License Version 2.0
-- -----------------------------------------------------------------------------

SPOOL &LOGDIR./23_blind_spot_pdb.csv

PROMPT # query: blind_spot_pdb
PROMPT # query_id: 23
PROMPT # dbsid: &DBSID
PROMPT # pdb: &PDB_NAME
PROMPT # generated: &GENERATED_ISO
PROMPT # cis_controls: 5.1,5.2
PROMPT # schema: principal=PSEUDO:DBUSER|oracle_maintained=KEEP|account_status=KEEP|coverage_status=KEEP|cover_paths=KEEP|policy_count=COUNT|ora_supplied_cover=KEEP|via_roles=KEEP|excepted_policies=KEEP|covering_policies=KEEP|account_class=KEEP|login_enabled=KEEP|actionable=KEEP

SET MARKUP CSV ON DELIMITER '|' QUOTE OFF

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
),
-- Derived classification, single source of truth for every roll-up
-- (standalone summary and tools/audit_report.py section 7.4):
--   account_class  ORACLE   = oracle_maintained 'Y' (Oracle-shipped schema)
--                  CUSTOMER = everything else
--   login_enabled  N = account_status contains LOCKED (cannot log in)
--                  Y = OPEN / EXPIRED / EXPIRED(GRACE) - login still possible
--   actionable     Y = BLIND_SPOT on a customer account that can still log in.
--                  This is the only subset that needs a decision; locked and
--                  Oracle-maintained blind spots are housekeeping, not risk.
enriched AS (
    SELECT f.*,
           CASE WHEN f.oracle_maintained = 'Y' THEN 'ORACLE'
                ELSE 'CUSTOMER' END AS account_class,
           CASE WHEN UPPER(f.account_status) LIKE '%LOCKED%' THEN 'N'
                ELSE 'Y' END        AS login_enabled,
           CASE WHEN f.coverage_status = 'BLIND_SPOT'
                 AND f.oracle_maintained = 'N'
                 AND UPPER(f.account_status) NOT LIKE '%LOCKED%'
                THEN 'Y' ELSE 'N' END AS actionable
    FROM   final f
)
SELECT
    principal,
    oracle_maintained,
    account_status,
    coverage_status    AS "coverage_status",
    cover_paths        AS "cover_paths",
    policy_count       AS "policy_count",
    ora_supplied_cover AS "ora_supplied_cover",
    via_roles          AS "via_roles",
    excepted_policies  AS "excepted_policies",
    covering_policies  AS "covering_policies",
    account_class      AS "account_class",
    login_enabled      AS "login_enabled",
    actionable         AS "actionable"
FROM   enriched
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

SET MARKUP CSV OFF
SPOOL OFF
