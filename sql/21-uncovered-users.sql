-- SPDX-License-Identifier: Apache-2.0
-- -----------------------------------------------------------------------------
-- OraDBA - Oracle Database Infrastructure and Security, 5630 Muri, Switzerland
-- -----------------------------------------------------------------------------
-- Name......: 21-uncovered-users.sql
-- Author....: Stefan Oehrli (oes) stefan.oehrli@oradba.ch
-- Date......: 2026.05.29
-- Revision..: 0.1.0
-- Purpose...: Identify DB users (accounts + roles) that are NOT covered by any
--             currently enabled non-logon audit policy. Three coverage tiers:
--
--             P1 (direct)  - user appears as BY USER entity in an enabled
--                            policy with at least one non-logon action.
--             P2 (role)    - user holds a role (via DBA_ROLE_PRIVS, depth=1)
--                            that appears as BY GRANTED ROLE entity in such a
--                            policy.
--             ALL_USERS    - at least one enabled non-logon policy has no user
--                            restriction (ALL USERS); when true every user is
--                            considered covered and the result set is empty.
--
-- Notes.....: "Non-logon policy" = policy with at least one audit_option that
--             is not LOGON, LOGOFF, SESSION REC, SESSION CON, or SESSION EX.
--             Oracle-supplied policies are excluded from coverage (they are
--             informational, not customer-controlled).
--             Role depth is 1 (direct grants only). Indirect chains (role
--             granted to role granted to user) are not traversed; verify with
--             SESSION_ROLES for specific users if needed.
--             Includes non-system user accounts AND roles (roles can be
--             subjects of BY GRANTED ROLE policies themselves and may have
--             no direct user grantees yet).
-- License...: Apache License Version 2.0
-- -----------------------------------------------------------------------------

SPOOL &LOGDIR./21_uncovered_users.csv

PROMPT # query: uncovered_users
PROMPT # query_id: 21
PROMPT # dbsid: &DBSID
PROMPT # pdb: &PDB_NAME
PROMPT # generated: &GENERATED_ISO
PROMPT # cis_controls: 5.1,5.2
PROMPT # schema: principal=PSEUDO:DBUSER|principal_type=KEEP|covered_direct=KEEP|covered_via_role=KEEP|covered_all_users=KEEP

SET MARKUP CSV ON DELIMITER '|' QUOTE OFF

WITH
-- Enabled custom policies that have at least one non-logon action
non_logon_policies AS (
    SELECT DISTINCT p.policy_name
    FROM   audit_unified_policies p
    JOIN   audit_unified_enabled_policies e
           ON  e.policy_name = p.policy_name
    WHERE  p.oracle_supplied = 'NO'
    AND    UPPER(p.audit_option) NOT IN (
               'LOGON', 'LOGOFF',
               'SESSION REC', 'SESSION CON', 'SESSION EX'
           )
),
-- Flag: at least one non-logon policy covers ALL USERS (no entity restriction)
all_users_flag AS (
    SELECT COUNT(*) AS cnt
    FROM   audit_unified_enabled_policies e
    JOIN   non_logon_policies nlp ON nlp.policy_name = e.policy_name
    WHERE  (e.entity_name IS NULL OR e.entity_name = '')
    AND    (e.entity_type IS NULL OR e.entity_type = '')
),
-- Directly covered users (BY USER binding)
direct_covered AS (
    SELECT DISTINCT UPPER(e.entity_name) AS principal
    FROM   audit_unified_enabled_policies e
    JOIN   non_logon_policies nlp ON nlp.policy_name = e.policy_name
    WHERE  UPPER(e.entity_type) = 'USER'
    AND    e.entity_name IS NOT NULL
),
-- Role-covered users (BY GRANTED ROLE, depth=1 via DBA_ROLE_PRIVS)
role_covered AS (
    SELECT DISTINCT UPPER(r.grantee) AS principal
    FROM   audit_unified_enabled_policies e
    JOIN   non_logon_policies nlp ON nlp.policy_name = e.policy_name
    JOIN   dba_role_privs r ON UPPER(r.granted_role) = UPPER(e.entity_name)
    WHERE  UPPER(e.entity_type) = 'ROLE'
),
-- All non-system principals: open user accounts + DB roles
all_principals AS (
    SELECT username   AS principal, 'USER' AS principal_type
    FROM   dba_users
    WHERE  oracle_maintained = 'N'
    AND    account_status     = 'OPEN'
    UNION ALL
    SELECT role       AS principal, 'ROLE' AS principal_type
    FROM   dba_roles
    WHERE  oracle_maintained = 'N'
)
SELECT
    ap.principal,
    ap.principal_type,
    CASE WHEN dc.principal IS NOT NULL THEN 'YES' ELSE 'NO' END AS "covered_direct",
    CASE WHEN rc.principal IS NOT NULL THEN 'YES' ELSE 'NO' END AS "covered_via_role",
    CASE WHEN (SELECT cnt FROM all_users_flag) > 0 THEN 'YES' ELSE 'NO' END
                                                                 AS "covered_all_users"
FROM   all_principals ap
LEFT JOIN direct_covered dc ON dc.principal = UPPER(ap.principal)
LEFT JOIN role_covered   rc ON rc.principal = UPPER(ap.principal)
-- Only show uncovered principals when no ALL USERS policy is active
WHERE  (SELECT cnt FROM all_users_flag) = 0
AND    dc.principal IS NULL
AND    rc.principal IS NULL
ORDER BY ap.principal_type, ap.principal;

SET MARKUP CSV OFF
SPOOL OFF
