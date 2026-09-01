-- SPDX-License-Identifier: Apache-2.0
-- -----------------------------------------------------------------------------
-- OraDBA - Oracle Database Infrastructure and Security, 5630 Muri, Switzerland
-- -----------------------------------------------------------------------------
-- Name......: 26-policy-effectiveness-cdb.sql
-- Author....: Stefan Oehrli (oes) stefan.oehrli@oradba.ch
-- Date......: 2026.09.01
-- Revision..: 0.1.0
-- Purpose...: Policy effectiveness, CDB scope (all open containers).
--             The reverse view of the blind-spot report: instead of asking
--             "is this user audited", it asks "does this enabled policy
--             actually reach anybody".
--
-- Scope.....: CDB$ROOT of a CDB. Not usable in a Non-CDB - use
--             25-policy-effectiveness.sql there. Run from a PDB it degrades
--             to that one container.
--
-- Why.......: See 25-policy-effectiveness.sql. The CDB case adds one failure
--             mode that the PDB view cannot see: a common policy created in
--             CDB$ROOT and enabled BY GRANTED ROLE, where the role has
--             grantees in some PDBs and none in others. The same policy is
--             then effective in one container and dead in the next.
--
-- Grain.....: One row per container x policy x enabled_option x entity_name.
--
-- Verdict...: OK               - entity resolves and reaches >= 1 user
--             ENTITY_MISSING   - the named user or role does not exist
--             ROLE_NO_GRANTEES - role exists, but no user holds it
--                                (transitively, PUBLIC included)
--             EXCLUSION_DEAD   - EXCEPT USER naming a non-existent user
--             EXCLUSION        - EXCEPT USER, entity exists (informational)
--             ALL_USERS        - unrestricted enablement
--
-- CDB notes.: Oracle provides no CDB_AUDIT_UNIFIED_* views - the Unified
--             Audit catalog views carry no DBA_/CDB_ prefix and are always
--             container-local, so the CDB-wide view is built with
--             CONTAINERS(). The user and role side uses the real catalog
--             views CDB_USERS / CDB_ROLES / CDB_ROLE_PRIVS / CDB_PDBS,
--             joined back on CON_ID.
--             CONTAINERS() returns OPEN containers only; a MOUNTED PDB is
--             silently absent. Cross-check V$PDBS before concluding a
--             container is clean.
--
-- Notes.....: Unlike 23/24 this query deliberately does NOT filter out
--             logon-only policies - whether an enablement resolves is
--             independent of which actions the policy audits.
-- License...: Apache License Version 2.0
-- -----------------------------------------------------------------------------

SPOOL &LOGDIR./26_policy_effectiveness_cdb.csv

PROMPT # query: policy_effectiveness_cdb
PROMPT # query_id: 26
PROMPT # dbsid: &DBSID
PROMPT # pdb: &PDB_NAME
PROMPT # generated: &GENERATED_ISO
PROMPT # cis_controls: 5.1,5.2
PROMPT # cdb: &IS_CDB
PROMPT # con_name: &PDB_NAME
PROMPT # schema: con_id=KEEP|pdb_name=PSEUDO:PDB|policy_name=KEEP|oracle_supplied=KEEP|enabled_option=KEEP|entity_name=PSEUDO:DBUSER|entity_type=KEEP|entity_resolves=KEEP|users_covered=COUNT|verdict=KEEP

SET MARKUP CSV ON DELIMITER '|' QUOTE OFF

WITH
-- Container name lookup - CDB$ROOT is con_id 1 and not in cdb_pdbs.
containers_map AS (
    SELECT 1 AS con_id, 'CDB$ROOT' AS pdb_name FROM dual
    UNION ALL
    SELECT con_id, pdb_name FROM cdb_pdbs
),
-- Enablement rows as Oracle stores them, per container.
enabled AS (
    SELECT DISTINCT
           e.con_id,
           e.policy_name,
           UPPER(e.enabled_option) AS enabled_option,
           UPPER(e.entity_name)    AS entity_name,
           UPPER(e.entity_type)    AS entity_type
    FROM   containers(audit_unified_enabled_policies) e
),
-- oracle_supplied is a policy attribute, not an enablement attribute.
pol AS (
    SELECT con_id,
           policy_name,
           MAX(oracle_supplied) AS oracle_supplied
    FROM   containers(audit_unified_policies)
    GROUP  BY con_id, policy_name
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
users AS (
    SELECT con_id, UPPER(username) AS username FROM cdb_users
),
roles AS (
    SELECT con_id, UPPER(role) AS role FROM cdb_roles
),
user_total AS (
    SELECT con_id, COUNT(*) AS cnt FROM users GROUP BY con_id
),
-- Per container and role: how many actual user accounts hold it.
role_grantees AS (
    SELECT rc.con_id,
           rc.granted_role AS role_name,
           COUNT(DISTINCT u.username) AS user_cnt
    FROM   role_closure rc
    JOIN   users u ON u.username = rc.grantee
                  AND u.con_id   = rc.con_id
    GROUP  BY rc.con_id, rc.granted_role
),
resolved AS (
    SELECT
        e.con_id,
        NVL(cm.pdb_name, 'CON_' || e.con_id) AS pdb_name,
        e.policy_name,
        NVL(p.oracle_supplied, 'NO') AS oracle_supplied,
        e.enabled_option,
        e.entity_name,
        e.entity_type,
        CASE
            WHEN e.entity_name = 'ALL USERS' THEN 'NA'
            WHEN e.entity_type = 'ROLE' THEN
                CASE WHEN EXISTS (SELECT 1 FROM roles r
                                  WHERE r.role   = e.entity_name
                                  AND   r.con_id = e.con_id)
                     THEN 'Y' ELSE 'N' END
            ELSE
                CASE WHEN EXISTS (SELECT 1 FROM users u
                                  WHERE u.username = e.entity_name
                                  AND   u.con_id   = e.con_id)
                     THEN 'Y' ELSE 'N' END
        END AS entity_resolves,
        CASE
            WHEN e.entity_name = 'ALL USERS'
                 THEN NVL((SELECT ut.cnt FROM user_total ut
                           WHERE ut.con_id = e.con_id), 0)
            WHEN e.entity_type = 'ROLE' THEN
                CASE
                    WHEN EXISTS (SELECT 1 FROM public_roles pu
                                 WHERE pu.con_id       = e.con_id
                                 AND   pu.granted_role = e.entity_name)
                         THEN NVL((SELECT ut.cnt FROM user_total ut
                                   WHERE ut.con_id = e.con_id), 0)
                    ELSE NVL((SELECT rg.user_cnt FROM role_grantees rg
                              WHERE rg.role_name = e.entity_name
                              AND   rg.con_id    = e.con_id), 0)
                END
            ELSE
                CASE WHEN EXISTS (SELECT 1 FROM users u
                                  WHERE u.username = e.entity_name
                                  AND   u.con_id   = e.con_id)
                     THEN 1 ELSE 0 END
        END AS users_covered
    FROM   enabled e
    LEFT   JOIN containers_map cm ON cm.con_id = e.con_id
    LEFT   JOIN pol p ON p.policy_name = e.policy_name
                     AND p.con_id      = e.con_id
)
SELECT
    con_id,
    pdb_name,
    policy_name,
    oracle_supplied,
    enabled_option     AS "enabled_option",
    entity_name,
    entity_type,
    entity_resolves    AS "entity_resolves",
    users_covered      AS "users_covered",
    CASE
        WHEN entity_name = 'ALL USERS'                    THEN 'ALL_USERS'
        WHEN enabled_option = 'EXCEPT USER'
             AND entity_resolves = 'N'                    THEN 'EXCLUSION_DEAD'
        WHEN enabled_option = 'EXCEPT USER'               THEN 'EXCLUSION'
        WHEN entity_resolves = 'N'                        THEN 'ENTITY_MISSING'
        WHEN entity_type = 'ROLE' AND users_covered = 0   THEN 'ROLE_NO_GRANTEES'
        WHEN users_covered = 0                            THEN 'NO_USERS'
        ELSE                                                   'OK'
    END                AS "verdict"
FROM   resolved
ORDER  BY
    CASE
        WHEN entity_resolves = 'N' AND enabled_option <> 'EXCEPT USER' THEN 1
        WHEN entity_type = 'ROLE' AND users_covered = 0
             AND entity_name <> 'ALL USERS'                            THEN 2
        WHEN entity_resolves = 'N'                                     THEN 3
        ELSE                                                                4
    END,
    con_id,
    oracle_supplied,
    policy_name,
    enabled_option,
    entity_name;

SET MARKUP CSV OFF
SPOOL OFF
