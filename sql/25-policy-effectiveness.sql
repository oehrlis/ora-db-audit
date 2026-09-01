-- SPDX-License-Identifier: Apache-2.0
-- -----------------------------------------------------------------------------
-- OraDBA - Oracle Database Infrastructure and Security, 5630 Muri, Switzerland
-- -----------------------------------------------------------------------------
-- Name......: 25-policy-effectiveness.sql
-- Author....: Stefan Oehrli (oes) stefan.oehrli@oradba.ch
-- Date......: 2026.09.01
-- Revision..: 0.1.0
-- Purpose...: Policy effectiveness, PDB scope (dba_* views, current container).
--             The reverse view of the blind-spot report: instead of asking
--             "is this user audited", it asks "does this enabled policy
--             actually reach anybody".
--
-- Scope.....: Current container only. Run in a PDB or in a Non-CDB. When run
--             in CDB$ROOT it reports the root container.
--             For a CDB-wide view use 26-policy-effectiveness-cdb.sql.
--
-- Why.......: A policy can be enabled, appear correct in
--             AUDIT_UNIFIED_ENABLED_POLICIES, and audit nothing at all:
--
--               BY USER <name>         where <name> was never created,
--                                      renamed, or has been dropped
--               BY GRANTED ROLE <role> where <role> exists but has no
--                                      grantees
--               BY GRANTED ROLE <role> where <role> does not exist
--               EXCEPT USER <name>     where <name> does not exist - a dead
--                                      exclusion, harmless but a drift marker
--
--             The blind-spot report (23/24) cannot surface this: it walks
--             users and reports the ones nobody covers. A policy pointing at
--             a non-existent principal simply contributes no coverage, and
--             looks identical to a policy that was never meant to cover
--             those users. This query closes that gap.
--
-- Grain.....: One row per policy x enabled_option x entity_name - exactly
--             the grain of AUDIT_UNIFIED_ENABLED_POLICIES. A single policy
--             routinely has several rows: enabling one policy
--             BY GRANTED ROLE <role> and additionally BY USER SYS is the
--             recommended pattern for privileged-activity policies, so
--             "the scope of a policy" is not a single value.
--
-- Verdict...: OK                - entity resolves and reaches >= 1 user
--             ENTITY_MISSING    - the named user or role does not exist
--             ROLE_NO_GRANTEES  - role exists, but no user holds it
--                                 (transitively, PUBLIC included)
--             EXCLUSION_DEAD    - EXCEPT USER naming a non-existent user
--             EXCLUSION         - EXCEPT USER, entity exists (informational)
--             ALL_USERS         - unrestricted enablement (no entity to
--                                 resolve); users_covered = all accounts
--
--             ENTITY_MISSING and ROLE_NO_GRANTEES are findings. Everything
--             else is context.
--
-- Notes.....: Unlike 23/24 this query deliberately does NOT filter out
--             logon-only policies. Whether an enablement resolves is
--             independent of which actions the policy audits, and a dead
--             LOGON policy is just as broken as a dead DDL policy.
--             Oracle-supplied policies are reported too, flagged via
--             oracle_supplied, so the report can restrict to the customer
--             configuration without losing the Oracle baseline view.
--             users_covered resolves role chains transitively (CONNECT BY)
--             and counts roles granted to PUBLIC for every user.
-- License...: Apache License Version 2.0
-- -----------------------------------------------------------------------------

SPOOL &LOGDIR./25_policy_effectiveness.csv

PROMPT # query: policy_effectiveness
PROMPT # query_id: 25
PROMPT # dbsid: &DBSID
PROMPT # pdb: &PDB_NAME
PROMPT # generated: &GENERATED_ISO
PROMPT # cis_controls: 5.1,5.2
PROMPT # schema: policy_name=KEEP|oracle_supplied=KEEP|enabled_option=KEEP|entity_name=PSEUDO:DBUSER|entity_type=KEEP|entity_resolves=KEEP|users_covered=COUNT|verdict=KEEP

SET MARKUP CSV ON DELIMITER '|' QUOTE OFF

WITH
-- Enablement rows as Oracle stores them: one per policy x option x entity.
enabled AS (
    SELECT DISTINCT
           e.policy_name,
           UPPER(e.enabled_option) AS enabled_option,
           UPPER(e.entity_name)    AS entity_name,
           UPPER(e.entity_type)    AS entity_type
    FROM   audit_unified_enabled_policies e
),
-- oracle_supplied is a policy attribute, not an enablement attribute. The
-- policy view has one row per audit_option, hence the aggregation.
pol AS (
    SELECT policy_name,
           MAX(oracle_supplied) AS oracle_supplied
    FROM   audit_unified_policies
    GROUP  BY policy_name
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
users AS (
    SELECT UPPER(username) AS username FROM dba_users
),
roles AS (
    SELECT UPPER(role) AS role FROM dba_roles
),
user_total AS (
    SELECT COUNT(*) AS cnt FROM users
),
-- Per role: how many actual user accounts hold it.
role_grantees AS (
    SELECT rc.granted_role AS role_name,
           COUNT(DISTINCT u.username) AS user_cnt
    FROM   role_closure rc
    JOIN   users u ON u.username = rc.grantee
    GROUP  BY rc.granted_role
),
resolved AS (
    SELECT
        e.policy_name,
        NVL(p.oracle_supplied, 'NO') AS oracle_supplied,
        e.enabled_option,
        e.entity_name,
        e.entity_type,
        -- Does the named principal exist at all?
        CASE
            WHEN e.entity_name = 'ALL USERS' THEN 'NA'
            WHEN e.entity_type = 'ROLE' THEN
                CASE WHEN EXISTS (SELECT 1 FROM roles r
                                  WHERE r.role = e.entity_name)
                     THEN 'Y' ELSE 'N' END
            ELSE
                CASE WHEN EXISTS (SELECT 1 FROM users u
                                  WHERE u.username = e.entity_name)
                     THEN 'Y' ELSE 'N' END
        END AS entity_resolves,
        -- How many user accounts this single enablement row reaches.
        CASE
            WHEN e.entity_name = 'ALL USERS'
                 THEN (SELECT cnt FROM user_total)
            WHEN e.entity_type = 'ROLE' THEN
                CASE
                    WHEN e.entity_name IN (SELECT granted_role
                                           FROM public_roles)
                         THEN (SELECT cnt FROM user_total)
                    ELSE NVL((SELECT rg.user_cnt FROM role_grantees rg
                              WHERE rg.role_name = e.entity_name), 0)
                END
            ELSE
                CASE WHEN EXISTS (SELECT 1 FROM users u
                                  WHERE u.username = e.entity_name)
                     THEN 1 ELSE 0 END
        END AS users_covered
    FROM   enabled e
    LEFT   JOIN pol p ON p.policy_name = e.policy_name
)
SELECT
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
    -- Findings first, then context.
    CASE
        WHEN entity_resolves = 'N' AND enabled_option <> 'EXCEPT USER' THEN 1
        WHEN entity_type = 'ROLE' AND users_covered = 0
             AND entity_name <> 'ALL USERS'                            THEN 2
        WHEN entity_resolves = 'N'                                     THEN 3
        ELSE                                                                4
    END,
    oracle_supplied,
    policy_name,
    enabled_option,
    entity_name;

SET MARKUP CSV OFF
SPOOL OFF
