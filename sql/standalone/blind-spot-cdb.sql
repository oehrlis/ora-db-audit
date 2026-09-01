-- SPDX-License-Identifier: Apache-2.0
-- -----------------------------------------------------------------------------
-- OraDBA - Oracle Database Infrastructure and Security, 5630 Muri, Switzerland
-- -----------------------------------------------------------------------------
-- Name......: blind-spot-cdb.sql
-- Author....: Stefan Oehrli (oes) stefan.oehrli@oradba.ch
-- Date......: 2026.09.01
-- Revision..: 0.2.0
-- Purpose...: Unified Audit blind-spot SUMMARY, CDB scope (all open
--             containers). Standalone - no tool, no setup, no spool file.
--             Copy the whole file into SQL*Plus or SQL Developer (run as
--             script, F5) and read the result on screen.
--
--             This is a condensed roll-up, NOT a row-per-user listing. The
--             per-user form expands to users x containers and is unreadable
--             on screen; it lives in sql/24-blind-spot-cdb.sql and feeds the
--             reporting pipeline.
--
-- Output....: A  Scorecard        - the verdict in a handful of lines
--             F  Container matrix - one line per open container
--             B  Coverage matrix  - account class x login state x coverage
--             C  Blind spots      - only accounts that need a decision
--             D  Blind-spot groups - actionable blind spots collapsed by
--                name pattern, with the number of containers each pattern
--                appears in
--             E  Policy effectiveness - enabled policies that reach nobody,
--                per container
--
-- Run as....: SYSDBA, or a COMMON user with SELECT on the data dictionary
--             (SELECT ANY DICTIONARY / SELECT_CATALOG_ROLE). Read-only -
--             no objects are created. A local PDB user cannot use
--             CONTAINERS() or the CDB_* views.
-- Run where.: In CDB$ROOT of a CDB. Not usable in a Non-CDB - use
--             blind-spot-pdb.sql there. Run from a PDB it degrades to that
--             one container.
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
-- Derived classification (identical to sql/24-blind-spot-cdb.sql, so the
-- numbers here match the generated report section 7.4):
--   account_class  ORACLE / CUSTOMER (from oracle_maintained)
--   login_enabled  N when account_status contains LOCKED
--   actionable     Y = BLIND_SPOT on a customer account that can still log
--                  in. That subset is the finding; locked and
--                  Oracle-maintained blind spots are housekeeping.
--
-- Important.: coverage_status counts customer-controlled policies only
--             (oracle_supplied = 'NO'). Oracle ships ORA_SECURECONFIG enabled
--             BY ALL USERS on virtually every database - counting it would
--             mark every user as covered and make the report meaningless.
--             Oracle-supplied coverage is still reported, in the column OCOV.
--
-- CDB notes.: Oracle does NOT provide CDB_AUDIT_UNIFIED_POLICIES or
--             CDB_AUDIT_UNIFIED_ENABLED_POLICIES. The Unified Audit catalog
--             views exist without a DBA_/CDB_ prefix and are always
--             container-local. The CDB-wide view is therefore built with the
--             CONTAINERS() clause, which fans the local view out over all
--             OPEN containers and adds CON_ID. The user and role side does
--             have real catalog views and uses CDB_USERS / CDB_ROLE_PRIVS /
--             CDB_PDBS, joined back on CON_ID.
--
--             CONTAINERS() returns OPEN containers only. A PDB in MOUNTED
--             state is silently absent - block F therefore prints the count
--             of non-open containers from CDB_PDBS so the omission is
--             visible instead of implied.
--
--             Common users appear once per container; that is intentional -
--             their policy assignment can differ per PDB.
--
-- Note......: Only policies with at least one non-logon action are counted.
--             LOGON/LOGOFF/SESSION* alone is session accounting, not
--             activity auditing.
-- License...: Apache License Version 2.0
-- -----------------------------------------------------------------------------

-- --- Report controls --------------------------------------------------------
-- bs_scope     which blind spots are listed in block C:
--                ACTIONABLE  customer accounts that can still log in (default)
--                CUSTOMER    every customer-account blind spot, incl. locked
--                ALL         every blind spot, incl. Oracle-maintained
-- bs_max_rows  hard cap on listed rows. Suppressed rows are always reported
--              with their count - a silent cut-off would hide findings.
-- grp_min      minimum members before a name pattern is reported as a group
--              in block D. 0 disables block D entirely.
DEFINE bs_scope    = ACTIONABLE
DEFINE bs_max_rows = 25
DEFINE grp_min     = 3

SET SERVEROUTPUT ON SIZE UNLIMITED FORMAT WRAPPED
SET LINESIZE 200
SET PAGESIZE 0
SET FEEDBACK OFF
SET VERIFY OFF
-- SQL*Plus defaults to TAB ON, which replaces runs of spaces in the output
-- with tab characters. That silently destroys the column alignment of every
-- table below, depending on the terminal tab stop. Must be OFF.
SET TAB OFF

DECLARE
    k_scope    CONSTANT VARCHAR2(20)  := UPPER('&bs_scope');
    k_max_rows CONSTANT PLS_INTEGER   := &bs_max_rows;
    k_w        CONSTANT PLS_INTEGER   := 78;

    TYPE t_rec IS RECORD (
        con_id             NUMBER,
        pdb_name           VARCHAR2(128),
        principal          VARCHAR2(128),
        account_status     VARCHAR2(32),
        coverage_status    VARCHAR2(20),
        account_class      VARCHAR2(10),
        login_enabled      VARCHAR2(1),
        actionable         VARCHAR2(1),
        ora_supplied_cover VARCHAR2(3)
    );
    TYPE t_tab IS TABLE OF t_rec;
    l_rows t_tab;

    -- Coverage matrix accumulator, keyed 'CLASS|LOGIN'
    TYPE t_cnt IS TABLE OF PLS_INTEGER INDEX BY VARCHAR2(32);
    m_total  t_cnt;
    m_direct t_cnt;
    m_role   t_cnt;
    m_all    t_cnt;
    m_exc    t_cnt;
    m_blind  t_cnt;

    -- Container matrix accumulator, keyed by CON_ID as string
    TYPE t_nm IS TABLE OF VARCHAR2(128) INDEX BY VARCHAR2(32);
    c_label  t_nm;
    c_users  t_cnt;
    c_cov    t_cnt;
    c_exc    t_cnt;
    c_blind  t_cnt;
    c_act    t_cnt;
    c_pol    t_cnt;

    l_users     PLS_INTEGER := 0;
    l_cust      PLS_INTEGER := 0;
    l_ora       PLS_INTEGER := 0;
    l_cust_cov  PLS_INTEGER := 0;
    l_except    PLS_INTEGER := 0;
    l_blind     PLS_INTEGER := 0;
    l_action    PLS_INTEGER := 0;
    l_listed    PLS_INTEGER := 0;
    l_matched   PLS_INTEGER := 0;
    l_cons      PLS_INTEGER := 0;
    l_notopen   PLS_INTEGER := 0;
    l_pct       VARCHAR2(10);
    l_key       VARCHAR2(32);

    -- Block D: name-pattern grouping over the actionable subset
    k_grp_min  CONSTANT PLS_INTEGER := &grp_min;
    d_count    t_cnt;    -- pattern -> members
    d_example  t_nm;     -- pattern -> first member seen
    d_pdbs     t_nm;     -- pattern -> ',con_id,con_id,' of containers seen
    l_dkey     VARCHAR2(200);
    l_dgrp     PLS_INTEGER := 0;
    l_dsingle  PLS_INTEGER := 0;

    -- Block E: policy effectiveness
    l_e_rows    PLS_INTEGER := 0;
    l_e_find    PLS_INTEGER := 0;

    PROCEDURE p (i_txt IN VARCHAR2 DEFAULT NULL) IS
    BEGIN
        dbms_output.put_line(NVL(i_txt, ''));
    END p;

    PROCEDURE hr IS
    BEGIN
        p(RPAD('-', k_w, '-'));
    END hr;

    -- Bump one cell. Associative arrays have no default, so every read has
    -- to tolerate a missing key.
    PROCEDURE bump (io_arr IN OUT t_cnt, i_key IN VARCHAR2) IS
    BEGIN
        IF io_arr.EXISTS(i_key) THEN
            io_arr(i_key) := io_arr(i_key) + 1;
        ELSE
            io_arr(i_key) := 1;
        END IF;
    END bump;

    FUNCTION cell (i_arr IN t_cnt, i_key IN VARCHAR2) RETURN PLS_INTEGER IS
    BEGIN
        RETURN CASE WHEN i_arr.EXISTS(i_key) THEN i_arr(i_key) ELSE 0 END;
    END cell;

    -- Pad a value to a fixed column width, truncating so that at least two
    -- spaces of separator always survive. Oracle identifiers go up to 128
    -- characters and account_status up to 30 (the combined expired-plus-locked
    -- forms), so a bare RPAD silently welds neighbouring columns together.
    -- Note: no literal ampersand anywhere in this file outside the DEFINEs -
    -- SQL*Plus substitutes it even inside comments and would prompt for input.
    FUNCTION pad (i_txt IN VARCHAR2, i_w IN PLS_INTEGER) RETURN VARCHAR2 IS
    BEGIN
        RETURN RPAD(SUBSTR(NVL(i_txt, '-'), 1, i_w - 2), i_w);
    END pad;

    -- Collapse a principal to a name pattern: strip a trailing number
    -- (ISC_DEV_01 -> ISC_DEV_*). Deliberately conservative - a pattern that
    -- merges unrelated accounts would hide a single finding inside a group,
    -- which is the exact failure this block exists to avoid. Anything with no
    -- trailing digits, or a stem shorter than 4 characters, is left ungrouped.
    FUNCTION name_pattern (i_name IN VARCHAR2) RETURN VARCHAR2 IS
        l_stem VARCHAR2(128);
    BEGIN
        l_stem := REGEXP_REPLACE(i_name, '[0-9]+$', '');
        IF l_stem = i_name OR LENGTH(l_stem) < 4 THEN
            RETURN NULL;
        END IF;
        RETURN l_stem || '*';
    END name_pattern;

    -- Does this row belong in block C under the configured scope?
    FUNCTION in_scope (i_r IN t_rec) RETURN BOOLEAN IS
    BEGIN
        IF i_r.coverage_status <> 'BLIND_SPOT' THEN
            RETURN FALSE;
        END IF;
        RETURN CASE k_scope
                   WHEN 'ALL'      THEN TRUE
                   WHEN 'CUSTOMER' THEN i_r.account_class = 'CUSTOMER'
                   ELSE                 i_r.actionable = 'Y'
               END;
    END in_scope;

BEGIN
    -- ---------------------------------------------------------------------
    -- Containers that CONTAINERS() cannot see - report, never imply.
    -- ---------------------------------------------------------------------
    -- CDB_PDBS carries STATUS but no OPEN_MODE - the open state only
    -- exists in V$PDBS. A restricted audit account may not have SELECT on
    -- V$ views, so a failure here must not abort the report; -1 means
    -- "unknown", which is reported as such rather than silently as zero.
    BEGIN
        SELECT COUNT(*)
        INTO   l_notopen
        FROM   v$pdbs
        WHERE  open_mode = 'MOUNTED';
    EXCEPTION
        WHEN OTHERS THEN
            l_notopen := -1;
    END;

    -- ---------------------------------------------------------------------
    -- Enabled customer activity policies per container
    -- ---------------------------------------------------------------------
    FOR r IN (
        SELECT e.con_id,
               COUNT(DISTINCT e.policy_name) AS pol_cust
        FROM   containers(audit_unified_enabled_policies) e
        JOIN   containers(audit_unified_policies) p
               ON  p.policy_name = e.policy_name
               AND p.con_id      = e.con_id
        WHERE  p.oracle_supplied = 'NO'
        AND    UPPER(p.audit_option) NOT IN (
                   'LOGON', 'LOGOFF',
                   'SESSION REC', 'SESSION CON', 'SESSION EX'
               )
        GROUP  BY e.con_id
    ) LOOP
        c_pol(TO_CHAR(r.con_id)) := r.pol_cust;
    END LOOP;

    -- ---------------------------------------------------------------------
    -- Coverage classification - same logic as sql/24-blind-spot-cdb.sql
    -- ---------------------------------------------------------------------
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
               'DIRECT' AS cover_path
        FROM   principals pr
        JOIN   by_user b ON b.entity_name = UPPER(pr.principal)
                        AND b.con_id      = pr.con_id
    ),
    cov_role AS (
        SELECT pr.con_id, pr.principal, r.policy_name, r.oracle_supplied,
               'ROLE' AS cover_path
        FROM   principals pr
        JOIN   role_closure rc ON rc.grantee  = UPPER(pr.principal)
                              AND rc.con_id   = pr.con_id
        JOIN   by_role      r  ON r.role_name = rc.granted_role
                              AND r.con_id    = pr.con_id
        UNION
        SELECT pr.con_id, pr.principal, r.policy_name, r.oracle_supplied,
               'ROLE' AS cover_path
        FROM   principals pr
        JOIN   by_role r ON r.con_id = pr.con_id
        WHERE  EXISTS (
                   SELECT 1 FROM public_roles pu
                   WHERE  pu.con_id       = pr.con_id
                   AND    pu.granted_role = r.role_name
               )
    ),
    cov_all AS (
        SELECT pr.con_id, pr.principal, u.policy_name, u.oracle_supplied,
               'ALL_USERS' AS cover_path
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
               MAX(CASE WHEN c.oracle_supplied = 'NO'
                         AND c.cover_path = 'DIRECT'    THEN 1 ELSE 0 END) AS has_direct,
               MAX(CASE WHEN c.oracle_supplied = 'NO'
                         AND c.cover_path = 'ROLE'      THEN 1 ELSE 0 END) AS has_role,
               MAX(CASE WHEN c.oracle_supplied = 'NO'
                         AND c.cover_path = 'ALL_USERS' THEN 1 ELSE 0 END) AS has_all,
               MAX(CASE WHEN c.oracle_supplied = 'YES'  THEN 1 ELSE 0 END) AS has_ora
        FROM   coverage c
        GROUP  BY c.con_id, c.principal
    ),
    -- Principals excepted from a customer-controlled policy. Only the
    -- existence matters here - the policy names are in the CSV query.
    exc AS (
        SELECT DISTINCT pr.con_id, pr.principal
        FROM   principals pr
        JOIN   excepted e ON e.entity_name = UPPER(pr.principal)
                         AND e.con_id      = pr.con_id
        WHERE  e.oracle_supplied = 'NO'
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
            CASE WHEN NVL(a.has_ora, 0) = 1 THEN 'YES' ELSE 'NO' END AS ora_supplied_cover
        FROM   principals pr
        LEFT   JOIN containers_map cm ON cm.con_id = pr.con_id
        LEFT   JOIN agg a ON a.con_id = pr.con_id AND a.principal = pr.principal
        LEFT   JOIN exc x ON x.con_id = pr.con_id AND x.principal = pr.principal
    )
    SELECT f.con_id,
           f.pdb_name,
           f.principal,
           f.account_status,
           f.coverage_status,
           CASE WHEN f.oracle_maintained = 'Y' THEN 'ORACLE'
                ELSE 'CUSTOMER' END,
           CASE WHEN UPPER(f.account_status) LIKE '%LOCKED%' THEN 'N'
                ELSE 'Y' END,
           CASE WHEN f.coverage_status = 'BLIND_SPOT'
                 AND f.oracle_maintained = 'N'
                 AND UPPER(f.account_status) NOT LIKE '%LOCKED%'
                THEN 'Y' ELSE 'N' END,
           f.ora_supplied_cover
    BULK   COLLECT INTO l_rows
    FROM   final f
    ORDER  BY f.con_id, f.oracle_maintained, f.principal;

    -- ---------------------------------------------------------------------
    -- Aggregate in one pass
    -- ---------------------------------------------------------------------
    FOR i IN 1 .. l_rows.COUNT LOOP
        l_key := l_rows(i).account_class || '|' || l_rows(i).login_enabled;
        l_users := l_users + 1;
        bump(m_total, l_key);

        CASE l_rows(i).coverage_status
            WHEN 'COVERED_DIRECT'    THEN bump(m_direct, l_key);
            WHEN 'COVERED_VIA_ROLE'  THEN bump(m_role,   l_key);
            WHEN 'COVERED_ALL_USERS' THEN bump(m_all,    l_key);
            WHEN 'EXCLUDED_EXCEPT'   THEN bump(m_exc,    l_key);
            ELSE                          bump(m_blind,  l_key);
        END CASE;

        -- Per-container roll-up (block F)
        l_key := TO_CHAR(l_rows(i).con_id);
        c_label(l_key) := l_rows(i).pdb_name;
        bump(c_users, l_key);
        IF l_rows(i).coverage_status LIKE 'COVERED%' THEN
            bump(c_cov, l_key);
        ELSIF l_rows(i).coverage_status = 'EXCLUDED_EXCEPT' THEN
            bump(c_exc, l_key);
        ELSE
            bump(c_blind, l_key);
        END IF;
        IF l_rows(i).actionable = 'Y' THEN
            bump(c_act, l_key);
        END IF;

        IF l_rows(i).account_class = 'CUSTOMER' THEN
            l_cust := l_cust + 1;
            IF l_rows(i).coverage_status LIKE 'COVERED%' THEN
                l_cust_cov := l_cust_cov + 1;
            END IF;
        ELSE
            l_ora := l_ora + 1;
        END IF;

        IF l_rows(i).coverage_status = 'EXCLUDED_EXCEPT' THEN
            l_except := l_except + 1;
        ELSIF l_rows(i).coverage_status = 'BLIND_SPOT' THEN
            l_blind := l_blind + 1;
        END IF;

        IF l_rows(i).actionable = 'Y' THEN
            l_action := l_action + 1;
        END IF;
    END LOOP;

    l_cons := c_users.COUNT;

    -- ---------------------------------------------------------------------
    -- Block A - scorecard
    -- ---------------------------------------------------------------------
    p;
    hr;
    p('UNIFIED AUDIT COVERAGE - CDB ' ||
      SYS_CONTEXT('USERENV', 'DB_NAME') ||
      ' - ' || TO_CHAR(SYSDATE, 'YYYY-MM-DD HH24:MI'));
    hr;

    l_pct := CASE WHEN l_cust = 0 THEN 'n/a'
                  ELSE TO_CHAR(ROUND(l_cust_cov * 100 / l_cust)) || '%' END;

    p('Containers analysed: ' || l_cons ||
      CASE WHEN l_notopen > 0
           THEN ' (' || l_notopen || ' MOUNTED - not visible to ' ||
                'CONTAINERS(), see block F)'
           WHEN l_notopen < 0
           THEN ' (MOUNTED containers not checked - no SELECT on V$PDBS)'
           ELSE '' END);
    p('User-container rows: ' || l_users || ' (' || l_cust ||
      ' customer, ' || l_ora || ' oracle-maintained)');
    p('Customer accounts covered by a customer policy: ' || l_cust_cov ||
      ' of ' || l_cust || ' (' || l_pct || ')');
    p('Deliberate exemptions (EXCLUDED_EXCEPT): ' || l_except);
    p('Blind spots: ' || l_blind || ' - thereof actionable: ' || l_action);
    p;
    p('A common user is counted once per container - its policy assignment');
    p('can differ per PDB, so the container is part of the identity here.');
    p;

    -- ---------------------------------------------------------------------
    -- Block F - container matrix
    -- ---------------------------------------------------------------------
    p('F) CONTAINER MATRIX (one line per open container)');
    p;
    p(RPAD('CON_ID', 8) || RPAD('CONTAINER', 22) || LPAD('POL', 5) ||
      LPAD('USERS', 7) || LPAD('COVERED', 9) || LPAD('EXCEPT', 8) ||
      LPAD('BLIND', 7) || LPAD('ACTIONABLE', 12));

    l_key := c_users.FIRST;
    WHILE l_key IS NOT NULL LOOP
        p(RPAD(l_key, 8) ||
          pad(c_label(l_key), 22) ||
          LPAD(cell(c_pol,   l_key), 5) ||
          LPAD(cell(c_users, l_key), 7) ||
          LPAD(cell(c_cov,   l_key), 9) ||
          LPAD(cell(c_exc,   l_key), 8) ||
          LPAD(cell(c_blind, l_key), 7) ||
          LPAD(cell(c_act,   l_key), 12));
        l_key := c_users.NEXT(l_key);
    END LOOP;
    p;
    p('POL = enabled customer activity policies in that container.');
    p('POL = 0 is the finding itself: nothing there can ever be covered.');

    IF l_notopen < 0 THEN
        p;
        p('!! Could not read V$PDBS (no SELECT privilege). A MOUNTED PDB is');
        p('!! invisible to CONTAINERS(), so this matrix may be incomplete.');
        p('!! Grant SELECT_CATALOG_ROLE, or check manually:');
        p('!!   SELECT con_id, name, open_mode FROM v$pdbs;');
    ELSIF l_notopen > 0 THEN
        p;
        p('!! ' || l_notopen || ' container(s) are MOUNTED and therefore');
        p('!! absent from this matrix - CONTAINERS() only returns OPEN');
        p('!! containers. Do not read their absence as "clean". List them:');
        p('!!   SELECT con_id, name, open_mode FROM v$pdbs');
        p('!!   WHERE open_mode = ''MOUNTED'';');
    END IF;
    p;

    -- ---------------------------------------------------------------------
    -- Block B - coverage matrix
    -- ---------------------------------------------------------------------
    p('B) COVERAGE MATRIX (best coverage path wins, columns are disjoint)');
    p;
    p(RPAD('CLASS', 10) || RPAD('LOGIN', 7) || LPAD('TOTAL', 7) ||
      LPAD('DIRECT', 8) || LPAD('ROLE', 6) || LPAD('ALL_USERS', 11) ||
      LPAD('EXCEPT', 8) || LPAD('BLIND', 7));

    FOR c IN (SELECT 'CUSTOMER' AS cls FROM dual
              UNION ALL
              SELECT 'ORACLE' FROM dual) LOOP
        FOR g IN (SELECT 'Y' AS le, 'yes' AS lbl FROM dual
                  UNION ALL
                  SELECT 'N', 'no' FROM dual) LOOP
            l_key := c.cls || '|' || g.le;
            IF cell(m_total, l_key) > 0 THEN
                p(RPAD(INITCAP(c.cls), 10) || RPAD(g.lbl, 7) ||
                  LPAD(cell(m_total,  l_key), 7) ||
                  LPAD(cell(m_direct, l_key), 8) ||
                  LPAD(cell(m_role,   l_key), 6) ||
                  LPAD(cell(m_all,    l_key), 11) ||
                  LPAD(cell(m_exc,    l_key), 8) ||
                  LPAD(cell(m_blind,  l_key), 7));
            END IF;
        END LOOP;
    END LOOP;
    p;
    p('LOGIN = can this account still log in (account_status not LOCKED).');
    p('A blind spot on a locked account is housekeeping, not exposure.');
    p;

    -- ---------------------------------------------------------------------
    -- Block C - blind spots in scope
    -- ---------------------------------------------------------------------
    p('C) BLIND SPOTS - scope ' || k_scope ||
      CASE k_scope
          WHEN 'ALL'      THEN ' (every blind spot)'
          WHEN 'CUSTOMER' THEN ' (all customer accounts, incl. locked)'
          ELSE                 ' (customer accounts that can still log in)'
      END);
    p;

    FOR i IN 1 .. l_rows.COUNT LOOP
        IF in_scope(l_rows(i)) THEN
            l_matched := l_matched + 1;
        END IF;
    END LOOP;

    IF l_matched = 0 THEN
        IF l_blind = 0 THEN
            p('None - every user is covered by at least one customer policy,');
            p('or is a deliberate EXCEPT exemption.');
        ELSE
            p('None in this scope. ' || l_blind || ' blind spot(s) exist ' ||
              'outside it (locked and/or oracle-maintained accounts).');
            p('Show them: DEFINE bs_scope = ALL  and re-run this script.');
        END IF;
        p;
    ELSE
        p(RPAD('CONTAINER', 22) || RPAD('PRINCIPAL', 32) ||
          RPAD('ACCOUNT_STATUS', 22) || RPAD('CLASS', 10) || 'OCOV');
        FOR i IN 1 .. l_rows.COUNT LOOP
            EXIT WHEN l_listed >= k_max_rows;
            IF in_scope(l_rows(i)) THEN
                l_listed := l_listed + 1;
                p(pad(l_rows(i).pdb_name, 22) ||
                  pad(l_rows(i).principal, 32) ||
                  pad(l_rows(i).account_status, 22) ||
                  pad(INITCAP(l_rows(i).account_class), 10) ||
                  l_rows(i).ora_supplied_cover);
            END IF;
        END LOOP;
        p;
        p('Listed ' || l_listed || ' of ' || l_matched || ' in scope.');

        -- Never cut off silently: name what was held back and how to get it.
        IF l_matched > l_listed THEN
            p((l_matched - l_listed) || ' further row(s) suppressed by ' ||
              'bs_max_rows = ' || k_max_rows || '.');
            p('Show them: DEFINE bs_max_rows = ' || (l_matched + 10) ||
              '  and re-run this script.');
        END IF;
        IF l_blind > l_matched THEN
            p((l_blind - l_matched) || ' further blind spot(s) outside ' ||
              'scope ' || k_scope || ' (locked and/or oracle-maintained).');
            p('Show them: DEFINE bs_scope = ALL  and re-run this script.');
        END IF;
        p;
        p('OCOV = an Oracle-supplied policy (e.g. ORA_SECURECONFIG) still');
        p('covers this user. It is not a substitute for a customer policy,');
        p('but it means dictionary and privilege events are not lost.');
        p;
    END IF;

    -- ---------------------------------------------------------------------
    -- Block D - actionable blind spots collapsed by name pattern
    -- ---------------------------------------------------------------------
    IF k_grp_min > 0 AND l_action > 0 THEN
        FOR i IN 1 .. l_rows.COUNT LOOP
            IF l_rows(i).actionable = 'Y' THEN
                l_dkey := name_pattern(l_rows(i).principal);
                IF l_dkey IS NULL THEN
                    l_dsingle := l_dsingle + 1;
                ELSE
                    bump(d_count, l_dkey);
                    IF NOT d_example.EXISTS(l_dkey) THEN
                        d_example(l_dkey) := l_rows(i).principal;
                        d_pdbs(l_dkey)    := ',';
                    END IF;
                    -- Distinct container list per pattern, kept as a delimited
                    -- string: an associative array cannot be counted by prefix.
                    IF INSTR(d_pdbs(l_dkey),
                             ',' || l_rows(i).con_id || ',') = 0 THEN
                        d_pdbs(l_dkey) := d_pdbs(l_dkey) ||
                                          l_rows(i).con_id || ',';
                    END IF;
                END IF;
            END IF;
        END LOOP;

        -- Patterns below the threshold are not a group - fold them back into
        -- the singleton count so the totals still add up to l_action.
        l_dkey := d_count.FIRST;
        WHILE l_dkey IS NOT NULL LOOP
            IF d_count(l_dkey) >= k_grp_min THEN
                l_dgrp := l_dgrp + 1;
            ELSE
                l_dsingle := l_dsingle + d_count(l_dkey);
            END IF;
            l_dkey := d_count.NEXT(l_dkey);
        END LOOP;

        IF l_dgrp > 0 THEN
            p('D) BLIND-SPOT GROUPS (actionable only, >= ' || k_grp_min ||
              ' members)');
            p;
            p(RPAD('PATTERN', 34) || LPAD('MEMBERS', 9) || LPAD('PDBS', 6) ||
              '  EXAMPLE');
            l_dkey := d_count.FIRST;
            WHILE l_dkey IS NOT NULL LOOP
                IF d_count(l_dkey) >= k_grp_min THEN
                    p(pad(l_dkey, 34) || LPAD(d_count(l_dkey), 9) ||
                      LPAD(LENGTH(d_pdbs(l_dkey)) -
                           LENGTH(REPLACE(d_pdbs(l_dkey), ',', '')) - 1, 6) ||
                      '  ' || d_example(l_dkey));
                END IF;
                l_dkey := d_count.NEXT(l_dkey);
            END LOOP;
            IF l_dsingle > 0 THEN
                p(RPAD('(ungrouped)', 34) || LPAD(l_dsingle, 9) ||
                  LPAD('-', 6) || '  -');
            END IF;
            p;
            p('PDBS = in how many containers this pattern appears. A pattern');
            p('spanning several containers is one finding with one remedy per');
            p('container. Members are listed individually in block C.');
            p;
        END IF;
    END IF;

    -- ---------------------------------------------------------------------
    -- Block E - policy effectiveness per container
    -- ---------------------------------------------------------------------
    p('E) POLICY EFFECTIVENESS (per container x policy x option x entity)');
    p;
    p(RPAD('CONTAINER', 18) || RPAD('POLICY', 30) || RPAD('OPTION', 17) ||
      RPAD('ENTITY', 22) || LPAD('USERS', 6) || '  VERDICT');

    FOR r IN (
        -- Same model as sql/26-policy-effectiveness-cdb.sql. Deliberately not
        -- restricted to non-logon policies: whether an enablement resolves is
        -- independent of which actions the policy audits.
        WITH cm AS (
            SELECT 1 AS con_id, 'CDB$ROOT' AS pdb_name FROM dual
            UNION ALL
            SELECT con_id, pdb_name FROM cdb_pdbs
        ),
        enabled AS (
            SELECT DISTINCT
                   e.con_id,
                   e.policy_name,
                   UPPER(e.enabled_option) AS enabled_option,
                   UPPER(e.entity_name)    AS entity_name,
                   UPPER(e.entity_type)    AS entity_type
            FROM   containers(audit_unified_enabled_policies) e
        ),
        pol AS (
            SELECT con_id, policy_name, MAX(oracle_supplied) AS oracle_supplied
            FROM   containers(audit_unified_policies)
            GROUP  BY con_id, policy_name
        ),
        rc AS (
            SELECT DISTINCT
                   con_id,
                   UPPER(CONNECT_BY_ROOT grantee) AS grantee,
                   UPPER(granted_role)            AS granted_role
            FROM   cdb_role_privs
            CONNECT BY NOCYCLE PRIOR UPPER(granted_role) = UPPER(grantee)
                       AND PRIOR con_id = con_id
        ),
        public_roles AS (
            SELECT con_id, granted_role FROM rc WHERE grantee = 'PUBLIC'
        ),
        u  AS (SELECT con_id, UPPER(username) AS username FROM cdb_users),
        ro AS (SELECT con_id, UPPER(role) AS role FROM cdb_roles),
        ut AS (SELECT con_id, COUNT(*) AS cnt FROM u GROUP BY con_id),
        rg AS (
            SELECT rc.con_id, rc.granted_role AS role_name,
                   COUNT(DISTINCT u.username) AS user_cnt
            FROM   rc JOIN u ON u.username = rc.grantee
                             AND u.con_id   = rc.con_id
            GROUP  BY rc.con_id, rc.granted_role
        ),
        resolved AS (
            SELECT e.con_id,
                   NVL(cmm.pdb_name, 'CON_' || e.con_id) AS pdb_name,
                   e.policy_name,
                   NVL(p.oracle_supplied, 'NO') AS oracle_supplied,
                   e.enabled_option,
                   e.entity_name,
                   e.entity_type,
                   CASE
                       WHEN e.entity_name = 'ALL USERS' THEN 'NA'
                       WHEN e.entity_type = 'ROLE' THEN
                           CASE WHEN EXISTS (SELECT 1 FROM ro
                                             WHERE ro.role   = e.entity_name
                                             AND   ro.con_id = e.con_id)
                                THEN 'Y' ELSE 'N' END
                       ELSE
                           CASE WHEN EXISTS (SELECT 1 FROM u
                                             WHERE u.username = e.entity_name
                                             AND   u.con_id   = e.con_id)
                                THEN 'Y' ELSE 'N' END
                   END AS entity_resolves,
                   CASE
                       WHEN e.entity_name = 'ALL USERS'
                            THEN NVL((SELECT ut.cnt FROM ut
                                      WHERE ut.con_id = e.con_id), 0)
                       WHEN e.entity_type = 'ROLE' THEN
                           CASE
                               WHEN EXISTS (SELECT 1 FROM public_roles pu
                                            WHERE pu.con_id       = e.con_id
                                            AND   pu.granted_role = e.entity_name)
                                    THEN NVL((SELECT ut.cnt FROM ut
                                              WHERE ut.con_id = e.con_id), 0)
                               ELSE NVL((SELECT rg.user_cnt FROM rg
                                         WHERE rg.role_name = e.entity_name
                                         AND   rg.con_id    = e.con_id), 0)
                           END
                       ELSE
                           CASE WHEN EXISTS (SELECT 1 FROM u
                                             WHERE u.username = e.entity_name
                                             AND   u.con_id   = e.con_id)
                                THEN 1 ELSE 0 END
                   END AS users_covered
            FROM   enabled e
            LEFT   JOIN cm cmm ON cmm.con_id = e.con_id
            LEFT   JOIN pol p  ON p.policy_name = e.policy_name
                              AND p.con_id      = e.con_id
        )
        SELECT con_id, pdb_name, policy_name, oracle_supplied, enabled_option,
               entity_name, entity_type, users_covered,
               CASE
                   WHEN entity_name = 'ALL USERS'                  THEN 'ALL_USERS'
                   WHEN enabled_option = 'EXCEPT USER'
                        AND entity_resolves = 'N'                  THEN 'EXCLUSION_DEAD'
                   WHEN enabled_option = 'EXCEPT USER'             THEN 'EXCLUSION'
                   WHEN entity_resolves = 'N'                      THEN 'ENTITY_MISSING'
                   WHEN entity_type = 'ROLE' AND users_covered = 0 THEN 'ROLE_NO_GRANTEES'
                   WHEN users_covered = 0                          THEN 'NO_USERS'
                   ELSE                                                 'OK'
               END AS verdict
        FROM   resolved
        ORDER  BY
            CASE
                WHEN entity_resolves = 'N'
                     AND enabled_option <> 'EXCEPT USER' THEN 1
                WHEN entity_type = 'ROLE' AND users_covered = 0
                     AND entity_name <> 'ALL USERS'      THEN 2
                WHEN entity_resolves = 'N'               THEN 3
                ELSE                                          4
            END,
            con_id, oracle_supplied, policy_name, enabled_option, entity_name
    ) LOOP
        l_e_rows := l_e_rows + 1;
        IF r.verdict IN ('ENTITY_MISSING', 'ROLE_NO_GRANTEES', 'NO_USERS') THEN
            l_e_find := l_e_find + 1;
        END IF;
        p(pad(r.pdb_name, 18) || pad(r.policy_name, 30) ||
          pad(r.enabled_option, 17) || pad(r.entity_name, 22) ||
          LPAD(r.users_covered, 6) || '  ' || r.verdict ||
          CASE WHEN r.oracle_supplied = 'YES' THEN ' (oracle)' ELSE '' END);
    END LOOP;

    p;
    IF l_e_find = 0 THEN
        p('All ' || l_e_rows || ' enablement row(s) resolve and reach at ' ||
          'least one account - no dead policy.');
    ELSE
        p('!! ' || l_e_find || ' of ' || l_e_rows || ' enablement row(s) ' ||
          'reach nobody.');
        p('!! ENTITY_MISSING   the named user or role does not exist');
        p('!! ROLE_NO_GRANTEES the role exists but no account holds it');
        p('!! Such a policy looks correctly configured and audits nothing.');
        p('!! In a CDB, check whether the same policy is healthy in another');
        p('!! container - that asymmetry is the usual root cause.');
    END IF;
    p('EXCLUSION_DEAD = an EXCEPT clause naming a non-existent user. Not a');
    p('coverage gap, but a marker that the policy has drifted from reality.');

    p;
    hr;
    p('Per-user detail:  sql/24-blind-spot-cdb.sql (CSV, one row per user)');
    p('Policy detail:    sql/26-policy-effectiveness-cdb.sql (CSV)');
    hr;
    p;
END;
/

SET FEEDBACK ON
SET PAGESIZE 200
SET TAB ON
