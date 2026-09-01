-- SPDX-License-Identifier: Apache-2.0
-- -----------------------------------------------------------------------------
-- OraDBA - Oracle Database Infrastructure and Security, 5630 Muri, Switzerland
-- -----------------------------------------------------------------------------
-- Name......: blind-spot-pdb.sql
-- Author....: Stefan Oehrli (oes) stefan.oehrli@oradba.ch
-- Date......: 2026.09.01
-- Revision..: 0.2.0
-- Purpose...: Unified Audit blind-spot SUMMARY, PDB scope (dba_* views,
--             current container). Standalone - no tool, no setup, no spool
--             file. Copy the whole file into SQL*Plus or SQL Developer (run
--             as script, F5) and read the result on screen.
--
--             This is a condensed roll-up, NOT a row-per-user listing. On a
--             database with a few hundred accounts the per-user form is
--             unreadable; the per-user CSV lives in sql/23-blind-spot-pdb.sql
--             and is meant for the reporting pipeline, not for the terminal.
--
-- Output....: A  Scorecard      - the verdict in a handful of lines
--             B  Coverage matrix - account class x login state x coverage
--             C  Blind spots     - only the accounts that need a decision
--             D  Blind-spot groups - actionable blind spots collapsed by
--                name pattern, so 40 numbered dev accounts read as one
--                finding with one remedy instead of 40 rows
--             E  Policy effectiveness - enabled policies that reach nobody.
--                The reverse view: C answers "who is unaudited", E answers
--                "which policy is silently doing nothing". A policy naming a
--                dropped user, or a role without grantees, looks correct in
--                AUDIT_UNIFIED_ENABLED_POLICIES and audits nothing.
--
-- Run as....: SYSDBA, or any account with SELECT on the data dictionary
--             (SELECT ANY DICTIONARY / SELECT_CATALOG_ROLE). Read-only -
--             no objects are created.
-- Run where.: In a PDB, or in a Non-CDB. When run in CDB$ROOT it reports the
--             root container only. For all containers of a CDB in one pass
--             use blind-spot-cdb.sql.
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
-- Derived classification (identical to sql/23-blind-spot-pdb.sql, so the
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
--             Oracle-supplied coverage is still reported, in the column
--             OCOV. A row with BLIND_SPOT + OCOV = YES means: the Oracle
--             baseline still catches dictionary and privilege events, but no
--             customer policy audits this user.
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

    -- Matrix accumulator, keyed 'CLASS|LOGIN'
    TYPE t_cnt IS TABLE OF PLS_INTEGER INDEX BY VARCHAR2(32);
    m_total  t_cnt;
    m_direct t_cnt;
    m_role   t_cnt;
    m_all    t_cnt;
    m_exc    t_cnt;
    m_blind  t_cnt;

    l_pol_cust  PLS_INTEGER := 0;
    l_pol_ora   PLS_INTEGER := 0;
    l_users     PLS_INTEGER := 0;
    l_cust      PLS_INTEGER := 0;
    l_ora       PLS_INTEGER := 0;
    l_cust_cov  PLS_INTEGER := 0;
    l_except    PLS_INTEGER := 0;
    l_blind     PLS_INTEGER := 0;
    l_action    PLS_INTEGER := 0;
    l_listed    PLS_INTEGER := 0;
    l_matched   PLS_INTEGER := 0;
    l_pct       VARCHAR2(10);

    -- Block D: name-pattern grouping over the actionable subset
    k_grp_min  CONSTANT PLS_INTEGER := &grp_min;
    TYPE t_nm IS TABLE OF VARCHAR2(128) INDEX BY VARCHAR2(200);
    d_count    t_cnt;    -- pattern -> members
    d_example  t_nm;     -- pattern -> first member seen
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

    -- Bump one matrix cell. Associative arrays have no default, so every
    -- read has to tolerate a missing key.
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
    -- (ISC_DEV_01 -> ISC_DEV_*) and, failing that, a trailing number inside
    -- the last underscore-separated token. Deliberately conservative - a
    -- pattern that merges unrelated accounts would hide a single finding
    -- inside a group, which is the exact failure this block exists to avoid.
    -- Anything with no digits, or a stem shorter than 4 characters, is left
    -- ungrouped and counted as a singleton.
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
    -- Enabled activity policies (non-logon actions only), customer vs Oracle
    -- ---------------------------------------------------------------------
    SELECT COUNT(DISTINCT CASE WHEN p.oracle_supplied = 'NO'
                               THEN e.policy_name END),
           COUNT(DISTINCT CASE WHEN p.oracle_supplied = 'YES'
                               THEN e.policy_name END)
    INTO   l_pol_cust, l_pol_ora
    FROM   audit_unified_enabled_policies e
    JOIN   audit_unified_policies p
           ON  p.policy_name = e.policy_name
    WHERE  UPPER(p.audit_option) NOT IN (
               'LOGON', 'LOGOFF',
               'SESSION REC', 'SESSION CON', 'SESSION EX'
           );

    -- ---------------------------------------------------------------------
    -- Coverage classification - same logic as sql/23-blind-spot-pdb.sql
    -- ---------------------------------------------------------------------
    WITH
    -- Enabled policies that audit real activity (>= 1 non-logon
    -- audit_option), flattened with their entity assignment rows.
    scope_pol AS (
        SELECT DISTINCT
               e.policy_name,
               UPPER(e.enabled_option) AS enabled_option,
               UPPER(e.entity_name)    AS entity_name,
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
    -- Policies applying to every user: explicit ALL USERS, plus every policy
    -- carrying an EXCEPT list (Oracle stores those without an ALL USERS row).
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
    -- Principals under review: database user accounts.
    principals AS (
        SELECT username AS principal,
               oracle_maintained,
               account_status
        FROM   dba_users
    ),
    -- Coverage path 1: named directly in the policy
    cov_direct AS (
        SELECT pr.principal, b.policy_name, b.oracle_supplied,
               'DIRECT' AS cover_path
        FROM   principals pr
        JOIN   by_user b ON b.entity_name = UPPER(pr.principal)
    ),
    -- Coverage path 2: holds a role the policy is enabled for
    cov_role AS (
        SELECT pr.principal, r.policy_name, r.oracle_supplied,
               'ROLE' AS cover_path
        FROM   principals pr
        JOIN   role_closure rc ON rc.grantee  = UPPER(pr.principal)
        JOIN   by_role      r  ON r.role_name = rc.granted_role
        UNION
        SELECT pr.principal, r.policy_name, r.oracle_supplied,
               'ROLE' AS cover_path
        FROM   principals pr
        CROSS  JOIN by_role r
        WHERE  r.role_name IN (SELECT granted_role FROM public_roles)
    ),
    -- Coverage path 3: unrestricted policy, unless excepted from it
    cov_all AS (
        SELECT pr.principal, u.policy_name, u.oracle_supplied,
               'ALL_USERS' AS cover_path
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
    -- One aggregated row per principal. has_* flags count
    -- customer-controlled policies only; Oracle coverage goes to has_ora.
    agg AS (
        SELECT c.principal,
               MAX(CASE WHEN c.oracle_supplied = 'NO'
                         AND c.cover_path = 'DIRECT'    THEN 1 ELSE 0 END) AS has_direct,
               MAX(CASE WHEN c.oracle_supplied = 'NO'
                         AND c.cover_path = 'ROLE'      THEN 1 ELSE 0 END) AS has_role,
               MAX(CASE WHEN c.oracle_supplied = 'NO'
                         AND c.cover_path = 'ALL_USERS' THEN 1 ELSE 0 END) AS has_all,
               MAX(CASE WHEN c.oracle_supplied = 'YES'  THEN 1 ELSE 0 END) AS has_ora
        FROM   coverage c
        GROUP  BY c.principal
    ),
    -- Principals excepted from a customer-controlled policy. Only the
    -- existence matters here - the policy names are in the CSV query.
    exc AS (
        SELECT DISTINCT pr.principal
        FROM   principals pr
        JOIN   excepted e ON e.entity_name = UPPER(pr.principal)
        WHERE  e.oracle_supplied = 'NO'
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
            CASE WHEN NVL(a.has_ora, 0) = 1 THEN 'YES' ELSE 'NO' END AS ora_supplied_cover
        FROM   principals pr
        LEFT   JOIN agg a ON a.principal = pr.principal
        LEFT   JOIN exc x ON x.principal = pr.principal
    )
    SELECT f.principal,
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
    ORDER  BY f.oracle_maintained, f.principal;

    -- ---------------------------------------------------------------------
    -- Aggregate in one pass
    -- ---------------------------------------------------------------------
    FOR i IN 1 .. l_rows.COUNT LOOP
        DECLARE
            l_key VARCHAR2(32) := l_rows(i).account_class || '|' ||
                                  l_rows(i).login_enabled;
        BEGIN
            l_users := l_users + 1;
            bump(m_total, l_key);

            CASE l_rows(i).coverage_status
                WHEN 'COVERED_DIRECT'    THEN bump(m_direct, l_key);
                WHEN 'COVERED_VIA_ROLE'  THEN bump(m_role,   l_key);
                WHEN 'COVERED_ALL_USERS' THEN bump(m_all,    l_key);
                WHEN 'EXCLUDED_EXCEPT'   THEN bump(m_exc,    l_key);
                ELSE                          bump(m_blind,  l_key);
            END CASE;

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
        END;
    END LOOP;

    -- ---------------------------------------------------------------------
    -- Block A - scorecard
    -- ---------------------------------------------------------------------
    p;
    hr;
    p('UNIFIED AUDIT COVERAGE - ' ||
      SYS_CONTEXT('USERENV', 'DB_NAME') || ' / ' ||
      SYS_CONTEXT('USERENV', 'CON_NAME') ||
      ' - ' || TO_CHAR(SYSDATE, 'YYYY-MM-DD HH24:MI'));
    hr;

    l_pct := CASE WHEN l_cust = 0 THEN 'n/a'
                  ELSE TO_CHAR(ROUND(l_cust_cov * 100 / l_cust)) || '%' END;

    p('Enabled activity policies: ' || l_pol_cust || ' customer, ' ||
      l_pol_ora || ' oracle-supplied');
    p('Database users: ' || l_users || ' (' || l_cust || ' customer, ' ||
      l_ora || ' oracle-maintained)');
    p('Customer accounts covered by a customer policy: ' || l_cust_cov ||
      ' of ' || l_cust || ' (' || l_pct || ')');
    p('Deliberate exemptions (EXCLUDED_EXCEPT): ' || l_except);
    p('Blind spots: ' || l_blind || ' - thereof actionable: ' || l_action);
    p;

    IF l_pol_cust = 0 THEN
        p('!! No customer-controlled activity policy is enabled. Every');
        p('!! coverage figure below is therefore 0 by construction - the');
        p('!! finding is the missing policy set, not the individual users.');
        p;
    END IF;

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
            DECLARE
                l_key VARCHAR2(32) := c.cls || '|' || g.le;
            BEGIN
                IF cell(m_total, l_key) > 0 THEN
                    p(RPAD(INITCAP(c.cls), 10) || RPAD(g.lbl, 7) ||
                      LPAD(cell(m_total,  l_key), 7) ||
                      LPAD(cell(m_direct, l_key), 8) ||
                      LPAD(cell(m_role,   l_key), 6) ||
                      LPAD(cell(m_all,    l_key), 11) ||
                      LPAD(cell(m_exc,    l_key), 8) ||
                      LPAD(cell(m_blind,  l_key), 7));
                END IF;
            END;
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
        p(RPAD('PRINCIPAL', 32) || RPAD('ACCOUNT_STATUS', 22) ||
          RPAD('CLASS', 10) || 'OCOV');
        FOR i IN 1 .. l_rows.COUNT LOOP
            EXIT WHEN l_listed >= k_max_rows;
            IF in_scope(l_rows(i)) THEN
                l_listed := l_listed + 1;
                p(pad(l_rows(i).principal, 32) ||
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
            p(RPAD('PATTERN', 34) || LPAD('MEMBERS', 9) || '  EXAMPLE');
            l_dkey := d_count.FIRST;
            WHILE l_dkey IS NOT NULL LOOP
                IF d_count(l_dkey) >= k_grp_min THEN
                    p(pad(l_dkey, 34) || LPAD(d_count(l_dkey), 9) ||
                      '  ' || d_example(l_dkey));
                END IF;
                l_dkey := d_count.NEXT(l_dkey);
            END LOOP;
            IF l_dsingle > 0 THEN
                p(RPAD('(ungrouped)', 34) || LPAD(l_dsingle, 9) || '  -');
            END IF;
            p;
            p('A group is one finding with one remedy - a single policy for');
            p('the pattern, or one decision to exempt it. Members are listed');
            p('individually in block C.');
            p;
        END IF;
    END IF;

    -- ---------------------------------------------------------------------
    -- Block E - policy effectiveness (does the enablement reach anybody?)
    -- ---------------------------------------------------------------------
    p('E) POLICY EFFECTIVENESS (one row per policy x option x entity)');
    p;
    p(RPAD('POLICY', 32) || RPAD('OPTION', 17) || RPAD('ENTITY', 24) ||
      LPAD('USERS', 6) || '  VERDICT');

    FOR r IN (
        -- Same model as sql/25-policy-effectiveness.sql. Deliberately not
        -- restricted to non-logon policies: whether an enablement resolves
        -- is independent of which actions the policy audits.
        WITH enabled AS (
            SELECT DISTINCT
                   e.policy_name,
                   UPPER(e.enabled_option) AS enabled_option,
                   UPPER(e.entity_name)    AS entity_name,
                   UPPER(e.entity_type)    AS entity_type
            FROM   audit_unified_enabled_policies e
        ),
        pol AS (
            SELECT policy_name, MAX(oracle_supplied) AS oracle_supplied
            FROM   audit_unified_policies
            GROUP  BY policy_name
        ),
        rc AS (
            SELECT DISTINCT
                   UPPER(CONNECT_BY_ROOT grantee) AS grantee,
                   UPPER(granted_role)            AS granted_role
            FROM   dba_role_privs
            CONNECT BY NOCYCLE PRIOR UPPER(granted_role) = UPPER(grantee)
        ),
        public_roles AS (
            SELECT granted_role FROM rc WHERE grantee = 'PUBLIC'
        ),
        u AS (SELECT UPPER(username) AS username FROM dba_users),
        ro AS (SELECT UPPER(role) AS role FROM dba_roles),
        ut AS (SELECT COUNT(*) AS cnt FROM u),
        rg AS (
            SELECT rc.granted_role AS role_name,
                   COUNT(DISTINCT u.username) AS user_cnt
            FROM   rc JOIN u ON u.username = rc.grantee
            GROUP  BY rc.granted_role
        ),
        resolved AS (
            SELECT e.policy_name,
                   NVL(p.oracle_supplied, 'NO') AS oracle_supplied,
                   e.enabled_option,
                   e.entity_name,
                   e.entity_type,
                   CASE
                       WHEN e.entity_name = 'ALL USERS' THEN 'NA'
                       WHEN e.entity_type = 'ROLE' THEN
                           CASE WHEN EXISTS (SELECT 1 FROM ro
                                             WHERE ro.role = e.entity_name)
                                THEN 'Y' ELSE 'N' END
                       ELSE
                           CASE WHEN EXISTS (SELECT 1 FROM u
                                             WHERE u.username = e.entity_name)
                                THEN 'Y' ELSE 'N' END
                   END AS entity_resolves,
                   CASE
                       WHEN e.entity_name = 'ALL USERS'
                            THEN (SELECT cnt FROM ut)
                       WHEN e.entity_type = 'ROLE' THEN
                           CASE
                               WHEN e.entity_name IN (SELECT granted_role
                                                      FROM public_roles)
                                    THEN (SELECT cnt FROM ut)
                               ELSE NVL((SELECT rg.user_cnt FROM rg
                                         WHERE rg.role_name = e.entity_name), 0)
                           END
                       ELSE
                           CASE WHEN EXISTS (SELECT 1 FROM u
                                             WHERE u.username = e.entity_name)
                                THEN 1 ELSE 0 END
                   END AS users_covered
            FROM   enabled e
            LEFT   JOIN pol p ON p.policy_name = e.policy_name
        )
        SELECT policy_name, oracle_supplied, enabled_option, entity_name,
               entity_type, users_covered,
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
            oracle_supplied, policy_name, enabled_option, entity_name
    ) LOOP
        l_e_rows := l_e_rows + 1;
        IF r.verdict IN ('ENTITY_MISSING', 'ROLE_NO_GRANTEES', 'NO_USERS') THEN
            l_e_find := l_e_find + 1;
        END IF;
        p(pad(r.policy_name, 32) || pad(r.enabled_option, 17) ||
          pad(r.entity_name, 24) || LPAD(r.users_covered, 6) || '  ' ||
          r.verdict ||
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
    END IF;
    p('EXCLUSION_DEAD = an EXCEPT clause naming a non-existent user. Not a');
    p('coverage gap, but a marker that the policy has drifted from reality.');

    p;
    hr;
    p('Per-user detail:  sql/23-blind-spot-pdb.sql (CSV, one row per user)');
    p('Policy detail:    sql/25-policy-effectiveness.sql (CSV)');
    hr;
    p;
END;
/

SET FEEDBACK ON
SET PAGESIZE 200
SET TAB ON
