# Rework Plan: Pure-Mode-Correct SQL + AI Report (v1.0 BLOCKER)

Status: **CONFIRMED 2026-05-28** (Stefan sign-off on the 4 strategic choices)
Author: Claude session 2026-05-28
Parent: `tasks/migration-plan.md`
Blocks: v1.0.0 release

---

## 1. Why this plan exists

During Group B (SQL migration), Stefan identified correctness issues in the
inherited audit_pack-0.5.0 logic that make v1.0 unshippable as-is. The
issues fall into three buckets:

1. **Pure-Mode vs Mixed-Mode contamination**: AI prompt + 01-config
   interpretation references legacy parameters (`audit_sys_operations`,
   `audit_syslog_level`, `audit_trail`) that have no effect in Pure
   Unified Auditing. These produce false-positive findings.
2. **`UNIFIED_AUDIT_POLICIES` mishandled as identity**: the column is a
   **comma-separated concatenation** when multiple policies match the
   same event. Current SQLs aggregate on the raw concat string; the
   reporter's Section 8.1 generates `ALTER AUDIT POLICY` statements
   against that concat - producing **functionally wrong DDL**.
3. **Coarse storage/config findings**: partition-tablespace check
   doesn't account for transient state when range-partitioning hasn't
   rolled over after `ALTER TABLE MOVE`.

## 2. Strategic decisions (Stefan-confirmed 2026-05-28)

| # | Decision | Value |
|---|----------|-------|
| R1 | v1.0 release | **Blocked until rework complete** |
| R2 | UAP-split strategy | **SQL-side** via `REGEXP_SUBSTR(... , 1, level)` + `CONNECT BY LEVEL <= REGEXP_COUNT(...) + 1` |
| R3 | Compliance sources (multi) | CIS Oracle 19c, CIS Oracle 21c (if available), DISA STIG Oracle 12c, Oracle Unified Audit Best Practice Guidelines |
| R4 | Group C+F (Python + Tests) | **Defer** until rework Phase B + D complete |
| R5 | Group D + E (bash + templates + use-case docs) | **Proceed in parallel** to rework |
| R6 | New skill for AI report rules? | **No** - codify as `docs/ai-analysis-rules.md` reference doc, embed into audit_report.py prompt. Existing `/oracle-audit` skill stays canonical for Pure-Mode policy design. |
| R7 | Report language (v1.0) | **German-only**; Phase D rewrite designs for future EN via centralised message dict; multilanguage shipping in v1.1+. |

## 3. Findings catalog

| ID | Issue | Severity | Affected files | Phase |
|----|-------|----------|----------------|-------|
| F1 | AI-prompt mentions `audit_sys_operations`, `audit_syslog_level`, `audit_trail` as Pure-Mode findings | HIGH | `audit_pack_report.py` prompt (~line 90-95 in source) | Phase A + D |
| F2 | Section 8.1 generates `ALTER AUDIT POLICY` from concat UAP - **functionally wrong DDL** | CRITICAL | `audit_pack_report.py` Section 8.1 generator | Phase B + D |
| F3 | SQLs aggregate on raw concat UAP string (per-policy semantics wrong) | HIGH | `sql/04-policy-volume.sql`, `sql/05-policy-user-action.sql`, `sql/06-policy-client-program.sql`, `sql/07-policy-host.sql`, `sql/15-noise-candidates.sql` (check 14 too) | Phase B |
| F4 | Partition-tablespace finding too coarse (transient state after ALTER MOVE) | MEDIUM | `sql/02-storage.sql` + AI prompt | Phase C |
| F5 | `audit_trail = DB` flagged in Pure Mode (Legacy parameter, no effect) | MEDIUM | `sql/01-config.sql` + AI prompt | Phase C + D |
| F6 | CIS/STIG mapping must filter Pure-Mode-relevant controls only | HIGH | `docs/compliance-mapping.md` (new) | Phase E |

## 4. Phases

### Phase A - Reference doc: `docs/ai-analysis-rules.md`

Single source of truth for what the AI analysis considers a valid Pure-Mode
finding. The audit_report.py prompt either embeds this verbatim or attaches
it. Future Claude sessions read it on demand.

**Sections**:

1. **Pure Mode scope** - explicit list of init parameters / objects that
   ARE relevant: `unified_audit_systemclause`, `AUDIT_UNIFIED_ENABLED_POLICIES`,
   `DBMS_AUDIT_MGMT`, `AUD$UNIFIED` partitions, `AUDIT_DATA` tablespace,
   `unified_audit_trail_cleanup_jobs`, mandatory audit binary `*.aud` files.
2. **Out of scope (Legacy)** - explicitly flag and SUPPRESS: `audit_trail`
   init param, `audit_sys_operations`, `audit_syslog_level`, traditional
   `AUDIT ...` syntax, `DBA_AUDIT_TRAIL` view, `AUD$` table. Document
   that flagging these is a known false-positive class.
3. **UAP-concat semantics** - explain the concat-string nature with a
   concrete example. State the rule: "when comparing or aggregating by
   policy name, ALWAYS use per-policy split (Section 5 SQL template).
   NEVER treat the raw column value as a single policy name."
4. **DDL source rule** - "Suggested policy modifications must reference
   the actual DDL via `DBMS_METADATA.GET_DDL('AUDIT_POLICY', p.policy_name)`,
   not be assembled from observed concat strings."
5. **Partition transient state** - explain that `ALTER TABLE AUD$UNIFIED
   MOVE TABLESPACE ...` only moves new partitions; existing partitions
   stay. A current partition in the old tablespace is **not** automatically
   a finding - check the DEFAULT tablespace for new partitions and the
   partition-creation history.
6. **Pure vs Mixed detection** - canonical query template + interpretation
   table.
7. **Reference list** - links to source documents (Oracle BP PDF, CIS
   benchmark versions, STIG version).

**Acceptance**: file exists at `docs/ai-analysis-rules.md`; audit_report.py
references it (either string-embed or file-attach in the prompt build);
each F1-F5 issue is explicitly addressed with a rule that prevents it.

**Commit**: `docs: add ai-analysis-rules.md (Pure-Mode source of truth)`

### Phase B - SQL UAP-split rewrites

**Helper pattern** (canonical UAP-split CTE, to be inlined per SQL):

```sql
WITH split_uap AS (
    SELECT
        TRIM(REGEXP_SUBSTR(t.unified_audit_policies, '[^,]+', 1, lvl.col_pos)) AS policy_name,
        t.event_timestamp_utc,
        t.dbusername,
        t.userhost,
        t.action_name,
        t.client_program_name
    FROM unified_audit_trail t
    CROSS JOIN (
        SELECT LEVEL AS col_pos FROM dual
        CONNECT BY LEVEL <= 20
    ) lvl
    WHERE t.unified_audit_policies IS NOT NULL
      AND lvl.col_pos <= REGEXP_COUNT(t.unified_audit_policies, ',') + 1
      AND t.event_timestamp_utc >= SYSTIMESTAMP - NUMTODSINTERVAL(TO_NUMBER('&days'), 'DAY')
      AND t.dbid = con_id_to_dbid(SYS_CONTEXT('USERENV','CON_ID'))
)
SELECT policy_name, COUNT(*) AS events, ...
FROM split_uap
GROUP BY policy_name
ORDER BY 2 DESC
FETCH FIRST TO_NUMBER('&top_n') ROWS ONLY;
```

The `CONNECT BY LEVEL <= 20` cap is conservative; typical UAP-concat
length is 1-3 entries. Validate via:

```sql
SELECT MAX(REGEXP_COUNT(unified_audit_policies, ',') + 1) FROM unified_audit_trail;
```

If max exceeds 15, bump the cap to 50.

**Files to rewrite**:

| File | Change |
|------|--------|
| `sql/04-policy-volume.sql` | Per-policy `events`/`distinct_users`/`distinct_hosts`/`first_seen`/`last_seen` via split CTE. Existing schema-hint line stays valid. |
| `sql/05-policy-user-action.sql` | Per-policy x user x action grid; split CTE. |
| `sql/06-policy-client-program.sql` | Per-policy x client_program; split CTE. |
| `sql/07-policy-host.sql` | Per-policy x host; split CTE. |
| `sql/15-noise-candidates.sql` | High-volume combos per-policy (not per-concat). Generates the input that Section 8.1 then turns into DDL-diffs. Critical correctness fix. |
| `sql/14-privileged-activity.sql` | Audit logic; concat-string issue likely also present (review during rewrite). |

**New file**: `sql/16-policy-ddl.sql` - one query that dumps
`DBMS_METADATA.GET_DDL('AUDIT_POLICY', p.policy_name)` for every enabled
policy. CSV format with two columns: `policy_name|policy_ddl` (DDL is
CLOB - emit base64-encoded or LOB-spool to file). This is the canonical
source for Section 8.1's WHEN-clause comparison.

**Per-SQL header note**: add comment block explaining the UAP-concat
semantics + why the split CTE is needed. Useful for OSS contributors
unfamiliar with this Oracle quirk.

**Acceptance**:

- For each rewritten SQL: side-by-side test against current 0.5.0 output
  shows per-policy correctness on a sample bundle with known multi-policy
  events.
- `sql/16-policy-ddl.sql` produces parseable DDL for at least the existing
  `ORA_*` mandatory policies in any test database.

**Commits**:

- `fix(sql): split UNIFIED_AUDIT_POLICIES concat in 04-07 + 15`
- `feat(sql): add 16-policy-ddl source for DDL-correct WHEN-clause generation`
- `fix(sql): review + correct 14-privileged-activity UAP-handling`

### Phase C - Config + Storage interpretation fixes

**`sql/01-config.sql`** rewrite:

- Detect Mixed vs Pure Mode unambiguously - the canonical signal is
  `DBA_AUDIT_MGMT_CONFIG_PARAMS` entries + `V$OPTION` 'Unified Auditing'
  + 26ai-specific signals if applicable.
- Emit `# audit_mode: pure|mixed|legacy` as a metadata line so reporter
  + AI prompt can suppress Mixed-Mode-only checks when mode=pure.
- Continue to capture `audit_trail` parameter value for completeness,
  but mark it `# legacy_param: true` in the schema-hint line so the
  reporter does not flag it.
- Add `unified_audit_systemclause` parameter capture if applicable to
  the Oracle version under audit.

**`sql/02-storage.sql`** rewrite:

- Capture **all** partitions of `AUD$UNIFIED` with their tablespace +
  high-value + creation timestamp.
- Capture the DEFAULT tablespace for new partitions (from
  `DBA_PART_TABLES.DEF_TABLESPACE_NAME`).
- Emit `# audit_data_tablespace_target` vs `# audit_data_tablespace_current_partition`
  as separate metadata lines.
- Schema-hint type tags get a new `TABLESPACE_STATE` type indicating
  the reporter should compare target-vs-current and only flag if
  target is wrong.

**Acceptance**: 01-config exposes `audit_mode` metadata; 02-storage
exposes target-vs-current tablespace; reporter + AI prompt logic updated
in Phase D to consume these without producing the F4/F5 false alarms.

**Commits**:

- `fix(sql): 01-config emits audit_mode metadata; legacy params marked`
- `fix(sql): 02-storage distinguishes target tablespace vs current partition`

### Phase D - audit_report.py rewrite (Section 8.1 + AI prompt)

**Section 8.1 WHEN-clause generator**:

- Input change: read post-split per-policy noise candidates from
  `15-noise-candidates.csv` (now correct after Phase B).
- For each candidate policy: load DDL from `16-policy-ddl.csv` (Phase B
  output) and parse the existing `WHEN ...` clause.
- Generate a **diff suggestion**: "current WHEN clause: X. Suggested
  addition to suppress observed combo: AND NOT (...)". Output is a
  valid `ALTER AUDIT POLICY <name> ADD ...` derived from the actual DDL,
  not synthesised from concat strings.

**AI prompt**:

- Strip the three legacy findings (F1).
- Strip the F4 + F5 false-positive cues; replace with the rules from
  `docs/ai-analysis-rules.md` (either embed string or attach file).
- Add explicit "Pure Mode only" framing at the top.
- Reformat Section B "Konfigurationsluecken" to reference only the
  Pure-Mode-valid checks from the rules doc.

**Future-readiness: i18n architecture constraint (Stefan-amendment 2026-05-28)**:

- v1.0.0 ships **German-only** output (Markdown report sections, finding
  labels, AI prompt language). No translation work in v1.0.
- v1.1+ target: dual-language output (DE + EN), selectable via a CLI
  flag (`--lang en|de`, default `de`).
- **Phase D rewrite MUST design for this** so v1.1 is an additive
  change, not a second rewrite:
  - Route every user-facing string through a single Python dict / module
    (e.g. `tools/audit_report_messages.py` containing `MESSAGES["de"]
    = {...}`). German is the initial population; the structure already
    supports `MESSAGES["en"] = {...}`.
  - Do **not** scatter `f"Abschnitt X - ..."` literals across the
    reporter code. Every literal lives in the messages dict, accessed
    via a `t(key)` helper.
  - The AI prompt itself is multi-paragraph - same rule applies. Either
    a single message-dict entry per prompt-section or a separate
    `prompts/audit_findings.de.md` file loaded at runtime.
  - The `docs/ai-analysis-rules.md` reference doc stays English (it is
    technical reference material, not user-facing report content).
- Reject: gettext / .po file infrastructure (overkill for ~50-100
  strings, adds dependency).

**Acceptance**: against a known-broken policy + sample bundle, the
generated `ALTER AUDIT POLICY ...` statement is parseable by `sqlplus`
and references only the singular policy being tuned. AI findings
contain zero references to `audit_trail`, `audit_sys_operations`,
`audit_syslog_level`. **Additionally**: `grep -nE '"[A-Z][a-z].*[a-z][.!?]"' tools/audit_report.py`
returns minimal hits - confirming user-facing strings are not scattered
as literals throughout the code but routed through the messages dict.

**Commits**:

- `feat(report): strip legacy-audit findings, ground prompt in ai-analysis-rules.md`
- `fix(report): rewrite section 8.1 to use DBMS_METADATA DDL, not concat strings`

### Phase E - CIS/STIG mapping (`docs/compliance-mapping.md`)

Replaces what was Group G in `migration-plan.md`. Scope expanded per Stefan's
multi-source confirmation.

**Sources**:

1. CIS Oracle 19c Benchmark (latest version - record version number in
   doc header).
2. CIS Oracle 21c Benchmark (if a Pure-Mode-aware version exists; else
   document the gap).
3. DISA STIG Oracle 12c (current STIG; many controls Mixed-Mode-only,
   filter).
4. Oracle Database Unified Audit Best Practice Guidelines (the linked
   PDF).

**Table schema**:

```text
| Control ID | Source         | Description (short)         | Applicability | Coverage                                        | Gap / Notes |
|------------|----------------|-----------------------------|---------------|-------------------------------------------------|-------------|
| 4.1.1      | CIS 19c v1.2.0 | Ensure audit policies cover ...| Pure Mode  | sql/03-policy-inventory; sql/15-noise-candidates | -          |
| V-219828   | STIG 12c       | Audit DDL ...               | Pure Mode     | sql/14-privileged-activity                      | -           |
| 4.1.5      | CIS 19c v1.2.0 | Ensure 'audit_sys_operations' ...| Legacy   | -                                               | N-A in Pure Mode (suppress finding) |
```

**Per-SQL metadata**: add `# cis_controls:` line to each query's preamble
listing the relevant control IDs (or `none` if the SQL is a primitive
data extractor with no compliance mapping).

**Acceptance**: doc cites version numbers; every Pure-Mode control from
the four sources is either covered by a SQL/policy or explicitly listed
as a gap; non-applicable controls are listed with reason.

**Commit**: `docs: compliance-mapping.md covering CIS 19c+21c, STIG 12c, Oracle BP`

## 5. Sequence (revised migration order)

```text
DONE:
  Group A (foundation)             - commits b508464, a31c6ba
  Group B (SQL files)              - commits 5d12e23, dc1fb01, 9d28f10, c6e809b

NOW (parallel-safe across 3 tracks):
  Track 1: Rework Phase A         (docs/ai-analysis-rules.md)
  Track 2: Group D                 (bash entry-point migration)
  Track 3: Group E                 (templates + use-case docs)

NEXT (after Phase A is in):
  Rework Phase B                   (SQL UAP-split + sql/16-policy-ddl)
  Rework Phase C                   (config + storage interpretation)

THEN:
  Group C (Python migration)       - already incorporates Phase D rewrite
  Rework Phase D                   (Section 8.1 + prompt cleanup) - inside Group C
  Rework Phase E                   (CIS/STIG mapping) - parallel to C

FINALLY:
  Group F (tests)                  - validates rework end-to-end
  Group H (OSS polish)             - README, Makefile, CI
  Group I (v1.0 release)
```

## 6. Skill question - explicit decision

Stefan asked: "beim AI Report => brauchen wir hier ggf ein geignetes
skill?"

**Decision: No new skill for v1.0.**

Reasoning:

- A skill is heavier infrastructure (frontmatter, trigger conditions,
  versioning). It pays off when the same knowledge is consumed across
  multiple unrelated repos.
- `docs/ai-analysis-rules.md` lives where it's used (inside this repo)
  and is consumed by two callers only: `audit_report.py` (string-embed
  or file-attach) and human Claude sessions on this repo (read on
  demand).
- `/oracle-audit` skill already exists and covers Pure-Mode policy
  design. It is the natural skill for "given this finding, what
  remediation policy?" questions.
- Post-v1.0, if the AI-report generator grows into a multi-turn
  reasoning agent with tool use (e.g. live DB introspection), then
  promote the rules doc into `/oracle-audit-report` skill.

If Stefan disagrees: easy upgrade path - move the rules doc into the
ai-toolkit/claude/skills/ tree, add frontmatter, symlink into
`.claude/skills/`. No content changes needed.

## 7. Risks + mitigations

| Risk | Mitigation |
|------|------------|
| `CONNECT BY LEVEL <= 20` cap insufficient for some sites | Phase B includes the validation query; cap is configurable per environment in the SQL header. |
| DBMS_METADATA.GET_DDL requires privileges not always available | Document required grants in `docs/use-cases/audit-analysis.md` (Group E). Fallback: emit a warning + skip Section 8.1 DDL-diff if DDL unavailable. |
| CIS 21c benchmark may not yet exist as Pure-Mode-aware doc | Phase E acceptance allows the doc to record that as an explicit gap. |
| Phase B SQL changes break the existing anonymizer's `# schema:` parser | The `# schema:` line per SQL stays unchanged - we only change the SELECT semantics. Anonymizer reads column names from schema-hint, not column values, so per-policy split is invisible to it. Verify in Group C migration. |
| Sample bundle in eng/tools/tests is pre-rework - tests may fail until regenerated | Phase B + C output is regression-tested against a freshly captured bundle. May need a Group F task: regenerate `tests/fixtures/sample_bundle.*` after rework. |
| Phase D ships German-only output but i18n-ready architecture is non-trivial - risk of underestimating effort | Acceptance criterion in Phase D requires grep verification that user-facing strings are centralised. If the rewrite touches >50 string sites, factor in +1h for centralisation. Tracked separately in v1.1 milestone (not v1.0 scope). |

## 8. What needs Stefan's input next

- ✅ Confirmed sign-off (4 strategic decisions, 2026-05-28).
- Awaiting: Stefan can start the parallel work (Group D bash, Group E
  templates+use-cases) directly. Phase A reference doc can begin
  immediately - I will use Opus for this since it's domain-heavy
  authoring, then dispatch Sonnet for Phase B SQL rewrites.

