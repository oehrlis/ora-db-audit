# ora-db-audit - Task Backlog

## Completed

### v1.6.0 - False Positive Detection Framework

- [x] Create `sql/20-fp-role-grantees.sql`
- [x] Create `tools/fp_patterns.json` with FP-001 to FP-004 patterns
- [x] Add FP detection engine to `tools/audit_report.py`
  - [x] `load_fp_patterns()`, `detect_false_positives()`, `render_fp_context_for_ai()`, `render_fp_section()`
  - [x] `--fp-patterns` CLI argument
  - [x] Wire into `_run_ai_analysis`
- [x] Extend AI system prompts (de/en) with Oracle engine behavior notes
- [x] Create `docs/false-positive-patterns.md`
- [x] Update `docs/ai-analysis-rules.md` - add §2.8 FP rule contract
- [x] CHANGELOG [1.6.0] + VERSION 1.5.0 → 1.6.0

### v1.7.0 - Report Improvements (F1-F7)

- [x] F1: Section 7.2.1 - event list for context-conditioned policies
- [x] F2: Section 7.2.2 - user list column in off-path host table
- [x] F3: Language-aware AI section header (de/en) via `t()`
- [x] F4: Executive summary AI sentinel + search-replace after `--ai` run
- [x] F5: Section 7.3 - uncovered users/roles + `sql/21-uncovered-users.sql`
- [x] F6a: Section 11 - custom policy DDL (oracle-supplied excluded)
- [x] F6b: `sql/20-fp-role-grantees.sql` + queries 19/21 added to `QUERIES` array
- [x] F7: Per-query sqlplus progress output `[N/M] filename ... done (Xs)`
- [x] CHANGELOG [1.7.0] + VERSION 1.6.0 → 1.7.0

---

## Open

<!-- add new tasks here -->
