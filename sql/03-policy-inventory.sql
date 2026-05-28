-- SPDX-License-Identifier: Apache-2.0
-- -----------------------------------------------------------------------------
-- Name......: 03-policy-inventory.sql
-- Purpose...: Enabled policies inventory: audit_unified_policies joined with
--             audit_unified_enabled_policies. Includes the WHEN-clause text
--             (audit_condition) for tuning analysis.
-- Pattern...: Full inventory with metadata. Uses QUOTE ON because
--             audit_condition is free text that may contain delimiter chars.
-- Notes.....: audit_condition newlines are squashed to single spaces.
-- -----------------------------------------------------------------------------

SPOOL &LOGDIR./03_policy_inventory.csv

PROMPT # query: policy_inventory
PROMPT # query_id: 03
PROMPT # dbsid: &DBSID
PROMPT # pdb: &PDB_NAME
PROMPT # generated: &GENERATED_ISO
PROMPT # schema: policy_name=KEEP|audit_option_type=KEEP|audit_option=KEEP|condition_eval_opt=KEEP|audit_condition=REDACT|oracle_supplied=KEEP|entity_name=PSEUDO:DBUSER|entity_type=KEEP|enabled_option=KEEP|success=KEEP|failure=KEEP

SET MARKUP CSV ON DELIMITER '|' QUOTE ON

SELECT
    p.policy_name                                                        AS "policy_name",
    p.audit_option_type                                                  AS "audit_option_type",
    p.audit_option                                                       AS "audit_option",
    p.condition_eval_opt                                                 AS "condition_eval_opt",
    REPLACE(REPLACE(NVL(p.audit_condition, ''), CHR(10), ' '), CHR(13), ' ')
                                                                         AS "audit_condition",
    p.oracle_supplied                                                    AS "oracle_supplied",
    NVL(e.entity_name, '')                                               AS "entity_name",
    NVL(e.entity_type, '')                                               AS "entity_type",
    NVL(e.enabled_option, '')                                            AS "enabled_option",
    NVL(e.success, '')                                                   AS "success",
    NVL(e.failure, '')                                                   AS "failure"
FROM audit_unified_policies p
LEFT JOIN audit_unified_enabled_policies e
    ON e.policy_name = p.policy_name
ORDER BY 1, 2, 3;

SET MARKUP CSV OFF
SPOOL OFF
