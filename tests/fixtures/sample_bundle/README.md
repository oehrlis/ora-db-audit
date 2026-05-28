# Audit Analysis Bundle (Synthetic Fixture)

Small synthetic bundle used by `tools/tests/` to smoke-test
`anonymize_bundle.py`. Contains all `# schema:` type-hint kinds:

- `KEEP` (`01_config.csv`)
- `REDACT` (`03_policy_inventory.csv` - `audit_condition`)
- `PSEUDO:DBUSER` (`08_top_users.csv`, `11_host_user_program.csv`)
- `PSEUDO:OSUSER`, `PSEUDO:CLIENT` (`11_host_user_program.csv`)
- `PSEUDO:HOST` (`11_host_user_program.csv`)
- `PSEUDO:SCHEMA`, `PSEUDO:OBJECT` (`10_top_objects.csv`)
- `COUNT`, `TIMESTAMP` (multiple)

Cross-category dedup case: `stefan.oehrli` appears in both `dbusername`
(DBUSER) and `os_username` (OSUSER) of `11_host_user_program.csv` and is
expected to receive **one** pseudonym (first category wins -> DBUSER).

Comma-list case: `04_policy_volume.csv` has
`ODB_LOC_LOGON_EVENTS_V1, ODB_LOC_DIRECT_ACCESS_V1` as one `policy_name`
value (KEEP type) - must pass through verbatim.
