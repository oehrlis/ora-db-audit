# Disclaimer

This software is provided "as is", without warranty of any kind,
express or implied, including but not limited to the warranties of
merchantability, fitness for a particular purpose, and noninfringement.

## No Vendor Endorsement

`ora-db-audit` is an independent open-source project. It is **not**
affiliated with, sponsored by, or endorsed by Oracle Corporation.
"Oracle" and related product names are trademarks of Oracle and/or
its affiliates.

## Audit Data Handling

The scripts and queries in this repository collect data from Oracle
Unified Audit trails. This data is sensitive and can include:

- Database and OS usernames
- Host names and terminal identifiers
- Client program names and IP addresses
- SQL text from audited statements

You are responsible for:

- Obtaining proper authorisation before running this toolkit against
  any database you do not personally own
- Anonymising customer-specific identifiers before sharing any output
  bundle outside the originating environment
- Complying with applicable data protection regulations (GDPR,
  industry-specific privacy laws) in your jurisdiction

Mapping files (`*.mapping.json`) produced by anonymisation contain
the reversal key from placeholder back to real values. Treat them
with the same care as the audit-trail data itself.

## Production Use

While care has been taken to write non-destructive, read-only analysis
queries, **test in a non-production environment first**. The
maintainers accept no liability for any direct, indirect, or
consequential damage arising from the use of this software.

## Patches and Updates

Oracle audit-trail behaviour can change between database versions and
patch levels. Verify the toolkit's output against your specific
DB version before relying on results for compliance or audit purposes.
