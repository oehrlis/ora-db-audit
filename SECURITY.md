# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.x     | Pre-release. Security fixes on a best-effort basis. |

Once v1.0.0 is released, the most recent MINOR version will receive
security updates.

## Reporting a Vulnerability

If you discover a security vulnerability in `ora-db-audit`, please
**do not open a public GitHub issue**.

Instead, send a detailed report to:

- **Email**: <oehrlis@oradba.ch>

Include:

- A description of the vulnerability and its potential impact
- Steps to reproduce
- Affected version(s)
- Any suggested mitigations

We will acknowledge receipt within 7 days and aim to publish a fix or
mitigation within 30 days for confirmed issues, depending on severity
and complexity.

## Data Sensitivity

This toolkit handles audit-trail data, which contains sensitive
identifiers (see [DISCLAIMER.md](DISCLAIMER.md)). Specific concerns
that warrant a security report:

- Bugs in the anonymisation logic that could leak real customer
  identifiers into output bundles
- Bypass of the `*.mapping.json` gitignore that risks committing
  reversal keys
- Privilege-escalation paths in the bash entry point
- SQL-injection patterns in dynamic query construction (PL/SQL EXEC
  IMMEDIATE blocks etc.)

## Out of scope

- Issues that require the attacker to already have full `SYSDBA` or
  `AUDIT_ADMIN` access on the target database
- Theoretical timing attacks on the anonymisation hash function
  unless a practical PoC is provided
- Vulnerabilities in third-party dependencies that are already
  publicly known and pending vendor patches (please link the upstream
  CVE instead)
