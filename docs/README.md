# Documentation

<!-- SPDX-License-Identifier: Apache-2.0 -->

Full documentation for the `ora-db-audit` Oracle Unified Auditing analysis and reporting toolkit.

## Contents

| Document | Description |
|----------|-------------|
| [installation.md](installation.md) | Prerequisites, installation options, database user setup, Python packages |
| [configuration.md](configuration.md) | Full CLI reference, all flags and options, output structure, patterns file, report sections |
| [usage.md](usage.md) | Use cases with complete examples: collection, anonymisation, reporting, SIEM export, AI findings |
| [troubleshooting.md](troubleshooting.md) | Common errors and fixes, FAQ |
| [best-practices.md](best-practices.md) | Data sensitivity, deployment recommendations, collection cadence, performance |
| [compliance-mapping.md](compliance-mapping.md) | CIS Oracle DB Benchmark / DISA STIG / Oracle BP control mapping |
| [ai-analysis-rules.md](ai-analysis-rules.md) | How the AI findings section is generated and what it covers |
| [roadmap.md](roadmap.md) | Planned features and known limitations |

## Use-Case Deep-Dives

Detailed workflow documentation in [use-cases/](use-cases/):

| Document | Description |
|----------|-------------|
| [use-cases/audit-analysis.md](use-cases/audit-analysis.md) | End-to-end CSV bundle pipeline |
| [use-cases/audit-log-anonymisation.md](use-cases/audit-log-anonymisation.md) | Anonymisation workflow and mapping file handling |
| [use-cases/off-path-detection.md](use-cases/off-path-detection.md) | Off-path host detection and pattern configuration |

## Quick Navigation

- **New to the tool?** Start with [installation.md](installation.md) then [usage.md](usage.md).
- **Looking for a specific flag?** See [configuration.md](configuration.md).
- **Something not working?** See [troubleshooting.md](troubleshooting.md).
- **Running for a customer?** See [../templates/collection-quickref.md](../templates/collection-quickref.md).
- **Compliance questions?** See [compliance-mapping.md](compliance-mapping.md).
