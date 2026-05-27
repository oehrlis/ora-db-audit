# Contributing to ora-db-audit

Thank you for your interest in this project. Contributions are welcome
under the [Apache License 2.0](LICENSE).

## How to contribute

1. **Open an issue first** for any non-trivial change. This lets us
   discuss scope and design before code is written.
2. **Fork** the repository and create a feature branch:

   ```bash
   git checkout -b feat/<short-description>
   ```

3. **Follow the coding conventions** documented in [CLAUDE.md](CLAUDE.md)
   (bash header, SemVer, Conventional Commits, markdown lint, etc).
4. **Run the linters** before submitting:

   ```bash
   make lint
   ```

5. **Update CHANGELOG.md** under `## [Unreleased]`.
6. **Open a pull request** against `main` with a clear description and
   a reference to the issue.

## Commit messages

This repo uses [Conventional Commits](https://www.conventionalcommits.org/):

```text
type(scope): description

types: feat | fix | docs | refactor | chore | test | ci
```

Example: `feat(sql): add noise-candidate heuristic for top-N users`

## Reporting bugs

Open an issue with:

- Oracle DB version (`SELECT BANNER_FULL FROM V$VERSION;`)
- Operating system + bash version
- Steps to reproduce
- Expected vs actual behaviour
- Anonymised excerpts of relevant output

**Never include real customer data, hostnames, or audit-trail
content** in bug reports.

## Security disclosures

See [SECURITY.md](SECURITY.md) for the vulnerability reporting process.

## Code of conduct

Be respectful. Constructive technical disagreement is welcome;
personal attacks are not.
