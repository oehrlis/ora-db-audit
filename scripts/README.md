# scripts/

Build and release helper scripts. These scripts are called by the `Makefile` - prefer
`make release` over running them directly.

## Scripts

| Script | Purpose |
|--------|---------|
| `bump_version.sh` | Bump the SemVer in `VERSION`, update `bin/ora-db-audit.sh` header, create `CHANGELOG.md` stub for the new version |

## Common Make Targets

```bash
make release    # bump VERSION, create CHANGELOG stub, tag
make dist       # build release tarball (dist/ora-db-audit-<VERSION>.tar.gz)
```
