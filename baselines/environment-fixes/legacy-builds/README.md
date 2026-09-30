# Legacy build recipes

Preserved from `dockerfiles-backup-20260704-150750.tar.gz`: **254 Dockerfiles and
43 build notes**, retaining exact original bytes. [source-manifest.json](source-manifest.json)
records every member's SHA-256 and the source bundle hash.

[recipe-index.json](recipe-index.json) lists each recipe, historical identifier,
`FROM` images, build-context instructions, and possible catalog matches.
[catalog.json](catalog.json) contains an allowlisted projection of 317 records
from a consistent snapshot of `runtime-catalog.db`. The similarly named
`runtime_catalog.db` was empty and was not used.

## Interpret the records carefully

- Catalog `build_status`: 191 `success`, 125 `failed`, 1 `timeout`.
- Catalog `is_verified`: 105 true, 212 false.
- Catalog `can_build`: 93 true, 50 false, 174 unspecified.
- 240 of 254 recipe folders match a catalog record by case-insensitive repository
  name and literal revision. This join is not proof that a particular catalog
  outcome was produced by that exact recipe; the snapshots have different dates.
- Numeric directory names remain unresolved historical identifiers. They have
  not been converted into invented commit SHAs. Unmatched recipes remain present.

Those flags are historical metadata, not newly tested assertions. The original
database's environment values, build logs/notes, instance table and job metadata
remain in the private recovery copy, not this public projection. No actual token
usage total was present in the catalog's token-usage field.

## Dependencies and safety

Recipes depend on local `route-hacker-*` base/cache images, source checkouts and
sometimes additional `COPY` inputs. They are not standalone Docker builds. Proxy
settings, mirror substitutions, skipped checks and compatibility edits are
preserved as historical choices, not recommended defaults. Review in an isolated
workspace before reuse; do not build untrusted targets with production secrets.

The export tool accepts only the pinned source hashes and allowlisted database
fields. Its SQLite reader uses `mode=ro&immutable=1` because the consistent
serialized snapshot retains a WAL-mode header. It never opens the live database
for writes, executes a recipe, or publishes the original database.
