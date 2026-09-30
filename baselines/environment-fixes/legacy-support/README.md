# Legacy builder support snapshot

The two files here are exact source bytes recovered on 2026-09-30 from Git
revision `7aa5b7aba78aa5a012874edb885ded0bd2f6cbf4`; the selected source paths were
clean. [source-manifest.json](source-manifest.json) records their hashes.

- `scripts/build_repo_docker.py` contains the historical base-image Dockerfile
  generator, project-build orchestration, proxy/mirror logic and recipe caching.
- `Dockerfile.runtime` is a specific historical Keycloak runtime recipe, not a
  universal runtime template.

This source snapshot is not proven to be the exact generator revision used for
July's archived recipe bundle. The six base/cache tags referenced by that bundle
did not resolve in the server's current default Docker daemon on 2026-09-30.
Image layers were not exported; this lookup does not prove absence from every
other daemon or disk. A tool-list-derived image tag is not a content digest.

Do not run these files as an archive check. The builder can invoke model APIs,
create containers, fetch dependencies and replace build directories. Historical
proxy settings and certificate-check bypasses require review before reuse.
Python syntax was parsed without executing or importing the builder.
