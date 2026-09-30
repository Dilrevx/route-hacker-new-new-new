# Compile fleet and constrained CodeQL repair

The archive includes **137 fleet cases**, each with its main Dockerfile and a
historical recipe/review/evidence projection. Earlier Dockerfile variants, small
build scripts, patches and Gradle settings are preserved where selected. The
directory name `fleet-138-v1` is historical; it does not imply 138 available cases.

Recorded fleet reviews were **135 accepted and two rejected** (akka-management
CVE-2025-46548 and geoserver CVE-2025-27505). Read each case's
`historical-receipt.json`: acceptance may cover selected modules or a bounded
compilation target, not a complete application, fresh CodeQL database or exploit.

`iris-a26/` preserves 242 validated repair decisions and 11 compact wave ledgers,
including unsuccessful and superseded attempts. The a26 policy forbade changing
the source revision or editing source; its repairs principally selected approved
toolchains, settings and build arguments. A CodeQL database repair is not a
vulnerability-detection result. Multiple waves can contain the same case: do not
sum attempts as unique repaired projects.

## Provenance and limitations

- [SOURCE_PROVENANCE.json](SOURCE_PROVENANCE.json) maps original input hashes to
  public hashes and records projections/path normalization.
- [FILE_MANIFEST.json](FILE_MANIFEST.json) covers 736 curated payload files;
  the enclosing archive manifest also covers this README and the file manifest.
- [docker-copy-mapping.json](docker-copy-mapping.json) links recipes to their
  expected context inputs. Its case-root context assumption is explicit;
  unresolved inputs may come from another build context.
- [dependency-provenance.json](dependency-provenance.json) inventories selected
  external files/directories. A hash or path is **not** a backup of that payload.

Original private preservation covers 5,629 small/medium files (700,365,740 bytes),
including receipts, settings, custom artifacts and the exact 18-file historical
execution package. It spans 15 a26 wave directories; not every wave had a compact
ledger. All 133 observed r8 settings files were preserved, including two nested
retry settings. Those private files are not implicitly published by this index.
The existing `compile-builder-v2` module is not asserted byte-identical to the
historical a26 executor.

Large dependencies remain on the source server: the bounded inventory identified
260 distinct not-yet-backed-up file hashes totaling **30,310,614,505 bytes**, plus
528 directory references not recursively preserved. These figures are not an
exhaustive server inventory. Offline dependency bundles, custom binaries and
container exports cannot be assumed easy to download or reconstruct later.

Historical scripts were not run, images were not rebuilt, and CodeQL was not
rerun for preservation. Host paths in public copies may be placeholders and
require deliberate remapping. Review shell commands, licensing, build scope and
all external dependencies in an isolated workspace before reuse.
