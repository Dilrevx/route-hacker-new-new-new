# ActiveMQ fileserver candidate verification

## Scope and provenance

- Repository: `apache/activemq`
- Audited commit: `4ba1a1689f33d81bd2349a2bb8c66f0c95b04d1d`
- Release tag at the commit: `activemq-5.11.0`
- Checkout: `workspace/activemq`
- Review mode: source/configuration inspection plus a non-network local receipt

## Verdict

**CONFIRMED** for the stated revision: the shipped default configuration exposes
an unauthenticated `/fileserver` web application, and its `MOVE` handler uses the
untrusted `Destination` request header to construct the filesystem destination
without constraining that destination to the fileserver resource base. The server
copies the existing source file to that filesystem path and then deletes the
source. The effective write scope is bounded by the operating-system permissions
of the ActiveMQ process and the existence/creatability of destination parent
directories.

This is source-backed confirmation of an arbitrary **process-writable**
destination, rather than a claim that any path on the host is writable.

## Evidence

### 1. Registration and request routing

`activemq-fileserver/src/main/webapp/WEB-INF/web.xml` registers both filters and
maps each to every path:

- Lines 26-29: `RestFilter` is registered.
- Lines 31-34: `FilenameGuardFilter` is registered first.
- Lines 36-44: both filters map to `/*`.
- Lines 46-54: Jetty's `DefaultServlet` maps to `/*`.

The requested location `web.xml:26` is therefore a real registration point, not
a dead declaration. The file supplies no `read-permission-role` or
`write-permission-role` init parameter.

### 2. Source-to-sink path

`activemq-fileserver/src/main/java/org/apache/activemq/util/RestFilter.java`:

- Lines 87-90 dispatch `MOVE` to `doMove`.
- Lines 103-111 permit it unless a `writePermissionRole` was configured; this
  descriptor does not configure one.
- Lines 113-114 obtain the fileserver source file and untrusted `Destination`
  **HTTP header**.
- Lines 121-124 parse that header as a `URL`, call `destinationUrl.getFile()`,
  use it directly as `new File(...)` for `IOHelper.copyFile`, and delete the
  source after the copy. No canonical-root comparison, allowlist, or
  storage-root containment check occurs on the destination.

`FilenameGuardFilter` does not close this route: its guards only override request
parameter and request-path getters (`FilenameGuardFilter.java:70-92`).
`RestFilter#doMove` reads the destination through `request.getHeader(...)`,
which that wrapper does not override.

The same filter also supports unauthenticated `PUT` under this descriptor:
`RestFilter.java:151-188` gates only when a write role exists, then writes the
request body to the resolved fileserver source path. This establishes a normal
application path to an existing source file; verification did not transmit any
request.

### 3. Default/common deployment exposure

At this commit the broker imports `jetty.xml` from its main release config
(`assembly/src/release/conf/activemq.xml:127-134`). The imported Jetty config:

- creates `/fileserver` with resource base `${activemq.home}/webapps/fileserver`
  (`assembly/src/release/conf/jetty.xml:68-73`);
- listens on `0.0.0.0:8161` (`jetty.xml:100-115`); and
- places the web app under a security handler whose defined path spec is
  `/api/*,/admin/*,*.jsp` (`jetty.xml:28-58`), not `/fileserver/*`.

The distribution also assembles the webapp into `webapps/fileserver`
(`assembly/src/main/descriptors/common-bin.xml:88-99`). Thus it is present and
configured in the normal 5.11.0 distribution rather than being only a test
module.

### 4. Historical status

The later commit `9fd5cb7dfe0fcc431f99d5e14206e0090e72f36b` is titled
`AMQ-5754 - disable file server by default`; its diff comments out the default
`/fileserver` WebAppContext and describes the application as disabled by default.
It is **not** an ancestor of the audited 5.11.0 commit.

The later `3dd86d04e8b90ba309819317d19e7260d414d9e7` (`AMQ-6276 - remove
fileserver webapp`) deletes the entire module in 2016. This supports that the
component had a subsequent security/lifecycle response, but it does not remove
the issue from the exact audited revision.

## Local-only receipt

`evidence/verify_fileserver_path.py` asserts the exact source and configuration
tokens listed above, confirms the descriptor has no write role, and then uses
only two controlled files below `evidence/local-path-receipt/`. It models the
same URL-path-to-`File` choice visible in `doMove` and verifies a benign file is
copied from the controlled storage root to a controlled path outside that root,
after which the source is removed.

Result: `evidence/local-path-receipt.json` reports:

- `destination_inside_storage_root: false`
- `destination_created: true`
- `source_removed_after_copy: true`
- `mode: local-only source-derived receipt; no service started; no HTTP sent`

## Limitations / remaining unproven

- No full broker/Jetty instance was started. The local host lacks a usable Java
  runtime and Maven, so this review did not run the legacy module's integration
  test. The source and deployment logic are sufficient to establish the path
  decision at the pinned revision.
- A real deployment's effective impact depends on the ActiveMQ process account:
  the destination parent must exist or be otherwise creatable, and the process
  must have write permission.
- Site-specific reverse-proxy reachability and administrator overrides cannot be
  inferred from source alone. The shipped connector is `0.0.0.0:8161`; a normal
  network policy may narrow external reachability.
- The receipt deliberately avoids a request sequence and does not claim any
  control over paths outside its local evidence sandbox.

## Artifacts

- `evidence/revision.txt` — pinned revision and release tag.
- `evidence/source-excerpts/` — line-numbered source/configuration excerpts and
  history diffs.
- `evidence/local-path-receipt.json` — output of the non-network receipt.
- `evidence/verify_fileserver_path.py` — receipt source.
- `evidence/SHA256SUMS` — hashes of the evidence files.
