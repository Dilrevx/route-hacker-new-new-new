# Upstream attribution and licensing boundary

This directory is a provenance-preserving historical archive. No blanket license or claim of original authorship is newly applied to the archived input files.

Patch paths retain the original upstream project/file names, including Apache Archiva, Flink, Hadoop, Hive, Ignite, Kyuubi, Pulsar, SkyWalking, Spark, Storm, Zeppelin, Knox and Superset. Source-insertion patches are experimental modifications, not upstream security fixes. Refer to each manifest entry's source version evidence and to the upstream project's license and notices before reuse.

The original patch bytes and historical script bytes are unchanged. Complete Java API-shim/runner sources are not redistributed here because the preservation pass did not establish their authorship/license provenance. The complete upstream NiFi launch script is also withheld until its referenced NOTICE/license packaging is restored. These exclusions are recorded by hash in `HELD.json`; they are not silently replaced with newly authored code.

Generated documentation and manifests describe provenance and verification; they do not relicense third-party inputs or establish that every archived recipe is independently runnable.
