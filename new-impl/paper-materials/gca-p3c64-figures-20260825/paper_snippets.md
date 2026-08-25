# Paper Snippets

## Guideline Case Paragraph

GCA produces mechanism-level guidelines that are more actionable than a raw CVE or CWE label. A representative example is `mech_jndi_untrusted_lookup_target`, the attacker-controlled JNDI lookup target guideline. The released guideline asks the auditor to trace attacker-controlled names, URLs, headers, configuration values, or lookup keys into JNDI, LDAP, RMI, naming-context, or remote lookup APIs, and to verify same-path constraints on scheme, authority, object factory, object type, and network destination. The example case `apache__axis-axis1-java::CVE-2023-51441` is attached to guideline `gl_mech_0046`. Across the candidate groups behind this mechanism, 14 historical CVEs map through heterogeneous CWE labels, including CWE-502 (7), CWE-20 (6), CWE-184 (3), CWE-74 (3), CWE-918 (2). This illustrates the paper's central use case: the online system receives a reusable security obligation rather than a project-specific signature.

## GCA Figure Caption

GCA separates vulnerability mechanism space from noisy CVE/CWE annotation space. On the 143-case paper set, the released primary sidecar covers 28 cases, while the audited headroom reaches 53 cases after current review-queue release, 73 cases after raw/noise candidate release, and 136 cases when all CVE IDs are ingested. The paired fan-out views show that one CWE can decompose into many mechanisms and one reusable mechanism can cross several CWE labels.

## P3C64 Figure Caption

P3C64 improves mechanism-conditioned known-anchor retrieval under the same 143 evaluation identities. Compared with Qwen3-Embedding-4B, P3C64 raises Hit@30 from 30 to 45, Hit@50 from 37 to 56, Hit@100 from 55 to 73, and Hit@200 from 74 to 84. The rank-shift view highlights cases that enter the Top-200 only after P3C64 adaptation, including TOCTOU, authorization, state-precondition, file-permission, and IRIS-style cases. The evidence supports improved mechanism-conditioned ranking; saved embedding vectors are needed for a direct embedding-geometry visualization.
