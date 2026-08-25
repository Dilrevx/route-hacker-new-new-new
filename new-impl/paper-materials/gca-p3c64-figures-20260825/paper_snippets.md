# Paper Snippets

## Guideline Case Paragraph

GCA produces mechanism-level guidelines that are more actionable than a raw CVE or CWE label. A representative example is `mech_jndi_untrusted_lookup_target`, the attacker-controlled JNDI lookup target guideline. The released guideline asks the auditor to trace attacker-controlled names, URLs, headers, configuration values, or lookup keys into JNDI, LDAP, RMI, naming-context, or remote lookup APIs, and to verify same-path constraints on scheme, authority, object factory, object type, and network destination. The example case `apache__axis-axis1-java::CVE-2023-51441` is attached to guideline `gl_mech_0046`. Across the candidate groups behind this mechanism, 14 historical CVEs map through heterogeneous CWE labels, including CWE-502 (7), CWE-20 (6), CWE-184 (3), CWE-74 (3), CWE-918 (2). This illustrates the paper's central use case: the online system receives a reusable security obligation rather than a project-specific signature.

## GCA Figure Caption

GCA separates vulnerability mechanism space from noisy CVE/CWE annotation space. The figure projects 260 CVE root-cause descriptions into one embedding coordinate system and renders the same points twice: first colored by primary CWE label, then colored by GCA mechanism. The CWE-colored view has lower local label consistency, with 10-NN same-label agreement 0.651 and cosine silhouette 0.139. The GCA-colored view has higher local mechanism consistency, with 10-NN same-label agreement 0.985 and cosine silhouette 0.334. This visualization supports the motivation that CWE labels are useful metadata but weak retrieval queries, while GCA mechanisms provide more coherent audit obligations.

## P3C64 Figure Caption

P3C64 improves mechanism-conditioned known-anchor retrieval under the same 143 evaluation identities. Compared with Qwen3-Embedding-4B, P3C64 raises Hit@30 from 30 to 45, Hit@50 from 37 to 56, Hit@100 from 55 to 73, and Hit@200 from 74 to 84. The PCA diagnostic applies the P3C64 query residual to CVE root-cause hypothesis embeddings and shows an increase in mechanism-label silhouette from 0.334 to 0.438, while the 10-NN same-mechanism score remains approximately stable. The rank-shift view highlights concrete cases that enter the Top-200 only after P3C64 adaptation, including TOCTOU, authorization, state-precondition, file-permission, and IRIS-style cases.
