# Embedding PCA Notes

## Figures

- `embedding_pca_cwe_vs_gca.svg`: same CVE root-cause embedding coordinates, colored once by primary CWE and once by GCA mechanism.
- `embedding_pca_p3c64_query_shift.svg`: released guideline texts before and after the P3C64 query residual adapter.
- `embedding_pca_p3c64_cve_hypothesis_shift.svg`: CVE root-cause hypothesis texts before and after the P3C64 query residual adapter.

## Quantitative Diagnostics

- CVE points: 260.
- CWE 10-NN same-label agreement: 0.651.
- GCA mechanism 10-NN same-label agreement: 0.985.
- Base guideline 10-NN same-mechanism agreement: 0.252.
- P3C64 guideline 10-NN same-mechanism agreement: 0.252.
- Base CVE-hypothesis 10-NN same-mechanism agreement: 0.985.
- P3C64 CVE-hypothesis 10-NN same-mechanism agreement: 0.982.

## Claim Boundary

Use the first figure as the visual motivation for replacing direct CWE-space grouping with mechanism-level GCA grouping.
Use the second figure as an adapter diagnostic and pair it with the Hit@K table; the retrieval metrics remain the primary P3C64 evidence.
