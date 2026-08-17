# Evaluation Results

These artifacts record two provider-substituted function-level VulRAG runs
over the same HCVR new-unified v2 evaluation inputs.

## Fixed Inputs

| Artifact | SHA-256 |
| --- | --- |
| QA receipt | `3c2e02e9910059380f92c87dbef3f8cc16f2b9a95ae832585b5e53abbf589c84` |
| Ordered 143-case allowlist | `3b3f452cc603b30992b9d2517afecb671207b2673692813197a4add0dd8502d0` |
| 137 function packets | `821b72941758b10e30f72ff0ad1b90ee74533ed854b73fe843e514940420dd42` |
| Six-case unresolved ledger | `c1bac85bda5bd88048558e34ada11713e0e792d802417579c5df7274a558dda4` |
| Frozen VulRAG knowledge | `a25e5c2cad51b7117bddc02677f1ec4544149979510415e46d1c53b73ce3e20f` |

## Results

| Metric | GPT-5.6-Sol (low) | DeepSeek-V4-Flash (low) |
| --- | ---: | ---: |
| Completed / failed / unresolved | 137 / 0 / 6 | 137 / 0 / 6 |
| Vulnerable verdicts | 14 | 28 |
| Detection rate over 137 functions | 10.22% | 20.44% |
| Detection rate over all 143 cases | 9.79% | 19.58% |
| LLM calls | 948 | 922 |
| TraeX-reported tokens | 7,941,516 | 1,355,278 |

The models agreed on 107 of 137 completed functions. The 30 flips consist of
22 GPT-negative to Flash-positive cases and eight GPT-positive to
Flash-negative cases. See `model-comparison.md` for their identities.

All 143 dataset entries are known vulnerable cases. These values measure
whether VulRAG classified the one recovered vulnerable-revision function as
vulnerable. They are not repository-level recall and are not official
`gpt-4o-mini` VulRAG results.

## Artifact Hashes

| Artifact | SHA-256 |
| --- | --- |
| `gpt-5.6-sol-low/evaluation-summary.json` | `52c09f0ee46e2c817527fc22e6d0cc09512f83ffa4529363f4a07690fa657b52` |
| `deepseek-v4-flash-low/evaluation-summary.json` | `ef6c4d6bba1dd4df2f435c3e335894b40962ad3e0cc416aa95ef20ba6af5a9d4` |
| `model-comparison.json` | `b84caa03a424af6cbfc7558a36beb58ee98e853f46bbc58588894cc4acff2a49` |
| `model-comparison.md` | `527fc764de6dd259a9a4bd287401a4eacc525e387b62da964771d90247014c61` |

The JSON summaries contain the ordered 143-case accounting with per-case
status, verdict, call count, and TraeX-reported token count. Full local receipts
also contain prompts and model outputs; they are intentionally omitted from
Git to avoid duplicating generated transcripts.
