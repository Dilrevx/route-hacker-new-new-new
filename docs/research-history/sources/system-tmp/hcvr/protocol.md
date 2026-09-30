# Frozen HCVR transfer onto the unchanged issue/snippet benchmark

User request: run the old HCVR embedding backend in the existing test framework.
This run is inference only: no adapter fitting, no RQ-VAE, no generative API, no
benchmark repair, no source-repository modification, no deletion or push.

Two fixed conditions: raw Qwen3-Embedding-0.6B and the SAME code bank with the
historical P3C64 query-only residual. Checkpoint SHA256:
5425766d0dff286fb78f218808b21f8a502b85be170f6a8c911f7db761bc8e16.
Hidden dimension 128, residual scale 0.1, per the existing backend. Reuse its
actual class and normalization functions without rewriting the model logic.
Use the local SentenceTransformer assets, no added prompt: the old backend's
encode() call does not specify a prompt and this model has no default prompt.

Use the exact previously frozen 316 test rows for each of function/window, same
IDs/order, same preprocessed issue prose and code text. Preserve noisy single-case
labels and report this limitation. Load 2337-row files only to select their fixed
test split; no fitting or selection on any split. Do not add a third dataset.

Use FP32, TF32/autocast disabled, eval mode, no gradients; encode in batches of 16.
Max sequence length 4096 only to avoid tokenizer-dependent silent truncation:
assert every input INCLUDING special tokens fits; record full token lengths.
Do not expand/re-slice snippets. HCVR's ordinary CLI default is 512; this run
explicitly preserves the existing benchmark strings with a checked larger cap.

Run function and window concurrently on separate idle GPUs. Base and adapted
conditions share exactly the same saved candidate array, not independently
generated caches. Report no new cluster claims from a query-only adapter.

Reuse the original dimension-independent unit()/metric() functions, including
7-decimal cosine ties, stable row-ID ordering, identical-doc-hash relevance.
Report R@1, R@10, MRR and per-case rank changes. No threshold or checkpoint search.
Independently recompute all cosine scores/ranks, check query adaptation against
the saved weights, and verify alpha=0 rank parity before claiming completion.
Record file hashes, real subprocess exit codes, versions, weights, token budgets,
row identity, top candidates and vectors; verify copied outputs locally.

The old checkpoint is trained on historical security-guideline supervision;
this is transfer to general issue queries, not a retraining or end-to-end HCVR
replication. Base-model pretraining overlap is not known. Do not use results
to assert benchmark label quality or general guideline-cluster quality.
