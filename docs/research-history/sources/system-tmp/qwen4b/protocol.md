# Qwen3-Embedding-4B, unchanged benchmark backend replacement

2026-09-20. User asks for Qwen4B after seeing Qwen0.6B/HCVR results.
Inference only, no adapter, no training, no RQ-VAE, no prompt search or benchmark
repair. Preserve all prior runs and frozen repositories; no deletion or push.

Use the exact same function/window test rows (316 each), source/issue strings,
row IDs, candidate pool, labels and original metric implementation as the
immediately preceding 0.6B comparison. Native 4B embedding dimension is 2560.
Use the previous raw SentenceTransformersEmbedder class directly from its pinned
source snapshot, with original last-token pooling, no prompt, FP32, no TF32 or
autocast, eval/no-grad, batch16, and max_seq_length4096 plus strict full-input
token-length checks. Do not reuse 0.6B vectors with the new model.
Export vectors to NumPy in one batch, as in the 0.6B P3C64 backend, instead of
per-scalar CUDA transfers in the generic backend; verify numerical parity with
the unmodified generic backend on the first query before full encoding.

Two independent view jobs run in parallel on two idle GPUs. Same 7-decimal cosine
ties, stable row-ID tie resolution, identical-doc-hash relevance. Report R@1,
R@10, MRR, and per-case changes relative to raw Qwen0.6B; compare historical
UniXcoder/HCVR numbers only on the same test IDs. Native dimensions differ, so
this is an off-the-shelf model comparison, not isolation of parameter count.

Verify finite normalized vectors, repeated small-batch encoding, all scores and
ranks through independent calculations, real subprocess exit codes, model/input
hashes, and a second local reload/recalculation. Save vectors and top candidates.
Do not claim that checkpoint hash checks establish unknown pretraining overlap.
