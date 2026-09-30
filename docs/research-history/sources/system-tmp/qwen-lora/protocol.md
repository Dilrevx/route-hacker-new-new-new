# Frozen pilot: Qwen4B LoRA versus unadapted Qwen8B

2026-09-20. User requested a 4B fine-tuning trial against "7B"; provisionally
interpret the comparator as cached Qwen3-Embedding-8B pending clarification.
No deletion, no push, no changes to frozen repositories or existing environments.

This is exploratory: the existing test set and raw 4B results have already been
seen. Do not claim a new blind benchmark or functional-equivalence labels.

## Fixed learning protocol

- Existing function view only for training; 1710 train, 311 validation, 316 test.
  Preserve split IDs and inputs; verify repo/component/doc/code isolation.
- Train on issue -> pre-patch function pairs. No generated labels or teacher.
  Multi-positive query-to-code InfoNCE, temperature 0.05; same doc-hash positives,
  mask identical-code nonpositive pairs instead of forcing false negatives.
  Other in-batch pairs are weak negatives, not verified semantic negatives.
- Shared query/code encoder, LoRA rank16, alpha32, dropout0, q/k/v/o attention
  projections only; frozen original weights, train LoRA only. This changes the
  encoder and code vectors, unlike the old post-embedding query-only adapter.
- BF16 backbone, FP32 adapter/optimizer and normalized logits, SDPA, gradient
  checkpointing, actual contrastive batch32, no gradient accumulation.
- Two parallel trials, learning rates 1e-5 and 5e-5, seed17, three epochs each;
  AdamW weight decay0.01, 10% linear warmup then cosine decay, gradient clip1.
- Evaluate validation every epoch; choose among six epoch checkpoints by
  validation MRR, then R@10, then lower LR and earlier epoch. Record epoch0 as a
  no-training reference; report failure if the best trained checkpoint loses.
  Do not use 8B/test scores for checkpoint selection or subsequent tuning.
- Separate disposable smoke run before training verifies gradients, unchanged
  base weights, zero-LoRA identity, memory, save/reload and loss math. It uses
  train data only and never supplies a checkpoint to the real trials.

## Fixed inference protocol

- Use the same no-query-instruction policy as the preceding 0.6B/4B runs.
  This is a controlled legacy configuration, not a best-prompt comparison.
  Official Qwen guidance recommends task instructions; acknowledge that limit.
- Final test: selected trained 4B and raw 8B, function and window views. Both
  query and candidate vectors are recomputed with the same selected encoder.
  Training uses function view; window result measures transfer without retraining.
- All final test inference FP32, no TF32/autocast, batch16, last-token pooling,
  full input length validation (max4096, no silent truncation). Raw4B references
  are existing FP32 results on identical IDs. Raw8B is sharded over two GPUs,
  without CPU/disk offload or model quantization.
- Same original cosine, 7-decimal tie handling, row-ID stable ranking, doc-hash
  relevance. R@10 primary comparison, also R@1/MRR and paired query deltas.
- Independently recalculate scores/ranks locally and verify checkpoint/output
  hashes and real process exit receipts. Keep all trials and failed diagnostics.

Implementation sources: official Qwen model cards, PEFT LoRA documentation,
SentenceTransformer device-map documentation. Dependencies resolved to an
isolated directory and recorded before model runs.
