# Previous method baseline

This directory preserves the historical P3 query-adapter experiment and connects
it to the dataset, inference code, guideline generation, and audit modules already
in this repository. It is an archival baseline, not a new training run.

**P3C64 uses Qwen3-Embedding-0.6B plus a query-only residual MLP.** The code encoder
is frozen. The separate frozen Qwen3-Embedding-4B comparison and the later 4B
query-LoRA experiments are not this model.

## Contents

| Location | Preserved material |
| --- | --- |
| [p3c64](p3c64/) | 68 original files: protocol, frozen cases and pairs, both P3C16 and P3C64 weights, training and competition ledgers, selection and external evaluation records, and 13 historical scripts |
| [helpers](helpers/) | Recovered M5 helper dependency closure, exact P4 generic-view builder, and guideline track definitions |
| [archive manifest](archive-manifest.json) | Sizes and SHA-256 hashes of the archived files |
| [verification tools](tools/) | Offline hash, split, ranking, and optional checkpoint checks |
| [verification receipt](verification-receipt.json) | Source-hash, metric, checkpoint, and public-download checks performed for this archive |
| [existing fixed143 results](../../new-impl/new-guideline/results/p3c64-fixed143-paper-eval-20260820/) | P3C64 and frozen 4B per-case rank tables, frozen identities, and comparison summaries |

The archived files retain their original bytes, including historical local paths.
Those paths are provenance, not portable defaults or instructions to overwrite a
current experiment. This is not an anonymized submission package. No server files
were deleted to create this archive.

## Model and data

The selected checkpoint is
[`p3c64/selection_run_v1/p3c64_state.pt`](p3c64/selection_run_v1/p3c64_state.pt):

- Frozen backbone: `Qwen/Qwen3-Embedding-0.6B`, historical snapshot
  `97b0c614be4d77ee51c0cef4e5f07c00f9eb65b3`.
- Query adapter: `1024 → 128 → 1024`, GELU, residual scale `0.1`, followed by
  normalization; no code-side adapter.
- Checkpoint SHA-256:
  `5425766d0dff286fb78f218808b21f8a502b85be170f6a8c911f7db761bc8e16`.
- Frozen development data: 155 cases, with 112 fitting and 43 selection cases;
  295 pair records, split 217 / 78; ten guideline tracks.
- Training competitors are unlabeled same-repository code, not certified-safe
  negative examples. Source anchors define positive bags for offline supervision.

P3C16 and its results are retained alongside the selected P3C64 variant. The
historical protocol's `pre_registered_not_executed` field describes when that
protocol was frozen; the separate selection outputs record its subsequent run.

## Result scopes

These are different evaluations and must not be combined into a single score.
The verifier recomputes the recorded metrics from the case-level rank ledgers.

| Scope | Model | Recall@30 | Recall@50 | Recall@100 |
| --- | --- | ---: | ---: | ---: |
| Original 43-case selection | Frozen 0.6B B0 | 25/43 | 28/43 | 31/43 |
| Original 43-case selection | P3C64 | 31/43 | 32/43 | 35/43 |
| P4 external, 21 covered cases | Frozen 0.6B B0 | 1/21 | 2/21 | 2/21 |
| P4 external, 21 covered cases | P3C64 | 5/21 | 6/21 | 10/21 |
| Fixed143 historical evaluation | Frozen 4B | 30/143 | 37/143 | 55/143 |
| Fixed143 historical evaluation | P3C64 | 45/143 | 56/143 | 73/143 |

The 43 cases were used for model selection, not a blind test. P4 contains 22
source cases; one has no mapped positive in the generated candidate universe and
is excluded from the 21-case retrieval metric, with its coverage record retained.
The fixed143 comparison uses the same 143 case identities, but its existing
comparison record reports different candidate counts for one case. It is not
evidence that the two candidate banks are byte-identical. The later September
4B experiments rebuilt their candidate inputs and are a separate experiment
family, even when they reuse case identities.

## Verify without a GPU

From the repository root, with Python 3.9 or newer:

```bash
python3 baselines/previous-method/tools/verify_baseline.py
python3 -m unittest discover -s baselines/previous-method/tools -p 'test_*.py'
```

The default verification uses only the standard library. With PyTorch available,
add `--check-weights` to validate both saved state dictionaries using
`weights_only=True`, including tensor keys, shapes, data types, and finite values.
These checks validate the preserved artifacts and recorded results; they do not
rerun training or embedding inference.

## Use the selected checkpoint

The existing inference implementation is
[`P3C64QueryResidualEmbedder`](../../new-impl/new-guideline/scripts/recall_guideline_anchors.py).
It requires PyTorch and Sentence Transformers, a local copy of the 0.6B model,
and source snapshots or network access to obtain the selected repositories.
The public model identifier alone is not a revision pin: use a local checkout of
the historical snapshot above when reproducing its encoder.

Example from the repository root, after setting `P3_MODEL_DIR` to that local model
directory and `P3_RUN_DIR` to a fresh, non-existing output directory:

```bash
python3 new-impl/new-guideline/scripts/recall_guideline_anchors.py \
  --qa new-impl/hcvr_new_unified_dataset_v2/receipts/hcvr_new_unified_paper_eval_rebalance_qa.v2.json \
  --cases-file new-impl/hcvr_new_unified_dataset_v2/dataset/new_unified_cases.v1.jsonl \
  --identity-file new-impl/new-guideline/results/p3c64-fixed143-paper-eval-20260820/paper_eval_143_identities.jsonl \
  --selection all --limit 143 --top-k 200 \
  --embedding-backend p3c64-query-residual \
  --embedding-model "$P3_MODEL_DIR" --embedding-device cuda \
  --p3c64-state baselines/previous-method/p3c64/selection_run_v1/p3c64_state.pt \
  --p3c64-hidden-dimension 128 --p3c64-residual-scale 0.1 \
  --max-seq-length 512 --text-max-chars 4000 \
  --output-dir "$P3_RUN_DIR" \
  --repo-cache "$P3_RUN_DIR-repo-cache" \
  --snapshot-root "$P3_RUN_DIR-snapshots"
```

This is a new inference run using the archived state, not a guarantee of exact
historical candidate generation. Record the model revision, source revisions,
candidate counts, selection, and all generation flags when comparing results.
Run `--help` before changing budgets or guideline inputs. The command was checked
against the current CLI; the full 143-repository job was not rerun for this archive.

## Existing pipeline components

Use the repository's existing implementations rather than a second copy:

- [Unified v2 cases, anchors, and receipts](../../new-impl/hcvr_new_unified_dataset_v2/).
- [Guideline generation and releases](../../new-impl/new-guideline/).
- [Recall and bounded auditing](../../new-impl/guideline-agent-pipeline/).
- [Build preparation](../../new-impl/compile-builder-v2/),
  [PoC runner](../../new-impl/poc-agent-runner/), and
  [runtime verifier](../../new-impl/runtime-v2-verifier-redesign/).
- [Historical model-size comparisons](../../new-impl/guideline-agent-pipeline/results/model_ablation_qwen_size_30/).

These links identify existing modules; this archival operation does not certify a
new end-to-end run across all of them.

## Preservation boundaries

The original fitting executor `run_m7_strict_runtime_residual_biencoder_v1.py`,
two original `/tmp` candidate pools, and their embedding caches were not found
during recovery. The locked M5 helper was recovered from an older script archive.
Consequently, **exact historical retraining is not restored**. The selected model,
frozen labels, historical scripts, result ledgers, and current inference code are
preserved; substituting September's rebuilt 4B pools would create a different run.

The 2.1 GB P4 pool contains third-party source snippets and is not included in
ordinary Git; its original summary, generation recipe, coverage, and hashes are
retained. A full local recovery copy has been verified against its original hash;
public redistribution requires a separate source and license review.

The two complete fixed143 ranking files are distributed as gzip attachments in
the [baseline release](https://github.com/Dilrevx/route-hacker-new-new-new/releases/tag/previous-method-baseline-20260930),
not as large Git blobs. [rank-assets.json](rank-assets.json) records both compressed
and original hashes. Decompression restores the original JSONL bytes, including
historical local paths. These files contain candidate locations, scores, overlap
labels, and ranks, not source text. Their ranks were checked against the tracked
compact tables, including every candidate and the first matching rank per case.

Server originals remain untouched. See [preservation inventory](preservation-inventory.json)
for the status of large and missing assets. A manifest alone is not a backup of
the corresponding large file.

The recent private `embed` query-LoRA research is not silently republished here.
Its public release scope must be decided separately from this historical archive.
