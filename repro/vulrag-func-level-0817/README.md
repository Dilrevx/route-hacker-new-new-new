# VulRAG Function-Level Reproduction 0817

This module runs the function-level VulRAG baseline over the HCVR new-unified
v2 paper evaluation set. It keeps VulRAG's frozen knowledge corpus, three-way
BM25 retrieval, and official `detect_code` path. The LLM transport is replaced
with `agent exec` on the local machine.

## Evaluation Boundary

The authoritative dataset receipt is:

```text
new-impl/hcvr_new_unified_dataset_v2/receipts/
  hcvr_new_unified_paper_eval_rebalance_qa.v2.json
```

The receipt validates 143 cases. Their ordered identities and vulnerable
revisions are stored in:

```text
new-impl/hcvr_new_unified_dataset_v2/receipts/
  hcvr_new_unified_fix_revision_paper_eval_review.v2.jsonl
```

The corresponding anchors are in:

```text
new-impl/hcvr_new_unified_dataset_v2/dataset/
  new_unified_cases.v1.jsonl
```

Some repository layouts keep the same files under `assets/` and `output/`.
The QA receipt in both layouts has SHA-256
`3c2e02e9910059380f92c87dbef3f8cc16f2b9a95ae832585b5e53abbf589c84`.

VulRAG consumes functions rather than repositories. The offline builder uses
dataset anchors only to recover a real syntax-tree function at the vulnerable
revision. It emits:

- `private_provenance`: anchor path and lines, retained for input auditing.
- `runtime_packet`: function code and neutral source metadata passed to VulRAG.
- `*.unresolved.jsonl`: every case that cannot be represented as a function.

The runtime packet excludes CWE labels, root-cause text, patches, fix
revisions, known findings, and anchor locations as model instructions.

Supported function grammars are C#, Go, Java, JavaScript, PHP, Python, Ruby,
TypeScript, and TSX. Top-level scripts, templates, static field initializers,
and other non-function units remain unresolved instead of becoming synthetic
code windows.

## Dependencies

Use the existing W6 VulRAG environment and install local Tree-sitter grammar
wheels. The builder does not download grammars while it runs.

```bash
W6_ROOT=/path/to/w6-vulrag-baseline

"$W6_ROOT/.venv/bin/pip" install \
  tree-sitter \
  tree-sitter-c-sharp \
  tree-sitter-go \
  tree-sitter-java \
  tree-sitter-javascript \
  tree-sitter-php \
  tree-sitter-python \
  tree-sitter-ruby \
  tree-sitter-typescript
```

The local Agent CLI executable must be authenticated and able to run:

```bash
agent exec \
  --skip-git-repo-check \
  --ephemeral \
  --ignore-user-config \
  --ignore-rules \
  --disable hooks \
  --sandbox read-only \
  -m GPT-5.6-Sol \
  -c 'model_reasoning_effort="low"' \
  'Reply with OK only.'
```

## Build Function Packets

```bash
DATASET=/path/to/new-impl/hcvr_new_unified_dataset_v2
RUN_ROOT=/path/to/vulrag-func-level-0817

"$W6_ROOT/.venv/bin/python" \
  repro/vulrag-func-level-0817/build_function_packets.py \
  --allowlist "$DATASET/receipts/hcvr_new_unified_fix_revision_paper_eval_review.v2.jsonl" \
  --cases "$DATASET/dataset/new_unified_cases.v1.jsonl" \
  --out "$RUN_ROOT/function_packets.v2.jsonl" \
  --run-root "$RUN_ROOT/source-work" \
  --max-functions-per-case 1
```

Source archives, verified trees, or previous exact-revision checkouts can be
reused with `--archive-index`, `--verified-tree-root`,
`--existing-input-root`, and `--existing-queue`. Otherwise the builder tries
the repository URL and vulnerable revision from the allowlist.

The command always rewrites the packet file and its adjacent
`function_packets.v2.unresolved.jsonl` ledger.

## Run VulRAG With Local Agent CLI

Single-case smoke:

```bash
"$W6_ROOT/.venv/bin/python" \
  repro/vulrag-func-level-0817/run_vulrag_agent_batch.py \
  --packets "$RUN_ROOT/function_packets.v2.jsonl" \
  --w6-root "$W6_ROOT" \
  --config "$W6_ROOT/config/vulrag-function-breadth-provider-substituted-glm-5.2.json" \
  --out-dir "$RUN_ROOT/agent-smoke" \
  --agent "codex" \
  --model GPT-5.6-Sol \
  --reasoning-effort low \
  --limit 1
```

Two disjoint local workers:

```bash
MODEL=DeepSeek-V4-Flash
MODEL_SLUG=deepseek-v4-flash

COMMON_ARGS="--packets $RUN_ROOT/function_packets.v2.jsonl \
--w6-root $W6_ROOT \
--config $W6_ROOT/config/vulrag-function-breadth-provider-substituted-glm-5.2.json \
--agent codex \
--model $MODEL \
--reasoning-effort low \
--stride 2"

"$W6_ROOT/.venv/bin/python" \
  repro/vulrag-func-level-0817/run_vulrag_agent_batch.py \
  $COMMON_ARGS \
  --start-index 0 \
  --runtime-key "vulrag-func-level-0817-$MODEL_SLUG-shard-0" \
  --out-dir "$RUN_ROOT/$MODEL_SLUG/shard-0" &

"$W6_ROOT/.venv/bin/python" \
  repro/vulrag-func-level-0817/run_vulrag_agent_batch.py \
  $COMMON_ARGS \
  --start-index 1 \
  --runtime-key "vulrag-func-level-0817-$MODEL_SLUG-shard-1" \
  --out-dir "$RUN_ROOT/$MODEL_SLUG/shard-1" &

wait
```

Each concurrent shard needs a unique `--runtime-key`; the W6 adapter otherwise
rebuilds the same runtime copy. Each completed case writes an atomic JSON
receipt and is skipped on resume. A failed receipt is retried by the next run.

## Output

Each case receipt records:

- function identity and source hash;
- VulRAG retrieval/detection result;
- Agent CLI model and reasoning effort;
- LLM call count, latency, and aggregate CLI-reported tokens;
- frozen knowledge-base hash;
- completed or failed execution status.

Final reporting uses all 143 evaluation cases as the denominator:

```text
completed + failed + unresolved = 143
```

This is a provider-substituted, multi-language function-level reproduction. It
is reported separately from official native `gpt-4o-mini` VulRAG and from
repository-level blind auditing.

## 2026-08-18 Evaluation

The two local Agent CLI runs used the same 137 function packets, frozen VulRAG
knowledge, BM25 retrieval, official `detect_code` logic, and two-worker
execution. Only the Agent CLI model changed.

| Metric | GPT-5.6-Sol (low) | DeepSeek-V4-Flash (low) |
| --- | ---: | ---: |
| Evaluation denominator | 143 | 143 |
| Recoverable function packets | 137 | 137 |
| Completed / failed / unresolved | 137 / 0 / 6 | 137 / 0 / 6 |
| Vulnerable verdicts | 14 | 28 |
| Detection rate over 137 functions | 10.22% | 20.44% |
| Detection rate over 143 cases | 9.79% | 19.58% |
| LLM calls | 948 | 922 |
| CLI-reported tokens | 7,941,516 | 1,355,278 |

All 143 evaluation entries are known vulnerable cases. A `vulnerable` verdict
therefore counts as a function-level detection for this run. The six unresolved
cases remain in the denominator: four source locations are not functions and
two vulnerable source revisions could not be materialized.

The two models agreed on 107 of 137 completed functions (78.10%). Flash changed
30 verdicts: 22 from `no_vulnerability_found` to `vulnerable`, and 8 in the
opposite direction. Flash used 17.07% of the CLI-reported tokens used by the
GPT-5.6-Sol run. This is a model comparison, not an official VulRAG result.

Committed result artifacts:

- `results/gpt-5.6-sol-low/evaluation-summary.json`
- `results/deepseek-v4-flash-low/evaluation-summary.json`
- `results/model-comparison.json`
- `results/model-comparison.md`

Each evaluation summary contains the ordered 143-case ledger. Detailed prompts
and model outputs remain in the local per-case receipts and are not duplicated
in Git.
