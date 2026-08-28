#!/usr/bin/env python3
"""Build an advisory LLM judge pack for recall candidate-pair diagnostics."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def safe_slug(value: str) -> str:
    return "".join(char if char.isalnum() else "_" for char in value).strip("_")[:120] or "case"


def normalize_rank(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value > 0:
        return value
    if isinstance(value, str) and value.isdigit():
        parsed = int(value)
        return parsed if parsed > 0 else None
    return None


def group_by_identity(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        identity = str(row.get("identity_key") or "")
        if identity:
            grouped.setdefault(identity, []).append(row)
    for identity_rows in grouped.values():
        identity_rows.sort(key=lambda row: normalize_rank(row.get("rank")) or 10**12)
    return grouped


def index_recall_results(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for row in rows:
        identity = str(row.get("identity_key") or "")
        if not identity:
            continue
        if identity in indexed:
            raise ValueError(f"duplicate recall result identity_key: {identity}")
        indexed[identity] = row
    return indexed


def bounded_path(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve()
    root_resolved = root.resolve()
    try:
        candidate.relative_to(root_resolved)
    except ValueError as exc:
        raise ValueError(f"candidate path escapes snapshot root: {relative}") from exc
    return candidate


def read_candidate_snippet(snapshot: Path, candidate: dict[str, Any], max_chars: int) -> str:
    file_name = str(candidate.get("file") or "")
    start_line = normalize_rank(candidate.get("start_line")) or 1
    end_line = normalize_rank(candidate.get("end_line")) or start_line
    path = bounded_path(snapshot, file_name)
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return ""
    start_index = max(0, start_line - 1)
    end_index = min(len(lines), max(start_index + 1, end_line))
    snippet_lines = [
        f"{line_number}: {line}"
        for line_number, line in enumerate(lines[start_index:end_index], start=start_line)
    ]
    text = "\n".join(snippet_lines)
    return text[:max_chars] if max_chars > 0 else text


def label_assignment(identity_key: str) -> tuple[str, str]:
    digest = hashlib.sha256(identity_key.encode("utf-8")).hexdigest()
    if int(digest[:2], 16) % 2 == 0:
        return "A", "B"
    return "B", "A"


def make_candidate_payload(
    *,
    label: str,
    candidate: dict[str, Any],
    snapshot: Path,
    max_snippet_chars: int,
) -> dict[str, Any]:
    return {
        "label": label,
        "file": candidate.get("file"),
        "lines": {
            "start": candidate.get("start_line"),
            "end": candidate.get("end_line"),
        },
        "symbol": candidate.get("symbol") or "",
        "span_kind": candidate.get("span_kind") or "",
        "snippet": read_candidate_snippet(snapshot, candidate, max_snippet_chars),
    }


def pair_prompt(item: dict[str, Any]) -> str:
    instruction = {
        "task": "Compare two anonymous recall candidates for one security guideline.",
        "review_scope": [
            "Judge semantic match to the guideline only.",
            "Choose the candidate that is more useful for a downstream security audit.",
            "Use only the guideline text, file path, symbol, and source snippet shown here.",
            "Do not infer from CVE IDs, known-anchor labels, rank, score, or benchmark metadata; those fields are intentionally omitted.",
            "Do not call tools, do not run shell commands, and do not try to write files; return the JSON object as the final answer only.",
        ],
        "expected_json": {
            "choice": "A|B|tie|neither",
            "candidate_a_relevance": 0.0,
            "candidate_b_relevance": 0.0,
            "confidence": 0.0,
            "rationale": "short explanation",
            "key_evidence": ["evidence in the chosen snippet"],
            "missing_information": ["what would be needed to judge better"],
        },
    }
    public_payload = {
        "judge_mode": "recall_candidate_pair_advisory",
        "guideline": item["guideline"],
        "candidates": item["candidates"],
    }
    return "\n".join(
        [
            "# Recall Candidate Pair Judge",
            "",
            "This is an advisory semantic QA task for recall diagnostics.",
            "It does not change retrieval rankings and it is not a vulnerability verdict.",
            "",
            "Instructions:",
            json.dumps(instruction, ensure_ascii=False, indent=2, sort_keys=True),
            "",
            "Payload:",
            json.dumps(public_payload, ensure_ascii=False, indent=2, sort_keys=True),
            "",
            "Return JSON only. Do not call tools or run commands.",
        ]
    )


def write_runner(output_dir: Path, *, default_cli: str, default_model: str) -> None:
    model_line = f'LLM_JUDGE_MODEL="${{LLM_JUDGE_MODEL:-{default_model}}}"' if default_model else 'LLM_JUDGE_MODEL="${LLM_JUDGE_MODEL:-}"'
    script_lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        'LLM_JUDGE_CLI="${LLM_JUDGE_CLI:-' + default_cli + '}"',
        model_line,
        'CONCURRENCY="${LLM_JUDGE_CONCURRENCY:-1}"',
        'case "$CONCURRENCY" in',
        '  ""|*[!0-9]*) echo "LLM_JUDGE_CONCURRENCY must be a positive integer" >&2; exit 2 ;;',
        "esac",
        'if [ "$CONCURRENCY" -lt 1 ]; then',
        '  echo "LLM_JUDGE_CONCURRENCY must be >= 1" >&2',
        "  exit 2",
        "fi",
        'run_with_timeout() {',
        '  local seconds="${LLM_JUDGE_TIMEOUT_SECONDS:-1800}"',
        '  if command -v timeout >/dev/null 2>&1; then',
        '    timeout "${seconds}s" "$@"',
        '  elif command -v perl >/dev/null 2>&1; then',
        '    perl -e \'alarm shift; exec @ARGV\' "$seconds" "$@"',
        "  else",
        '    "$@"',
        "  fi",
        "}",
        'OUT_DIR="${1:-judge_outputs}"',
        'mkdir -p "$OUT_DIR"',
        'run_one() {',
        '  local prompt="$1"',
        '  local name',
        '  name="$(basename "$prompt" .md)"',
        '  local args=("$LLM_JUDGE_CLI" exec --sandbox read-only)',
        '  if [ -n "$LLM_JUDGE_MODEL" ]; then',
        '    args+=(--model "$LLM_JUDGE_MODEL")',
        "  fi",
        '  if [ -n "${LLM_JUDGE_EXTRA_ARGS:-}" ]; then',
        '    # shellcheck disable=SC2206',
        '    args+=(${LLM_JUDGE_EXTRA_ARGS})',
        "  fi",
        '  run_with_timeout "${args[@]}" -o "$OUT_DIR/$name.json" < "$prompt"',
        "}",
        "export OUT_DIR LLM_JUDGE_CLI LLM_JUDGE_MODEL LLM_JUDGE_EXTRA_ARGS LLM_JUDGE_TIMEOUT_SECONDS",
        "export -f run_with_timeout run_one",
        'find prompts -name "*.md" -type f | sort | xargs -n 1 -P "$CONCURRENCY" bash -c \'run_one "$1"\' _',
        "",
    ]
    runner = output_dir / "run_agent_judge.sh"
    runner.write_text("\n".join(script_lines), encoding="utf-8")
    runner.chmod(0o755)


def build_judge_items(
    *,
    recall_results: list[dict[str, Any]],
    top_candidates: list[dict[str, Any]],
    max_snippet_chars: int,
    max_rows: int,
    allow_empty_snippets: bool = False,
) -> list[dict[str, Any]]:
    recall_by_identity = index_recall_results(recall_results)
    candidates_by_identity = group_by_identity(top_candidates)
    items: list[dict[str, Any]] = []
    for identity in sorted(candidates_by_identity):
        recall_row = recall_by_identity.get(identity)
        if not recall_row:
            continue
        candidates = candidates_by_identity[identity]
        top1 = candidates[0] if candidates else None
        anchor = next((row for row in candidates if row.get("known_anchor_overlap")), None)
        if not top1 or not anchor:
            continue
        if top1 is anchor:
            continue
        top1_anchor_id = top1.get("anchor_id")
        overlap_anchor_id = anchor.get("anchor_id")
        if top1_anchor_id and overlap_anchor_id and top1_anchor_id == overlap_anchor_id:
            continue
        snapshot = Path(str(recall_row.get("snapshot") or ""))
        anchor_label, top1_label = label_assignment(identity)
        candidate_payloads = [
            make_candidate_payload(
                label=anchor_label,
                candidate=anchor,
                snapshot=snapshot,
                max_snippet_chars=max_snippet_chars,
            ),
            make_candidate_payload(
                label=top1_label,
                candidate=top1,
                snapshot=snapshot,
                max_snippet_chars=max_snippet_chars,
            ),
        ]
        if not allow_empty_snippets and any(not row["snippet"].strip() for row in candidate_payloads):
            continue
        candidate_payloads.sort(key=lambda row: row["label"])
        items.append(
            {
                "identity_key": identity,
                "case_id": recall_row.get("case_id"),
                "repo_key": recall_row.get("repo_key"),
                "hcvr_type": recall_row.get("hcvr_type"),
                "guideline": recall_row.get("guideline"),
                "prompt_file": f"prompts/{safe_slug(identity)}.md",
                "output_file": f"{safe_slug(identity)}.json",
                "judge_mode": "recall_candidate_pair_advisory",
                "hidden_expected_anchor_label": anchor_label,
                "hidden_top1_label": top1_label,
                "hidden_anchor_rank": anchor.get("rank"),
                "hidden_top1_rank": top1.get("rank"),
                "hidden_anchor_file": anchor.get("file"),
                "hidden_top1_file": top1.get("file"),
                "hidden_anchor_score": anchor.get("score"),
                "hidden_top1_score": top1.get("score"),
                "candidate_count": recall_row.get("candidate_count"),
                "known_anchor_count": recall_row.get("known_anchor_count"),
                "candidates": candidate_payloads,
                "policy": "advisory_semantic_pair_judge_not_recall_metric_not_hidden_routing",
            }
        )
        if max_rows > 0 and len(items) >= max_rows:
            break
    return items


def write_readme(output_dir: Path, *, row_count: int, default_cli: str, default_model: str) -> None:
    model_note = f" Defaults to `{default_model}`." if default_model else ""
    lines = [
        "# Recall Candidate Pair Judge Pack",
        "",
        "This pack asks LLM-as-judge to compare anonymous recall candidates for semantically clean ranked misses.",
        "It is advisory semantic QA only: it does not update guidelines, does not score embedding recall, and does not gate Top-K claims.",
        "",
        "## Inputs",
        "",
        f"- Pair prompts: {row_count}",
        "- Each prompt compares the current Top-1 candidate with the best exported known-anchor-overlap candidate.",
        "- The prompt omits rank, score, known-anchor labels, CVE IDs, and benchmark metadata.",
        "- By default, pairs whose source snippets cannot be read from the snapshot path are skipped.",
        "- `judge_inputs.jsonl` keeps hidden labels for offline analysis after the judge run.",
        "",
        "## Run",
        "",
        "```bash",
        "LLM_JUDGE_CLI=codex LLM_JUDGE_MODEL=DeepSeek-V4-Pro LLM_JUDGE_CONCURRENCY=2 LLM_JUDGE_TIMEOUT_SECONDS=1800 ./run_agent_judge.sh judge_outputs",
        "```",
        "",
        f"The runner defaults to `{default_cli}`.{model_note} Override both with environment variables when the local provider changes.",
        "",
        "## Summarize",
        "",
        "```bash",
        "python3 ../../scripts/summarize_recall_candidate_pair_judge_outputs.py \\",
        "  --judge-inputs judge_inputs.jsonl \\",
        "  --judge-output-dir judge_outputs \\",
        "  --output-dir judge_summary",
        "```",
        "",
        "Use this only to decide whether a semantic reranker is worth a same-identity A/B. Do not feed choices back into retrieval labels or guideline generation.",
        "",
    ]
    (output_dir / "README.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--recall-results", type=Path, required=True)
    parser.add_argument("--top-candidates", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--max-snippet-chars", type=int, default=4000)
    parser.add_argument("--max-rows", type=int, default=0, help="0 means all eligible pairs.")
    parser.add_argument(
        "--allow-empty-snippets",
        action="store_true",
        help="Generate prompts even when candidate source snippets cannot be read.",
    )
    parser.add_argument("--default-cli", default="codex")
    parser.add_argument("--default-model", default="DeepSeek-V4-Pro")
    args = parser.parse_args()
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise FileExistsError(f"refusing to overwrite non-empty output directory: {args.output_dir}")
    if args.max_snippet_chars < 0:
        raise SystemExit("--max-snippet-chars cannot be negative")
    if args.max_rows < 0:
        raise SystemExit("--max-rows cannot be negative")

    items = build_judge_items(
        recall_results=read_jsonl(args.recall_results),
        top_candidates=read_jsonl(args.top_candidates),
        max_snippet_chars=args.max_snippet_chars,
        max_rows=args.max_rows,
        allow_empty_snippets=args.allow_empty_snippets,
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    prompts_dir = args.output_dir / "prompts"
    prompts_dir.mkdir(parents=True, exist_ok=True)
    public_inputs: list[dict[str, Any]] = []
    for item in items:
        prompt_path = args.output_dir / item["prompt_file"]
        prompt_path.write_text(pair_prompt(item), encoding="utf-8")
        public_item = {key: value for key, value in item.items() if key != "candidates"}
        public_inputs.append(public_item)
    write_jsonl(args.output_dir / "judge_inputs.jsonl", public_inputs)
    write_runner(args.output_dir, default_cli=args.default_cli, default_model=args.default_model)
    write_readme(args.output_dir, row_count=len(items), default_cli=args.default_cli, default_model=args.default_model)
    print(json.dumps({"row_count": len(items), "output_dir": str(args.output_dir)}, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
