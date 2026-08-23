#!/usr/bin/env python3
"""Build an advisory TraeX judge pack for list-wise recall reranking diagnostics."""

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


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def safe_slug(value: str) -> str:
    return "".join(char if char.isalnum() else "_" for char in value).strip("_")[:120] or "case"


def normalize_positive_int(value: Any) -> int | None:
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
        identity_rows.sort(key=lambda row: normalize_positive_int(row.get("rank")) or 10**12)
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
    start_line = normalize_positive_int(candidate.get("start_line")) or 1
    end_line = normalize_positive_int(candidate.get("end_line")) or start_line
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


def candidate_shuffle_key(identity_key: str, candidate: dict[str, Any]) -> str:
    stable = "|".join(
        [
            identity_key,
            str(candidate.get("anchor_id") or ""),
            str(candidate.get("file") or ""),
            str(candidate.get("start_line") or ""),
            str(candidate.get("end_line") or ""),
        ]
    )
    return hashlib.sha256(stable.encode("utf-8")).hexdigest()


def candidate_public_payload(candidate_id: str, candidate: dict[str, Any], snippet: str) -> dict[str, Any]:
    return {
        "candidate_id": candidate_id,
        "file": candidate.get("file"),
        "lines": {
            "start": candidate.get("start_line"),
            "end": candidate.get("end_line"),
        },
        "symbol": candidate.get("symbol") or "",
        "span_kind": candidate.get("span_kind") or "",
        "snippet": snippet,
    }


def candidate_hidden_payload(candidate_id: str, candidate: dict[str, Any], prompt_position: int) -> dict[str, Any]:
    return {
        "candidate_id": candidate_id,
        "prompt_position": prompt_position,
        "anchor_id": candidate.get("anchor_id"),
        "rank": candidate.get("rank"),
        "score": candidate.get("score"),
        "known_anchor_overlap": bool(candidate.get("known_anchor_overlap")),
        "file": candidate.get("file"),
        "start_line": candidate.get("start_line"),
        "end_line": candidate.get("end_line"),
        "symbol": candidate.get("symbol") or "",
    }


def list_prompt(item: dict[str, Any]) -> str:
    instruction = {
        "task": "Score anonymous recall candidates for one security guideline.",
        "review_scope": [
            "Judge semantic match to the guideline only.",
            "For each candidate, estimate whether it is useful as an audit entry point.",
            "Use only the guideline text, file path, symbol, and source snippet shown here.",
            "Do not infer from CVE IDs, known-anchor labels, original rank, original score, or benchmark metadata; those fields are intentionally omitted.",
            "Do not call tools, do not run shell commands, and do not try to write files; return the JSON object as the final answer only.",
        ],
        "expected_json": {
            "candidate_scores": [
                {
                    "candidate_id": "C001",
                    "relevance": 0.0,
                    "audit_priority": "high|medium|low|none",
                    "rationale": "short explanation",
                    "key_evidence": ["evidence in this snippet"],
                }
            ],
            "top_choices": ["C001"],
            "confidence": 0.0,
            "missing_information": ["what would be needed to judge better"],
        },
    }
    public_payload = {
        "judge_mode": "recall_candidate_list_advisory",
        "guideline": item["guideline"],
        "shard": {
            "shard_index": item["shard_index"],
            "shard_count": item["shard_count"],
            "candidate_count": len(item["candidates"]),
        },
        "candidates": item["candidates"],
    }
    return "\n".join(
        [
            "# Recall Candidate List Judge",
            "",
            "This is an advisory semantic QA task for recall reranking diagnostics.",
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
    model_line = f'TRAE_JUDGE_MODEL="${{TRAE_JUDGE_MODEL:-{default_model}}}"' if default_model else 'TRAE_JUDGE_MODEL="${TRAE_JUDGE_MODEL:-}"'
    script_lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        'TRAE_JUDGE_CLI="${TRAE_JUDGE_CLI:-' + default_cli + '}"',
        model_line,
        'CONCURRENCY="${TRAE_JUDGE_CONCURRENCY:-1}"',
        'case "$CONCURRENCY" in',
        '  ""|*[!0-9]*) echo "TRAE_JUDGE_CONCURRENCY must be a positive integer" >&2; exit 2 ;;',
        "esac",
        'if [ "$CONCURRENCY" -lt 1 ]; then',
        '  echo "TRAE_JUDGE_CONCURRENCY must be >= 1" >&2',
        "  exit 2",
        "fi",
        'run_with_timeout() {',
        '  local seconds="${TRAE_JUDGE_TIMEOUT_SECONDS:-1800}"',
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
        '  local args=("$TRAE_JUDGE_CLI" exec --sandbox read-only)',
        '  if [ -n "$TRAE_JUDGE_MODEL" ]; then',
        '    args+=(--model "$TRAE_JUDGE_MODEL")',
        "  fi",
        '  if [ -n "${TRAE_JUDGE_EXTRA_ARGS:-}" ]; then',
        '    # shellcheck disable=SC2206',
        '    args+=(${TRAE_JUDGE_EXTRA_ARGS})',
        "  fi",
        '  run_with_timeout "${args[@]}" -o "$OUT_DIR/$name.json" < "$prompt"',
        "}",
        "export OUT_DIR TRAE_JUDGE_CLI TRAE_JUDGE_MODEL TRAE_JUDGE_EXTRA_ARGS TRAE_JUDGE_TIMEOUT_SECONDS",
        "export -f run_with_timeout run_one",
        'find prompts -name "*.md" -type f | sort | xargs -n 1 -P "$CONCURRENCY" bash -c \'run_one "$1"\' _',
        "",
    ]
    runner = output_dir / "run_traex_judge.sh"
    runner.write_text("\n".join(script_lines), encoding="utf-8")
    runner.chmod(0o755)


def chunked(rows: list[dict[str, Any]], chunk_size: int) -> Iterable[list[dict[str, Any]]]:
    for index in range(0, len(rows), chunk_size):
        yield rows[index : index + chunk_size]


def build_judge_items(
    *,
    recall_results: list[dict[str, Any]],
    top_candidates: list[dict[str, Any]],
    max_rank: int,
    candidates_per_prompt: int,
    max_snippet_chars: int,
    max_cases: int,
    allow_empty_snippets: bool = False,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if max_rank <= 0:
        raise ValueError("max_rank must be positive")
    if candidates_per_prompt <= 0:
        raise ValueError("candidates_per_prompt must be positive")
    recall_by_identity = index_recall_results(recall_results)
    candidates_by_identity = group_by_identity(top_candidates)
    items: list[dict[str, Any]] = []
    skipped_empty = 0
    skipped_no_candidates = 0
    selected_identities = 0
    for identity in sorted(candidates_by_identity):
        recall_row = recall_by_identity.get(identity)
        if not recall_row:
            continue
        ranked = [
            row
            for row in candidates_by_identity[identity]
            if (normalize_positive_int(row.get("rank")) or 10**12) <= max_rank
        ]
        if not ranked:
            skipped_no_candidates += 1
            continue
        selected_identities += 1
        snapshot = Path(str(recall_row.get("snapshot") or ""))
        public_candidates: list[dict[str, Any]] = []
        hidden_candidates: list[dict[str, Any]] = []
        for candidate in sorted(ranked, key=lambda row: candidate_shuffle_key(identity, row)):
            snippet = read_candidate_snippet(snapshot, candidate, max_snippet_chars)
            if not snippet.strip() and not allow_empty_snippets:
                skipped_empty += 1
                continue
            candidate_id = f"C{len(public_candidates) + 1:03d}"
            public_candidates.append(candidate_public_payload(candidate_id, candidate, snippet))
            hidden_candidates.append(candidate_hidden_payload(candidate_id, candidate, len(public_candidates)))
        if not public_candidates:
            skipped_no_candidates += 1
            continue
        shards = list(chunked(public_candidates, candidates_per_prompt))
        hidden_by_id = {row["candidate_id"]: row for row in hidden_candidates}
        for shard_index, shard in enumerate(shards, start=1):
            shard_hidden = [hidden_by_id[row["candidate_id"]] for row in shard]
            items.append(
                {
                    "identity_key": identity,
                    "case_id": recall_row.get("case_id"),
                    "repo_key": recall_row.get("repo_key"),
                    "hcvr_type": recall_row.get("hcvr_type"),
                    "guideline": recall_row.get("guideline"),
                    "shard_index": shard_index,
                    "shard_count": len(shards),
                    "prompt_file": f"prompts/{safe_slug(identity)}.shard{shard_index:03d}.md",
                    "output_file": f"{safe_slug(identity)}.shard{shard_index:03d}.json",
                    "judge_mode": "recall_candidate_list_advisory",
                    "hidden_candidates": shard_hidden,
                    "candidate_count": recall_row.get("candidate_count"),
                    "judged_candidate_count": len(public_candidates),
                    "known_anchor_count": recall_row.get("known_anchor_count"),
                    "max_rank": max_rank,
                    "candidates": shard,
                    "policy": "advisory_semantic_list_judge_not_recall_metric_not_hidden_routing",
                }
            )
        if max_cases > 0 and selected_identities >= max_cases:
            break
    build_summary = {
        "schema_version": "hcvr_recall_candidate_list_judge_pack.v1",
        "identity_count": selected_identities,
        "prompt_count": len(items),
        "max_rank": max_rank,
        "candidates_per_prompt": candidates_per_prompt,
        "max_snippet_chars": max_snippet_chars,
        "skipped_empty_snippet_candidates": skipped_empty,
        "skipped_no_candidate_identities": skipped_no_candidates,
        "policy": [
            "Prompts hide original rank, score, known-anchor labels, CVE IDs, and benchmark metadata.",
            "Hidden labels are stored only in judge_inputs.jsonl for offline post-run diagnostics.",
            "This pack is advisory semantic QA for reranker design, not a recall result.",
        ],
    }
    return items, build_summary


def write_readme(output_dir: Path, *, build_summary: dict[str, Any], default_cli: str, default_model: str) -> None:
    model_note = f" Defaults to `{default_model}`." if default_model else ""
    lines = [
        "# Recall Candidate List Judge Pack",
        "",
        "This pack asks TraeX/LLM-as-judge to score shuffled Top-N recall candidates for each case.",
        "It is advisory semantic QA only: it does not update guidelines, does not score embedding recall, and does not gate Top-K claims.",
        "",
        "## Inputs",
        "",
        f"- Identities: {build_summary['identity_count']}",
        f"- Prompt shards: {build_summary['prompt_count']}",
        f"- Candidate max rank: {build_summary['max_rank']}",
        f"- Candidates per prompt: {build_summary['candidates_per_prompt']}",
        f"- Skipped unreadable snippets: {build_summary['skipped_empty_snippet_candidates']}",
        "",
        "Each prompt omits original rank, score, known-anchor labels, CVE IDs, and benchmark metadata.",
        "`judge_inputs.jsonl` keeps hidden metadata only for offline analysis after judge completion.",
        "",
        "## Run",
        "",
        "```bash",
        "TRAE_JUDGE_CLI=traex TRAE_JUDGE_MODEL=DeepSeek-V4-Pro TRAE_JUDGE_EXTRA_ARGS='--disallowed-tool exec' TRAE_JUDGE_CONCURRENCY=2 TRAE_JUDGE_TIMEOUT_SECONDS=1800 ./run_traex_judge.sh judge_outputs",
        "```",
        "",
        f"The runner defaults to `{default_cli}`.{model_note} Override both with environment variables when the local provider changes.",
        "",
        "## Summarize",
        "",
        "```bash",
        "python3 ../../scripts/summarize_recall_candidate_list_judge_outputs.py \\",
        "  --judge-inputs judge_inputs.jsonl \\",
        "  --judge-output-dir judge_outputs \\",
        "  --output-dir judge_summary",
        "```",
        "",
        "Use this only to decide whether a semantic reranker/query A/B is worth running. Do not feed choices back into retrieval labels or guideline generation.",
        "",
    ]
    (output_dir / "README.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--recall-results", type=Path, required=True)
    parser.add_argument("--top-candidates", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--max-rank", type=int, default=200)
    parser.add_argument("--candidates-per-prompt", type=int, default=20)
    parser.add_argument("--max-snippet-chars", type=int, default=1200)
    parser.add_argument("--max-cases", type=int, default=0, help="0 means all eligible identities.")
    parser.add_argument("--allow-empty-snippets", action="store_true")
    parser.add_argument("--default-cli", default="traex")
    parser.add_argument("--default-model", default="DeepSeek-V4-Pro")
    args = parser.parse_args()
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise FileExistsError(f"refusing to overwrite non-empty output directory: {args.output_dir}")
    if args.max_snippet_chars < 0:
        raise SystemExit("--max-snippet-chars cannot be negative")
    if args.max_rank <= 0:
        raise SystemExit("--max-rank must be positive")
    if args.candidates_per_prompt <= 0:
        raise SystemExit("--candidates-per-prompt must be positive")
    if args.max_cases < 0:
        raise SystemExit("--max-cases cannot be negative")

    items, build_summary = build_judge_items(
        recall_results=read_jsonl(args.recall_results),
        top_candidates=read_jsonl(args.top_candidates),
        max_rank=args.max_rank,
        candidates_per_prompt=args.candidates_per_prompt,
        max_snippet_chars=args.max_snippet_chars,
        max_cases=args.max_cases,
        allow_empty_snippets=args.allow_empty_snippets,
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "prompts").mkdir(parents=True, exist_ok=True)
    public_inputs: list[dict[str, Any]] = []
    for item in items:
        prompt_path = args.output_dir / item["prompt_file"]
        prompt_path.write_text(list_prompt(item), encoding="utf-8")
        public_item = {key: value for key, value in item.items() if key != "candidates"}
        public_inputs.append(public_item)
    write_jsonl(args.output_dir / "judge_inputs.jsonl", public_inputs)
    write_json(args.output_dir / "build_summary.json", build_summary)
    write_runner(args.output_dir, default_cli=args.default_cli, default_model=args.default_model)
    write_readme(args.output_dir, build_summary=build_summary, default_cli=args.default_cli, default_model=args.default_model)
    print(json.dumps({"prompt_count": len(items), "output_dir": str(args.output_dir)}, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
