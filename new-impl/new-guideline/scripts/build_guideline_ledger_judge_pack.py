#!/usr/bin/env python3
"""Build a LLM judge pack for source-reviewed guideline ledger rows."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Iterable


DEFAULT_RUBRIC = Path("new-impl/new-guideline/guidelines/judge_rubric.v1.md")


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


def slug_for_row(row: dict[str, Any]) -> str:
    guideline_id = str(row.get("guideline_id") or "guideline")
    boundary_label = str(row.get("boundary_label") or "boundary")
    return f"{guideline_id}.{boundary_label}".replace("/", "_")


def ledger_prompt(row: dict[str, Any], rubric: str) -> str:
    instruction = {
        "task": "Review one source-reviewed guideline boundary ledger row.",
        "decision_values": ["accept", "revise", "split", "merge", "needs_evidence"],
        "review_scope": [
            "Judge semantic boundary quality only.",
            "Check whether source shape, sink/effect, missing guard, exploit precondition, and safe fix are coherent.",
            "Check whether representative cases support the boundary decision.",
            "Do not judge embedding recall, known-anchor rank, Top-K metrics, or model performance.",
            "Do not invent new source evidence. If evidence is insufficient, return needs_evidence.",
            "Do not call tools, do not run shell commands, and do not try to write files; return the JSON object as the final answer only.",
        ],
        "expected_json": {
            "decision": "accept|revise|split|merge|needs_evidence",
            "coherence_score": 0.0,
            "coverage_score": 0.0,
            "actionability_score": 0.0,
            "retrieval_query_quality": 0.0,
            "main_issue": "short explanation",
            "suggested_guideline": "rewrite if decision is revise or split",
            "split_suggestions": ["submechanism A", "submechanism B"],
            "evidence_notes": ["case-level evidence or missing evidence"],
        },
    }
    payload = {
        "judge_mode": "source_reviewed_boundary_advisory",
        "rubric": "Use the common guideline semantic rubric, then apply the ledger-specific scope above.",
        "ledger_row": row,
    }
    return "\n".join(
        [
            rubric.strip(),
            "",
            "Ledger-specific instructions:",
            json.dumps(instruction, ensure_ascii=False, indent=2, sort_keys=True),
            "",
            "Ledger boundary payload:",
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
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


def write_readme(output_dir: Path, *, ledger: Path, row_count: int, rubric_name: str, default_cli: str, default_model: str) -> None:
    model_note = f" Defaults to `{default_model}`." if default_model else ""
    lines = [
        "# Ledger Boundary Judge Pack",
        "",
        "This pack asks LLM-as-judge to review source-reviewed guideline ledger rows.",
        "It is advisory semantic QA only: it does not update guidelines, does not score embedding recall, and does not gate Top-K claims.",
        "",
        "## Inputs",
        "",
        f"- Ledger: `{ledger}`",
        f"- Rows: {row_count}",
        f"- Rubric: `{rubric_name}`",
        "",
        "## Run",
        "",
        "```bash",
        "LLM_JUDGE_CLI=codex LLM_JUDGE_MODEL=DeepSeek-V4-Pro LLM_JUDGE_CONCURRENCY=4 LLM_JUDGE_TIMEOUT_SECONDS=1800 ./run_agent_judge.sh judge_outputs",
        "```",
        "",
        f"The runner defaults to `{default_cli}`.{model_note} Override both with environment variables when the local provider changes.",
        "",
        "## Summarize",
        "",
        "```bash",
        "python3 ../../scripts/summarize_guideline_judge_outputs.py \\",
        "  --judge-inputs judge_inputs.jsonl \\",
        "  --judge-output-dir judge_outputs \\",
        "  --output-dir judge_summary",
        "```",
        "",
        "Use the summary as a review queue. Do not feed judge decisions back into recall labels without source review and same-identity recall reruns.",
        "",
    ]
    (output_dir / "README.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--rubric", type=Path, default=DEFAULT_RUBRIC)
    parser.add_argument("--decision", action="append", help="Optional boundary_decision filter; repeatable.")
    parser.add_argument("--max-rows", type=int, default=0, help="0 means all rows after filtering.")
    parser.add_argument("--default-cli", default="codex")
    parser.add_argument("--default-model", default="DeepSeek-V4-Pro")
    args = parser.parse_args()
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise FileExistsError(f"refusing to overwrite non-empty output directory: {args.output_dir}")

    rows = read_jsonl(args.ledger)
    if args.decision:
        wanted = set(args.decision)
        rows = [row for row in rows if row.get("boundary_decision") in wanted]
    if args.max_rows > 0:
        rows = rows[: args.max_rows]

    args.output_dir.mkdir(parents=True, exist_ok=True)
    prompts_dir = args.output_dir / "prompts"
    prompts_dir.mkdir(parents=True, exist_ok=True)
    rubric = args.rubric.read_text(encoding="utf-8")
    judge_inputs: list[dict[str, Any]] = []
    for row in rows:
        slug = slug_for_row(row)
        prompt_path = prompts_dir / f"{slug}.md"
        prompt_path.write_text(ledger_prompt(row, rubric), encoding="utf-8")
        judge_inputs.append(
            {
                "guideline_id": row.get("guideline_id"),
                "boundary_label": row.get("boundary_label"),
                "boundary_decision": row.get("boundary_decision"),
                "mechanism": {
                    "mechanism_id": row.get("mechanism_id"),
                    "name": row.get("mechanism_name"),
                },
                "prompt_file": str(prompt_path.relative_to(args.output_dir)),
                "output_file": f"{slug}.json",
                "judge_mode": "source_reviewed_boundary_advisory",
            }
        )
    write_jsonl(args.output_dir / "judge_inputs.jsonl", judge_inputs)
    (args.output_dir / args.rubric.name).write_text(rubric, encoding="utf-8")
    write_runner(args.output_dir, default_cli=args.default_cli, default_model=args.default_model)
    write_readme(
        args.output_dir,
        ledger=args.ledger,
        row_count=len(rows),
        rubric_name=args.rubric.name,
        default_cli=args.default_cli,
        default_model=args.default_model,
    )
    print(json.dumps({"row_count": len(rows), "output_dir": str(args.output_dir)}, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
