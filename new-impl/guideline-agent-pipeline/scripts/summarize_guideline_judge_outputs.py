#!/usr/bin/env python3
"""Summarize TraeX/LLM judge outputs for guideline group quality."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


DECISIONS = ("accept", "revise", "split", "merge", "needs_evidence")
SCORE_FIELDS = ("coherence_score", "coverage_score", "actionability_score", "retrieval_query_quality")


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


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def format_tsv(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, float):
        return f"{value:.4f}"
    if isinstance(value, (list, tuple)):
        return ",".join(str(item) for item in value)
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value).replace("\t", " ").replace("\n", " ")


def write_tsv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        handle.write("\t".join(fields) + "\n")
        for row in rows:
            handle.write("\t".join(format_tsv(row.get(field)) for field in fields) + "\n")


def strip_code_fence(text: str) -> str:
    stripped = text.strip()
    if not stripped.startswith("```"):
        return stripped
    lines = stripped.splitlines()
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines).strip()


def extract_json_object(text: str) -> dict[str, Any]:
    decoder = json.JSONDecoder()
    candidate = strip_code_fence(text)
    for start, char in enumerate(candidate):
        if char != "{":
            continue
        try:
            value, _ = decoder.raw_decode(candidate[start:])
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    raise ValueError("no JSON object found")


def normalize_decision(value: Any) -> str:
    decision = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    return decision if decision in DECISIONS else "invalid"


def normalize_score(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    if score < 0:
        return 0.0
    if score > 1:
        return 1.0
    return score


def expected_output_path(judge_output_dir: Path, item: dict[str, Any]) -> Path:
    guideline_id = str(item.get("guideline_id") or "")
    output_file = item.get("output_file")
    if output_file:
        return judge_output_dir / str(output_file)
    return judge_output_dir / f"{guideline_id}.json"


def parse_one_output(output_path: Path) -> tuple[dict[str, Any] | None, str]:
    if not output_path.is_file():
        return None, "missing_output"
    try:
        return extract_json_object(output_path.read_text(encoding="utf-8")), ""
    except Exception as exc:  # noqa: BLE001 - report parser errors as data.
        return None, f"parse_error: {exc}"


def summarize(
    *,
    judge_inputs: list[dict[str, Any]],
    judge_output_dir: Path,
    low_score_threshold: float,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    decision_counts: Counter[str] = Counter()
    parsed_count = 0
    missing_count = 0
    invalid_count = 0
    low_score_count = 0
    score_sums: dict[str, float] = {field: 0.0 for field in SCORE_FIELDS}
    score_counts: Counter[str] = Counter()

    for item in judge_inputs:
        guideline_id = str(item.get("guideline_id") or "")
        output_path = expected_output_path(judge_output_dir, item)
        parsed, error = parse_one_output(output_path)
        row: dict[str, Any] = {
            "guideline_id": guideline_id,
            "mechanism_id": (item.get("mechanism") or {}).get("mechanism_id"),
            "mechanism_name": (item.get("mechanism") or {}).get("name"),
            "prompt_file": item.get("prompt_file"),
            "output_file": str(output_path),
            "parse_error": error,
        }
        if parsed is None:
            if error == "missing_output":
                missing_count += 1
            else:
                invalid_count += 1
            row.update({"decision": "missing" if error == "missing_output" else "invalid"})
            rows.append(row)
            continue

        parsed_count += 1
        decision = normalize_decision(parsed.get("decision"))
        if decision == "invalid":
            invalid_count += 1
        decision_counts[decision] += 1
        row["decision"] = decision
        for field in SCORE_FIELDS:
            score = normalize_score(parsed.get(field))
            row[field] = score
            if score is not None:
                score_sums[field] += score
                score_counts[field] += 1
        row["main_issue"] = str(parsed.get("main_issue") or "").strip()
        row["suggested_guideline"] = str(parsed.get("suggested_guideline") or "").strip()
        row["split_suggestions"] = parsed.get("split_suggestions") if isinstance(parsed.get("split_suggestions"), list) else []
        row["evidence_notes"] = parsed.get("evidence_notes") if isinstance(parsed.get("evidence_notes"), list) else []
        present_scores = [row[field] for field in SCORE_FIELDS if isinstance(row.get(field), float)]
        row["min_score"] = min(present_scores) if present_scores else None
        if row["min_score"] is not None and row["min_score"] < low_score_threshold:
            low_score_count += 1
            row["low_score"] = True
        else:
            row["low_score"] = False
        rows.append(row)

    summary = {
        "schema_version": "hcvr_guideline_llm_judge_summary.v1",
        "judge_input_count": len(judge_inputs),
        "judge_output_dir": str(judge_output_dir),
        "parsed_count": parsed_count,
        "missing_output_count": missing_count,
        "invalid_output_count": invalid_count,
        "decision_counts": dict(sorted(decision_counts.items())),
        "accepted_count": decision_counts.get("accept", 0),
        "needs_revision_count": sum(decision_counts.get(decision, 0) for decision in DECISIONS if decision != "accept"),
        "low_score_threshold": low_score_threshold,
        "low_score_count": low_score_count,
        "average_scores": {
            field: (score_sums[field] / score_counts[field] if score_counts[field] else None)
            for field in SCORE_FIELDS
        },
    }
    rows.sort(key=judge_row_sort_key)
    return summary, rows


def judge_row_sort_key(row: dict[str, Any]) -> tuple[int, float, str]:
    decision = row.get("decision")
    if decision in {"missing", "invalid"}:
        class_rank = 0
    elif decision != "accept":
        class_rank = 1
    elif row.get("low_score"):
        class_rank = 2
    else:
        class_rank = 3
    min_score = row.get("min_score")
    score_rank = float(min_score) if isinstance(min_score, float) else -1.0
    return class_rank, score_rank, str(row.get("guideline_id") or "")


def write_readme(output_dir: Path, summary: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    lines = [
        "# Guideline LLM Judge Summary",
        "",
        "This report summarizes TraeX/LLM-as-judge outputs for guideline group quality.",
        "It is separate from embedding recall and should be used as advisory semantic evidence for guideline iteration.",
        "",
        "## Summary",
        "",
        f"- Judge inputs: {summary['judge_input_count']}",
        f"- Parsed outputs: {summary['parsed_count']}",
        f"- Missing outputs: {summary['missing_output_count']}",
        f"- Invalid outputs: {summary['invalid_output_count']}",
        f"- Accepted groups: {summary['accepted_count']}",
        f"- Needs revision/split/merge/evidence: {summary['needs_revision_count']}",
        f"- Low-score groups: {summary['low_score_count']} at threshold {summary['low_score_threshold']}",
        f"- Decision counts: {summary['decision_counts']}",
        f"- Average scores: {summary['average_scores']}",
        "",
    ]
    problem_rows = [row for row in rows if row.get("decision") != "accept" or row.get("low_score")]
    if problem_rows:
        lines.extend(["## Highest Priority Rows", ""])
        for row in problem_rows[:20]:
            lines.append(
                f"- `{row['guideline_id']}` `{row.get('mechanism_id')}`: "
                f"decision={row.get('decision')}, min_score={row.get('min_score')}, issue={row.get('main_issue', '')}"
            )
        lines.append("")
    (output_dir / "README.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--judge-inputs", type=Path, required=True)
    parser.add_argument("--judge-output-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--low-score-threshold", type=float, default=0.6)
    args = parser.parse_args()
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise FileExistsError(f"refusing to overwrite non-empty output directory: {args.output_dir}")

    judge_inputs = read_jsonl(args.judge_inputs)
    summary, rows = summarize(
        judge_inputs=judge_inputs,
        judge_output_dir=args.judge_output_dir,
        low_score_threshold=args.low_score_threshold,
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_json(args.output_dir / "summary.json", summary)
    write_jsonl(args.output_dir / "judge_report.jsonl", rows)
    write_tsv(
        args.output_dir / "judge_report.tsv",
        rows,
        [
            "guideline_id",
            "mechanism_id",
            "decision",
            "coherence_score",
            "coverage_score",
            "actionability_score",
            "retrieval_query_quality",
            "min_score",
            "low_score",
            "parse_error",
            "main_issue",
        ],
    )
    write_readme(args.output_dir, summary, rows)
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
