#!/usr/bin/env python3
"""Summarize advisory LLM judge outputs for recall candidate pairs."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


CHOICES = ("A", "B", "tie", "neither")
SCORE_FIELDS = ("candidate_a_relevance", "candidate_b_relevance", "confidence")


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


def normalize_choice(value: Any) -> str:
    choice = str(value or "").strip()
    lower = choice.lower()
    if choice in {"A", "B"}:
        return choice
    if lower in {"tie", "neither"}:
        return lower
    return "invalid"


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
    output_file = item.get("output_file")
    if output_file:
        return judge_output_dir / str(output_file)
    identity = str(item.get("identity_key") or "case").replace("/", "_").replace(":", "_")
    return judge_output_dir / f"{identity}.json"


def parse_one_output(output_path: Path) -> tuple[dict[str, Any] | None, str]:
    if not output_path.is_file():
        return None, "missing_output"
    try:
        return extract_json_object(output_path.read_text(encoding="utf-8")), ""
    except Exception as exc:  # noqa: BLE001 - parser failures are data.
        return None, f"parse_error: {exc}"


def summarize(
    *,
    judge_inputs: list[dict[str, Any]],
    judge_output_dir: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    choice_counts: Counter[str] = Counter()
    outcome_counts: Counter[str] = Counter()
    parsed_count = 0
    missing_count = 0
    invalid_count = 0
    score_sums: dict[str, float] = {field: 0.0 for field in SCORE_FIELDS}
    score_counts: Counter[str] = Counter()

    for item in judge_inputs:
        output_path = expected_output_path(judge_output_dir, item)
        parsed, error = parse_one_output(output_path)
        row: dict[str, Any] = {
            "identity_key": item.get("identity_key"),
            "repo_key": item.get("repo_key"),
            "hcvr_type": item.get("hcvr_type"),
            "output_file": str(output_path),
            "parse_error": error,
            "hidden_expected_anchor_label": item.get("hidden_expected_anchor_label"),
            "hidden_top1_label": item.get("hidden_top1_label"),
            "hidden_anchor_rank": item.get("hidden_anchor_rank"),
            "hidden_top1_rank": item.get("hidden_top1_rank"),
            "hidden_anchor_file": item.get("hidden_anchor_file"),
            "hidden_top1_file": item.get("hidden_top1_file"),
            "candidate_count": item.get("candidate_count"),
        }
        if parsed is None:
            if error == "missing_output":
                missing_count += 1
                row["choice"] = "missing"
                row["choice_outcome"] = "missing"
            else:
                invalid_count += 1
                row["choice"] = "invalid"
                row["choice_outcome"] = "invalid"
            rows.append(row)
            outcome_counts[str(row["choice_outcome"])] += 1
            continue

        parsed_count += 1
        choice = normalize_choice(parsed.get("choice"))
        if choice == "invalid":
            invalid_count += 1
        choice_counts[choice] += 1
        row["choice"] = choice
        expected = str(item.get("hidden_expected_anchor_label") or "")
        top1 = str(item.get("hidden_top1_label") or "")
        if choice == expected:
            outcome = "anchor_overlap_chosen"
        elif choice == top1:
            outcome = "top1_chosen"
        elif choice in {"tie", "neither"}:
            outcome = choice
        else:
            outcome = "invalid"
        row["choice_outcome"] = outcome
        outcome_counts[outcome] += 1
        for field in SCORE_FIELDS:
            score = normalize_score(parsed.get(field))
            row[field] = score
            if score is not None:
                score_sums[field] += score
                score_counts[field] += 1
        row["rationale"] = str(parsed.get("rationale") or "").strip()
        row["key_evidence"] = parsed.get("key_evidence") if isinstance(parsed.get("key_evidence"), list) else []
        row["missing_information"] = (
            parsed.get("missing_information")
            if isinstance(parsed.get("missing_information"), list)
            else []
        )
        rows.append(row)

    summary = {
        "schema_version": "hcvr_recall_candidate_pair_judge_summary.v1",
        "judge_input_count": len(judge_inputs),
        "judge_output_dir": str(judge_output_dir),
        "parsed_count": parsed_count,
        "missing_output_count": missing_count,
        "invalid_output_count": invalid_count,
        "choice_counts": dict(sorted(choice_counts.items())),
        "choice_outcome_counts": dict(sorted(outcome_counts.items())),
        "anchor_overlap_choice_rate": (
            outcome_counts.get("anchor_overlap_chosen", 0) / parsed_count
            if parsed_count
            else None
        ),
        "top1_choice_rate": (
            outcome_counts.get("top1_chosen", 0) / parsed_count
            if parsed_count
            else None
        ),
        "average_scores": {
            field: (score_sums[field] / score_counts[field] if score_counts[field] else None)
            for field in SCORE_FIELDS
        },
        "policy": [
            "This is advisory semantic pair-judging for recall diagnostics.",
            "It does not update guidelines, sidecars, ranking, embedding weights, or audit prompts.",
            "Hidden labels are used only after judge output is collected to estimate reranker potential.",
        ],
    }
    rows.sort(key=lambda row: (str(row.get("choice_outcome") or ""), str(row.get("identity_key") or "")))
    return summary, rows


def write_readme(output_dir: Path, summary: dict[str, Any], rows: list[dict[str, Any]]) -> None:
    lines = [
        "# Recall Candidate Pair Judge Summary",
        "",
        "This report summarizes advisory LLM-as-judge choices over anonymous recall candidate pairs.",
        "It is separate from embedding recall metrics and should only guide whether a reranker/query A/B is worth running.",
        "",
        "## Summary",
        "",
        f"- Judge inputs: {summary['judge_input_count']}",
        f"- Parsed outputs: {summary['parsed_count']}",
        f"- Missing outputs: {summary['missing_output_count']}",
        f"- Invalid outputs: {summary['invalid_output_count']}",
        f"- Choice counts: {summary['choice_counts']}",
        f"- Choice outcomes: {summary['choice_outcome_counts']}",
        f"- Anchor-overlap choice rate: {summary['anchor_overlap_choice_rate']}",
        f"- Top1 choice rate: {summary['top1_choice_rate']}",
        f"- Average scores: {summary['average_scores']}",
        "",
        "## Rows",
        "",
        "| Identity | Outcome | Choice | Anchor Rank | Top1 File | Anchor File | Rationale |",
        "| --- | --- | --- | ---: | --- | --- | --- |",
    ]
    for row in rows:
        lines.append(
            f"| `{row.get('identity_key')}` | `{row.get('choice_outcome')}` | `{row.get('choice')}` | "
            f"{format_tsv(row.get('hidden_anchor_rank'))} | {format_tsv(row.get('hidden_top1_file'))} | "
            f"{format_tsv(row.get('hidden_anchor_file'))} | {format_tsv(row.get('rationale'))} |"
        )
    lines.extend(
        [
            "",
            "## Policy",
            "",
            "- Hidden expected labels are used only after judge completion for offline diagnostic statistics.",
            "- Do not convert judge choices into training labels, guideline text, regex fallback, or production routing without a separate reviewed experiment.",
            "- A strong anchor-overlap choice rate motivates a same-identity reranker A/B; it is not itself a paper-facing recall result.",
            "",
        ]
    )
    (output_dir / "README.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--judge-inputs", type=Path, required=True)
    parser.add_argument("--judge-output-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise FileExistsError(f"refusing to overwrite non-empty output directory: {args.output_dir}")

    summary, rows = summarize(
        judge_inputs=read_jsonl(args.judge_inputs),
        judge_output_dir=args.judge_output_dir,
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_json(args.output_dir / "summary.json", summary)
    write_jsonl(args.output_dir / "judge_report.jsonl", rows)
    write_tsv(
        args.output_dir / "judge_report.tsv",
        rows,
        [
            "identity_key",
            "choice_outcome",
            "choice",
            "candidate_a_relevance",
            "candidate_b_relevance",
            "confidence",
            "hidden_anchor_rank",
            "hidden_top1_rank",
            "hidden_anchor_file",
            "hidden_top1_file",
            "parse_error",
            "rationale",
        ],
    )
    write_readme(args.output_dir, summary, rows)
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
