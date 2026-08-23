#!/usr/bin/env python3
"""Summarize advisory list-wise LLM judge outputs for recall reranking diagnostics."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


PRIORITY_ORDER = {"high": 3, "medium": 2, "low": 1, "none": 0}


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


def normalize_priority(value: Any) -> str:
    priority = str(value or "").strip().lower()
    return priority if priority in PRIORITY_ORDER else "invalid"


def expected_output_path(judge_output_dir: Path, item: dict[str, Any]) -> Path:
    output_file = item.get("output_file")
    if output_file:
        return judge_output_dir / str(output_file)
    identity = str(item.get("identity_key") or "case").replace("/", "_").replace(":", "_")
    shard = int(item.get("shard_index") or 1)
    return judge_output_dir / f"{identity}.shard{shard:03d}.json"


def parse_one_output(output_path: Path) -> tuple[dict[str, Any] | None, str]:
    if not output_path.is_file():
        return None, "missing_output"
    try:
        return extract_json_object(output_path.read_text(encoding="utf-8")), ""
    except Exception as exc:  # noqa: BLE001 - parser failures are data.
        return None, f"parse_error: {exc}"


def candidate_sort_key(row: dict[str, Any]) -> tuple[float, int, float, int]:
    relevance = row.get("relevance")
    relevance_score = relevance if isinstance(relevance, float) else -1.0
    priority = PRIORITY_ORDER.get(str(row.get("audit_priority") or ""), -1)
    original_rank = row.get("hidden_original_rank")
    rank_penalty = -int(original_rank) if isinstance(original_rank, int) else -10**12
    prompt_position = row.get("prompt_position")
    position_penalty = -int(prompt_position) if isinstance(prompt_position, int) else -10**12
    return relevance_score, priority, rank_penalty, position_penalty


def summarize(
    *,
    judge_inputs: list[dict[str, Any]],
    judge_output_dir: Path,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    candidate_rows: list[dict[str, Any]] = []
    prompt_counts: Counter[str] = Counter()
    invalid_candidate_count = 0
    parsed_prompt_count = 0
    missing_prompt_count = 0
    invalid_prompt_count = 0

    for item in judge_inputs:
        output_path = expected_output_path(judge_output_dir, item)
        parsed, error = parse_one_output(output_path)
        hidden = {
            str(row.get("candidate_id")): row
            for row in item.get("hidden_candidates", [])
            if row.get("candidate_id")
        }
        if parsed is None:
            if error == "missing_output":
                missing_prompt_count += 1
                prompt_counts["missing"] += 1
            else:
                invalid_prompt_count += 1
                prompt_counts["invalid"] += 1
            for hidden_row in hidden.values():
                candidate_rows.append(
                    {
                        "identity_key": item.get("identity_key"),
                        "repo_key": item.get("repo_key"),
                        "hcvr_type": item.get("hcvr_type"),
                        "shard_index": item.get("shard_index"),
                        "candidate_id": hidden_row.get("candidate_id"),
                        "hidden_original_rank": hidden_row.get("rank"),
                        "known_anchor_overlap": hidden_row.get("known_anchor_overlap"),
                        "file": hidden_row.get("file"),
                        "parse_error": error,
                        "judge_output_file": str(output_path),
                    }
                )
            continue

        parsed_prompt_count += 1
        prompt_counts["parsed"] += 1
        scores = parsed.get("candidate_scores")
        if not isinstance(scores, list):
            invalid_prompt_count += 1
            prompt_counts["invalid_candidate_scores"] += 1
            scores = []
        scored_ids: set[str] = set()
        for score_row in scores:
            if not isinstance(score_row, dict):
                invalid_candidate_count += 1
                continue
            candidate_id = str(score_row.get("candidate_id") or "")
            hidden_row = hidden.get(candidate_id)
            if not hidden_row:
                invalid_candidate_count += 1
                continue
            scored_ids.add(candidate_id)
            candidate_rows.append(
                {
                    "identity_key": item.get("identity_key"),
                    "repo_key": item.get("repo_key"),
                    "hcvr_type": item.get("hcvr_type"),
                    "shard_index": item.get("shard_index"),
                    "candidate_id": candidate_id,
                    "hidden_original_rank": hidden_row.get("rank"),
                    "hidden_original_score": hidden_row.get("score"),
                    "known_anchor_overlap": hidden_row.get("known_anchor_overlap"),
                    "file": hidden_row.get("file"),
                    "start_line": hidden_row.get("start_line"),
                    "end_line": hidden_row.get("end_line"),
                    "symbol": hidden_row.get("symbol"),
                    "prompt_position": hidden_row.get("prompt_position"),
                    "relevance": normalize_score(score_row.get("relevance")),
                    "audit_priority": normalize_priority(score_row.get("audit_priority")),
                    "rationale": str(score_row.get("rationale") or "").strip(),
                    "key_evidence": score_row.get("key_evidence") if isinstance(score_row.get("key_evidence"), list) else [],
                    "parse_error": "",
                    "judge_output_file": str(output_path),
                }
            )
        for candidate_id, hidden_row in hidden.items():
            if candidate_id in scored_ids:
                continue
            candidate_rows.append(
                {
                    "identity_key": item.get("identity_key"),
                    "repo_key": item.get("repo_key"),
                    "hcvr_type": item.get("hcvr_type"),
                    "shard_index": item.get("shard_index"),
                    "candidate_id": candidate_id,
                    "hidden_original_rank": hidden_row.get("rank"),
                    "hidden_original_score": hidden_row.get("score"),
                    "known_anchor_overlap": hidden_row.get("known_anchor_overlap"),
                    "file": hidden_row.get("file"),
                    "start_line": hidden_row.get("start_line"),
                    "end_line": hidden_row.get("end_line"),
                    "symbol": hidden_row.get("symbol"),
                    "prompt_position": hidden_row.get("prompt_position"),
                    "parse_error": "missing_candidate_score",
                    "judge_output_file": str(output_path),
                }
            )

    identity_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in candidate_rows:
        identity_groups[str(row.get("identity_key") or "")].append(row)

    identity_rows: list[dict[str, Any]] = []
    hit_counts = {1: 0, 3: 0, 5: 0, 10: 0}
    identities_with_anchor = 0
    identities_with_scored_anchor = 0
    for identity, rows in sorted(identity_groups.items()):
        scored_rows = [row for row in rows if isinstance(row.get("relevance"), float)]
        reranked = sorted(scored_rows, key=candidate_sort_key, reverse=True)
        anchor_rows = [row for row in rows if row.get("known_anchor_overlap")]
        scored_anchor_rows = [row for row in reranked if row.get("known_anchor_overlap")]
        if anchor_rows:
            identities_with_anchor += 1
        if scored_anchor_rows:
            identities_with_scored_anchor += 1
        best_anchor = scored_anchor_rows[0] if scored_anchor_rows else (anchor_rows[0] if anchor_rows else None)
        best_anchor_judge_rank = None
        if best_anchor and best_anchor in reranked:
            best_anchor_judge_rank = reranked.index(best_anchor) + 1
            for k in hit_counts:
                if best_anchor_judge_rank <= k:
                    hit_counts[k] += 1
        top_row = reranked[0] if reranked else None
        identity_rows.append(
            {
                "identity_key": identity,
                "repo_key": rows[0].get("repo_key") if rows else None,
                "hcvr_type": rows[0].get("hcvr_type") if rows else None,
                "candidate_count": len(rows),
                "scored_candidate_count": len(scored_rows),
                "known_anchor_candidate_count": len(anchor_rows),
                "scored_known_anchor_candidate_count": len(scored_anchor_rows),
                "best_known_anchor_original_rank": best_anchor.get("hidden_original_rank") if best_anchor else None,
                "best_known_anchor_judge_rank": best_anchor_judge_rank,
                "best_known_anchor_relevance": best_anchor.get("relevance") if best_anchor else None,
                "judge_top_candidate_id": top_row.get("candidate_id") if top_row else None,
                "judge_top_known_anchor_overlap": top_row.get("known_anchor_overlap") if top_row else None,
                "judge_top_original_rank": top_row.get("hidden_original_rank") if top_row else None,
                "judge_top_file": top_row.get("file") if top_row else None,
            }
        )

    identity_count = len(identity_rows)
    hit_denominator = identities_with_scored_anchor
    summary = {
        "schema_version": "hcvr_recall_candidate_list_judge_summary.v1",
        "judge_input_count": len(judge_inputs),
        "judge_output_dir": str(judge_output_dir),
        "parsed_prompt_count": parsed_prompt_count,
        "missing_prompt_count": missing_prompt_count,
        "invalid_prompt_count": invalid_prompt_count,
        "invalid_candidate_score_count": invalid_candidate_count,
        "prompt_counts": dict(sorted(prompt_counts.items())),
        "identity_count": identity_count,
        "identities_with_known_anchor_candidate": identities_with_anchor,
        "identities_with_scored_known_anchor_candidate": identities_with_scored_anchor,
        "judge_rerank_hit_counts": {f"top_{k}": count for k, count in sorted(hit_counts.items())},
        "judge_rerank_hit_rates": {
            f"top_{k}": (count / hit_denominator if hit_denominator else None)
            for k, count in sorted(hit_counts.items())
        },
        "judge_rerank_hit_rate_denominator": hit_denominator,
        "identity_coverage_gap_count": identity_count - identities_with_scored_anchor,
        "policy": [
            "This is advisory semantic list judging for recall/reranker diagnostics.",
            "It does not update guidelines, sidecars, ranking, embedding weights, or audit prompts.",
            "Hidden known-anchor labels are used only after judge output is collected to estimate reranker potential.",
            "Judge rerank Hit@K is computed only over identities whose judged candidate set contains a scored known-anchor-overlap candidate.",
        ],
    }
    candidate_rows.sort(
        key=lambda row: (
            str(row.get("identity_key") or ""),
            row.get("hidden_original_rank") if isinstance(row.get("hidden_original_rank"), int) else 10**12,
            str(row.get("candidate_id") or ""),
        )
    )
    identity_rows.sort(key=lambda row: (row.get("best_known_anchor_judge_rank") is None, row.get("best_known_anchor_judge_rank") or 10**12, str(row.get("identity_key") or "")))
    return summary, candidate_rows, identity_rows


def write_readme(output_dir: Path, summary: dict[str, Any], identity_rows: list[dict[str, Any]]) -> None:
    lines = [
        "# Recall Candidate List Judge Summary",
        "",
        "This report summarizes advisory TraeX/LLM-as-judge list-wise scores over shuffled recall candidates.",
        "It is separate from embedding recall metrics and should only guide whether a reranker/query A/B is worth running.",
        "",
        "## Summary",
        "",
        f"- Judge prompt shards: {summary['judge_input_count']}",
        f"- Parsed prompt shards: {summary['parsed_prompt_count']}",
        f"- Missing prompt shards: {summary['missing_prompt_count']}",
        f"- Invalid prompt shards: {summary['invalid_prompt_count']}",
        f"- Candidate score parse issues: {summary['invalid_candidate_score_count']}",
        f"- Identities: {summary['identity_count']}",
        f"- Identities with scored known-anchor candidates: {summary['identities_with_scored_known_anchor_candidate']}",
        f"- Identity coverage gaps: {summary['identity_coverage_gap_count']}",
        f"- Judge rerank hit counts: {summary['judge_rerank_hit_counts']}",
        f"- Judge rerank hit rates over eligible identities: {summary['judge_rerank_hit_rates']}",
        "",
        "## Identity Rows",
        "",
        "| Identity | Judge Anchor Rank | Original Anchor Rank | Judge Top Is Anchor | Judge Top Original Rank | Judge Top File |",
        "| --- | ---: | ---: | --- | ---: | --- |",
    ]
    for row in identity_rows:
        lines.append(
            f"| `{row.get('identity_key')}` | {format_tsv(row.get('best_known_anchor_judge_rank'))} | "
            f"{format_tsv(row.get('best_known_anchor_original_rank'))} | "
            f"{format_tsv(row.get('judge_top_known_anchor_overlap'))} | "
            f"{format_tsv(row.get('judge_top_original_rank'))} | {format_tsv(row.get('judge_top_file'))} |"
        )
    lines.extend(
        [
            "",
            "## Policy",
            "",
            "- Hidden known-anchor labels are used only after judge completion for offline diagnostic statistics.",
            "- Do not convert judge choices into training labels, guideline text, regex fallback, or production routing without a separate reviewed experiment.",
            "- A strong judge rerank hit rate motivates a same-identity reranker A/B; it is not itself a paper-facing recall result.",
            "- If no judged candidate set contains known-anchor overlap, this report is a Top-N semantic-quality sample and cannot evaluate anchor reranking.",
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

    summary, candidate_rows, identity_rows = summarize(
        judge_inputs=read_jsonl(args.judge_inputs),
        judge_output_dir=args.judge_output_dir,
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_json(args.output_dir / "summary.json", summary)
    write_jsonl(args.output_dir / "candidate_scores.jsonl", candidate_rows)
    write_jsonl(args.output_dir / "identity_summary.jsonl", identity_rows)
    write_tsv(
        args.output_dir / "identity_summary.tsv",
        identity_rows,
        [
            "identity_key",
            "best_known_anchor_judge_rank",
            "best_known_anchor_original_rank",
            "best_known_anchor_relevance",
            "judge_top_known_anchor_overlap",
            "judge_top_original_rank",
            "judge_top_file",
        ],
    )
    write_readme(args.output_dir, summary, identity_rows)
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
