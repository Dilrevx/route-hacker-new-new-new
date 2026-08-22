#!/usr/bin/env python3
"""Evaluate guideline grouping quality independently of embedding recall."""

from __future__ import annotations

import argparse
import json
import math
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


DEFAULT_BUDGETS = (30, 50, 100, 200, 500)
ACTIONABILITY_FIELDS = ("source_shape", "sink_shape", "missing_guard", "typical_fix")
JUDGE_DECISIONS = ("accept", "revise", "split", "merge", "needs_evidence")
BALANCED_JUDGE_BUCKETS = (
    "evidence_limited",
    "label_mixed",
    "clean_control",
    "small_group",
    "source_only",
)


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def write_tsv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        handle.write("\t".join(fields) + "\n")
        for row in rows:
            handle.write("\t".join(format_tsv(row.get(field)) for field in fields) + "\n")


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


def normalize_label(value: Any) -> str:
    return str(value or "").strip() or "unspecified"


def case_cve_ids(case: dict[str, Any]) -> list[str]:
    vuln = case.get("vulnerability") or {}
    values = [vuln.get("id"), *(vuln.get("aliases") or [])]
    return [str(value).strip() for value in values if str(value or "").strip()]


def load_cases(path: Path | None) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    if path is None:
        return {}, {}, {}
    by_identity: dict[str, dict[str, Any]] = {}
    by_case_id: dict[str, dict[str, Any]] = {}
    by_cve: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for case in read_jsonl(path):
        identity = str(case.get("identity_key") or "")
        case_id = str(case.get("new_unified_case_id") or case.get("case_id") or "")
        if identity:
            by_identity[identity] = case
        if case_id:
            by_case_id[case_id] = case
        for cve_id in case_cve_ids(case):
            by_cve[cve_id].append(case)
    return by_identity, by_case_id, by_cve


def case_primary_hcvr(case: dict[str, Any] | None) -> str:
    if not case:
        return "missing_case_metadata"
    classification = case.get("classification") or {}
    return normalize_label(classification.get("primary_hcvr_type"))


def case_cwes(case: dict[str, Any] | None) -> list[str]:
    if not case:
        return ["missing_case_metadata"]
    classification = case.get("classification") or {}
    cwes = [str(item).strip() for item in classification.get("cwe_ids") or [] if str(item or "").strip()]
    return cwes or ["unspecified"]


def entropy(counter: Counter[str]) -> float:
    total = sum(counter.values())
    if total <= 0 or len(counter) <= 1:
        return 0.0
    raw = 0.0
    for count in counter.values():
        p = count / total
        raw -= p * math.log(p)
    return raw / math.log(len(counter))


def purity(counter: Counter[str]) -> float:
    total = sum(counter.values())
    if total <= 0:
        return 0.0
    return max(counter.values()) / total


def majority(counter: Counter[str]) -> str:
    if not counter:
        return ""
    return sorted(counter.items(), key=lambda item: (-item[1], item[0]))[0][0]


def compact_text(value: Any, limit: int = 600) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def trace_rationales(case: dict[str, Any], *, limit: int = 3) -> list[str]:
    trace = case.get("vulnerability_trace") or {}
    values: list[str] = []
    for key in ("summary", "rationale"):
        text = compact_text(trace.get(key), 500)
        if text:
            values.append(text)
    for node in trace.get("nodes") or []:
        text = compact_text(node.get("rationale"), 500)
        if text and text not in values:
            values.append(text)
        if len(values) >= limit:
            break
    return values[:limit]


def anchor_examples(case: dict[str, Any], *, limit: int = 5) -> list[dict[str, Any]]:
    anchors = []
    for anchor in case.get("recall_anchors") or []:
        anchors.append(
            {
                "file": anchor.get("file"),
                "start_line": anchor.get("start_line"),
                "end_line": anchor.get("end_line"),
                "symbol": anchor.get("symbol"),
                "span_kind": anchor.get("span_kind"),
            }
        )
        if len(anchors) >= limit:
            break
    return anchors


def summarize_case_for_judge(case: dict[str, Any]) -> dict[str, Any]:
    vulnerability = case.get("vulnerability") or {}
    return {
        "identity_key": case.get("identity_key"),
        "case_id": case.get("new_unified_case_id") or case.get("case_id"),
        "cve_ids": case_cve_ids(case),
        "primary_hcvr_type": case_primary_hcvr(case),
        "cwe_ids": case_cwes(case),
        "vulnerability_description": compact_text(vulnerability.get("description"), 700),
        "trace_evidence": trace_rationales(case),
        "anchor_examples": anchor_examples(case),
    }


def load_guideline_payloads(release_dir: Path) -> list[dict[str, Any]]:
    index_path = release_dir / "index.json"
    if not index_path.is_file():
        raise FileNotFoundError(f"missing release index: {index_path}")
    index = read_json(index_path)
    payloads: list[dict[str, Any]] = []
    for item in index.get("items") or []:
        file_name = item.get("file_name")
        if not file_name:
            continue
        guideline_path = release_dir / "guidelines" / str(file_name)
        if not guideline_path.is_file():
            raise FileNotFoundError(f"missing guideline payload: {guideline_path}")
        payloads.append(read_json(guideline_path))
    return payloads


def load_override_case_links(
    release_dir: Path,
    by_identity: dict[str, dict[str, Any]],
    by_case_id: dict[str, dict[str, Any]],
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, list[dict[str, Any]]]]:
    path = release_dir / "guideline_overrides.jsonl"
    if not path.is_file():
        return {}, {}
    links: dict[str, list[dict[str, Any]]] = defaultdict(list)
    unresolved: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in read_jsonl(path):
        guideline_ids = [str(value) for value in row.get("guideline_ids") or [] if str(value or "")]
        case = by_identity.get(str(row.get("identity_key") or "")) or by_case_id.get(str(row.get("case_id") or ""))
        for guideline_id in guideline_ids:
            if case is None:
                unresolved[guideline_id].append(row)
            else:
                links[guideline_id].append(case)
    return links, unresolved


def actionability_score(payload: dict[str, Any]) -> tuple[float, list[str]]:
    mechanism = payload.get("mechanism") or {}
    present = [field for field in ACTIONABILITY_FIELDS if str(mechanism.get(field) or "").strip()]
    return len(present) / len(ACTIONABILITY_FIELDS), present


def evaluate_release(
    *,
    release_dir: Path,
    cases_file: Path | None,
    min_purity: float,
    singleton_soft_cap: int,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    by_identity, by_case_id, by_cve = load_cases(cases_file)
    payloads = load_guideline_payloads(release_dir)
    override_links, unresolved_override_links = load_override_case_links(release_dir, by_identity, by_case_id)
    candidates_path = release_dir / "mechanism_candidates.jsonl"
    pending_candidate_count = 0
    if candidates_path.is_file():
        pending_candidate_count = sum(1 for row in read_jsonl(candidates_path) if row.get("status") == "pending_review")

    case_assignments: list[dict[str, Any]] = []
    group_rows: list[dict[str, Any]] = []
    unique_assigned_cases: set[str] = set()
    flagged_counts: Counter[str] = Counter()

    for payload in payloads:
        guideline_id = str(payload.get("guideline_id") or "")
        group_key = str(payload.get("guideline_group_key") or guideline_id)
        mechanism = payload.get("mechanism") or {}
        cases = override_links.get(guideline_id) or []
        if not cases:
            for cve_id in payload.get("cve_ids") or []:
                cases.extend(by_cve.get(str(cve_id), []))
        cases_by_identity: dict[str, dict[str, Any]] = {}
        for case in cases:
            identity = str(case.get("identity_key") or case.get("new_unified_case_id") or "")
            if identity and identity not in cases_by_identity:
                cases_by_identity[identity] = case

        hcvr_counter: Counter[str] = Counter()
        cwe_counter: Counter[str] = Counter()
        identities: list[str] = []
        cve_ids: list[str] = []
        for case in cases_by_identity.values():
            identity = str(case.get("identity_key") or case.get("new_unified_case_id") or "")
            if identity:
                unique_assigned_cases.add(identity)
                identities.append(identity)
            for cve_id in case_cve_ids(case):
                cve_ids.append(cve_id)
            hcvr_counter[case_primary_hcvr(case)] += 1
            for cwe_id in case_cwes(case):
                cwe_counter[cwe_id] += 1
            case_assignments.append(
                {
                    "identity_key": identity,
                    "case_id": case.get("new_unified_case_id") or case.get("case_id"),
                    "cve_ids": case_cve_ids(case),
                    "guideline_id": guideline_id,
                    "guideline_group_key": group_key,
                    "mechanism_id": mechanism.get("mechanism_id"),
                    "mechanism_name": mechanism.get("name"),
                    "mechanism_family": mechanism.get("family"),
                    "primary_hcvr_type": case_primary_hcvr(case),
                    "cwe_ids": case_cwes(case),
                }
            )

        source_cve_ids = sorted({str(cve_id) for cve_id in payload.get("cve_ids") or [] if str(cve_id or "")})
        unresolved_override_count = len(unresolved_override_links.get(guideline_id) or [])
        cve_ids = sorted(set(cve_ids))
        assigned_count = len(set(identities))
        hcvr_purity = purity(hcvr_counter)
        cwe_purity = purity(cwe_counter)
        hcvr_entropy = entropy(hcvr_counter)
        cwe_entropy = entropy(cwe_counter)
        action_score, action_fields = actionability_score(payload)
        flags: list[str] = []
        if assigned_count == 0:
            flags.append("source_only_no_case_metadata")
        elif assigned_count <= singleton_soft_cap:
            flags.append("small_group")
        if len(hcvr_counter) > 1 and hcvr_purity < min_purity:
            flags.append("mixed_hcvr")
        if len(cwe_counter) > 1 and cwe_purity < min_purity:
            flags.append("mixed_cwe")
        if action_score < 1.0:
            flags.append("incomplete_actionability_fields")
        family = str(mechanism.get("family") or "")
        mech_id = str(mechanism.get("mechanism_id") or "")
        if family == "pending_review" or mech_id.startswith("pending_mech_"):
            flags.append("pending_review")
        flagged_counts.update(flags)
        group_rows.append(
            {
                "guideline_id": guideline_id,
                "guideline_group_key": group_key,
                "mechanism_id": mech_id,
                "mechanism_name": mechanism.get("name"),
                "mechanism_family": family,
                "assigned_case_count": assigned_count,
                "source_cve_count": len(source_cve_ids),
                "metadata_cve_count": len(cve_ids),
                "unresolved_override_count": unresolved_override_count,
                "primary_hcvr_majority": majority(hcvr_counter),
                "primary_hcvr_purity": round(hcvr_purity, 4),
                "primary_hcvr_entropy": round(hcvr_entropy, 4),
                "cwe_majority": majority(cwe_counter),
                "cwe_purity": round(cwe_purity, 4),
                "cwe_entropy": round(cwe_entropy, 4),
                "actionability_score": round(action_score, 4),
                "actionability_fields": action_fields,
                "flags": flags,
                "guideline_text": compact_text(payload.get("guideline_text"), 2000),
                "cluster_summary": compact_text(payload.get("cluster_summary"), 1200),
                "example_cves": (cve_ids or source_cve_ids)[:8],
                "example_identities": sorted(set(identities))[:8],
                "judge_case_examples": [
                    summarize_case_for_judge(case)
                    for case in sorted(cases_by_identity.values(), key=lambda item: str(item.get("identity_key") or ""))[:8]
                ],
            }
        )

    total_cases = len(by_identity) if by_identity else 0
    evaluated_groups = [row for row in group_rows if row["assigned_case_count"] > 0]
    weighted_case_total = sum(row["assigned_case_count"] for row in evaluated_groups)
    source_only_groups = [row for row in group_rows if row["assigned_case_count"] == 0]
    summary = {
        "schema_version": "hcvr_guideline_group_eval.v1",
        "release_dir": str(release_dir),
        "cases_file": str(cases_file) if cases_file else None,
        "guideline_count": len(group_rows),
        "evaluated_group_count": len(evaluated_groups),
        "source_only_group_count": len(source_only_groups),
        "total_case_count": total_cases,
        "assigned_unique_case_count": len(unique_assigned_cases),
        "case_coverage_rate": (len(unique_assigned_cases) / total_cases if total_cases else None),
        "pending_candidate_count": pending_candidate_count,
        "small_group_count": flagged_counts.get("small_group", 0),
        "source_only_no_case_metadata_count": flagged_counts.get("source_only_no_case_metadata", 0),
        "mixed_hcvr_group_count": flagged_counts.get("mixed_hcvr", 0),
        "mixed_cwe_group_count": flagged_counts.get("mixed_cwe", 0),
        "flagged_group_count": sum(1 for row in group_rows if row["flags"]),
        "flag_counts": dict(sorted(flagged_counts.items())),
        "macro_primary_hcvr_purity": (
            sum(row["primary_hcvr_purity"] for row in evaluated_groups) / len(evaluated_groups)
            if evaluated_groups
            else 0.0
        ),
        "weighted_primary_hcvr_purity": (
            sum(row["primary_hcvr_purity"] * row["assigned_case_count"] for row in evaluated_groups) / weighted_case_total
            if weighted_case_total
            else 0.0
        ),
        "macro_cwe_purity": (
            sum(row["cwe_purity"] for row in evaluated_groups) / len(evaluated_groups)
            if evaluated_groups
            else 0.0
        ),
        "weighted_cwe_purity": (
            sum(row["cwe_purity"] * row["assigned_case_count"] for row in evaluated_groups) / weighted_case_total
            if weighted_case_total
            else 0.0
        ),
    }
    return summary, sorted(group_rows, key=lambda row: (bool(row["flags"]) is False, -row["assigned_case_count"], row["guideline_id"])), case_assignments


def write_readme(output_dir: Path, summary: dict[str, Any], group_rows: list[dict[str, Any]]) -> None:
    flagged = [row for row in group_rows if row["flags"]]
    lines = [
        "# Guideline Group Evaluation",
        "",
        "This report evaluates the offline guideline grouping itself. It does not use embedding scores, recall ranks, or known anchor locations.",
        "",
        "## Summary",
        "",
        f"- Guidelines: {summary['guideline_count']}",
        f"- Evaluated groups with case metadata: {summary['evaluated_group_count']}",
        f"- Source-only groups without case metadata: {summary['source_only_group_count']}",
        f"- Assigned unique cases: {summary['assigned_unique_case_count']} / {summary['total_case_count'] or 'unknown'}",
        f"- Case coverage rate: {summary['case_coverage_rate'] if summary['case_coverage_rate'] is not None else 'unknown'}",
        f"- Pending candidate rows: {summary['pending_candidate_count']}",
        f"- Small groups: {summary['small_group_count']}",
        f"- Mixed HCVR groups: {summary['mixed_hcvr_group_count']}",
        f"- Mixed CWE groups: {summary['mixed_cwe_group_count']}",
        f"- Weighted HCVR purity: {summary['weighted_primary_hcvr_purity']:.4f}",
        f"- Weighted CWE purity: {summary['weighted_cwe_purity']:.4f}",
        "",
        "## Interpretation",
        "",
        "Use this report as a diagnostic triage view for guideline releases, not as a hard pass/fail gate. A release can have clean mechanism groups but still perform poorly with a particular embedding model, and a release can improve recall while exposing overly broad or mixed guideline groups.",
        "HCVR/CWE purity is computed only for groups that can be joined to unified case metadata; source-only historical CVE groups are reported separately instead of being treated as impure.",
        "The structural labels are weak triage signals, not optimization targets and not the final definition of a good guideline. Mechanism quality should also be reviewed with human or LLM judging over the grouped CVE evidence, and final paper claims still require same-identity embedding recall.",
        "",
    ]
    if flagged:
        lines.extend(["## Flagged Groups", ""])
        for row in flagged[:20]:
            lines.append(
                f"- `{row['guideline_id']}` `{row['mechanism_id']}`: "
                f"cases={row['assigned_case_count']}, source_cves={row['source_cve_count']}, flags={','.join(row['flags'])}, "
                f"HCVR={row['primary_hcvr_majority']}:{row['primary_hcvr_purity']:.2f}, "
                f"CWE={row['cwe_majority']}:{row['cwe_purity']:.2f}"
            )
        lines.append("")
    output_dir.joinpath("README.md").write_text("\n".join(lines), encoding="utf-8")


DEFAULT_JUDGE_RUBRIC = Path(__file__).parents[1] / "guidelines" / "judge_rubric.v1.md"


def judge_prompt(item: dict[str, Any], rubric: str) -> str:
    return "\n".join(
        [
            rubric.strip(),
            "",
            "Guideline group payload:",
            json.dumps(item, ensure_ascii=False, indent=2, sort_keys=True),
        ]
    )


def select_judge_rows(
    group_rows: list[dict[str, Any]],
    *,
    group_filter: str,
    max_groups: int,
) -> list[dict[str, Any]]:
    if max_groups <= 0:
        return []
    if group_filter == "all":
        candidates = group_rows
    elif group_filter == "flagged":
        candidates = [row for row in group_rows if row["flags"] and row["assigned_case_count"] > 0]
    elif group_filter == "evaluated":
        candidates = [row for row in group_rows if row["assigned_case_count"] > 0]
    elif group_filter == "balanced":
        return select_balanced_judge_rows(group_rows, max_groups=max_groups)
    else:
        raise ValueError(f"unsupported judge group filter: {group_filter}")
    return candidates[:max_groups]


def judge_review_bucket(row: dict[str, Any]) -> str:
    flags = set(row.get("flags") or [])
    assigned = int(row.get("assigned_case_count") or 0)
    if assigned == 0:
        return "source_only"
    if flags & {"pending_review", "incomplete_actionability_fields"}:
        return "evidence_limited"
    if flags & {"mixed_hcvr", "mixed_cwe"}:
        return "label_mixed"
    if flags & {"small_group"}:
        return "small_group"
    return "clean_control"


def select_balanced_judge_rows(group_rows: list[dict[str, Any]], *, max_groups: int) -> list[dict[str, Any]]:
    buckets: dict[str, list[dict[str, Any]]] = {bucket: [] for bucket in BALANCED_JUDGE_BUCKETS}
    for row in group_rows:
        buckets[judge_review_bucket(row)].append(row)

    selected: list[dict[str, Any]] = []
    seen: set[str] = set()
    while len(selected) < max_groups:
        before = len(selected)
        for bucket in BALANCED_JUDGE_BUCKETS:
            while buckets[bucket]:
                row = buckets[bucket].pop(0)
                guideline_id = str(row.get("guideline_id") or "")
                if guideline_id in seen:
                    continue
                selected.append(row)
                seen.add(guideline_id)
                break
            if len(selected) >= max_groups:
                break
        if len(selected) == before:
            break
    return selected


def write_judge_pack(
    judge_dir: Path,
    *,
    group_rows: list[dict[str, Any]],
    group_filter: str,
    max_groups: int,
    rubric_path: Path = DEFAULT_JUDGE_RUBRIC,
) -> None:
    judge_dir.mkdir(parents=True, exist_ok=True)
    rubric = rubric_path.read_text(encoding="utf-8")
    rows = []
    prompts_dir = judge_dir / "prompts"
    prompts_dir.mkdir(parents=True, exist_ok=True)
    for row in select_judge_rows(group_rows, group_filter=group_filter, max_groups=max_groups):
        item = {
            "guideline_id": row["guideline_id"],
            "guideline_group_key": row["guideline_group_key"],
            "mechanism": {
                "mechanism_id": row["mechanism_id"],
                "name": row["mechanism_name"],
                "family": row["mechanism_family"],
            },
            "guideline_text": row["guideline_text"],
            "cluster_summary": row["cluster_summary"],
            "structural_sanity": {
                "assigned_case_count": row["assigned_case_count"],
                "source_cve_count": row["source_cve_count"],
                "metadata_cve_count": row["metadata_cve_count"],
                "primary_hcvr_majority": row["primary_hcvr_majority"],
                "primary_hcvr_purity": row["primary_hcvr_purity"],
                "cwe_majority": row["cwe_majority"],
                "cwe_purity": row["cwe_purity"],
                "flags": row["flags"],
            },
            "judge_selection_reason": judge_review_bucket(row),
            "case_examples": row["judge_case_examples"],
        }
        prompt_path = prompts_dir / f"{row['guideline_id']}.md"
        prompt_path.write_text(judge_prompt(item, rubric), encoding="utf-8")
        rows.append({**item, "prompt_file": str(prompt_path.relative_to(judge_dir))})
    rubric_dest = judge_dir / rubric_path.name
    rubric_dest.write_text(rubric, encoding="utf-8")
    write_jsonl(judge_dir / "judge_inputs.jsonl", rows)
    script_lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
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
        '  run_with_timeout traecli exec --sandbox read-only -o "$OUT_DIR/$name.json" < "$prompt"',
        "}",
        "export OUT_DIR TRAE_JUDGE_TIMEOUT_SECONDS",
        "export -f run_with_timeout run_one",
        'find prompts -name "*.md" -type f | sort | xargs -n 1 -P "$CONCURRENCY" bash -c \'run_one "$1"\' _',
        "",
    ]
    runner = judge_dir / "run_traex_judge.sh"
    runner.write_text("\n".join(script_lines), encoding="utf-8")
    runner.chmod(0o755)
    readme_lines = [
        "# LLM Judge Pack",
        "",
        "This pack is for semantic guideline-group review. It is intentionally separate from embedding recall evaluation and from the structural HCVR/CWE sanity checker.",
        f"The prompt rubric is stored in `{rubric_dest.name}` so the judgment criteria can be reviewed and versioned independently from code.",
        "The default recommended `balanced` filter samples evidence-limited, label-mixed, clean-control, small, and source-only groups in round-robin order, so review does not optimize only for historical bad cases or label-purity flags.",
        "",
        "Judgment target: whether the guideline captures a coherent reusable vulnerability mechanism across the listed cases, and whether the text is actionable as an audit query.",
        "",
        "Run from this directory:",
        "",
        "```bash",
        "TRAE_JUDGE_TIMEOUT_SECONDS=1800 TRAE_JUDGE_CONCURRENCY=4 ./run_traex_judge.sh judge_outputs",
        "```",
        "",
        "Summarize completed judge outputs:",
        "",
        "```bash",
        "python3 ../../../scripts/summarize_guideline_judge_outputs.py \\",
        "  --judge-inputs judge_inputs.jsonl \\",
        "  --judge-output-dir judge_outputs \\",
        "  --output-dir judge_summary",
        "```",
        "",
        "For a single group:",
        "",
        "```bash",
        "timeout 30m traecli exec -o judge_outputs/gl_mech_0001.json < prompts/gl_mech_0001.md",
        "```",
        "",
        "The expected response is JSON with `decision`, four 0..1 scores, and short revision or split suggestions.",
        "LLM judge output is advisory evidence for guideline iteration; it is not used to build online retrieval queries.",
        "",
    ]
    (judge_dir / "README.md").write_text("\n".join(readme_lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-dir", type=Path, required=True)
    parser.add_argument("--cases-file", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--min-purity", type=float, default=0.67)
    parser.add_argument("--singleton-soft-cap", type=int, default=1)
    parser.add_argument("--judge-pack-dir", type=Path)
    parser.add_argument("--judge-group-filter", choices=("flagged", "evaluated", "all", "balanced"), default="balanced")
    parser.add_argument("--judge-max-groups", type=int, default=20)
    parser.add_argument(
        "--judge-rubric",
        type=Path,
        default=DEFAULT_JUDGE_RUBRIC,
        help="Markdown rubric prepended to every TraeX judge prompt.",
    )
    args = parser.parse_args()
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise FileExistsError(f"refusing to overwrite non-empty output directory: {args.output_dir}")
    summary, group_rows, case_assignments = evaluate_release(
        release_dir=args.release_dir,
        cases_file=args.cases_file,
        min_purity=args.min_purity,
        singleton_soft_cap=args.singleton_soft_cap,
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_json(args.output_dir / "summary.json", summary)
    write_jsonl(args.output_dir / "group_report.jsonl", group_rows)
    write_jsonl(args.output_dir / "case_assignments.jsonl", case_assignments)
    write_tsv(
        args.output_dir / "group_report.tsv",
        group_rows,
        [
            "guideline_id",
            "guideline_group_key",
            "mechanism_id",
            "mechanism_family",
            "assigned_case_count",
            "source_cve_count",
            "metadata_cve_count",
            "primary_hcvr_majority",
            "primary_hcvr_purity",
            "cwe_majority",
            "cwe_purity",
            "actionability_score",
            "flags",
            "example_cves",
        ],
    )
    write_readme(args.output_dir, summary, group_rows)
    if args.judge_pack_dir:
        write_judge_pack(
            args.judge_pack_dir,
            group_rows=group_rows,
            group_filter=args.judge_group_filter,
            max_groups=args.judge_max_groups,
            rubric_path=args.judge_rubric,
        )
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
