#!/usr/bin/env python3
"""Run and score Unified V2 Experiment A ablations.

The script is intentionally scoped to the paper-eval 143-case ablation run:
it verifies the frozen dataset receipts, runs a case-level bounded audit prompt
for each variant, and scores emitted findings against frozen reference locations.
Direct source-location matches are deterministic.  A finding that does not
match mechanically is sent to a separate read-only harness process for a narrow
localization decision; the judge never performs a new vulnerability audit.
"""

from __future__ import annotations

import argparse
import collections
import concurrent.futures
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import time
from pathlib import Path
from typing import Any, Iterable

from run_hcvr_case_anchor_audits import (
    build_guideline,
    ensure_snapshot,
    parse_report,
    safe_slug,
)


EXPECTED_CASE_COUNT = 143
EXPECTED_COMPOSITION = {
    "IRIS-derived": 45,
    "non-IRIS no-fixed-source/sink proxy": 68,
    "non-IRIS source-sink/contrast/other": 30,
}
GENERIC_AUDIT_PROMPT = """Perform a bounded vulnerability audit of the target repository.

Focus on whether attacker-controlled input, principal identity, resource identity,
request state, file/path data, serialized data, template data, network data, or
other externally influenced values can reach a sensitive operation without the
required validation, authorization, isolation, lifecycle precondition, or stable
check-use binding.

Use the supplied candidate trace anchors only as starting points. Inspect the
smallest relevant callers, callees, data flow, state transitions, guards, and
sensitive effects needed to localize the most likely vulnerable method. Do not
use external vulnerability writeups, patches, historical PoCs, or internet
search. Do not modify the repository.
"""

FILE_LINE_RE = re.compile(
    r"(?P<file>[A-Za-z0-9_./@+-]+\.(?:java|kt|scala|py|go|ts|tsx|js|jsx|c|cc|cpp|h|hpp|rs|rb|php|xml|yaml|yml|properties|conf|cfg))"
    r"(?::|#L| line )(?P<line>[1-9][0-9]*)"
)


VARIANT_LABELS = {
    "full": "GCA(full)",
    "minus_rank": "-Rank",
    "minus_guideline": "-Guideline",
    "minus_poc": "-PoC",
}

LOCALIZATION_VERDICTS = {"match", "no_match", "inconclusive"}


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def load_guideline_overrides(path: Path | None) -> dict[str, str]:
    """Load a versioned type-to-obligation mapping for audit stage only.

    Overrides deliberately do not affect recall.  They are an explicit,
    hash-recorded experimental input rather than a hidden case-level prompt
    adjustment.
    """
    if path is None:
        return {}
    payload = read_json(path)
    values = payload.get("overrides") or {}
    if not isinstance(values, dict) or not all(
        isinstance(key, str) and isinstance(value, str) and value.strip()
        for key, value in values.items()
    ):
        raise ValueError(f"invalid guideline overrides: {path}")
    return {key: value.strip() for key, value in values.items()}


def append_jsonl(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
        handle.flush()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_command(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    input_text: str,
    timeout: int,
) -> tuple[int | None, str, str]:
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        cwd=cwd,
        env=env,
        start_new_session=True,
    )
    try:
        output, _ = process.communicate(input=input_text, timeout=timeout)
        return process.returncode, output or "", "completed"
    except subprocess.TimeoutExpired as error:
        output = error.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            more_output, _ = process.communicate(timeout=5)
            output += more_output or ""
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            more_output, _ = process.communicate()
            output += more_output or ""
        return process.returncode, output, "timeout"


def load_paper_eval_cases(
    cases_file: Path,
    allowlist: Path,
    *,
    limit: int | None = None,
    skip: int = 0,
) -> list[dict[str, Any]]:
    identities = [row["identity_key"] for row in read_jsonl(allowlist)]
    if skip < 0:
        raise ValueError("skip must be non-negative")
    if limit is not None and limit < 1:
        raise ValueError("limit must be positive when set")
    selected_identities = identities[skip : skip + limit if limit is not None else None]
    order = {identity: index for index, identity in enumerate(selected_identities)}
    cases = [
        row
        for row in read_jsonl(cases_file)
        if row.get("identity_key") in order
    ]
    cases.sort(key=lambda row: order[row["identity_key"]])
    missing = [
        identity
        for identity in selected_identities
        if identity not in {row["identity_key"] for row in cases}
    ]
    if missing:
        raise ValueError(f"allowlist identities missing from cases file: {missing[:10]}")
    return cases


def verify_dataset(qa_path: Path, cases_file: Path, allowlist: Path, summary_path: Path) -> dict[str, Any]:
    qa = read_json(qa_path)
    errors: list[str] = []
    if qa.get("case_count") != EXPECTED_CASE_COUNT:
        errors.append(f"case_count={qa.get('case_count')} expected {EXPECTED_CASE_COUNT}")
    if qa.get("unique_identity_count") != EXPECTED_CASE_COUNT:
        errors.append(
            f"unique_identity_count={qa.get('unique_identity_count')} expected {EXPECTED_CASE_COUNT}"
        )
    if qa.get("composition_buckets") != EXPECTED_COMPOSITION:
        errors.append(
            f"composition={qa.get('composition_buckets')} expected {EXPECTED_COMPOSITION}"
        )
    anchor_qa = qa.get("anchor_qa") or {}
    if anchor_qa.get("cases_below_10_unique_locations") != 0:
        errors.append(
            "cases_below_10_unique_locations="
            f"{anchor_qa.get('cases_below_10_unique_locations')}"
        )
    if int(anchor_qa.get("min_unique_locations") or 0) < 10:
        errors.append(f"min_unique_locations={anchor_qa.get('min_unique_locations')} < 10")
    allow_count = sum(1 for _ in read_jsonl(allowlist))
    if allow_count != EXPECTED_CASE_COUNT:
        errors.append(f"allowlist_count={allow_count} expected {EXPECTED_CASE_COUNT}")
    if errors:
        raise ValueError("; ".join(errors))
    return {
        "qa_path": str(qa_path.resolve()),
        "qa_sha256": sha256_file(qa_path),
        "cases_path": str(cases_file.resolve()),
        "cases_sha256": sha256_file(cases_file),
        "allowlist_path": str(allowlist.resolve()),
        "allowlist_sha256": sha256_file(allowlist),
        "summary_path": str(summary_path.resolve()),
        "summary_sha256": sha256_file(summary_path),
        "case_count": qa.get("case_count"),
        "unique_identity_count": qa.get("unique_identity_count"),
        "composition_buckets": qa.get("composition_buckets"),
        "anchor_qa": anchor_qa,
        "qa_status": qa.get("status"),
        "qa_errors": qa.get("errors") or [],
    }


def load_recall_results(path: Path | None) -> dict[str, dict[str, Any]]:
    if path is None:
        return {}
    return {row["identity_key"]: row for row in read_jsonl(path)}


def normalize_anchor(row: dict[str, Any], rank: int) -> dict[str, Any]:
    return {
        "anchor_id": row.get("anchor_id") or f"anchor::{rank}",
        "file": row.get("file") or "",
        "start_line": int(row.get("start_line") or 0),
        "end_line": int(row.get("end_line") or row.get("start_line") or 0),
        "symbol": row.get("symbol") or "",
        "span_kind": row.get("span_kind") or "",
        "rank": rank,
        "score": row.get("score"),
        "retrieval_source": row.get("retrieval_source"),
    }


def select_ranked_anchors(
    case: dict[str, Any],
    recall_results: dict[str, dict[str, Any]],
    budget: int,
) -> list[dict[str, Any]]:
    recall = recall_results.get(case["identity_key"])
    if not recall:
        raise ValueError(f"missing recall result for {case['identity_key']}")
    anchors = list(recall.get("top_anchors") or [])[:budget]
    if not anchors:
        raise ValueError(f"recall result has no anchors for {case['identity_key']}")
    return [normalize_anchor(anchor, index) for index, anchor in enumerate(anchors, start=1)]


def remove_rank_order(anchors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return the identical recalled candidates in a rank-independent order.

    This is the only candidate-side change for ``-Rank``.  In particular, it
    must not substitute a mechanical source slicer or otherwise change recall
    coverage: doing so would conflate retrieval coverage with trace ordering.
    The original rank remains in the receipt for provenance, but is withheld
    from the worker prompt.
    """
    return sorted(
        anchors,
        key=lambda anchor: (
            str(anchor.get("file") or ""),
            int(anchor.get("start_line") or 0),
            int(anchor.get("end_line") or 0),
            str(anchor.get("symbol") or ""),
            str(anchor.get("anchor_id") or ""),
        ),
    )


def build_type_guideline(
    case: dict[str, Any],
    guideline_overrides: dict[str, str] | None = None,
) -> str:
    typ = str((case.get("classification") or {}).get("primary_hcvr_type") or "")
    override = (guideline_overrides or {}).get(typ)
    if override:
        return f"HCVR type: {typ}\nGuideline: {override}"
    raw = build_guideline(case)
    kept = [
        line
        for line in raw.splitlines()
        if line.startswith("HCVR type:") or line.startswith("Guideline:") or line.startswith("CWE:")
    ]
    return "\n".join(kept) or GENERIC_AUDIT_PROMPT


def build_source_context(
    snapshot: Path,
    anchors: list[dict[str, Any]],
    *,
    max_anchors: int,
    context_lines: int,
    max_chars: int,
) -> str:
    chunks: list[str] = []
    used = 0
    for anchor in anchors[:max_anchors]:
        rel_file = str(anchor.get("file") or "")
        if not rel_file:
            continue
        file_path = (snapshot / rel_file).resolve()
        try:
            file_path.relative_to(snapshot.resolve())
        except ValueError:
            continue
        if not file_path.is_file():
            continue
        try:
            lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        start_line = max(1, int(anchor.get("start_line") or 1))
        end_line = max(start_line, int(anchor.get("end_line") or start_line))
        start = max(1, start_line - context_lines)
        end = min(len(lines), end_line + context_lines)
        numbered = "\n".join(
            f"{line_no:05d}| {lines[line_no - 1]}"
            for line_no in range(start, end + 1)
        )
        chunk = (
            f"--- anchor rank={anchor.get('rank')} file={rel_file} "
            f"lines={start_line}-{end_line} symbol={anchor.get('symbol') or ''} ---\n"
            f"{numbered}\n"
        )
        if used + len(chunk) > max_chars:
            remaining = max_chars - used
            if remaining > 500:
                chunks.append(chunk[:remaining] + "\n[truncated]\n")
            break
        chunks.append(chunk)
        used += len(chunk)
    return "\n".join(chunks) if chunks else "(no inline source context available)"


def anchor_directory(anchor: dict[str, Any]) -> tuple[str, ...]:
    """Return the repository-relative parent directory of an anchor."""
    file = str(anchor.get("file") or "").replace("\\", "/")
    parts = tuple(part for part in file.split("/")[:-1] if part and part != ".")
    return parts


def directory_distance(left: dict[str, Any], right: dict[str, Any]) -> int:
    """Tree distance between two anchor parent directories.

    A smaller value means the candidates are likely to share local callers,
    helper methods, or invariants.  It is used only to compose audit groups;
    retrieval rank remains attached to every candidate.
    """
    left_parts = anchor_directory(left)
    right_parts = anchor_directory(right)
    common = 0
    for left_part, right_part in zip(left_parts, right_parts):
        if left_part != right_part:
            break
        common += 1
    return len(left_parts) + len(right_parts) - 2 * common


def group_anchors_by_directory(
    anchors: list[dict[str, Any]],
    group_size: int,
) -> list[list[dict[str, Any]]]:
    """Partition every selected anchor into directory-local bounded groups.

    The first unassigned anchor in a content-derived canonical order seeds a
    group. The nearest remaining anchors in the repository directory tree fill
    that group, with file/span identity resolving ties. This deterministic
    greedy clustering keeps all Top-K anchors while giving one audit invocation
    a coherent local exploration surface. It intentionally does not consume
    retrieval rank: otherwise the -Rank ablation would still let rank choose
    which candidates share a bounded audit session.
    """
    if group_size < 1:
        raise ValueError("anchor group size must be positive")
    # The full and -Rank variants must share group membership without rank
    # influencing that membership. Rank is only a presentation/order signal in
    # the full prompt; the -Rank prompt removes it entirely.
    canonical_key = lambda anchor: (
        "/".join(anchor_directory(anchor)),
        str(anchor.get("file") or ""),
        int(anchor.get("start_line") or 0),
        int(anchor.get("end_line") or 0),
        str(anchor.get("symbol") or ""),
        str(anchor.get("anchor_id") or ""),
    )
    remaining = sorted(anchors, key=canonical_key)
    groups: list[list[dict[str, Any]]] = []
    while remaining:
        seed = remaining.pop(0)
        group = [seed]
        while remaining and len(group) < group_size:
            # Use the closest current member so a chain of nearby directories
            # remains together; source identity makes the result stable.
            best_index = min(
                range(len(remaining)),
                key=lambda index: (
                    min(directory_distance(remaining[index], member) for member in group),
                    canonical_key(remaining[index]),
                ),
            )
            group.append(remaining.pop(best_index))
        groups.append(group)
    return groups


def format_anchor_group(
    anchors: list[dict[str, Any]],
    *,
    group_index: int,
    group_count: int,
    show_rank: bool,
) -> str:
    lines = [
        f"Candidate group {group_index}/{group_count} ({len(anchors)} anchors; directory-local grouping):"
    ]
    for anchor in anchors:
        rank = f"rank={anchor['rank']} " if show_rank else ""
        lines.append(
            f"- {rank}id={anchor['anchor_id']} file={anchor['file']} "
            f"lines={anchor['start_line']}-{anchor['end_line']} "
            f"symbol={anchor.get('symbol') or ''} "
            f"span={anchor.get('span_kind') or ''}"
        )
    return "\n".join(lines)


def build_group_prompt(
    *,
    case: dict[str, Any],
    snapshot: Path,
    variant: str,
    anchors: list[dict[str, Any]],
    group_index: int,
    group_count: int,
    model_budget_note: str,
    source_context: str | None = None,
    include_case_metadata: bool = False,
    guideline_overrides: dict[str, str] | None = None,
) -> str:
    vuln = case.get("vulnerability") or {}
    revisions = case.get("revisions") or {}
    if variant == "minus_guideline":
        guideline = GENERIC_AUDIT_PROMPT
        family_line = ""
    else:
        guideline = build_type_guideline(case, guideline_overrides)
        classification = case.get("classification") or {}
        family_line = (
            "HCVR vulnerability family: "
            f"{classification.get('primary_hcvr_type') or 'unspecified'}\n"
        )
    ranked_note = (
        "The candidate anchors are ranked by guideline-conditioned trace recall."
        if variant != "minus_rank"
        else "The candidate anchors are deliberately unsorted; do not assume earlier anchors are more important."
    )
    anchors_text = format_anchor_group(
        anchors,
        group_index=group_index,
        group_count=group_count,
        show_rank=variant != "minus_rank",
    )
    case_metadata = ""
    if include_case_metadata:
        case_metadata = (
            "Case identity (bookkeeping only; do not use it as vulnerability knowledge): "
            f"{case['identity_key']}\n"
            "Vulnerability ID (bookkeeping only; do not use external knowledge): "
            f"{vuln.get('id', '')}\n"
        )
    source_section = ""
    if source_context is not None:
        source_section = f"""
Optional inline source context:
These excerpts are a convenience only. They are not a boundary on repository
reading: inspect the checkout agentically as needed, beginning with candidates.

```text
{source_context}
```
"""
    return f"""You are one bounded audit worker in the HCVR ablation experiment.

Repository: {snapshot}
Exact vulnerable checkout: {revisions.get("checkout_revision", "")}
{case_metadata}{family_line}
Budget: {model_budget_note}

Audit obligation:
{guideline}

Candidate trace anchors:
{ranked_note}
{anchors_text}
{source_section}

Instructions:
- The audit obligation defines the risk scope. Do not substitute a different,
  more familiar vulnerability class merely because it is nearby.
- This worker owns exactly the {len(anchors)} listed anchors. Consider every
  listed anchor, but triage quickly: if a candidate cannot plausibly implement
  the guideline family, mark it dismissed and move on. Do not broaden into a
  repository-wide generic vulnerability search.
- For a plausible candidate, use read-only agentic repository exploration only
  for the smallest local path needed to decide it: the enclosing method and, if
  necessary, direct callers/callees, local guards, data flow, state transitions,
  and sensitive effects. Repository reading is allowed; exhaustive browsing is
  not the task.
- Finish this group promptly after all {len(anchors)} candidates have a
  disposition. A concrete, localized in-scope finding is required before
  reporting risk; otherwise emit no findings.
- Return exactly {len(anchors)} candidate_dispositions: one for each listed
  anchor_id. This is the completeness receipt for the group, not a request to
  produce a finding for every anchor.
- Do not read patches, external advisories, historical PoCs, internet search results, or files outside the repository.
- Do not modify files or run destructive commands.
- Emit one structured finding for every distinct, concrete in-scope risk you
  can localize. Emit zero findings when no candidate yields a concrete risk.
- A finding must name the vulnerable method or closest enclosing code region and cite exact source file and line range.
- Prefer a narrow vulnerable method range over a broad file range.

Return exactly one JSON object with this shape:
{{
  "variant": "{variant}",
  "findings": [
    {{
      "title": "short title",
      "file": "relative/path/File.java",
      "start_line": 1,
      "end_line": 1,
      "symbol": "methodOrFunctionName",
      "confidence": 0.0,
      "rationale": "why this method is vulnerable",
      "missing_or_incorrect_condition": "guard, authorization, validation, state precondition, or check-use binding issue",
      "sensitive_effect": "sensitive operation reached by the flaw",
      "poc_observation": "runtime condition or value a PoC agent should observe"
    }}
  ],
  "candidate_dispositions": [
    {{
      "anchor_id": "candidate id from this group",
      "status": "risk|dismissed|insufficient_evidence",
      "reason": "one short guideline-specific reason"
    }}
  ],
  "no_finding_reason": "filled only when findings is empty"
}}
"""


def extract_json_object(text: str) -> dict[str, Any] | None:
    stripped = text.strip()
    # TraeX/Codex can prepend a short natural-language summary even when the
    # prompt asks for exactly one JSON object. Prefer a fenced JSON payload
    # before falling back to whole-output parsing, so a valid emitted finding
    # is not discarded solely because of that presentation wrapper.
    for match in re.finditer(r"```(?:json)?\s*(\{.*?\})\s*```", stripped, re.DOTALL | re.IGNORECASE):
        try:
            value = json.loads(match.group(1))
            if isinstance(value, dict):
                return value
        except json.JSONDecodeError:
            continue
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped)
        stripped = re.sub(r"\s*```$", "", stripped)
    try:
        value = json.loads(stripped)
        return value if isinstance(value, dict) else None
    except json.JSONDecodeError:
        pass
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start == -1 or end <= start:
        return None
    try:
        value = json.loads(stripped[start : end + 1])
        return value if isinstance(value, dict) else None
    except json.JSONDecodeError:
        return None


def fallback_findings_from_report(text: str) -> list[dict[str, Any]]:
    decision, confidence = parse_report(text)
    if decision != "risk":
        return []
    locations = []
    seen: set[tuple[str, int]] = set()
    for match in FILE_LINE_RE.finditer(text):
        file = match.group("file")
        line = int(match.group("line"))
        key = (file, line)
        if key in seen:
            continue
        seen.add(key)
        locations.append((file, line))
    if not locations:
        return []
    file, line = locations[0]
    return [
        {
            "title": "fallback risk location",
            "file": file,
            "start_line": line,
            "end_line": line,
            "symbol": "",
            "confidence": confidence,
            "rationale": "fallback location extracted from a non-JSON risk report",
            "missing_or_incorrect_condition": "",
            "sensitive_effect": "",
            "poc_observation": "",
        }
    ]


def normalize_findings(value: Any, report_text: str) -> list[dict[str, Any]]:
    if not isinstance(value, dict):
        return fallback_findings_from_report(report_text)
    raw_findings = value.get("findings")
    if not isinstance(raw_findings, list):
        return fallback_findings_from_report(report_text)
    findings: list[dict[str, Any]] = []
    for item in raw_findings:
        if not isinstance(item, dict):
            continue
        file = item.get("file")
        if not isinstance(file, str) or not file.strip():
            continue
        try:
            start = int(item.get("start_line"))
            end = int(item.get("end_line") or start)
        except (TypeError, ValueError):
            continue
        if start < 1:
            continue
        if end < start:
            end = start
        findings.append(
            {
                "title": str(item.get("title") or ""),
                "file": file.strip(),
                "start_line": start,
                "end_line": end,
                "symbol": str(item.get("symbol") or ""),
                "confidence": item.get("confidence"),
                "rationale": str(item.get("rationale") or ""),
                "missing_or_incorrect_condition": str(item.get("missing_or_incorrect_condition") or ""),
                "sensitive_effect": str(item.get("sensitive_effect") or ""),
                "poc_observation": str(item.get("poc_observation") or ""),
            }
        )
    return findings


VALID_DISPOSITION_STATUSES = {"risk", "dismissed", "insufficient_evidence"}


def validate_candidate_dispositions(
    dispositions: Any,
    anchors: list[dict[str, Any]],
) -> tuple[bool, str]:
    """Validate the group completeness receipt without forgiving model drift.

    A group can be scored only when the model returned exactly one disposition
    for every supplied candidate identifier.  This catches dropped anchors,
    duplicates, and small identifier transcription errors that would otherwise
    silently turn a partial audit into a completed receipt.
    """
    if not isinstance(dispositions, list):
        return False, "candidate_dispositions is not a list"
    expected_ids = [str(anchor.get("anchor_id") or "") for anchor in anchors]
    if any(not anchor_id for anchor_id in expected_ids):
        return False, "selected anchors contain an empty anchor_id"
    actual_ids: list[str] = []
    for index, disposition in enumerate(dispositions):
        if not isinstance(disposition, dict):
            return False, f"candidate_dispositions[{index}] is not an object"
        anchor_id = disposition.get("anchor_id")
        if not isinstance(anchor_id, str) or not anchor_id:
            return False, f"candidate_dispositions[{index}].anchor_id is missing"
        if disposition.get("status") not in VALID_DISPOSITION_STATUSES:
            return False, (
                f"candidate_dispositions[{index}].status={disposition.get('status')!r} "
                f"not in {sorted(VALID_DISPOSITION_STATUSES)}"
            )
        actual_ids.append(anchor_id)
    if collections.Counter(actual_ids) != collections.Counter(expected_ids):
        missing = list((collections.Counter(expected_ids) - collections.Counter(actual_ids)).elements())
        unexpected = list((collections.Counter(actual_ids) - collections.Counter(expected_ids)).elements())
        return False, (
            "candidate_dispositions anchor_id mismatch; "
            f"missing={missing[:3]} unexpected={unexpected[:3]}"
        )
    return True, ""


def parse_opencode_events(text: str) -> tuple[str, dict[str, Any]]:
    final_text = ""
    usage = {
        "input": 0,
        "output": 0,
        "reasoning": 0,
        "cache_read": 0,
        "cache_write": 0,
        "step_finish_count": 0,
    }
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        part = event.get("part") or {}
        if event.get("type") == "text":
            final_text = str(part.get("text") or "")
        if event.get("type") == "step_finish":
            tokens = part.get("tokens") or {}
            cache = tokens.get("cache") or {}
            usage["input"] += int(tokens.get("input") or 0)
            usage["output"] += int(tokens.get("output") or 0)
            usage["reasoning"] += int(tokens.get("reasoning") or 0)
            usage["cache_read"] += int(cache.get("read") or 0)
            usage["cache_write"] += int(cache.get("write") or 0)
            usage["step_finish_count"] += 1
    return final_text, usage


def run_anchor_group_audit(
    *,
    audit_runner: str,
    codex: str,
    opencode: str,
    model: str,
    codex_home: Path,
    temp_root: Path,
    output: Path,
    variant: str,
    case: dict[str, Any],
    snapshot: Path,
    anchors: list[dict[str, Any]],
    group_index: int,
    group_count: int,
    timeout: int,
    model_budget_note: str,
    source_context: str | None,
    include_case_metadata: bool,
    guideline_overrides: dict[str, str] | None,
    retry_attempt: int = 0,
) -> dict[str, Any]:
    identity = case["identity_key"]
    slug = safe_slug(identity)
    variant_dir = output / variant
    reports_dir = variant_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    group_slug = f"{slug}.group-{group_index:03d}-of-{group_count:03d}"
    if retry_attempt:
        group_slug += f".retry-{retry_attempt:03d}"
    report_path = reports_dir / f"{group_slug}.json"
    events_path = reports_dir / f"{group_slug}.events.jsonl"
    prompt_path = reports_dir / f"{group_slug}.prompt.txt"
    prompt = build_group_prompt(
        case=case,
        snapshot=snapshot,
        variant=variant,
        anchors=anchors,
        group_index=group_index,
        group_count=group_count,
        model_budget_note=model_budget_note,
        source_context=source_context,
        include_case_metadata=include_case_metadata,
        guideline_overrides=guideline_overrides,
    )
    prompt_path.write_text(prompt, encoding="utf-8")
    environment = os.environ.copy()
    environment["CODEX_HOME"] = str(codex_home)
    environment["TMPDIR"] = str(temp_root)
    started = time.time()
    token_usage: dict[str, Any] = {}
    if audit_runner == "opencode":
        command = [
            opencode,
            "run",
            "--format",
            "json",
            "--model",
            model,
            prompt,
        ]
        returncode, output_text, state = run_command(
            command,
            cwd=snapshot,
            env=environment,
            input_text="",
            timeout=timeout,
        )
        events_path.write_text(output_text, encoding="utf-8")
        report_text, token_usage = parse_opencode_events(output_text)
        report_path.write_text(report_text, encoding="utf-8")
        if state == "completed" and returncode != 0:
            state = "opencode_failed"
    else:
        command = [
            codex,
            "exec",
            "--ignore-rules",
            "--ephemeral",
            "--sandbox",
            "read-only",
            "--skip-git-repo-check",
            "--cd",
            str(snapshot),
            "--model",
            model,
            "--output-last-message",
            str(report_path),
            "--json",
            "--color",
            "never",
            "-",
        ]
        returncode, output_text, state = run_command(
            command,
            cwd=snapshot,
            env=environment,
            input_text=prompt,
            timeout=timeout,
        )
        events_path.write_text(output_text, encoding="utf-8")
        if state == "completed" and returncode != 0:
            state = "codex_failed"
        report_text = report_path.read_text(encoding="utf-8") if report_path.is_file() else ""
    parsed = extract_json_object(report_text)
    findings = normalize_findings(parsed, report_text)
    dispositions = (parsed or {}).get("candidate_dispositions") if isinstance(parsed, dict) else []
    if state == "completed" and parsed is None:
        state = "invalid_json_report"
    disposition_valid, disposition_error = validate_candidate_dispositions(dispositions, anchors)
    if state == "completed" and not disposition_valid:
        state = "invalid_dispositions"
    classification = case.get("classification") or {}
    return {
        "schema_version": "hcvr_ablation_a_case_audit.v1",
        "variant": variant,
        "variant_label": VARIANT_LABELS[variant],
        "identity_key": identity,
        "case_id": case.get("new_unified_case_id"),
        "hcvr_type": classification.get("primary_hcvr_type"),
        "cwe_ids": classification.get("cwe_ids") or [],
        "repo_url": case["repository"]["repo_url"],
        "checkout_revision": case["revisions"]["checkout_revision"],
        "state": state,
        "audit_runner": audit_runner,
        "returncode": returncode,
        "duration_seconds": round(time.time() - started, 3),
        "token_usage": token_usage,
        "anchor_budget": len(anchors),
        "anchors": anchors,
        "group_index": group_index,
        "group_count": group_count,
        "retry_attempt": retry_attempt,
        "finding_count": len(findings),
        "findings": findings,
        "candidate_dispositions": dispositions,
        "disposition_valid": disposition_valid,
        "disposition_error": disposition_error,
        "report": str(report_path),
        "report_sha256": sha256_file(report_path) if report_path.is_file() else None,
        "events": str(events_path),
        "prompt": str(prompt_path),
    }


def merge_group_token_usage(group_rows: list[dict[str, Any]]) -> dict[str, int]:
    keys = ("input", "output", "reasoning", "cache_read", "cache_write", "step_finish_count")
    return {
        key: sum(int((row.get("token_usage") or {}).get(key) or 0) for row in group_rows)
        for key in keys
    }


def reusable_completed_group(
    group_row: dict[str, Any],
    anchors: list[dict[str, Any]],
) -> bool:
    """Return whether a prior group can be reused as complete evidence."""
    if group_row.get("state") != "completed":
        return False
    valid, _ = validate_candidate_dispositions(
        group_row.get("candidate_dispositions"), anchors
    )
    return valid


def run_case_grouped_audit(
    *,
    audit_runner: str,
    codex: str,
    opencode: str,
    model: str,
    codex_home: Path,
    temp_root: Path,
    output: Path,
    variant: str,
    case: dict[str, Any],
    snapshot: Path,
    anchors: list[dict[str, Any]],
    anchor_group_size: int,
    group_timeout: int,
    model_budget_note: str,
    inline_source_context: bool,
    inline_context_anchors: int,
    inline_context_lines: int,
    inline_context_max_chars: int,
    include_case_metadata: bool,
    guideline_overrides: dict[str, str] | None,
    existing_groups: dict[int, dict[str, Any]] | None = None,
    retry_incomplete_groups: bool = False,
) -> dict[str, Any]:
    """Audit all selected Top-K candidates via independent local groups.

    Groups execute sequentially within a case so that top-level concurrency is
    the only provider load control.  Every group has its own prompt, events,
    final report, timeout, and finding list; the case receipt is their lossless
    aggregate.
    """
    groups = group_anchors_by_directory(anchors, anchor_group_size)
    rows: list[dict[str, Any]] = []
    reused_group_count = 0
    retried_group_count = 0
    for group_index, group in enumerate(groups, start=1):
        prompt_group = remove_rank_order(group) if variant == "minus_rank" else group
        previous = (existing_groups or {}).get(group_index)
        if previous and reusable_completed_group(previous, group):
            # A valid first attempt is immutable evidence.  Resume must never
            # spend provider budget or overwrite its prompt/events/report.
            rows.append(previous)
            reused_group_count += 1
            continue
        if previous and not retry_incomplete_groups:
            rows.append(previous)
            reused_group_count += 1
            continue
        source_context = None
        if inline_source_context:
            source_context = build_source_context(
                snapshot,
                group,
                max_anchors=inline_context_anchors,
                context_lines=inline_context_lines,
                max_chars=inline_context_max_chars,
            )
        fresh = run_anchor_group_audit(
            audit_runner=audit_runner,
            codex=codex,
            opencode=opencode,
            model=model,
            codex_home=codex_home,
            temp_root=temp_root,
            output=output,
            variant=variant,
            case=case,
            snapshot=snapshot,
                anchors=prompt_group,
            group_index=group_index,
            group_count=len(groups),
            timeout=group_timeout,
            model_budget_note=model_budget_note,
            source_context=source_context,
            include_case_metadata=include_case_metadata,
            guideline_overrides=guideline_overrides,
                retry_attempt=(int(previous.get("retry_attempt") or 0) + 1) if previous else 0,
        )
        if previous:
            fresh["retry_of_state"] = previous.get("state")
            fresh["retry_of_report"] = previous.get("report")
            retried_group_count += 1
        rows.append(fresh)
    findings = [finding for row in rows for finding in row.get("findings") or []]
    group_states = collections.Counter(str(row.get("state") or "unknown") for row in rows)
    states = set(group_states)
    if states <= {"completed"}:
        state = "completed"
    elif "timeout" in states:
        state = "partial_timeout"
    elif len(states) == 1:
        state = next(iter(states))
    else:
        state = "partial_group_failure"
    identity = case["identity_key"]
    classification = case.get("classification") or {}
    return {
        "schema_version": "hcvr_ablation_a_case_audit.v2",
        "variant": variant,
        "variant_label": VARIANT_LABELS[variant],
        "identity_key": identity,
        "case_id": case.get("new_unified_case_id"),
        "hcvr_type": classification.get("primary_hcvr_type"),
        "cwe_ids": classification.get("cwe_ids") or [],
        "repo_url": case["repository"]["repo_url"],
        "checkout_revision": case["revisions"]["checkout_revision"],
        "state": state,
        "audit_runner": audit_runner,
        "anchor_budget": len(anchors),
        "anchor_group_size": anchor_group_size,
        "group_count": len(groups),
        "group_state_counts": dict(group_states),
        "reused_group_count": reused_group_count,
        "retried_group_count": retried_group_count,
        "groups": rows,
        "anchors": anchors,
        "finding_count": len(findings),
        "findings": findings,
        "token_usage": merge_group_token_usage(rows),
        "duration_seconds": round(sum(float(row.get("duration_seconds") or 0) for row in rows), 3),
    }


def line_overlap(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    return max(a_start, b_start) <= min(a_end, b_end)


def truth_methods(case: dict[str, Any]) -> list[dict[str, Any]]:
    methods: list[dict[str, Any]] = []
    for node in (case.get("vulnerability_trace") or {}).get("nodes") or []:
        file = node.get("file")
        if not file:
            continue
        try:
            start = int(node.get("start_line"))
            end = int(node.get("end_line") or start)
        except (TypeError, ValueError):
            continue
        if start < 1:
            continue
        if end < start:
            end = start
        methods.append(
            {
                "file": file,
                "start_line": start,
                "end_line": end,
                "symbol": node.get("symbol") or "",
                "span_kind": node.get("span_kind") or "",
                "trace_node_id": node.get("trace_node_id"),
            }
        )
    return methods


def finding_hits_truth(finding: dict[str, Any], truth: list[dict[str, Any]]) -> dict[str, Any] | None:
    file = finding.get("file")
    try:
        start = int(finding.get("start_line"))
        end = int(finding.get("end_line") or start)
    except (TypeError, ValueError):
        return None
    symbol = str(finding.get("symbol") or "").strip()
    for method in truth:
        if file != method["file"]:
            continue
        method_symbol = str(method.get("symbol") or "").strip()
        if symbol and method_symbol and symbol == method_symbol:
            return method
        if line_overlap(start, end, int(method["start_line"]), int(method["end_line"])):
            return method
    return None


def run_localization_judge(
    *,
    audit_runner: str,
    codex: str,
    opencode: str,
    model: str,
    codex_home: Path,
    temp_root: Path,
    output_dir: Path,
    snapshot: Path,
    case: dict[str, Any],
    finding: dict[str, Any],
    finding_index: int,
    truth: list[dict[str, Any]],
    timeout: int,
) -> dict[str, Any]:
    """Run a distinct read-only harness process and persist its decision receipt."""
    reports_dir = output_dir / "localization_judges"
    reports_dir.mkdir(parents=True, exist_ok=True)
    slug = f"{safe_slug(case['identity_key'])}.finding-{finding_index:04d}"
    prompt_path = reports_dir / f"{slug}.prompt.txt"
    events_path = reports_dir / f"{slug}.events.jsonl"
    report_path = reports_dir / f"{slug}.json"
    receipt_path = reports_dir / f"{slug}.receipt.json"
    prompt = build_localization_judge_prompt(finding=finding, truth=truth)
    prompt_path.write_text(prompt, encoding="utf-8")
    environment = os.environ.copy()
    environment["CODEX_HOME"] = str(codex_home)
    environment["TMPDIR"] = str(temp_root)
    started = time.time()
    token_usage: dict[str, Any] = {}
    if audit_runner == "opencode":
        command = [opencode, "run", "--format", "json", "--model", model, prompt]
        returncode, output_text, state = run_command(
            command, cwd=snapshot, env=environment, input_text="", timeout=timeout
        )
        events_path.write_text(output_text, encoding="utf-8")
        report_text, token_usage = parse_opencode_events(output_text)
        report_path.write_text(report_text, encoding="utf-8")
        if state == "completed" and returncode != 0:
            state = "opencode_failed"
    else:
        command = [
            codex, "exec", "--ignore-rules", "--ephemeral", "--sandbox", "read-only",
            "--skip-git-repo-check", "--cd", str(snapshot), "--model", model,
            "--output-last-message", str(report_path), "--json", "--color", "never", "-",
        ]
        returncode, output_text, state = run_command(
            command, cwd=snapshot, env=environment, input_text=prompt, timeout=timeout
        )
        events_path.write_text(output_text, encoding="utf-8")
        if state == "completed" and returncode != 0:
            state = "codex_failed"
        report_text = report_path.read_text(encoding="utf-8") if report_path.is_file() else ""
    parsed = extract_json_object(report_text)
    valid, error, matched_ids = validate_localization_verdict(parsed, truth)
    if state == "completed" and not valid:
        state = "invalid_judge_report"
    receipt = {
        "schema_version": "hcvr_ablation_a_localization_judge.v1",
        "identity_key": case["identity_key"],
        "finding_index": finding_index,
        "finding": finding,
        "checkout_revision": case["revisions"]["checkout_revision"],
        "state": state,
        "verdict": (parsed or {}).get("verdict") if isinstance(parsed, dict) else None,
        "matched_reference_ids": matched_ids,
        "valid": valid,
        "validation_error": error,
        "audit_runner": audit_runner,
        "model": model,
        "returncode": returncode,
        "duration_seconds": round(time.time() - started, 3),
        "token_usage": token_usage,
        "prompt": str(prompt_path),
        "prompt_sha256": sha256_file(prompt_path),
        "events": str(events_path),
        "report": str(report_path),
        "report_sha256": sha256_file(report_path) if report_path.is_file() else None,
    }
    write_json(receipt_path, receipt)
    receipt["receipt"] = str(receipt_path)
    receipt["receipt_sha256"] = sha256_file(receipt_path)
    return receipt


def reuse_localization_judge_receipt(
    *,
    receipts_dir: Path,
    case: dict[str, Any],
    finding: dict[str, Any],
    finding_index: int,
    truth: list[dict[str, Any]],
) -> dict[str, Any]:
    """Load a Full localization decision for -PoC without resampling a judge."""
    slug = f"{safe_slug(case['identity_key'])}.finding-{finding_index:04d}.receipt.json"
    receipt_path = receipts_dir / "localization_judges" / slug
    if not receipt_path.is_file():
        return {
            "state": "missing_judge_receipt",
            "valid": False,
            "validation_error": f"missing reused localization receipt: {receipt_path}",
        }
    receipt = read_json(receipt_path)
    if receipt.get("identity_key") != case["identity_key"]:
        return {"state": "invalid_reused_judge_receipt", "valid": False, "validation_error": "identity mismatch"}
    if receipt.get("finding_index") != finding_index:
        return {"state": "invalid_reused_judge_receipt", "valid": False, "validation_error": "finding index mismatch"}
    if receipt.get("finding") != finding:
        return {"state": "invalid_reused_judge_receipt", "valid": False, "validation_error": "finding payload mismatch"}
    valid, error, matched = validate_localization_verdict(
        {"verdict": receipt.get("verdict"), "matched_reference_ids": receipt.get("matched_reference_ids"), "reason": "reused receipt"},
        truth,
    )
    if receipt.get("state") != "completed" or not receipt.get("valid") or not valid:
        return {
            "state": "invalid_reused_judge_receipt",
            "valid": False,
            "validation_error": error or str(receipt.get("validation_error") or "judge receipt incomplete"),
        }
    receipt = dict(receipt)
    receipt["matched_reference_ids"] = matched
    receipt["reused_from"] = str(receipt_path)
    receipt["reused_from_sha256"] = sha256_file(receipt_path)
    return receipt


def build_localization_judge_prompt(
    *,
    finding: dict[str, Any],
    truth: list[dict[str, Any]],
) -> str:
    """Render a narrow, independent localization-only harness task."""
    references = [
        {
            "reference_id": index,
            "file": item.get("file"),
            "start_line": item.get("start_line"),
            "end_line": item.get("end_line"),
            "symbol": item.get("symbol") or "",
            "span_kind": item.get("span_kind") or "",
        }
        for index, item in enumerate(truth, start=1)
    ]
    payload = json.dumps(
        {"finding": finding, "frozen_reference_locations": references},
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )
    return """You are an independent localization judge. Decide only whether
an emitted finding identifies the same vulnerable implementation location as
at least one frozen reference location in this checkout. This is NOT a
vulnerability audit: do not look for other bugs, do not use the internet, and
do not use git history, patches, advisories, CVE text, or external writeups.

You may read only the minimum relevant source around the supplied finding and
frozen reference locations to resolve enclosing-method ownership, aliases, or
line drift. Return exactly one JSON object and no Markdown:
{
  "verdict": "match" | "no_match" | "inconclusive",
  "matched_reference_ids": [integer],
  "reason": "short localization-only explanation"
}

A "match" verdict is allowed only when the finding and at least one reference
identify the same implementation method or semantic code location. Return
"inconclusive" when the supplied evidence cannot establish that relationship.

Input JSON:
""" + payload


def validate_localization_verdict(
    parsed: Any,
    truth: list[dict[str, Any]],
) -> tuple[bool, str, list[int]]:
    if not isinstance(parsed, dict):
        return False, "judge report is not a JSON object", []
    verdict = parsed.get("verdict")
    if verdict not in LOCALIZATION_VERDICTS:
        return False, f"invalid judge verdict: {verdict!r}", []
    matched = parsed.get("matched_reference_ids")
    if not isinstance(matched, list) or any(
        not isinstance(value, int) or value < 1 or value > len(truth)
        for value in matched
    ):
        return False, "matched_reference_ids must be valid one-based reference ids", []
    if verdict == "match" and not matched:
        return False, "match verdict requires at least one matched reference id", []
    if verdict != "match" and matched:
        return False, "non-match verdict must not name matched reference ids", []
    reason = parsed.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        return False, "judge reason is required", []
    return True, "", matched


def case_receipt_is_complete(row: dict[str, Any] | None) -> tuple[bool, str]:
    """Return whether a case row is eligible for a formal comparison.

    Score diagnostics may be useful while a long-running pilot is in flight,
    but a formal ablation row requires all selected cases and every group-level
    completeness receipt.  This gate prevents timeout/invalid receipts from
    being converted into paper metrics by omission.
    """
    if not row:
        return False, "missing_case_receipt"
    if row.get("state") != "completed":
        return False, f"case_state={row.get('state') or 'unknown'}"
    groups = row.get("groups")
    # Unit-score fixtures and legacy one-shot runners may not have group rows.
    # New grouped receipts always do, and each must validate independently.
    if groups is None:
        return True, ""
    if not isinstance(groups, list) or not groups:
        return False, "missing_group_receipts"
    for group in groups:
        if not isinstance(group, dict):
            return False, "malformed_group_receipt"
        if not reusable_completed_group(group, list(group.get("anchors") or [])):
            return False, f"group_{group.get('group_index')}={group.get('state') or 'unknown'}"
    return True, ""


def score_variant(
    variant_dir: Path,
    cases_by_identity: dict[str, dict[str, Any]],
    *,
    denominator: int,
    results_path: Path | None = None,
    stage2_source_variant: str | None = None,
    localization_judges: bool = False,
    localization_audit_runner: str = "codex",
    localization_codex: str = "codex",
    localization_opencode: str = "opencode",
    localization_model: str = "",
    localization_codex_home: Path | None = None,
    localization_temp_root: Path | None = None,
    localization_snapshot_root: Path | None = None,
    localization_timeout: int = 300,
    localization_reuse_dir: Path | None = None,
) -> dict[str, Any]:
    source_path = results_path or (variant_dir / "case_results.jsonl")
    rows = list(read_jsonl(source_path)) if source_path.is_file() else []
    rows_by_identity = {row["identity_key"]: row for row in rows}
    case_scores: list[dict[str, Any]] = []
    tp = 0
    fp = 0
    fn = 0
    completeness_failures: list[dict[str, str]] = []
    localization_failures: list[dict[str, str]] = []
    for identity, case in cases_by_identity.items():
        row = rows_by_identity.get(identity)
        receipt_complete, receipt_error = case_receipt_is_complete(row)
        if not receipt_complete:
            completeness_failures.append({"identity_key": identity, "reason": receipt_error})
        truth = truth_methods(case)
        findings = list((row or {}).get("findings") or [])
        case_alarms = len(findings)
        matched_finding_indexes: list[int] = []
        hit_methods: list[dict[str, Any]] = []
        finding_localizations: list[dict[str, Any]] = []
        for index, finding in enumerate(findings):
            hit_method = finding_hits_truth(finding, truth)
            if hit_method is not None:
                matched_finding_indexes.append(index)
                if hit_method not in hit_methods:
                    hit_methods.append(hit_method)
                finding_localizations.append(
                    {"finding_index": index, "decision": "deterministic_match", "reference": hit_method}
                )
                continue
            if not localization_judges:
                finding_localizations.append(
                    {"finding_index": index, "decision": "deterministic_no_match"}
                )
                continue
            if not truth:
                localization_failures.append({"identity_key": identity, "reason": "no_frozen_reference_locations"})
                finding_localizations.append(
                    {"finding_index": index, "decision": "judge_unavailable_no_reference"}
                )
                continue
            if not (localization_codex_home and localization_temp_root and localization_snapshot_root):
                raise ValueError("localization judge paths are required when localization_judges is enabled")
            snapshot = localization_snapshot_root / f"{safe_slug(case['repository']['repo_key'])}__{case['revisions']['checkout_revision'][:12]}"
            if not snapshot.is_dir():
                localization_failures.append({"identity_key": identity, "reason": "missing_frozen_snapshot"})
                finding_localizations.append(
                    {"finding_index": index, "decision": "judge_unavailable_missing_snapshot"}
                )
                continue
            judge = (
                reuse_localization_judge_receipt(
                    receipts_dir=localization_reuse_dir,
                    case=case,
                    finding=finding,
                    finding_index=index,
                    truth=truth,
                )
                if localization_reuse_dir is not None
                else run_localization_judge(
                    audit_runner=localization_audit_runner,
                    codex=localization_codex,
                    opencode=localization_opencode,
                    model=localization_model,
                    codex_home=localization_codex_home,
                    temp_root=localization_temp_root,
                    output_dir=variant_dir,
                    snapshot=snapshot,
                    case=case,
                    finding=finding,
                    finding_index=index,
                    truth=truth,
                    timeout=localization_timeout,
                )
            )
            finding_localizations.append(
                {"finding_index": index, "decision": "independent_judge", "receipt": judge}
            )
            if judge.get("state") != "completed" or not judge.get("valid"):
                localization_failures.append(
                    {"identity_key": identity, "reason": f"judge_state={judge.get('state')}"}
                )
                continue
            if judge.get("verdict") == "match":
                matched_finding_indexes.append(index)
                matched = [truth[ref_id - 1] for ref_id in judge.get("matched_reference_ids") or []]
                for method in matched:
                    if method not in hit_methods:
                        hit_methods.append(method)
        # The experiment contract evaluates recall at case granularity.  Select
        # at most one true alarm per case (the first truth-localizing emitted
        # finding in output order); every other emitted finding remains an
        # alarm and therefore contributes FP.  This keeps case-level TP/FN
        # while enforcing the required invariant Alarms == TP + FP even when
        # a model emits duplicate hits or several locations on the same case.
        case_tp = 1 if hit_methods else 0
        case_fp = case_alarms - case_tp
        case_fn = 1 if not hit_methods else 0
        tp += case_tp
        fp += case_fp
        fn += case_fn
        case_scores.append(
            {
                "identity_key": identity,
                "state": (row or {}).get("state", "not_run"),
                "receipt_complete": receipt_complete,
                "receipt_error": receipt_error,
                "alarm_count": case_alarms,
                "tp": case_tp,
                "fp": case_fp,
                "fn": case_fn,
                "hit_truth": hit_methods,
                "findings": findings,
                "matched_finding_count": len(matched_finding_indexes),
                "scored_true_finding_index": matched_finding_indexes[0] if matched_finding_indexes else None,
                "truth_method_count": len(truth),
                "localization_decisions": finding_localizations,
            }
        )
    recall = tp / denominator if denominator else 0.0
    alarms = tp + fp
    precision = tp / alarms if alarms else 0.0
    f1 = (2 * tp) / (2 * tp + fp + fn) if (2 * tp + fp + fn) else 0.0
    states = collections.Counter((row.get("state") or "unknown") for row in rows)
    stage2_formal_eligible = not completeness_failures and len(rows_by_identity) == denominator
    localization_formal_eligible = not localization_failures
    is_full_variant = variant_dir.name == "full"
    score = {
        "schema_version": "hcvr_ablation_a_score.v1",
        "variant": variant_dir.name,
        "variant_label": VARIANT_LABELS.get(variant_dir.name, variant_dir.name),
        "case_count": denominator,
        "completed_count": states["completed"],
        "stage2_formal_eligible": stage2_formal_eligible,
        "formal_eligible": stage2_formal_eligible and localization_formal_eligible and not is_full_variant,
        "confirmation_required": is_full_variant,
        "confirmation_eligible": not is_full_variant,
        "formal_blocker": (
            "confirmation_pending" if is_full_variant and stage2_formal_eligible and localization_formal_eligible
            else "localization_judge_incomplete" if not localization_formal_eligible else None
        ),
        "completeness_failure_count": len(completeness_failures),
        "completeness_failure_examples": completeness_failures[:10],
        "localization_judges_enabled": localization_judges,
        "localization_formal_eligible": localization_formal_eligible,
        "localization_failure_count": len(localization_failures),
        "localization_failure_examples": localization_failures[:10],
        "state_counts": dict(states),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "recall": recall,
        "precision": precision,
        "f1": f1,
        "alarms": alarms,
        "confirmed": "N/A (confirmation stage not integrated)",
        "stage2_results_path": str(source_path.resolve()),
        "stage2_results_sha256": sha256_file(source_path) if source_path.is_file() else None,
        "stage2_source_variant": stage2_source_variant or variant_dir.name,
        "case_scores": case_scores,
    }
    write_json(variant_dir / "score_summary.json", score)
    with (variant_dir / "case_scores.jsonl").open("w", encoding="utf-8") as handle:
        for row in case_scores:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    return score


def attach_confirmation_summary(variant_dir: Path, score: dict[str, Any]) -> dict[str, Any]:
    """Attach only a receipt-bound stage-3 total to the GCA(full) score.

    Confirmation can filter/label emitted alarms, but it cannot change the
    common stage-2 TP/FP/FN scorer used for the ablation table.
    """
    path = variant_dir / "confirmation" / "confirmation_summary.json"
    if not path.is_file():
        return score
    summary = read_json(path)
    expected_stage2_sha = score.get("stage2_results_sha256")
    observed_stage2_sha = summary.get("stage2_results_sha256")
    if not expected_stage2_sha or observed_stage2_sha != expected_stage2_sha:
        raise ValueError(
            "confirmation summary is not bound to the scored full stage-2 receipt: "
            f"expected={expected_stage2_sha} observed={observed_stage2_sha}"
        )
    count = summary.get("confirmed_count")
    finding_count = summary.get("finding_count")
    if not isinstance(count, int) or count < 0:
        raise ValueError("confirmation_summary.confirmed_count must be a non-negative integer")
    if not isinstance(finding_count, int) or finding_count != score.get("alarms"):
        raise ValueError(
            "confirmation summary finding_count must equal full stage-2 alarm count; "
            f"expected={score.get('alarms')} observed={finding_count}"
        )
    score = dict(score)
    if not score.get("stage2_formal_eligible"):
        raise ValueError("cannot attach confirmation to an incomplete stage-2 receipt")
    score["confirmed"] = count
    score["confirmation_eligible"] = True
    score["formal_eligible"] = True
    score["formal_blocker"] = None
    score["confirmation_summary_path"] = str(path.resolve())
    score["confirmation_summary_sha256"] = sha256_file(path)
    write_json(variant_dir / "score_summary.json", score)
    return score


def load_existing_case_results(path: Path) -> dict[str, dict[str, Any]]:
    if not path.is_file():
        return {}
    # Later rows supersede earlier partial receipts for the same case.
    return {row["identity_key"]: row for row in read_jsonl(path) if row.get("identity_key")}


def run_variant(
    *,
    args: argparse.Namespace,
    variant: str,
    cases: list[dict[str, Any]],
    recall_results: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    variant_dir = args.output_dir / variant
    variant_dir.mkdir(parents=True, exist_ok=True)
    if variant == "minus_poc":
        # -PoC is a stage-3 ablation, not an independently sampled audit run.
        # It must score the exact stage-2 evidence used by GCA(full); otherwise
        # model nondeterminism is confounded with the confirmation-stage delta.
        full_results = args.output_dir / "full" / "case_results.jsonl"
        if not full_results.is_file():
            raise FileNotFoundError(
                "-PoC requires the immutable GCA(full) stage-2 receipt at "
                f"{full_results}; run full first or resume a completed full run"
            )
        stage2_source = {
            "schema_version": "hcvr_ablation_a_stage2_reuse.v1",
            "variant": "minus_poc",
            "source_variant": "full",
            "source_path": str(full_results.resolve()),
            "source_sha256": sha256_file(full_results),
            "reason": "-PoC reuses GCA(full) stage-2 receipt; it disables only stage 3",
        }
        write_json(variant_dir / "stage2_source.json", stage2_source)
        cases_by_identity = {case["identity_key"]: case for case in cases}
        return score_variant(
            variant_dir,
            cases_by_identity,
            denominator=len(cases),
            results_path=full_results,
            stage2_source_variant="full",
            localization_judges=args.localization_judges,
            localization_audit_runner=args.localization_audit_runner,
            localization_codex=args.localization_codex,
            localization_opencode=args.localization_opencode,
            localization_model=args.localization_model,
            localization_codex_home=args.codex_home.resolve(),
            localization_temp_root=args.localization_temp_root.resolve(),
            localization_snapshot_root=args.snapshot_root.resolve(),
            localization_timeout=args.localization_timeout,
            localization_reuse_dir=args.output_dir / "full",
        )
    result_path = variant_dir / "case_results.jsonl"
    existing_rows = load_existing_case_results(result_path) if args.resume else {}
    codex_path = shutil.which(args.codex) or args.codex
    opencode_path = shutil.which(args.opencode) or args.opencode
    if args.audit_runner == "codex" and shutil.which(args.codex) is None:
        raise FileNotFoundError(f"codex executable not found: {args.codex}")
    if args.audit_runner == "opencode" and shutil.which(args.opencode) is None:
        raise FileNotFoundError(f"opencode executable not found: {args.opencode}")
    temp_root = args.temp_root.resolve()
    temp_root.mkdir(parents=True, exist_ok=True)
    def handle_case(case: dict[str, Any]) -> dict[str, Any]:
        existing = existing_rows.get(case["identity_key"])
        if existing and not args.retry_incomplete_groups:
            return {"identity_key": case["identity_key"], "state": "skipped_existing"}
        if existing and existing.get("state") == "completed":
            return {"identity_key": case["identity_key"], "state": "skipped_existing"}
        try:
            snapshot = ensure_snapshot(
                case,
                args.repo_cache.resolve(),
                args.snapshot_root.resolve(),
                args.clone_timeout,
            )
            anchors = select_ranked_anchors(case, recall_results, args.anchor_budget)
            return run_case_grouped_audit(
                audit_runner=args.audit_runner,
                codex=codex_path,
                opencode=opencode_path,
                model=args.model,
                codex_home=args.codex_home.resolve(),
                temp_root=temp_root,
                output=args.output_dir.resolve(),
                variant=variant,
                case=case,
                snapshot=snapshot,
                anchors=anchors,
                anchor_group_size=args.anchor_group_size,
                group_timeout=args.group_timeout,
                model_budget_note=args.model_budget_note,
                inline_source_context=args.inline_source_context,
                inline_context_anchors=args.inline_context_anchors,
                inline_context_lines=args.inline_context_lines,
                inline_context_max_chars=args.inline_context_max_chars,
                include_case_metadata=args.include_case_metadata,
                guideline_overrides=args.guideline_overrides_map,
                existing_groups={
                    int(group_row.get("group_index")): group_row
                    for group_row in (existing or {}).get("groups") or []
                    if group_row.get("group_index") is not None
                },
                retry_incomplete_groups=args.retry_incomplete_groups,
            )
        except BaseException as error:  # record per-case failures and keep the batch moving
            return {
                "schema_version": "hcvr_ablation_a_case_audit.v1",
                "variant": variant,
                "variant_label": VARIANT_LABELS[variant],
                "identity_key": case["identity_key"],
                "case_id": case.get("new_unified_case_id"),
                "repo_url": case["repository"]["repo_url"],
                "checkout_revision": case["revisions"]["checkout_revision"],
                "state": "case_failed",
                "error": f"{type(error).__name__}: {error}",
                "finding_count": 0,
                "findings": [],
            }

    pending = [
        case
        for case in cases
        if not (
            existing_rows.get(case["identity_key"])
            and (
                not args.retry_incomplete_groups
                or existing_rows[case["identity_key"]].get("state") == "completed"
            )
        )
    ]
    if args.concurrency == 1:
        for case in pending:
            row = handle_case(case)
            append_jsonl(result_path, row)
            print(
                json.dumps(
                    {
                        "variant": variant,
                        "identity_key": row["identity_key"],
                        "state": row["state"],
                        "finding_count": row.get("finding_count"),
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                ),
                flush=True,
            )
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
            future_to_case = {pool.submit(handle_case, case): case for case in pending}
            for future in concurrent.futures.as_completed(future_to_case):
                row = future.result()
                append_jsonl(result_path, row)
                print(
                    json.dumps(
                        {
                            "variant": variant,
                            "identity_key": row["identity_key"],
                            "state": row["state"],
                            "finding_count": row.get("finding_count"),
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                    ),
                    flush=True,
                )
    cases_by_identity = {case["identity_key"]: case for case in cases}
    score = score_variant(
        variant_dir,
        cases_by_identity,
        denominator=len(cases),
        localization_judges=args.localization_judges,
        localization_audit_runner=args.localization_audit_runner,
        localization_codex=args.localization_codex,
        localization_opencode=args.localization_opencode,
        localization_model=args.localization_model,
        localization_codex_home=args.codex_home.resolve(),
        localization_temp_root=args.localization_temp_root.resolve(),
        localization_snapshot_root=args.snapshot_root.resolve(),
        localization_timeout=args.localization_timeout,
    )
    return attach_confirmation_summary(variant_dir, score) if variant == "full" else score


def format_rate(value: float) -> str:
    return f"{value:.3f}"


def write_run_report(
    *,
    output_dir: Path,
    dataset_receipt: dict[str, Any],
    scores: list[dict[str, Any]],
    args: argparse.Namespace,
) -> None:
    by_variant = {score["variant"]: score for score in scores}
    rows = []
    for variant in ("full", "minus_rank", "minus_guideline", "minus_poc"):
        score = by_variant.get(variant)
        if score is None:
            rows.append(f"{VARIANT_LABELS[variant]} | PENDING | PENDING | PENDING | PENDING | N/A")
            continue
        if not score.get("formal_eligible"):
            if score.get("formal_blocker") == "confirmation_pending":
                rows.append(
                    f"{score['variant_label']} | PENDING_CONFIRMATION | PENDING_CONFIRMATION | "
                    f"PENDING_CONFIRMATION | PENDING_CONFIRMATION | N/A"
                )
                continue
            rows.append(
                f"{score['variant_label']} | INCOMPLETE | INCOMPLETE | INCOMPLETE | INCOMPLETE | "
                f"N/A (receipt failures={score.get('completeness_failure_count', 'unknown')})"
            )
            continue
        rows.append(
            " | ".join(
                [
                    score["variant_label"],
                    format_rate(score["recall"]),
                    format_rate(score["precision"]),
                    format_rate(score["f1"]),
                    str(score["alarms"]),
                    str(score.get("confirmed", "N/A")),
                ]
            )
        )
    count_rows = []
    for variant in ("full", "minus_rank", "minus_guideline", "minus_poc"):
        score = by_variant.get(variant)
        if score is None:
            continue
        count_rows.append(
            f"{score['variant_label']} | TP={score['tp']} | FP={score['fp']} | FN={score['fn']} | "
            f"formal_eligible={score.get('formal_eligible')} | receipt_failures={score.get('completeness_failure_count')} | states={score['state_counts']}"
        )
    flips = build_flip_notes(by_variant)
    report = f"""# Unified V2 Experiment A Ablation Report

## 1. 背景与目标

本报告覆盖 Experiment A（三项消融）。目标是用同一 143-case paper-eval 集合、同一审计后端、同一候选 anchor budget 和同一 scorer，比较完整 GCA 链路与三个消融项：关闭 trace 排序、清空 guideline 约束、以及去掉 PoC 确认阶段。消融解释的 claim 是：召回排序、guideline 义务约束、以及后续确认阶段分别贡献定位效率、审计约束和 false-alarm 削减证据。

当前脚本真实运行 stage-2 bounded audit，并对模型 emitted finding 做统一 TP/FP/FN 评分。GCA(full) 仅在 `full/confirmation/confirmation_summary.json` 通过 finding、revision、runtime provenance、PoC artifact/evidence 与独立 verifier verdict 的全部绑定校验后，才填写 Confirmed 并成为 formal eligible；否则报告行显示 `PENDING_CONFIRMATION`，而不是可贴论文的数字。`-PoC` 始终复用 full 的同一份 stage-2 receipt，并且不运行/不读取 confirmation receipt。

## 2. 数据集与环境

- QA receipt: `{dataset_receipt['qa_path']}`
- QA SHA-256: `{dataset_receipt['qa_sha256']}`
- Allowlist: `{dataset_receipt['allowlist_path']}`
- Allowlist SHA-256: `{dataset_receipt['allowlist_sha256']}`
- Cases file: `{dataset_receipt['cases_path']}`
- Cases SHA-256: `{dataset_receipt['cases_sha256']}`
- Summary file: `{dataset_receipt['summary_path']}`
- Summary SHA-256: `{dataset_receipt['summary_sha256']}`
- Case count: `{dataset_receipt['case_count']}`
- Unique identity count: `{dataset_receipt['unique_identity_count']}`
- Composition: `{dataset_receipt['composition_buckets']}`
- Anchor QA: min unique locations `{dataset_receipt['anchor_qa'].get('min_unique_locations')}`, max unique locations `{dataset_receipt['anchor_qa'].get('max_unique_locations')}`, cases below 10 `{dataset_receipt['anchor_qa'].get('cases_below_10_unique_locations')}`
- Branch/commit: `{args.git_branch}` / `{args.git_commit}`
- Audit runner: `{args.audit_runner}`
- Audit backend model: `{args.model}`
- Requested maximum anchor budget: `{args.anchor_budget}`
- Actual recalled candidates per selected case: min `{args.actual_anchor_count_min}`, max `{args.actual_anchor_count_max}`, cases below requested maximum `{args.actual_anchor_count_below_budget}`. Each case consumes `K_i=min(requested budget, available recalled candidates)`; every ablation variant shares the same `K_i` for that case.
- Audit timeout per 10-anchor group: `{args.group_timeout}` seconds
- Concurrency: `{args.concurrency}`
- Optional inline source context: `{args.inline_source_context}`; anchors `{args.inline_context_anchors}`, context lines `{args.inline_context_lines}`, max chars `{args.inline_context_max_chars}`. It is supplementary and does not restrict agentic checkout exploration.
- Candidate protocol: consume Top-K `{args.anchor_budget}` candidates through directory-local groups of `{args.anchor_group_size}`. Every candidate is owned by exactly one group. Each group has an independent read-only harness session, log, and `{args.group_timeout}`-second timeout; a case completes after all of its groups have been attempted.
- Audit-stage guideline overrides: `{args.guideline_overrides}` (SHA-256 `{sha256_file(args.guideline_overrides)}`; types `{sorted(args.guideline_overrides_map)}`). They replace only the matching type's audit obligation and do not alter the frozen recall result file.
- Randomness control: deterministic case allowlist order, deterministic Top-K recall receipt, deterministic rank-removed file/line ordering for -Rank, and deterministic directory-local grouping derived only from source paths/spans (not retrieval rank); no sampling parameter is set by the harness.

## 3. 方法与配置

固定部分：143-case allowlist、vulnerable checkout、repository snapshot materialization、同一个冻结的 Top-K recall receipt、per-case `K_i=min({args.anchor_budget}, available)`、directory-local group membership、audit backend model、timeout 和 scorer 在所有行中共享。每个 group 只有在 `candidate_dispositions` 与其输入的 anchor ID 一一精确对应时才可以标记 completed；少一个、重复一个或转写错误都作为无效 receipt 重跑。scorer 将 vulnerability trace nodes 作为冻结的 vulnerable-method proxy。每个 case 最多产生一个 TP：若多个 finding 都命中该 case 的 truth，仅首个命中作为 TP，其余仍计为 emitted alarms/FP；因此逐行恒有 `Alarms = TP + FP`，FN 保持 case-level 定义。

GCA(full): uses guideline-conditioned ranked anchors and the audit-only type guideline projected from `build_guideline`（不传递 case description、CVE、fix 或 truth location）。The stage-2 emitted finding is scored here. Stage 3 consumes the emitted findings through `bridge_audit_findings_to_runtime_poc.py`; it can fill Confirmed only after receipt-bound runtime/PoC/independent-verifier evidence is present.

-Rank: keeps precisely the same Top-K anchor IDs, files, line spans and directory-local group membership as full. Group membership is source-derived and rank-independent. -Rank deterministically reorders candidates within each group by file/line and removes every rank field from the harness prompt. This row therefore isolates rank priority without changing candidate coverage or the group-level budget allocation.

-Guideline: keeps the ranked anchors and audit budget fixed but replaces the case-specific guideline with the generic prompt below. The prompt intentionally omits both the HCVR family/type label and any case-specific vulnerability metadata.

```text
{GENERIC_AUDIT_PROMPT}
```

-PoC: reuses the byte-identical `full/case_results.jsonl` stage-2 receipt (the source path and SHA-256 are recorded in `minus_poc/stage2_source.json`), then reports that same stage-2 bounded-audit score without preparing, running, or reading confirmation evidence. This isolates the two-stage versus three-stage delta without resampling the audit model. Its Confirmed column is N/A by definition.

## 4. 结果

Variant | Recall | Precision | F1 | Alarms | Confirmed
{chr(10).join(rows)}

Raw TP/FP/FN counts:
{chr(10).join(count_rows) if count_rows else 'No completed rows yet.'}

Representative hit/miss flips:
{flips}

## 5. 异常与缺口

The confirmation bridge rejects (rather than counts) any runtime that lacks source-attested exact revision lineage, any PoC/verifier receipt lacking finding SHA binding, any missing artifact/evidence/reproduce command for a CONFIRMED verdict, or every verifier result other than CONFIRMED. The present PoC runner still needs to emit these structured receipts automatically after its autonomous sessions; until it does, full Confirmed remains N/A. Any per-case materialization, model, timeout, JSON-format, disposition-completeness, runtime, or confirmation-receipt failures are preserved in the corresponding output roots.

## 6. 复现入口

Run root: `{output_dir}`

One-command rerun for the same A scope:

```bash
python {Path(__file__).resolve()} --output-dir {output_dir} --qa {dataset_receipt['qa_path']} --cases-file {dataset_receipt['cases_path']} --allowlist {dataset_receipt['allowlist_path']} --summary {dataset_receipt['summary_path']} --recall-results {args.recall_results} --repo-cache {args.repo_cache} --snapshot-root {args.snapshot_root} --codex-home {args.codex_home} --temp-root {args.temp_root} --audit-runner {args.audit_runner} --model {args.model} --anchor-budget {args.anchor_budget} --variants {','.join(args.variants)} --resume
```

Primary output files:
- `{output_dir}/dataset_receipt.json`
- `{output_dir}/ablation_config.json`
- `{output_dir}/<variant>/case_results.jsonl`
- `{output_dir}/<variant>/score_summary.json`
- `{output_dir}/<variant>/case_scores.jsonl`
- `{output_dir}/full/confirmation/confirmation_summary.json` (only after a valid stage-3 run)

Pure-text table for LaTeX:

Variant | Recall | Precision | F1 | Alarms | Confirmed
{chr(10).join(rows)}
"""
    (output_dir / "experiment_a_report.md").write_text(report, encoding="utf-8")


def build_flip_notes(by_variant: dict[str, dict[str, Any]]) -> str:
    full = by_variant.get("full")
    if full is None:
        return "GCA(full) has not completed, so flip analysis is pending."
    full_scores = {row["identity_key"]: row for row in full.get("case_scores") or []}
    notes: list[str] = []
    for variant in ("minus_rank", "minus_guideline", "minus_poc"):
        score = by_variant.get(variant)
        if score is None:
            continue
        current = {row["identity_key"]: row for row in score.get("case_scores") or []}
        lost = [
            identity
            for identity, row in full_scores.items()
            if row.get("tp") == 1 and current.get(identity, {}).get("tp") != 1
        ][:3]
        gained = [
            identity
            for identity, row in current.items()
            if row.get("tp") == 1 and full_scores.get(identity, {}).get("tp") != 1
        ][:3]
        notes.append(
            f"{VARIANT_LABELS[variant]}: full-hit to miss examples={lost or []}; miss to hit examples={gained or []}."
        )
    return "\n".join(notes) if notes else "Flip analysis is pending until at least one ablation row completes."


def parse_variants(value: str) -> list[str]:
    variants = [item.strip() for item in value.split(",") if item.strip()]
    allowed = set(VARIANT_LABELS)
    bad = [variant for variant in variants if variant not in allowed]
    if bad:
        raise argparse.ArgumentTypeError(f"unknown variants: {bad}; allowed={sorted(allowed)}")
    return variants


def git_value(command: list[str], cwd: Path) -> str:
    try:
        return subprocess.check_output(command, cwd=cwd, text=True).strip()
    except Exception:
        return "unknown"


def main() -> None:
    parser = argparse.ArgumentParser()
    root = Path(__file__).resolve().parents[2]
    parser.add_argument("--qa", type=Path, default=root / "hcvr_new_unified_dataset_v2/receipts/hcvr_new_unified_paper_eval_rebalance_qa.v2.json")
    parser.add_argument("--cases-file", type=Path, default=root / "hcvr_new_unified_dataset_v2/dataset/new_unified_cases.v1.jsonl")
    parser.add_argument("--allowlist", type=Path, default=root / "hcvr_new_unified_dataset_v2/receipts/hcvr_new_unified_fix_revision_paper_eval_review.v2.jsonl")
    parser.add_argument("--summary", type=Path, default=root / "hcvr_new_unified_dataset_v2/dataset/summary.v1.json")
    parser.add_argument("--recall-results", type=Path, required=True)
    parser.add_argument(
        "--guideline-overrides",
        type=Path,
        default=root / "guideline-agent-pipeline/configs/manual_audit_guideline_overrides.v1.json",
        help="Versioned audit-stage type overrides; use --guideline-overrides '' is not supported, pass a JSON file or omit after editing defaults.",
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--repo-cache", type=Path, required=True)
    parser.add_argument("--snapshot-root", type=Path, required=True)
    parser.add_argument("--codex-home", type=Path, default=Path.home() / ".trae")
    parser.add_argument("--temp-root", type=Path, required=True)
    parser.add_argument("--audit-runner", choices=("codex", "opencode"), default="codex")
    parser.add_argument("--codex", default="codex")
    parser.add_argument("--opencode", default="opencode")
    parser.add_argument("--model", default="DeepSeek-V4-Pro")
    parser.add_argument(
        "--localization-judges",
        action="store_true",
        help="For findings without a deterministic frozen-reference match, run a separate localization-only receipt using the same runner, executable, model, and timeout as Stage 2.",
    )
    parser.add_argument("--variants", type=parse_variants, default=["full", "minus_rank", "minus_guideline", "minus_poc"])
    parser.add_argument("--limit", type=int)
    parser.add_argument("--skip", type=int, default=0)
    parser.add_argument(
        "--anchor-budget",
        type=int,
        default=200,
        help="Consume this many Top-K candidates in the single case-level audit prompt.",
    )
    parser.add_argument(
        "--anchor-group-size",
        type=int,
        default=10,
        help="Candidates per independent directory-local audit group; this does not truncate Top-K.",
    )
    parser.add_argument(
        "--group-timeout",
        type=int,
        default=300,
        help="Maximum seconds for one independent anchor-group audit session.",
    )
    parser.add_argument("--clone-timeout", type=int, default=600)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument(
        "--retry-incomplete-groups",
        action="store_true",
        help="With --resume, reuse completed groups and rerun only timeout/invalid/failure groups.",
    )
    parser.add_argument("--model-budget-note", default="single bounded audit response; inspect only the minimal relevant source path")
    parser.add_argument("--inline-source-context", action="store_true")
    parser.add_argument("--inline-context-anchors", type=int, default=8)
    parser.add_argument("--inline-context-lines", type=int, default=20)
    parser.add_argument("--inline-context-max-chars", type=int, default=60_000)
    parser.add_argument(
        "--include-case-metadata",
        action="store_true",
        help="Include case/CVE identifiers as bookkeeping metadata, not audit knowledge.",
    )
    args = parser.parse_args()

    if (
        args.anchor_budget < 1
        or args.anchor_group_size < 1
        or args.group_timeout < 1
        or args.concurrency < 1
    ):
        raise SystemExit("anchor-budget, anchor-group-size, group-timeout, and concurrency must be positive")
    if args.skip < 0 or (args.limit is not None and args.limit < 1):
        raise SystemExit("skip must be non-negative and limit must be positive when set")
    args.output_dir = args.output_dir.resolve()
    args.localization_audit_runner = args.audit_runner
    args.localization_codex = args.codex
    args.localization_opencode = args.opencode
    args.localization_model = args.model
    args.localization_timeout = args.group_timeout
    args.localization_temp_root = (args.temp_root / "localization-judges").resolve()
    args.localization_temp_root.mkdir(parents=True, exist_ok=True)
    args.guideline_overrides = args.guideline_overrides.resolve()
    args.guideline_overrides_map = load_guideline_overrides(args.guideline_overrides)
    if args.output_dir.exists() and not args.resume:
        raise FileExistsError(f"refusing existing output dir without --resume: {args.output_dir}")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    args.repo_cache.mkdir(parents=True, exist_ok=True)
    args.snapshot_root.mkdir(parents=True, exist_ok=True)
    dataset_receipt = verify_dataset(
        args.qa.resolve(),
        args.cases_file.resolve(),
        args.allowlist.resolve(),
        args.summary.resolve(),
    )
    write_json(args.output_dir / "dataset_receipt.json", dataset_receipt)
    cases = load_paper_eval_cases(
        args.cases_file.resolve(),
        args.allowlist.resolve(),
        limit=args.limit,
        skip=args.skip,
    )
    recall_results = load_recall_results(args.recall_results.resolve())
    expected_run_cases = len(cases)
    needed_identities = {case["identity_key"] for case in cases}
    present_needed = len(needed_identities.intersection(recall_results))
    if present_needed < expected_run_cases:
        raise ValueError(
            f"recall results cover {present_needed}/{expected_run_cases} selected cases"
        )
    actual_anchor_counts = [
        len(select_ranked_anchors(case, recall_results, args.anchor_budget))
        for case in cases
    ]
    args.actual_anchor_count_min = min(actual_anchor_counts) if actual_anchor_counts else 0
    args.actual_anchor_count_max = max(actual_anchor_counts) if actual_anchor_counts else 0
    args.actual_anchor_count_below_budget = sum(
        count < args.anchor_budget for count in actual_anchor_counts
    )
    repo_root = root.parent
    args.git_branch = git_value(["git", "rev-parse", "--abbrev-ref", "HEAD"], repo_root)
    args.git_commit = git_value(["git", "rev-parse", "HEAD"], repo_root)
    config = {
        "schema_version": "hcvr_ablation_a_config.v3",
        "runner_script": str(Path(__file__).resolve()),
        "runner_script_sha256": sha256_file(Path(__file__).resolve()),
        "variants": args.variants,
        "audit_runner": args.audit_runner,
        "model": args.model,
        "anchor_budget": args.anchor_budget,
        "actual_anchor_count_min": args.actual_anchor_count_min,
        "actual_anchor_count_max": args.actual_anchor_count_max,
        "actual_anchor_count_below_budget": args.actual_anchor_count_below_budget,
        "anchor_group_size": args.anchor_group_size,
        "case_count": expected_run_cases,
        "full_dataset_case_count": EXPECTED_CASE_COUNT,
        "feasibility_subset": expected_run_cases != EXPECTED_CASE_COUNT,
        "limit": args.limit,
        "skip": args.skip,
        "group_timeout": args.group_timeout,
        "concurrency": args.concurrency,
        "localization_judges": args.localization_judges,
        "localization_inherits_stage2_runner": True,
        "localization_audit_runner": args.audit_runner,
        "localization_model": args.model,
        "localization_timeout": args.group_timeout,
        "localization_temp_root": str(args.localization_temp_root),
        "retry_incomplete_groups": args.retry_incomplete_groups,
        "inline_source_context": args.inline_source_context,
        "inline_context_anchors": args.inline_context_anchors,
        "inline_context_lines": args.inline_context_lines,
        "inline_context_max_chars": args.inline_context_max_chars,
        "include_case_metadata": args.include_case_metadata,
        "guideline_overrides_path": str(args.guideline_overrides),
        "guideline_overrides_sha256": sha256_file(args.guideline_overrides),
        "guideline_override_types": sorted(args.guideline_overrides_map),
        "recall_results": str(args.recall_results.resolve()),
        "git_branch": args.git_branch,
        "git_commit": args.git_commit,
        "scoring": {
            "tp": "at most one emitted finding per case: deterministic frozen-reference overlap/symbol match, or a valid independent localization-judge match receipt",
            "fp": "every emitted finding other than the one scored TP for its case, including duplicate or additional truth-overlapping findings",
            "fn": "case has no emitted finding overlapping any vulnerability_trace node",
            "recall_denominator": expected_run_cases,
            "alarms": "TP+FP; raw emitted finding total after the one-TP-per-case policy",
            "f1": "2*TP/(2*TP+FP+FN)",
            "unresolved_localization": "when --localization-judges is enabled, every non-deterministic finding requires a valid independent judge receipt; missing/failed receipts make the row formal-ineligible",
        },
    }
    write_json(args.output_dir / "ablation_config.json", config)
    scores = []
    for variant in args.variants:
        score = run_variant(
            args=args,
            variant=variant,
            cases=cases,
            recall_results=recall_results,
        )
        scores.append(score)
        write_run_report(
            output_dir=args.output_dir,
            dataset_receipt=dataset_receipt,
            scores=scores,
            args=args,
        )
    write_json(args.output_dir / "all_scores.json", {score["variant"]: score for score in scores})
    write_run_report(
        output_dir=args.output_dir,
        dataset_receipt=dataset_receipt,
        scores=scores,
        args=args,
    )


if __name__ == "__main__":
    main()
