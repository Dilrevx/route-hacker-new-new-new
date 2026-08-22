#!/usr/bin/env python3
"""Compare guideline sidecars by the text consumed by recall."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from run_hcvr_case_anchor_audits import direct_guideline_text, read_json, read_jsonl


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_sidecar(path: Path) -> dict[str, str]:
    if path.suffix.lower() == ".json":
        payload = read_json(path)
        if isinstance(payload, dict) and "guidelines" in payload:
            payload = payload["guidelines"]
        if isinstance(payload, dict):
            rows = []
            for key, value in payload.items():
                if isinstance(value, str):
                    rows.append({"identity_key": key, "guideline_text": value})
                elif isinstance(value, dict):
                    row = dict(value)
                    row.setdefault("identity_key", key)
                    rows.append(row)
                else:
                    rows.append({"identity_key": key})
        elif isinstance(payload, list):
            rows = payload
        else:
            raise ValueError(f"unsupported sidecar JSON shape: {path}")
    else:
        rows = list(read_jsonl(path))

    sidecar: dict[str, str] = {}
    duplicates: list[str] = []
    for row in rows:
        identity = row.get("identity_key") or row.get("new_unified_case_id") or row.get("case_id") or row.get("id")
        text = direct_guideline_text(row)
        if not identity or not text:
            continue
        key = str(identity)
        if key in sidecar:
            duplicates.append(key)
            continue
        sidecar[key] = text.strip()
    if duplicates:
        raise ValueError(f"duplicate sidecar keys in {path}: {sorted(duplicates)[:10]}")
    if not sidecar:
        raise ValueError(f"sidecar has no recall-consumable guideline rows: {path}")
    return sidecar


def compare_sidecars(left: dict[str, str], right: dict[str, str]) -> dict[str, Any]:
    left_keys = set(left)
    right_keys = set(right)
    common = sorted(left_keys & right_keys)
    changed = [key for key in common if left[key] != right[key]]
    return {
        "schema_version": "hcvr_guideline_sidecar_comparison.v1",
        "left_count": len(left),
        "right_count": len(right),
        "common_count": len(common),
        "same_key_set": left_keys == right_keys,
        "left_only_count": len(left_keys - right_keys),
        "right_only_count": len(right_keys - left_keys),
        "changed_text_count": len(changed),
        "recall_consumed_text_equivalent": left_keys == right_keys and not changed,
        "left_only_sample": sorted(left_keys - right_keys)[:20],
        "right_only_sample": sorted(right_keys - left_keys)[:20],
        "changed_text_sample": changed[:20],
    }


def write_markdown(path: Path, summary: dict[str, Any]) -> None:
    lines = [
        "# Guideline Sidecar Equivalence",
        "",
        "This report compares guideline sidecars by the key and guideline text that the recall runner consumes.",
        "It intentionally ignores release-only metadata that does not affect `apply_guideline_overrides()`.",
        "",
        "## Summary",
        "",
        f"- Left: `{summary['left_label']}`",
        f"- Right: `{summary['right_label']}`",
        f"- Left rows: {summary['left_count']}",
        f"- Right rows: {summary['right_count']}",
        f"- Common rows: {summary['common_count']}",
        f"- Same key set: {summary['same_key_set']}",
        f"- Changed consumed guideline texts: {summary['changed_text_count']}",
        f"- Recall-consumed text equivalent: {summary['recall_consumed_text_equivalent']}",
        "",
        "## Boundary",
        "",
        "If `recall_consumed_text_equivalent` is true, a deterministic recall runner with the same identity file, snapshots, candidate slicing, embedding backend, and ranking parameters should produce the same rankings even if the sidecar files differ in non-consumed metadata.",
        "This equivalence report is evidence for reusing an existing same-identity recall table only under those unchanged runtime conditions.",
        "",
    ]
    if summary["changed_text_sample"]:
        lines.append("## Changed Text Sample")
        lines.append("")
        for key in summary["changed_text_sample"]:
            lines.append(f"- `{key}`")
        lines.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--left", type=Path, required=True)
    parser.add_argument("--right", type=Path, required=True)
    parser.add_argument("--left-label", default="left")
    parser.add_argument("--right-label", default="right")
    parser.add_argument("--output-json", type=Path, required=True)
    parser.add_argument("--output-md", type=Path, required=True)
    args = parser.parse_args()

    left_path = args.left.resolve()
    right_path = args.right.resolve()
    left = read_sidecar(left_path)
    right = read_sidecar(right_path)
    summary = compare_sidecars(left, right)
    summary.update(
        {
            "left_label": args.left_label,
            "right_label": args.right_label,
            "left_path": str(left_path),
            "right_path": str(right_path),
            "left_sha256": sha256_file(left_path),
            "right_sha256": sha256_file(right_path),
        }
    )
    write_json(args.output_json, summary)
    write_markdown(args.output_md, summary)
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
