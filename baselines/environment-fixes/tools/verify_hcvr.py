"""Validate the HCVR repair-knowledge archive, without executing old recipes."""

from collections import Counter
from pathlib import Path
import argparse
import json
import re

from verify_archive import read_json, require, safe_path, verify_entries


def verify(root):
    root = Path(root)
    manifest = read_json(root / "file-manifest.json")
    totals = verify_entries(root, manifest["files"])
    expected = {r["path"] for r in manifest["files"]}
    actual = set()
    for path in root.rglob("*"):
        require(not path.is_symlink(), "Symlink in HCVR archive")
        relative = path.relative_to(root).as_posix()
        if path.is_file() and relative not in {"file-manifest.json", "verification.json"}:
            actual.add(relative)
    require(actual == expected, "HCVR payload coverage mismatch")
    sources = read_json(root / "source-provenance.json")["sources"]
    by_source = {r["source_id"]: r for r in sources}
    require(len(by_source) == len(sources), "Duplicate source identity")
    for row in sources:
        require(re.fullmatch(r"[a-f0-9]{64}", row["sha256"]), "Bad source hash")
        require(type(row["bytes"]) is int and row["bytes"] >= 0, "Bad source size")
        require(not row["source_relative_path"].startswith("/"), "Private absolute source path")
        require(".." not in Path(row["source_relative_path"]).parts, "Unsafe source label")
    index = read_json(root / "case-index.json")
    seen = set()
    paths = set()
    records = 0
    for entry in index["cases"]:
        require(entry["case_id"] not in seen, "Duplicate case identity")
        seen.add(entry["case_id"])
        require(entry["path"] not in paths, "Duplicate case path")
        paths.add(entry["path"])
        case = read_json(safe_path(root, entry["path"]))
        require(case["case_id"] == entry["case_id"], "Case mapping mismatch")
        require(case["new_execution_performed"] is False, "Historical result relabeled")
        require(len(case["records"]) == entry["record_count"], "Record count mismatch")
        counts = dict(Counter(r["evidence_level"] for r in case["records"]))
        require(counts == entry["evidence_counts"], "Evidence count mismatch")
        for row in case["records"]:
            require(row["source"]["source_id"] in by_source, "Unbound evidence source")
            require(isinstance(row["source"]["pointer"], str), "Missing evidence pointer")
            for reference in row.get("duplicate_source_references", []):
                require(reference["source_id"] in by_source, "Unbound duplicate evidence source")
                require(isinstance(reference["pointer"], str), "Missing duplicate evidence pointer")
            require(row["historical_status"] is not None, "Missing original status")
            require(row["new_execution_performed"] is False, "Historical record relabeled")
        records += len(case["records"])
    require(paths == {p for p in expected if p.startswith("cases/")}, "Case coverage mismatch")
    require(len(seen) == index["case_count"], "Case total mismatch")
    require(records == index["record_count"], "Record total mismatch")
    return dict(totals, cases=len(seen), records=records, original_sources=len(sources),
                scope="archive_integrity_only_no_build_or_runtime_execution")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1] / "hcvr")
    args = parser.parse_args()
    print(json.dumps(verify(args.root), indent=2))
