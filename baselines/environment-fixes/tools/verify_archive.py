#!/usr/bin/env python3
"""Read-only preservation checks. Never build images, start services, or run recipes."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path, PurePosixPath
import re


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_object(pairs):
    obj = {}
    for key, value in pairs:
        require(key not in obj, f"Duplicate JSON key: {key}")
        obj[key] = value
    return obj


def read_json(path):
    return json.loads(path.read_text(), object_pairs_hook=unique_object)


def safe_path(root, name):
    require(isinstance(name, str) and name and "\\" not in name and ":" not in name,
            "Invalid archive path")
    relative = PurePosixPath(name)
    require(not relative.is_absolute() and ".." not in relative.parts
            and relative.as_posix() == name, f"Unsafe path: {name}")
    current = root
    for part in relative.parts:
        current = current / part
        require(not current.is_symlink(), f"Symlink not allowed: {name}")
    require(current.resolve().is_relative_to(root.resolve()), f"Path escapes root: {name}")
    return current


def verify_entries(root, entries):
    require(isinstance(entries, list) and entries, "Nonempty file manifest required")
    seen = set()
    size = 0
    for item in entries:
        name = item["path"]
        path = safe_path(root, name)
        require(name not in seen, f"Duplicate entry: {name}")
        seen.add(name)
        require(type(item["bytes"]) is int and item["bytes"] >= 0, f"Invalid size: {name}")
        require(isinstance(item["sha256"], str)
                and re.fullmatch(r"[a-f0-9]{64}", item["sha256"]), f"Invalid hash: {name}")
        require(path.is_file() and path.stat().st_size == item["bytes"], f"Missing or wrong size: {name}")
        require(sha256(path) == item["sha256"], f"Hash mismatch: {name}")
        size += item["bytes"]
    return {"files": len(seen), "bytes": size}


def verify_payload_coverage(directory, prefix, exported):
    actual = set()
    for path in (directory / prefix).rglob("*"):
        require(not path.is_symlink(), "Symlink in payload")
        if path.is_file():
            actual.add(path.relative_to(directory).as_posix())
    require(actual == set(exported), "Payload contains missing, unlisted or withheld files")


def verify_legacy(root):
    legacy = root / "legacy-builds"
    source = read_json(legacy / "source-manifest.json")
    result = verify_entries(legacy, source["files"])
    records = read_json(legacy / "catalog.json")["records"]
    recipes = read_json(legacy / "recipe-index.json")["recipes"]
    require(len(records) == 317 and len({r["id"] for r in records}) == 317, "Legacy catalog identity mismatch")
    require(len(recipes) == 254 and len({r["recipe"] for r in recipes}) == 254, "Legacy recipe identity mismatch")
    indexed = {r["recipe"] for r in recipes}
    require(indexed == {r["path"] for r in source["files"] if r["path"].endswith("/Dockerfile")},
            "Legacy recipe/source manifest mismatch")
    summary = source["summary"]
    require(len(source["files"]) - len(recipes) == summary["build_notes"] == 43, "Legacy note count mismatch")
    require(sum(bool(r["catalog_id_candidates"]) for r in recipes) == summary["recipe_folders_with_literal_catalog_match"] == 240,
            "Legacy join count mismatch")
    for field, summary_key in (("build_status", "catalog_build_status"), ("is_verified", "catalog_is_verified"), ("can_build", "catalog_can_build")):
        require(dict(Counter(str(r[field]) for r in records)) == summary[summary_key], "Legacy summary mismatch")
    from export_legacy import FIELDS
    require(all(set(r) == set(FIELDS) for r in records), "Non-allowlisted legacy catalog field")
    verify_payload_coverage(legacy, "recipes", [r["path"] for r in source["files"]])
    return result


def verify_runtime(root):
    directory = root / "runtime-v2"
    index = read_json(directory / "runtime-environment-index.json")
    tasks, attempts = index["tasks"], index["attempts"]
    require(len(tasks) == index["task_count"] == 143, "Runtime task count mismatch")
    require(len({row["task_id"] for row in tasks}) == 143, "Duplicate runtime task")
    require(len(attempts) == index["attempt_count"] == 152, "Runtime attempt count mismatch")
    require(len({(r["task_id"], r["attempt"]) for r in attempts}) == 152, "Duplicate runtime attempt")
    counts = dict(Counter(row["historical_attempt_status"] for row in attempts))
    require(counts == index["historical_attempt_status_counts"] == {"passed": 143, "failed": 9},
            "Runtime historical outcome mismatch")
    by_attempt = {(r["task_id"], r["attempt"]): r for r in attempts}
    for task in tasks:
        attempt = by_attempt.get((task["task_id"], task["final_attempt"]))
        require(attempt and attempt["historical_attempt_status"] == "passed", "Invalid runtime final mapping")
        require(task["historical_task_status"] == "runtime_ready", "Unexpected runtime task status")
    files = []
    for row in index["recipes"]:
        if row["publication_status"] == "index_only":
            require("export_path" not in row, "Withheld file still marked exported")
            continue
        if row["transformation"] == "byte_exact":
            require(row["source"]["sha256"] == row["export_sha256"], "Original runtime bytes mismatch")
        files.append({"path": row["export_path"], "bytes": row["export_bytes"], "sha256": row["export_sha256"]})
    result = verify_entries(directory, files)
    require(result["files"] == index["exported_recipe_count"] and result["bytes"] == index["exported_recipe_bytes"],
            "Runtime exported totals mismatch")
    require(index["index_only_count"] == len(index["recipes"]) - len(files), "Runtime held count mismatch")
    verify_payload_coverage(directory, "recipes", [r["path"] for r in files])
    result["historical_attempts"] = counts
    return result


def verify_source_runtime(root):
    directory = root / "source-runtime"
    manifest = read_json(directory / "MANIFEST.json")
    files = []
    for row in manifest["files"]:
        require(row["source_sha256"] == row["published_sha256"], "Source/runtime original byte mismatch")
        files.append({"path": row["path"], "bytes": row["bytes"], "sha256": row["published_sha256"]})
    result = verify_entries(directory, files)
    require(result == {"files": manifest["file_count"], "bytes": manifest["bytes"]}, "Source/runtime totals mismatch")
    cases = read_json(directory / "CASE_INDEX.json")["cases"]
    require(len(cases) == 22 and len({r["case_id"] for r in cases}) == 22, "Source/runtime case mismatch")
    require(all(r["original_vulnerable_exact_source_claim"] is False for r in cases), "Synthetic provenance changed")
    require(sum(r["origin_label"] == "source_inserted" for r in cases) == 20, "Source insertion label mismatch")
    require(sum(r["origin_label"] == "superset_base_and_patched_control" for r in cases) == 2, "Superset control label mismatch")
    validate_source_runtime_status(cases)
    held = read_json(directory / "HELD.json")
    validate_held(held, files)
    verify_payload_coverage(directory, "files", [r["path"] for r in files])
    return result


def validate_held(held, published):
    require(held["not_included"] == len(held["files"]) == 95, "Held count mismatch")
    allowed = {"sha256", "reason", "source_provenance"}
    require(all(set(r) <= allowed and {"sha256", "reason"} <= set(r) for r in held["files"]), "Invalid held fields")
    require(sum(set(r) == {"sha256", "reason"} for r in held["files"]) == 2, "Sensitive held metadata mismatch")
    require(all(re.fullmatch(r"[a-f0-9]{64}", r["sha256"]) for r in held["files"]), "Invalid held digest")
    require(not ({r["sha256"] for r in held["files"]} & {r["sha256"] for r in published}), "Withheld content was published")


def validate_source_runtime_status(cases):
    by_id = {r["case_id"]: r for r in cases}
    for identity in ("superset-cve2017-18342", "superset-cve2020-14343"):
        require(by_id[identity]["origin_label"] == "superset_base_and_patched_control", "Superset control label mismatch")
    pulsar = by_id["apache_pulsar__CVE-2021-44228__source_inserted"]
    verdicts = {Path(r["source_record"]).name: r["recorded"].get("status") for r in pulsar["recorded_verdicts"]}
    require(verdicts.get("runtime-source-runner-verify.json") == "TP_RUNTIME_VERIFIED_SOURCE_RUNNER",
            "Pulsar source-runner verdict changed")
    require(verdicts.get("runtime-source-verify.json") == "FAILED", "Pulsar runtime failure erased")


def verify_codeql_compile(root):
    directory = root / "codeql-compile"
    manifest = read_json(directory / "FILE_MANIFEST.json")
    result = verify_entries(directory, manifest["files"])
    require(result["files"] == 736, "Compile archive file count mismatch")
    provenance = read_json(directory / "SOURCE_PROVENANCE.json")["files"]
    require(len(provenance) == len({r["published_path"] for r in provenance}) == 735, "Compile provenance coverage mismatch")
    for row in provenance:
        require(sha256(safe_path(directory, row["published_path"])) == row["published_sha256"], "Compile provenance hash mismatch")
    cases = [p for p in (directory / "fleet-138-v1").iterdir() if p.is_dir()]
    require(len(cases) == 137 and all((p / "Dockerfile").is_file() for p in cases), "Compile case/Dockerfile count mismatch")
    counts = Counter(read_json(p / "historical-receipt.json")["review"]["verdict"] for p in cases)
    require(dict(counts) == {"accepted": 135, "rejected": 2}, "Historical compile review outcomes changed")
    require(len(list((directory / "iris-a26").rglob("validated-decision*.json"))) == 242, "Repair decision count mismatch")
    require(len(list((directory / "iris-a26").rglob("w1_llm_repair_receipts.compact.json"))) == 11, "Repair ledger count mismatch")
    result["fleet_historical_reviews"] = dict(counts)
    return result


def verify(root):
    manifest = read_json(root / "archive-manifest.json")
    result = verify_entries(root, manifest["files"])
    require(result["files"] == manifest["file_count"] and result["bytes"] == manifest["bytes"],
            "Manifest totals mismatch")
    seen = {entry["path"] for entry in manifest["files"]}
    actual = set()
    for path in root.rglob("*"):
        if "__pycache__" in path.parts:
            require(path.is_dir() or (path.is_file() and path.suffix == ".pyc" and not path.is_symlink()),
                    "Unexpected content under __pycache__")
            continue
        require(not path.is_symlink(), f"Symlink found: {path.relative_to(root)}")
        if path.is_file() and path.relative_to(root).as_posix() not in ("archive-manifest.json", "verification-receipt.json"):
            actual.add(path.relative_to(root).as_posix())
    require(actual == seen, f"Coverage mismatch: unlisted={sorted(actual-seen)}, missing={sorted(seen-actual)}")
    result["legacy_original_bytes"] = verify_legacy(root)
    result["legacy_support"] = verify_entries(root / "legacy-support", read_json(root / "legacy-support/source-manifest.json")["files"])
    result["runtime_v2"] = verify_runtime(root)
    result["source_runtime"] = verify_source_runtime(root)
    result["codeql_compile"] = verify_codeql_compile(root)
    if (root / "hcvr").exists():
        from verify_hcvr import verify as verify_hcvr
        result["hcvr"] = verify_hcvr(root / "hcvr")
    result["manifest_sha256"] = sha256(root / "archive-manifest.json")
    result["scope"] = "preservation_integrity_only_no_build_or_runtime_rerun"
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    print(json.dumps(verify(args.root), indent=2))
