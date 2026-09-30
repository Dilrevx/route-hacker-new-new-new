#!/usr/bin/env python3
"""Check archived bytes and recompute historical metrics, without training.

The default check uses Python's standard library only. --check-weights also
requires PyTorch and checks both P3C16 and P3C64 with its restricted weights-only
loader, never pickle's unrestricted loader. This verifies preservation and report consistency, not
the original training execution, candidate construction, or label correctness.
"""

import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
import sys


P3C64_SHA256 = "5425766d0dff286fb78f218808b21f8a502b85be170f6a8c911f7db761bc8e16"
P3C64_PATH = "p3c64/selection_run_v1/p3c64_state.pt"
CHECKPOINTS = {
    "P3C16": {"path": "p3c64/selection_run_v1/p3c16_state.pt",
              "sha256": "f0bd466c325754c2c6acd00f2e35cc601282c6d516c06ebac3ba441bf466d470"},
    "P3C64": {"path": P3C64_PATH, "sha256": P3C64_SHA256},
}
KS = (1, 3, 5, 10, 20, 30, 50, 100, 200, 500)
FIXED_KS = (30, 50, 100, 150, 200, 300, 500)
FIXED_COMPARISON_KS = (30, 50, 100, 200, 300, 500)
FIXED_REPORT = "new-impl/new-guideline/results/p3c64-fixed143-paper-eval-20260820"


class VerificationError(ValueError):
    """An archive or report failed a check."""


def require(condition, message):
    if not condition:
        raise VerificationError(message)


def equal(actual, expected, label):
    """Compare a recomputed scalar to a recorded scalar, with float tolerance."""
    if isinstance(actual, float):
        require(type(expected) in (int, float) and math.isfinite(expected)
                and math.isclose(actual, expected, rel_tol=1e-11, abs_tol=1e-12),
                f"{label}: recomputed {actual!r}, recorded {expected!r}")
    else:
        require(type(actual) is type(expected) and actual == expected,
                f"{label}: recomputed {actual!r}, recorded {expected!r}")


def unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_constant(value):
    raise VerificationError(f"non-finite JSON number: {value}")


def parse_json(text, label):
    try:
        return json.loads(text, object_pairs_hook=unique_json_object,
                          parse_constant=reject_constant)
    except (ValueError, TypeError) as exc:
        raise VerificationError(f"{label}: {exc}") from exc


def read_json(path):
    return parse_json(path.read_text(encoding="utf-8"), str(path))


def read_jsonl(path):
    rows = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        require(bool(line.strip()), f"{path}:{number}: blank JSONL row")
        row = parse_json(line, f"{path}:{number}")
        require(isinstance(row, dict), f"{path}:{number}: row must be an object")
        rows.append(row)
    require(bool(rows), f"{path}: empty JSONL file")
    return rows


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def safe_archive_path(root, name):
    require(isinstance(name, str) and bool(name) and "\\" not in name,
            f"unsafe archive path: {name!r}")
    relative = PurePosixPath(name)
    require(bool(relative.parts) and not relative.is_absolute() and ".." not in relative.parts
            and relative.as_posix() == name and ":" not in name,
            f"unsafe archive path: {name!r}")
    require(relative.parts[0] in {"p3c64", "helpers"},
            f"unexpected archive prefix: {name}")
    current = root
    for part in relative.parts:
        current = current / part
        require(not current.is_symlink(), f"symlink not permitted: {name}")
    require(current.resolve().is_relative_to(root.resolve()),
            f"path escapes archive root: {name}")
    return current


def verify_manifest(root, manifest_path):
    manifest = read_json(manifest_path)
    require(isinstance(manifest, dict) and bool(manifest.get("schema_version")),
            "manifest requires schema_version")
    entries = manifest.get("files")
    require(isinstance(entries, list) and bool(entries), "manifest files must be a nonempty list")
    seen = set()
    total_bytes = 0
    for entry in entries:
        require(isinstance(entry, dict), "manifest entry must be an object")
        name = entry["path"]
        path = safe_archive_path(root, name)
        require(name not in seen, f"duplicate manifest path: {name}")
        seen.add(name)
        require(type(entry["bytes"]) is int and entry["bytes"] >= 0,
                f"invalid byte count: {name}")
        require(isinstance(entry["sha256"], str)
                and re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]),
                f"invalid SHA-256: {name}")
        require(path.is_file(), f"missing archive file: {name}")
        equal(path.stat().st_size, entry["bytes"], f"bytes: {name}")
        equal(sha256(path), entry["sha256"], f"SHA-256: {name}")
        total_bytes += entry["bytes"]
    actual = set()
    for prefix in ("p3c64", "helpers"):
        directory = root / prefix
        require(not directory.is_symlink(), f"symlink not permitted: {prefix}")
        if directory.exists():
            for path in directory.rglob("*"):
                require(not path.is_symlink(), f"symlink not permitted: {path}")
                if path.is_file():
                    actual.add(path.relative_to(root).as_posix())
    require(actual == seen,
            f"manifest coverage mismatch; unlisted={sorted(actual - seen)}, "
            f"missing={sorted(seen - actual)}")
    for key, computed in (("file_count", len(seen)), ("bytes", total_bytes)):
        if key in manifest:
            equal(computed, manifest[key], f"manifest total {key}")
    return {"file_count": len(seen), "bytes": total_bytes,
            "manifest_sha256": sha256(manifest_path)}


def unique_rows(rows, key, label):
    result = {}
    for row in rows:
        value = row.get(key)
        require(isinstance(value, str) and bool(value), f"{label}: invalid {key}")
        require(value not in result, f"{label}: duplicate {key}: {value}")
        result[value] = row
    return result


def valid_rank(value, candidate_count, label):
    require(type(candidate_count) is int and candidate_count > 0,
            f"{label}: invalid candidate_count: {candidate_count!r}")
    require(value is None or (type(value) is int and 1 <= value <= candidate_count),
            f"{label}: rank must be null or an integer in [1, {candidate_count}]: {value!r}")
    return value


def hit(rank, k):
    return rank is not None and rank <= k


def rank_metrics(rows, rank_key, flag_prefix, ks, identity_key="case_id"):
    require(bool(rows), "cannot compute metrics for an empty ledger")
    unique_rows(rows, identity_key, rank_key)
    ranks = []
    for row in rows:
        label = f"{row[identity_key]}:{rank_key}"
        require(rank_key in row, f"{label}: missing rank field (not an explicit null)")
        rank = valid_rank(row[rank_key], row.get("candidate_count"), label)
        ranks.append(rank)
        for k in ks:
            key = f"{flag_prefix}hit_at_{k}"
            require(key in row, f"{label}: missing {key}")
            equal(hit(rank, k), row[key], f"{label}:{key}")
        if "mrr_contribution" in row:
            equal(0.0 if rank is None else 1.0 / rank, row["mrr_contribution"],
                  f"{label}:mrr_contribution")
    count = len(rows)
    metrics = {"case_count": count, "cases_with_hit": sum(r is not None for r in ranks),
               "MRR": math.fsum(1.0 / r for r in ranks if r is not None) / count}
    metrics.update({f"R@{k}": sum(hit(r, k) for r in ranks) / count for k in ks})
    return metrics


def percentiles(values):
    ordered = sorted(values)
    require(bool(ordered), "cannot compute percentiles without hits")
    result = {"min": float(ordered[0]), "max": float(ordered[-1])}
    for p in (25, 50, 75, 90, 95, 99):
        index = (len(ordered) - 1) * (p / 100)
        lower, upper = math.floor(index), math.ceil(index)
        result[f"p{p}"] = float(ordered[lower] + (ordered[upper] - ordered[lower]) * (index - lower))
    return result


def verify_split(p3):
    directory = p3 / "frozen_development_split_v1"
    cases = read_jsonl(directory / "p3_development_cases.v1.jsonl")
    pairs = read_jsonl(directory / "p3_development_pairs.v1.jsonl")
    by_case = unique_rows(cases, "case_id", "frozen cases")
    unique_rows(pairs, "pair_id", "frozen pairs")
    counts = read_json(directory / "summary.json")["counts"]
    case_counts = dict(Counter(row["p3_split"] for row in cases))
    pair_counts = dict(Counter(row["p3_split"] for row in pairs))
    equal(len(cases), 155, "frozen case count")
    equal(len(pairs), 295, "frozen pair count")
    equal(case_counts, {"p3_fitting": 112, "p3_selection": 43}, "frozen case splits")
    equal(pair_counts, {"p3_fitting": 217, "p3_selection": 78}, "frozen pair splits")
    equal(len(cases), counts["eligible_case_count"], "summary case count")
    equal(len(pairs), counts["pair_count"], "summary pair count")
    equal(case_counts, counts["case_count_by_split"], "summary case splits")
    equal(pair_counts, counts["pair_count_by_split"], "summary pair splits")
    families = {split: {r["p3_project_family"] for r in cases if r["p3_split"] == split}
                for split in case_counts}
    require(not families["p3_fitting"] & families["p3_selection"],
            "project families overlap between fitting and selection")
    equal(len(set.union(*families.values())), counts["eligible_project_family_count"],
          "summary project-family count")
    for pair in pairs:
        require(pair["case_id"] in by_case, f"pair references unknown case: {pair['pair_id']}")
        case = by_case[pair["case_id"]]
        for field in ("p3_split", "p3_project_family", "track_id", "repo_key"):
            equal(pair[field], case[field], f"{pair['pair_id']}:{field}")
        equal(pair["guideline_text"], case["query_text"], f"{pair['pair_id']}:query")
    equal({p["case_id"] for p in pairs}, set(by_case), "pair-backed cases")
    for split, label in (("p3_fitting", "fitting"), ("p3_selection", "selection")):
        tracks = dict(Counter(r["track_id"] for r in cases if r["p3_split"] == split))
        equal(tracks, counts[f"{label}_track_case_counts"], f"{label} track counts")
    selection_ids = {r["case_id"] for r in cases if r["p3_split"] == "p3_selection"}
    return {"case_count": len(cases), "pair_count": len(pairs), "case_splits": case_counts,
            "pair_splits": pair_counts, "project_family_overlap": 0}, selection_ids


def verify_historical_ledger(directory, ledger_name, methods, count, expected_ids=None):
    rows = read_jsonl(directory / ledger_name)
    summary = read_json(directory / "summary.json")
    equal(len(rows), count, f"{directory.name}:case count")
    by_case = unique_rows(rows, "case_id", directory.name)
    if expected_ids is not None:
        equal(set(by_case), expected_ids, f"{directory.name}:case identities")
    scope = summary["evaluation_scope"]
    equal(len(rows), scope["case_count"], f"{directory.name}:summary case count")
    equal(dict(Counter(r["track_id"] for r in rows)), scope["track_counts"],
          f"{directory.name}:track counts")
    equal(len({r["repo_key"] for r in rows}), scope["repository_count"],
          f"{directory.name}:repository count")
    if "candidate_count_total" in scope:
        equal(sum(r["candidate_count"] for r in rows), scope["candidate_count_total"],
              f"{directory.name}:candidate count")
    equal(set(summary["metrics"]), set(methods), f"{directory.name}:reported variants")
    metrics = {}
    for method in methods:
        actual = rank_metrics(rows, f"{method}_rank", f"{method}_", KS)
        recorded = summary["metrics"][method]
        for key, value in actual.items():
            equal(value, recorded[key], f"{directory.name}:{method}:{key}")
        ranks, normalized = [], []
        for row in rows:
            rank = row[f"{method}_rank"]
            if rank is not None:
                ranks.append(rank)
                norm = (rank - 1) / max(1, row["candidate_count"] - 1)
                equal(norm, row[f"{method}_normalized_rank"], f"{row['case_id']}:{method}:normalized rank")
                normalized.append(norm)
            else:
                equal(None, row[f"{method}_normalized_rank"], f"{row['case_id']}:{method}:normalized rank")
        for key, values in (("first_rank", ranks), ("normalized_first_rank", normalized)):
            for name, value in percentiles(values).items():
                equal(value, recorded[key][name], f"{directory.name}:{method}:{key}:{name}")
        metrics[method] = actual
    return metrics


def verify_fixed143(repository):
    directory = repository / FIXED_REPORT
    identities = unique_rows(read_jsonl(directory / "paper_eval_143_identities.jsonl"),
                             "identity_key", "fixed143 identities")
    equal(len(identities), 143, "fixed143 identity count")
    summary = read_json(directory / "summary.json")
    comparison = read_json(directory / "qwen4b_comparison.json")
    equal(list(FIXED_COMPARISON_KS), comparison.get("budgets"), "fixed143 comparison budgets")
    ledgers, metrics = {}, {}
    for method, filename in (("P3C64", "p3c64_case_rank_table.jsonl"),
                             ("Qwen4B", "qwen4b_case_rank_table.jsonl")):
        rows = read_jsonl(directory / filename)
        unique_rows(rows, "case_id", method)
        indexed = unique_rows(rows, "identity_key", method)
        equal(set(indexed), set(identities), f"fixed143 {method} identities")
        require(all(row["state"] == "completed" for row in rows),
                f"fixed143 {method}: not all cases completed")
        actual = rank_metrics(rows, "best_known_anchor_rank", "", FIXED_KS, "identity_key")
        actual["candidate_count"] = sum(r["candidate_count"] for r in rows)
        ledgers[method], metrics[method] = indexed, actual
    p3, qwen = metrics["P3C64"], metrics["Qwen4B"]
    saved = summary["metrics"]
    equal(len(identities), summary["identity_count"], "fixed143 summary identities")
    for key in ("case_count", "candidate_count"):
        equal(p3[key], saved[key], f"fixed143 summary {key}")
    equal(p3["case_count"], saved["completed_count"], "fixed143 completed")
    equal(0, saved["failed_count"], "fixed143 failures")
    equal(p3["cases_with_hit"], saved["hit_cases"], "fixed143 hits")
    equal(p3["MRR"], saved["mrr"], "fixed143 MRR")
    for field in ("missing_identities", "merge_failures"):
        equal([], summary[field], f"fixed143 {field}")
    for k in FIXED_COMPARISON_KS:
        hits = sum(hit(row["best_known_anchor_rank"], k) for row in ledgers["P3C64"].values())
        equal(hits, saved[f"hit_count_at_{k}"], f"fixed143 summary hits @{k}")
        equal(p3[f"R@{k}"], saved[f"known_anchor_hit_at_{k}"], f"fixed143 summary recall @{k}")
    for k in FIXED_COMPARISON_KS:
        record = comparison["metrics_on_common_identities"][f"hit_at_{k}"]
        for side, values, ledger in (("left", p3, ledgers["P3C64"]), ("right", qwen, ledgers["Qwen4B"])):
            hits = sum(hit(r["best_known_anchor_rank"], k) for r in ledger.values())
            equal(hits, record[f"{side}_count"], f"fixed143 {side} hit count @{k}")
            equal(values[f"R@{k}"], record[f"{side}_rate"], f"fixed143 {side} recall @{k}")
        equal(record["left_count"] - record["right_count"], record["delta_count"], f"fixed143 delta count @{k}")
        equal(p3[f"R@{k}"] - qwen[f"R@{k}"], record["delta_rate"], f"fixed143 delta recall @{k}")
    for side, values in (("left", p3), ("right", qwen)):
        equal(values["MRR"], comparison["metrics_on_common_identities"]["mrr"][side], f"fixed143 {side} MRR")
        equal(values["candidate_count"], comparison["candidate_count_on_common"][f"{side}_total"], f"fixed143 {side} candidate total")
        equal(143, comparison[f"{side}_count"], f"fixed143 {side} count")
        equal(0, comparison[f"{side}_only_count"], f"fixed143 {side}-only count")
    equal(143, comparison["common_count"], "fixed143 common count")
    equal(p3["MRR"] - qwen["MRR"], comparison["metrics_on_common_identities"]["mrr"]["delta"], "fixed143 MRR delta")
    different = []
    for identity in identities:
        left, right = ledgers["P3C64"][identity], ledgers["Qwen4B"][identity]
        for field in ("case_id", "repo_key", "checkout_revision"):
            equal(left[field], right[field], f"fixed143 {identity}:{field}")
        if left["candidate_count"] != right["candidate_count"]:
            different.append({"identity_key": identity, "P3C64": left["candidate_count"], "Qwen4B": right["candidate_count"]})
    equal(len(different), comparison["candidate_count_on_common"]["different_count"], "fixed143 unequal candidate counts")
    return {"metrics": metrics, "candidate_count_differences": different,
            "scope": "Recorded first-hit ranks, not a rerun against the full candidate pools."}


def check_weights(path):
    try:
        import torch
    except ImportError as exc:
        raise VerificationError("--check-weights requires PyTorch; no weight check was performed") from exc
    try:
        state = torch.load(path, map_location="cpu", weights_only=True)
    except Exception as exc:
        raise VerificationError(f"restricted weights-only loading failed: {exc}") from exc
    expected = {"query_projection.first.weight": (128, 1024),
                "query_projection.first.bias": (128,),
                "query_projection.output.weight": (1024, 128),
                "query_projection.output.bias": (1024,)}
    require(isinstance(state, dict) and set(state) == set(expected), "unexpected checkpoint keys")
    for key, shape in expected.items():
        require(torch.is_tensor(state[key]), f"checkpoint value is not a tensor: {key}")
        equal(tuple(state[key].shape), shape, f"checkpoint shape: {key}")
        require(state[key].dtype == torch.float32,
                f"checkpoint dtype must be float32: {key}: {state[key].dtype}")
        require(bool(torch.isfinite(state[key]).all()), f"non-finite checkpoint tensor: {key}")
    return {"status": "passed", "loader": "torch.load(weights_only=True)",
            "dtype": "float32",
            "shapes": {key: list(shape) for key, shape in expected.items()}}


def verify_checkpoint_hashes(baseline):
    digests = {}
    for variant, checkpoint in CHECKPOINTS.items():
        digest = sha256(baseline / checkpoint["path"])
        equal(digest, checkpoint["sha256"], f"historical {variant} checkpoint")
        digests[variant] = digest
    return digests


def check_archived_weights(baseline):
    results = {}
    for variant, checkpoint in CHECKPOINTS.items():
        try:
            results[variant] = check_weights(baseline / checkpoint["path"])
        except VerificationError as exc:
            raise VerificationError(f"{variant}: {exc}") from exc
    return {"status": "passed", "checkpoints": results}


def verify(baseline, repository, manifest_path, weights=False):
    integrity = verify_manifest(baseline, manifest_path)
    checkpoint_hashes = verify_checkpoint_hashes(baseline)
    p3 = baseline / "p3c64"
    split, selection_ids = verify_split(p3)
    selection = verify_historical_ledger(p3 / "selection_run_v1", "case_rank_ledger.jsonl",
                                         ("B0", "P3C16", "P3C64"), 43, selection_ids)
    inputs = read_json(p3 / "selection_run_v1/summary.json")["input_hashes"]
    for key, relative in {"p3_cases": "frozen_development_split_v1/p3_development_cases.v1.jsonl",
                          "p3_pairs": "frozen_development_split_v1/p3_development_pairs.v1.jsonl",
                          "p3_split_summary": "frozen_development_split_v1/summary.json",
                          "run_spec": "p3_run_spec_v1.json"}.items():
        equal(sha256(p3 / relative), inputs[key], f"historical input hash: {key}")
    decision = read_json(p3 / "selection_run_v1/selection_decision.json")
    equal("P3C64", decision["selected_variant"], "selected variant")
    external = verify_historical_ledger(p3 / "p4_external_b0_vs_p3c64_one_shot_v1",
                                        "case_rank_ledger.v1.jsonl", ("B0", "P3C64"), 21)
    weight_result = check_archived_weights(baseline) if weights else {"status": "not_requested"}
    return {"status": "passed", "archive_integrity": integrity, "frozen_development_split": split,
            "selection_43": selection, "external_21": external, "fixed143": verify_fixed143(repository),
            "checkpoint_sha256": P3C64_SHA256, "checkpoint_sha256_by_variant": checkpoint_hashes,
            "weight_tensor_check": weight_result,
            "limitations": ["This is an integrity and recorded-metric replay, not a training or retrieval rerun.",
                            "Hashes establish consistency with the manifest, not correctness of labels or provenance.",
                            "Unarchived full candidate pools, embeddings, and repository snapshots are not checked.",
                            "Fixed143 candidate counts differ between methods for the reported identity; equal universes are not claimed."]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    default = Path(__file__).resolve().parents[1]
    parser.add_argument("--baseline-root", type=Path, default=default)
    parser.add_argument("--repository-root", type=Path, default=None)
    parser.add_argument("--manifest", type=Path, default=None)
    parser.add_argument("--check-weights", action="store_true")
    args = parser.parse_args(argv)
    baseline = args.baseline_root.resolve()
    try:
        result = verify(baseline, args.repository_root or baseline.parents[1],
                        args.manifest or baseline / "archive-manifest.json", args.check_weights)
    except (VerificationError, OSError, KeyError, TypeError, AttributeError, IndexError) as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, ensure_ascii=False))
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
