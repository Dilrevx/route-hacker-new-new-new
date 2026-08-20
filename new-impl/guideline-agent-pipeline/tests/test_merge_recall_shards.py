from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "merge_recall_shards.py"


def load_module():
    spec = importlib.util.spec_from_file_location("merge_recall_shards", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def test_merge_shards_orders_by_identity_file_and_summarizes(tmp_path: Path):
    module = load_module()
    shard_root = tmp_path / "shards"
    output = tmp_path / "merged"
    identity_file = tmp_path / "identities.jsonl"
    write_jsonl(
        identity_file,
        [
            {"identity_key": "case-b"},
            {"identity_key": "case-a"},
        ],
    )
    write_jsonl(
        shard_root / "002" / "recall_results.jsonl",
        [
            {
                "identity_key": "case-a",
                "state": "completed",
                "candidate_count": 10,
                "best_known_anchor_rank": 40,
            }
        ],
    )
    write_jsonl(
        shard_root / "001" / "recall_results.jsonl",
        [
            {
                "identity_key": "case-b",
                "state": "completed",
                "candidate_count": 20,
                "best_known_anchor_rank": 5,
            }
        ],
    )
    write_jsonl(
        shard_root / "001" / "selected_cases.jsonl",
        [{"identity_key": "case-b", "rank": 1}],
    )

    summary = module.merge_shards(
        shard_root=shard_root,
        output_dir=output,
        identity_file=identity_file,
        budgets=[10, 50],
    )

    merged = read_jsonl(output / "recall_results.jsonl")
    assert [row["identity_key"] for row in merged] == ["case-b", "case-a"]
    assert summary["metrics"]["completed_count"] == 2
    assert summary["metrics"]["hit_count_at_10"] == 1
    assert summary["metrics"]["hit_count_at_50"] == 2
    assert summary["metrics"]["candidate_count"] == 30


def test_merge_shards_marks_missing_identity(tmp_path: Path):
    module = load_module()
    shard_root = tmp_path / "shards"
    output = tmp_path / "merged"
    identity_file = tmp_path / "identities.jsonl"
    write_jsonl(identity_file, [{"identity_key": "case-missing"}])
    shard_root.mkdir()

    summary = module.merge_shards(
        shard_root=shard_root,
        output_dir=output,
        identity_file=identity_file,
        budgets=[10],
    )

    assert summary["missing_identities"] == ["case-missing"]
    assert summary["metrics"]["case_count"] == 1
    assert summary["metrics"]["failed_count"] == 1
