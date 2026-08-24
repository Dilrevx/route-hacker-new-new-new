import json
import runpy
from pathlib import Path


def write_summary(path: Path, payload: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload) + "\n", encoding="utf-8")


def test_best_effort_report_keeps_full_universe_denominator(tmp_path):
    module = runpy.run_path(
        str(
            Path(__file__).resolve().parents[1]
            / "scripts"
            / "summarize_iris213_best_effort.py"
        )
    )
    universe = tmp_path / "universe.jsonl"
    universe.write_text(
        "\n".join(
            json.dumps({"project_slug": slug, "case_index": index, "iris_query": "cwe-022wLLM"})
            for index, slug in enumerate(("case-a", "case-b", "case-c"), start=1)
        )
        + "\n",
        encoding="utf-8",
    )
    root = tmp_path / "artifacts"
    write_summary(
        root / "native-a" / "summary.json",
        {
            "schema_version": "iris_native_traex_run.v1",
            "created_at": "2026-08-24T00:00:00+00:00",
            "status": "completed_verified",
            "verified_completion": True,
            "case": {"project_slug": "case-a", "case_id": "a", "iris_query": "cwe-022wLLM"},
            "iris_statistics": {
                "vanilla_paths": 2,
                "vanilla_results": 1,
                "vanilla_tp_paths_method": 1,
                "vanilla_recall_method": True,
                "posthoc_paths": 1,
                "posthoc_results": 1,
                "posthoc_tp_paths_method": 1,
                "posthoc_recall_method": True,
            },
        },
    )
    write_summary(
        root / "native-b" / "summary.json",
        {
            "schema_version": "iris_native_traex_run.v1",
            "created_at": "2026-08-24T00:00:00+00:00",
            "status": "completed_verified",
            "verified_completion": True,
            "case": {"project_slug": "case-b", "case_id": "b", "iris_query": "cwe-022wLLM"},
            "iris_statistics": {
                "vanilla_paths": 1,
                "vanilla_results": 1,
                "vanilla_tp_paths_method": 0,
                "vanilla_recall_method": False,
                "posthoc_paths": 0,
                "posthoc_results": 0,
                "posthoc_tp_paths_method": 0,
                "posthoc_recall_method": False,
            },
        },
    )
    write_summary(
        root / "codeql-a" / "summary.json",
        {
            "schema_version": "iris_native_traex_official_codeql_baseline.v1",
            "created_at": "2026-08-24T00:00:00+00:00",
            "status": "completed_verified",
            "verified_completion": True,
            "case": {"project_slug": "case-a", "case_id": "a", "iris_query": "cwe-022wLLM"},
            "evaluation": {
                "num_paths": 3,
                "num_results": 2,
                "num_tp_paths_method": 1,
                "recall_method": True,
            },
        },
    )

    output = tmp_path / "out"
    report = module["main"]
    import sys
    from unittest.mock import patch

    with patch.object(
        sys,
        "argv",
        [
            "summarize_iris213_best_effort.py",
            "--universe-jsonl",
            str(universe),
            "--artifact-root",
            str(root),
            "--output-dir",
            str(output),
        ],
    ):
        assert report() == 0

    data = json.loads((output / "comparison.213.json").read_text(encoding="utf-8"))
    assert data["coverage"]["universe_case_count"] == 3
    assert data["coverage"]["native_completed_verified_case_count"] == 2
    assert data["coverage"]["codeql_completed_verified_case_count"] == 1
    assert data["coverage"]["native_completed_missing_codeql_count"] == 1
    assert data["metrics"]["vanilla"]["case_hits"] == 1
    assert data["metrics"]["vanilla"]["best_effort_recall_method"] == 1 / 3
    assert data["metrics"]["vanilla"]["completed_subset_recall_method"] == 1 / 2
    assert data["metrics"]["codeql"]["best_effort_recall_method"] == 1 / 3
