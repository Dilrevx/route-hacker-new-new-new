from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path


BUILD_SCRIPT = Path(__file__).parents[1] / "scripts" / "build_recall_candidate_list_judge_pack.py"
SUMMARY_SCRIPT = Path(__file__).parents[1] / "scripts" / "summarize_recall_candidate_list_judge_outputs.py"


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def make_case(tmp_path: Path) -> tuple[list[dict], list[dict]]:
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    for name in ["A.java", "B.java", "C.java"]:
        (snapshot / name).write_text(f"class {name[0]} {{\n  void method() {{}}\n}}\n", encoding="utf-8")
    recall_results = [
        {
            "identity_key": "repo::CVE-1",
            "case_id": "case-1",
            "repo_key": "repo",
            "hcvr_type": "authz",
            "guideline": "Trace user-controlled IDs into privileged reads.",
            "snapshot": str(snapshot),
            "candidate_count": 3,
            "known_anchor_count": 1,
        }
    ]
    top_candidates = [
        {
            "identity_key": "repo::CVE-1",
            "anchor_id": "a",
            "rank": 1,
            "score": 0.9,
            "file": "A.java",
            "start_line": 1,
            "end_line": 3,
            "known_anchor_overlap": False,
        },
        {
            "identity_key": "repo::CVE-1",
            "anchor_id": "b",
            "rank": 2,
            "score": 0.8,
            "file": "B.java",
            "start_line": 1,
            "end_line": 3,
            "known_anchor_overlap": True,
        },
        {
            "identity_key": "repo::CVE-1",
            "anchor_id": "c",
            "rank": 3,
            "score": 0.7,
            "file": "C.java",
            "start_line": 1,
            "end_line": 3,
            "known_anchor_overlap": False,
        },
    ]
    return recall_results, top_candidates


def test_list_pack_prompt_hides_recall_metadata(tmp_path: Path):
    builder = load_module(BUILD_SCRIPT, "build_recall_candidate_list_judge_pack")
    recall_results, top_candidates = make_case(tmp_path)

    items, summary = builder.build_judge_items(
        recall_results=recall_results,
        top_candidates=top_candidates,
        max_rank=3,
        candidates_per_prompt=10,
        max_snippet_chars=1000,
        max_cases=0,
    )

    assert summary["identity_count"] == 1
    assert len(items) == 1
    prompt = builder.list_prompt(items[0])
    assert "Trace user-controlled IDs" in prompt
    assert "candidate_id" in prompt
    assert "known_anchor_overlap" not in prompt
    assert '"rank"' not in prompt
    assert '"score"' not in prompt
    assert "CVE-1" not in prompt
    assert len(items[0]["hidden_candidates"]) == 3
    assert any(row["known_anchor_overlap"] for row in items[0]["hidden_candidates"])


def test_list_pack_cli_writes_sharded_pack(tmp_path: Path):
    recall_results, top_candidates = make_case(tmp_path)
    recall_path = tmp_path / "recall.jsonl"
    candidates_path = tmp_path / "candidates.jsonl"
    output = tmp_path / "pack"
    write_jsonl(recall_path, recall_results)
    write_jsonl(candidates_path, top_candidates)

    result = subprocess.run(
        [
            sys.executable,
            str(BUILD_SCRIPT),
            "--recall-results",
            str(recall_path),
            "--top-candidates",
            str(candidates_path),
            "--output-dir",
            str(output),
            "--max-rank",
            "3",
            "--candidates-per-prompt",
            "2",
            "--default-cli",
            "codex",
            "--default-model",
            "DeepSeek-V4-Pro",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    build_summary = json.loads((output / "build_summary.json").read_text(encoding="utf-8"))
    assert build_summary["prompt_count"] == 2
    rows = [json.loads(line) for line in (output / "judge_inputs.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 2
    assert all("hidden_candidates" in row for row in rows)
    assert not any("candidates" in row for row in rows)
    prompts = sorted((output / "prompts").glob("*.md"))
    assert len(prompts) == 2
    prompt_text = "\n".join(path.read_text(encoding="utf-8") for path in prompts)
    assert "known_anchor_overlap" not in prompt_text
    assert '"score"' not in prompt_text
    assert '"rank"' not in prompt_text
    runner = (output / "run_agent_judge.sh").read_text(encoding="utf-8")
    assert "exec --sandbox read-only" in runner


def test_summarize_list_judge_outputs_computes_hidden_rerank_hit(tmp_path: Path):
    summarizer = load_module(SUMMARY_SCRIPT, "summarize_recall_candidate_list_judge_outputs")
    output_dir = tmp_path / "judge_outputs"
    output_dir.mkdir()
    (output_dir / "case.shard001.json").write_text(
        json.dumps(
            {
                "candidate_scores": [
                    {"candidate_id": "C001", "relevance": 0.2, "audit_priority": "low", "rationale": "weak"},
                    {"candidate_id": "C002", "relevance": 0.9, "audit_priority": "high", "rationale": "strong"},
                    {"candidate_id": "C003", "relevance": 0.1, "audit_priority": "none", "rationale": "none"},
                ],
                "top_choices": ["C002"],
                "confidence": 0.8,
                "missing_information": [],
            }
        ),
        encoding="utf-8",
    )
    judge_inputs = [
        {
            "identity_key": "case",
            "repo_key": "repo",
            "hcvr_type": "authz",
            "shard_index": 1,
            "output_file": "case.shard001.json",
            "hidden_candidates": [
                {"candidate_id": "C001", "rank": 1, "score": 0.9, "known_anchor_overlap": False, "file": "A.java"},
                {"candidate_id": "C002", "rank": 42, "score": 0.7, "known_anchor_overlap": True, "file": "B.java"},
                {"candidate_id": "C003", "rank": 2, "score": 0.8, "known_anchor_overlap": False, "file": "C.java"},
            ],
        }
    ]

    summary, candidate_rows, identity_rows = summarizer.summarize(
        judge_inputs=judge_inputs,
        judge_output_dir=output_dir,
    )

    assert summary["parsed_prompt_count"] == 1
    assert summary["identity_count"] == 1
    assert summary["judge_rerank_hit_counts"]["top_1"] == 1
    assert summary["judge_rerank_hit_rates"]["top_1"] == 1.0
    assert len(candidate_rows) == 3
    assert identity_rows[0]["best_known_anchor_judge_rank"] == 1
    assert identity_rows[0]["judge_top_known_anchor_overlap"] is True


def test_summarize_list_judge_outputs_excludes_uncovered_identities_from_hit_rate(tmp_path: Path):
    summarizer = load_module(SUMMARY_SCRIPT, "summarize_recall_candidate_list_judge_outputs")
    output_dir = tmp_path / "judge_outputs"
    output_dir.mkdir()
    (output_dir / "case.shard001.json").write_text(
        json.dumps(
            {
                "candidate_scores": [
                    {"candidate_id": "C001", "relevance": 0.8, "audit_priority": "high", "rationale": "best"},
                    {"candidate_id": "C002", "relevance": 0.2, "audit_priority": "low", "rationale": "weak"},
                ],
                "top_choices": ["C001"],
                "confidence": 0.8,
                "missing_information": [],
            }
        ),
        encoding="utf-8",
    )
    judge_inputs = [
        {
            "identity_key": "case",
            "repo_key": "repo",
            "hcvr_type": "authz",
            "shard_index": 1,
            "output_file": "case.shard001.json",
            "hidden_candidates": [
                {"candidate_id": "C001", "rank": 1, "score": 0.9, "known_anchor_overlap": False, "file": "A.java"},
                {"candidate_id": "C002", "rank": 2, "score": 0.8, "known_anchor_overlap": False, "file": "B.java"},
            ],
        }
    ]

    summary, _, identity_rows = summarizer.summarize(
        judge_inputs=judge_inputs,
        judge_output_dir=output_dir,
    )

    assert summary["identity_count"] == 1
    assert summary["identities_with_known_anchor_candidate"] == 0
    assert summary["identities_with_scored_known_anchor_candidate"] == 0
    assert summary["identity_coverage_gap_count"] == 1
    assert summary["judge_rerank_hit_rate_denominator"] == 0
    assert summary["judge_rerank_hit_rates"]["top_1"] is None
    assert identity_rows[0]["judge_top_known_anchor_overlap"] is False
