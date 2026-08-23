from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path


BUILD_SCRIPT = Path(__file__).parents[1] / "scripts" / "build_recall_candidate_pair_judge_pack.py"
SUMMARY_SCRIPT = Path(__file__).parents[1] / "scripts" / "summarize_recall_candidate_pair_judge_outputs.py"


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def test_build_pair_pack_hides_anchor_labels_from_prompt(tmp_path: Path):
    builder = load_module(BUILD_SCRIPT, "build_recall_candidate_pair_judge_pack")
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    (snapshot / "A.java").write_text("class A {\n  void top() {}\n}\n", encoding="utf-8")
    (snapshot / "B.java").write_text("class B {\n  void anchor() {}\n}\n", encoding="utf-8")
    recall_results = [
        {
            "identity_key": "repo::CVE-1",
            "case_id": "case-1",
            "repo_key": "repo",
            "hcvr_type": "authz",
            "guideline": "Trace user-controlled IDs into privileged reads.",
            "snapshot": str(snapshot),
            "candidate_count": 2,
            "known_anchor_count": 1,
        }
    ]
    top_candidates = [
        {
            "identity_key": "repo::CVE-1",
            "rank": 1,
            "file": "A.java",
            "start_line": 1,
            "end_line": 3,
            "known_anchor_overlap": False,
            "score": 0.9,
        },
        {
            "identity_key": "repo::CVE-1",
            "rank": 2,
            "file": "B.java",
            "start_line": 1,
            "end_line": 3,
            "known_anchor_overlap": True,
            "score": 0.8,
        },
    ]

    items = builder.build_judge_items(
        recall_results=recall_results,
        top_candidates=top_candidates,
        max_snippet_chars=1000,
        max_rows=0,
    )

    assert len(items) == 1
    prompt = builder.pair_prompt(items[0])
    assert "Trace user-controlled IDs" in prompt
    assert "known_anchor_overlap" not in prompt
    assert "hidden_expected_anchor_label" not in prompt
    assert "CVE-1" not in prompt
    assert "class A" in prompt
    assert "class B" in prompt
    assert items[0]["hidden_expected_anchor_label"] in {"A", "B"}
    assert items[0]["hidden_top1_label"] in {"A", "B"}


def test_build_pair_pack_cli_writes_runner_and_inputs(tmp_path: Path):
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    (snapshot / "A.java").write_text("class A {}\n", encoding="utf-8")
    (snapshot / "B.java").write_text("class B {}\n", encoding="utf-8")
    recall_path = tmp_path / "recall.jsonl"
    candidates_path = tmp_path / "candidates.jsonl"
    output = tmp_path / "pack"
    write_jsonl(
        recall_path,
        [
            {
                "identity_key": "repo::CVE-1",
                "case_id": "case-1",
                "repo_key": "repo",
                "hcvr_type": "authz",
                "guideline": "Guideline text",
                "snapshot": str(snapshot),
                "candidate_count": 2,
                "known_anchor_count": 1,
            }
        ],
    )
    write_jsonl(
        candidates_path,
        [
            {"identity_key": "repo::CVE-1", "rank": 1, "file": "A.java", "start_line": 1, "end_line": 1, "known_anchor_overlap": False},
            {"identity_key": "repo::CVE-1", "rank": 2, "file": "B.java", "start_line": 1, "end_line": 1, "known_anchor_overlap": True},
        ],
    )

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
            "--default-cli",
            "traex",
            "--default-model",
            "DeepSeek-V4-Pro",
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    rows = [json.loads(line) for line in (output / "judge_inputs.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 1
    assert "hidden_expected_anchor_label" in rows[0]
    assert not any("candidates" in row for row in rows)
    prompt = next((output / "prompts").glob("*.md")).read_text(encoding="utf-8")
    assert "known_anchor_overlap" not in prompt
    runner = (output / "run_traex_judge.sh").read_text(encoding="utf-8")
    assert "exec --sandbox read-only" in runner
    assert "--disallowed-tool exec" in (output / "README.md").read_text(encoding="utf-8")


def test_build_pair_pack_skips_pairs_with_unreadable_snippets_by_default(tmp_path: Path):
    builder = load_module(BUILD_SCRIPT, "build_recall_candidate_pair_judge_pack")
    recall_results = [
        {
            "identity_key": "repo::CVE-1",
            "case_id": "case-1",
            "repo_key": "repo",
            "hcvr_type": "authz",
            "guideline": "Trace user-controlled IDs into privileged reads.",
            "snapshot": str(tmp_path / "missing-snapshot"),
            "candidate_count": 2,
            "known_anchor_count": 1,
        }
    ]
    top_candidates = [
        {
            "identity_key": "repo::CVE-1",
            "rank": 1,
            "file": "A.java",
            "start_line": 1,
            "end_line": 3,
            "known_anchor_overlap": False,
        },
        {
            "identity_key": "repo::CVE-1",
            "rank": 2,
            "file": "B.java",
            "start_line": 1,
            "end_line": 3,
            "known_anchor_overlap": True,
        },
    ]

    items = builder.build_judge_items(
        recall_results=recall_results,
        top_candidates=top_candidates,
        max_snippet_chars=1000,
        max_rows=0,
    )

    assert items == []


def test_summarize_pair_judge_outputs_counts_hidden_anchor_choice(tmp_path: Path):
    summarizer = load_module(SUMMARY_SCRIPT, "summarize_recall_candidate_pair_judge_outputs")
    output_dir = tmp_path / "judge_outputs"
    output_dir.mkdir()
    (output_dir / "case1.json").write_text(
        json.dumps(
            {
                "choice": "B",
                "candidate_a_relevance": 0.2,
                "candidate_b_relevance": 0.9,
                "confidence": 0.8,
                "rationale": "B matches the sink.",
                "key_evidence": ["sink"],
                "missing_information": [],
            }
        ),
        encoding="utf-8",
    )
    (output_dir / "case2.json").write_text('{"choice":"A","confidence":0.5}', encoding="utf-8")
    judge_inputs = [
        {
            "identity_key": "case1",
            "output_file": "case1.json",
            "hidden_expected_anchor_label": "B",
            "hidden_top1_label": "A",
            "hidden_anchor_rank": 150,
            "hidden_top1_rank": 1,
        },
        {
            "identity_key": "case2",
            "output_file": "case2.json",
            "hidden_expected_anchor_label": "B",
            "hidden_top1_label": "A",
            "hidden_anchor_rank": 200,
            "hidden_top1_rank": 1,
        },
        {
            "identity_key": "case3",
            "output_file": "case3.json",
            "hidden_expected_anchor_label": "A",
            "hidden_top1_label": "B",
        },
    ]

    summary, rows = summarizer.summarize(judge_inputs=judge_inputs, judge_output_dir=output_dir)

    assert summary["judge_input_count"] == 3
    assert summary["parsed_count"] == 2
    assert summary["missing_output_count"] == 1
    assert summary["choice_counts"] == {"A": 1, "B": 1}
    assert summary["choice_outcome_counts"] == {
        "anchor_overlap_chosen": 1,
        "missing": 1,
        "top1_chosen": 1,
    }
    assert summary["anchor_overlap_choice_rate"] == 0.5
    by_id = {row["identity_key"]: row for row in rows}
    assert by_id["case1"]["choice_outcome"] == "anchor_overlap_chosen"
    assert by_id["case2"]["choice_outcome"] == "top1_chosen"
