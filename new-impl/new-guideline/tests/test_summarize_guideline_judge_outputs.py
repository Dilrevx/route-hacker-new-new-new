from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "summarize_guideline_judge_outputs.py"


def load_module():
    spec = importlib.util.spec_from_file_location("summarize_guideline_judge_outputs", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_extract_json_object_accepts_fenced_json():
    module = load_module()

    parsed = module.extract_json_object(
        """```json
{"decision": "accept", "coherence_score": 0.9}
```"""
    )

    assert parsed["decision"] == "accept"
    assert parsed["coherence_score"] == 0.9


def test_summarize_counts_missing_invalid_and_low_score(tmp_path: Path):
    module = load_module()
    output_dir = tmp_path / "judge_outputs"
    output_dir.mkdir()
    (output_dir / "gl_good.json").write_text(
        json.dumps(
            {
                "decision": "accept",
                "coherence_score": 0.9,
                "coverage_score": 0.8,
                "actionability_score": 0.85,
                "retrieval_query_quality": 0.75,
                "main_issue": "",
            }
        ),
        encoding="utf-8",
    )
    (output_dir / "gl_split.json").write_text(
        """```json
{
  "decision": "split",
  "coherence_score": 0.4,
  "coverage_score": 0.5,
  "actionability_score": 0.7,
  "retrieval_query_quality": 0.6,
  "main_issue": "two mechanisms are mixed"
}
```""",
        encoding="utf-8",
    )
    (output_dir / "gl_bad.json").write_text("not json", encoding="utf-8")
    judge_inputs = [
        {"guideline_id": "gl_good", "mechanism": {"mechanism_id": "mech_good", "name": "good"}},
        {"guideline_id": "gl_split", "mechanism": {"mechanism_id": "mech_split", "name": "split"}},
        {"guideline_id": "gl_bad", "mechanism": {"mechanism_id": "mech_bad", "name": "bad"}},
        {"guideline_id": "gl_missing", "mechanism": {"mechanism_id": "mech_missing", "name": "missing"}},
    ]

    summary, rows = module.summarize(judge_inputs=judge_inputs, judge_output_dir=output_dir, low_score_threshold=0.6)

    assert summary["judge_input_count"] == 4
    assert summary["parsed_count"] == 2
    assert summary["missing_output_count"] == 1
    assert summary["invalid_output_count"] == 1
    assert summary["decision_counts"] == {"accept": 1, "split": 1}
    assert summary["accepted_count"] == 1
    assert summary["needs_revision_count"] == 1
    assert summary["low_score_count"] == 1
    by_id = {row["guideline_id"]: row for row in rows}
    assert by_id["gl_split"]["low_score"]
    assert by_id["gl_bad"]["decision"] == "invalid"
    assert by_id["gl_missing"]["decision"] == "missing"
