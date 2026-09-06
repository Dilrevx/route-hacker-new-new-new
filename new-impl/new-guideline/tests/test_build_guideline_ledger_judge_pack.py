from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "build_guideline_ledger_judge_pack.py"


def load_module():
    spec = importlib.util.spec_from_file_location("build_guideline_ledger_judge_pack", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def test_ledger_prompt_limits_judge_scope_to_semantics():
    module = load_module()
    row = {
        "guideline_id": "gl_mech_test",
        "mechanism_id": "mech_test",
        "mechanism_name": "test mechanism",
        "boundary_label": "candidate_boundary_01",
        "boundary_decision": "promote_boundary",
        "source_shape": "source",
        "sink_or_sensitive_effect": "sink",
        "missing_guard": "guard",
        "representative_cases": ["repo::CVE-1"],
    }

    prompt = module.ledger_prompt(row, "RUBRIC")

    assert "Review one source-reviewed guideline boundary ledger row" in prompt
    assert "Do not judge embedding recall" in prompt
    assert "gl_mech_test" in prompt
    assert "Return JSON only" in prompt


def test_cli_writes_prompts_and_runner(tmp_path: Path):
    ledger = tmp_path / "ledger.jsonl"
    rubric = tmp_path / "rubric.md"
    output = tmp_path / "judge_pack"
    write_jsonl(
        ledger,
        [
            {
                "guideline_id": "gl_a",
                "mechanism_id": "mech_a",
                "mechanism_name": "mechanism A",
                "boundary_label": "candidate_boundary_01",
                "boundary_decision": "promote_boundary",
            },
            {
                "guideline_id": "gl_b",
                "mechanism_id": "mech_b",
                "mechanism_name": "mechanism B",
                "boundary_label": "candidate_boundary_02",
                "boundary_decision": "needs_more_evidence",
            },
        ],
    )
    rubric.write_text("Judge rubric", encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--ledger",
            str(ledger),
            "--rubric",
            str(rubric),
            "--decision",
            "promote_boundary",
            "--output-dir",
            str(output),
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
    rows = [json.loads(line) for line in (output / "judge_inputs.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 1
    assert rows[0]["guideline_id"] == "gl_a"
    prompt = (output / "prompts" / "gl_a.candidate_boundary_01.md").read_text(encoding="utf-8")
    assert "Ledger boundary payload" in prompt
    runner = (output / "run_agent_judge.sh").read_text(encoding="utf-8")
    assert "LLM_JUDGE_CLI=\"${LLM_JUDGE_CLI:-codex}\"" in runner
    assert "LLM_JUDGE_MODEL=\"${LLM_JUDGE_MODEL:-DeepSeek-V4-Pro}\"" in runner
    assert "LLM_JUDGE_EXTRA_ARGS" in runner
