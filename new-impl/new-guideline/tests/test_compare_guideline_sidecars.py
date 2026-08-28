from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "compare_guideline_sidecars.py"


def load_module():
    sys.path.insert(0, str(SCRIPT.parent))
    spec = importlib.util.spec_from_file_location("compare_guideline_sidecars", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def test_compare_sidecars_ignores_non_consumed_metadata():
    module = load_module()

    summary = module.compare_sidecars(
        {
            "case-a": "Audit stable resource binding.",
            "case-b": "Audit JNDI lookup guard.",
        },
        {
            "case-b": "Audit JNDI lookup guard.",
            "case-a": "Audit stable resource binding.",
        },
    )

    assert summary["same_key_set"]
    assert summary["changed_text_count"] == 0
    assert summary["recall_consumed_text_equivalent"]


def test_read_sidecar_supports_release_json_shapes(tmp_path: Path):
    module = load_module()
    sidecar = tmp_path / "guidelines.json"
    sidecar.write_text(
        json.dumps(
            {
                "guidelines": {
                    "case-a": {
                        "guideline_text": "Audit explicit guideline text.",
                        "release_ready": True,
                        "ignored_metadata": {"score": 1},
                    },
                    "case-b": "Audit string guideline.",
                }
            }
        ),
        encoding="utf-8",
    )

    rows = module.read_sidecar(sidecar)

    assert rows == {
        "case-a": "Audit explicit guideline text.",
        "case-b": "Audit string guideline.",
    }


def test_cli_writes_equivalence_report(tmp_path: Path):
    left = tmp_path / "left.jsonl"
    right = tmp_path / "right.jsonl"
    output_json = tmp_path / "summary.json"
    output_md = tmp_path / "README.md"
    write_jsonl(
        left,
        [
            {
                "identity_key": "case-a",
                "guideline_text": "Audit source-sink guard.",
                "source_fingerprint": "old",
            }
        ],
    )
    write_jsonl(
        right,
        [
            {
                "identity_key": "case-a",
                "retrieval_guideline": "Audit source-sink guard.",
                "source_fingerprint": "new",
            }
        ],
    )

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--left",
            str(left),
            "--right",
            str(right),
            "--left-label",
            "r7",
            "--right-label",
            "r8",
            "--output-json",
            str(output_json),
            "--output-md",
            str(output_md),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode == 0
    summary = json.loads(output_json.read_text(encoding="utf-8"))
    assert summary["left_sha256"] != summary["right_sha256"]
    assert summary["recall_consumed_text_equivalent"]
    assert "Recall-consumed text equivalent: True" in output_md.read_text(encoding="utf-8")
