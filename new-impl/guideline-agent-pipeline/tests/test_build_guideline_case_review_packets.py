from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "build_guideline_case_review_packets.py"


def load_module():
    spec = importlib.util.spec_from_file_location("build_guideline_case_review_packets", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def sample_row() -> dict:
    return {
        "pack_priority": 1,
        "guideline_id": "gl_a",
        "mechanism_id": "mech_a",
        "repair_kind": "split_mechanism_boundary",
        "main_issue": "mixed boundary",
        "evidence_gaps": ["mechanism_boundary"],
        "proposed_boundaries": [
            {
                "boundary_label": "candidate_boundary_01",
                "description": "Boundary one.",
                "status": "needs_case_assignment_and_source_validation",
            }
        ],
        "source_trace_examples": [
            {
                "identity_key": "repo::CVE-1",
                "cve_ids": ["CVE-1"],
                "primary_hcvr_type": "ssrf",
                "first_anchor": {"file": "A.java", "start_line": 1, "end_line": 2, "symbol": "A.m"},
                "first_trace_evidence": "source reaches sink",
            }
        ],
        "review_entry_only_examples": [],
        "missing_trace_examples": [],
    }


def test_render_packet_contains_evidence_fields_and_guardrails():
    module = load_module()

    text = module.render_packet(sample_row())

    assert "# gl_a Evidence Review Packet" in text
    assert "## Reviewer Evidence Fields" in text
    assert "- Source shape:" in text
    assert "repo::CVE-1" in text
    assert "Do not convert split suggestions" in text


def test_build_packets_writes_index_and_packet(tmp_path: Path):
    module = load_module()

    summary = module.build_packets([sample_row()], tmp_path)

    assert summary["packet_count"] == 1
    packet = tmp_path / summary["packets"][0]["packet"]
    assert packet.is_file()
    assert "Boundary one." in packet.read_text(encoding="utf-8")


def test_cli_writes_case_review_packets(tmp_path: Path):
    repair_pack = tmp_path / "boundary_repair_pack.jsonl"
    output = tmp_path / "packets"
    write_jsonl(repair_pack, [sample_row()])

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--boundary-repair-pack",
            str(repair_pack),
            "--output-dir",
            str(output),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode == 0
    summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    assert summary["packet_count"] == 1
    assert (output / "README.md").is_file()
    assert (output / "packets" / "01-gl_a.md").is_file()
