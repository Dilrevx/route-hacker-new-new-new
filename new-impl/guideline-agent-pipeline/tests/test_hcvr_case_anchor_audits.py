from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "run_hcvr_case_anchor_audits.py"


def load_module():
    spec = importlib.util.spec_from_file_location("hcvr_case_anchor_audits", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def sample_case() -> dict:
    return {
        "identity_key": "owner__repo::CVE-2099-0001",
        "new_unified_case_id": "case::1",
        "repository": {
            "repo_key": "owner__repo",
            "repo_url": "https://github.com/owner/repo.git",
        },
        "revisions": {"checkout_revision": "a" * 40},
        "classification": {
            "primary_hcvr_type": "authorization_bypass",
            "cwe_ids": ["CWE-863"],
        },
        "vulnerability": {
            "id": "CVE-2099-0001",
            "description": "A sensitive object update misses object-scoped authorization.",
        },
        "recall_anchors": [
            {
                "anchor_id": "anchor::1",
                "file": "src/App.java",
                "start_line": 10,
                "end_line": 20,
                "symbol": "App.update",
                "span_kind": "method",
            }
        ],
    }


def test_parse_report_uses_last_binary_footer():
    module = load_module()
    decision, confidence = module.parse_report(
        "Discussion of risk and no-risk alternatives.\n"
        "Decision: no-risk\n"
        "Confidence: 0.67\n"
    )
    assert decision == "no-risk"
    assert confidence == 0.67
    assert module.parse_report("**Decision: risk**\n**Confidence: 0.85**") == (
        "risk",
        0.85,
    )
    assert module.parse_report("No required footer.") == (None, None)


def test_has_command_execution_requires_real_event():
    module = load_module()
    fake_xml = json.dumps(
        {
            "type": "item.completed",
            "item": {
                "type": "agent_message",
                "text": "<function=exec_command>cat file</function>",
            },
        }
    )
    real_event = json.dumps(
        {
            "type": "item.completed",
            "item": {"type": "command_execution", "command": "cat file"},
        }
    )
    assert not module.has_command_execution(fake_xml)
    assert module.has_command_execution(f"{fake_xml}\nnot-json\n{real_event}\n")


def test_load_selected_cases_uses_added_identity_order(tmp_path: Path):
    module = load_module()
    cases_path = tmp_path / "cases.jsonl"
    case_a = sample_case()
    case_b = sample_case() | {"identity_key": "owner__repo::CVE-2099-0002"}
    cases_path.write_text(
        json.dumps(case_b) + "\n" + json.dumps(case_a) + "\n",
        encoding="utf-8",
    )
    qa_path = tmp_path / "qa.json"
    qa_path.write_text(
        json.dumps(
            {
                "added_identities": [
                    "owner__repo::CVE-2099-0001",
                    "owner__repo::CVE-2099-0002",
                ],
                "files": {"cases": {"path": str(cases_path)}},
            }
        ),
        encoding="utf-8",
    )
    selected = module.load_selected_cases(qa_path, limit=2, skip=0)
    assert [row["identity_key"] for row in selected] == [
        "owner__repo::CVE-2099-0001",
        "owner__repo::CVE-2099-0002",
    ]


def test_prompt_treats_anchor_as_entry_not_reading_boundary(tmp_path: Path):
    module = load_module()
    case = sample_case()
    anchor = module.pick_anchor(case, 0)
    guideline = module.build_guideline(case)
    prompt = module.build_prompt(
        case=case,
        anchor=anchor,
        snapshot=tmp_path,
        guideline=guideline,
    )
    assert "investigation entry, not proof" in prompt
    assert "not a boundary on repository reading" in prompt
    assert "concrete sensitive operation" in prompt
    assert "PoC agent should observe or instrument" in prompt
    assert "exact file:line locations" in prompt
    assert "Do not return unknown" in prompt


def test_prepare_packet_writes_prompt_and_handoff_fields(tmp_path: Path):
    module = load_module()
    output = tmp_path / "out"
    (output / "reports").mkdir(parents=True)
    case = sample_case()
    anchor = module.pick_anchor(case, 0)
    row = module.write_prepare_packet(
        output=output,
        case=case,
        anchor=anchor,
        snapshot=tmp_path / "snapshot",
    )
    assert row["state"] == "prepared"
    prompt = Path(row["prompt"]).read_text(encoding="utf-8")
    assert "Decision value must be either risk or no-risk" in prompt
    assert "Confidence value must be a decimal" in prompt
