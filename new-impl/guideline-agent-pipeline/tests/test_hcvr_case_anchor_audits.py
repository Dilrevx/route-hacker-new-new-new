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
        "quality": {"dataset_status": "accepted"},
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
    selected = module.load_selected_cases(qa_path, limit=2, skip=0, selection="added")
    assert [row["identity_key"] for row in selected] == [
        "owner__repo::CVE-2099-0001",
        "owner__repo::CVE-2099-0002",
    ]


def test_load_selected_cases_all_uses_accepted_cases_with_anchors(tmp_path: Path):
    module = load_module()
    cases_path = tmp_path / "cases.jsonl"
    accepted = sample_case()
    skipped = sample_case() | {
        "identity_key": "owner__repo::CVE-2099-0002",
        "quality": {"dataset_status": "rejected"},
    }
    accepted2 = sample_case() | {"identity_key": "owner__repo::CVE-2099-0003"}
    cases_path.write_text(
        "".join(json.dumps(row) + "\n" for row in [skipped, accepted, accepted2]),
        encoding="utf-8",
    )
    qa_path = tmp_path / "qa.json"
    qa_path.write_text(
        json.dumps({"files": {"cases": {"path": str(cases_path)}}}),
        encoding="utf-8",
    )
    selected = module.load_selected_cases(qa_path, limit=2, skip=0, selection="all")
    assert [row["identity_key"] for row in selected] == [
        "owner__repo::CVE-2099-0001",
        "owner__repo::CVE-2099-0003",
    ]


def test_load_selected_cases_can_follow_identity_file(tmp_path: Path):
    module = load_module()
    cases_path = tmp_path / "cases.jsonl"
    case_a = sample_case()
    case_b = sample_case() | {"identity_key": "owner__repo::CVE-2099-0002"}
    cases_path.write_text(
        "".join(json.dumps(row) + "\n" for row in [case_a, case_b]),
        encoding="utf-8",
    )
    identities_path = tmp_path / "identities.jsonl"
    identities_path.write_text(
        json.dumps({"identity_key": "owner__repo::CVE-2099-0002"}) + "\n",
        encoding="utf-8",
    )
    qa_path = tmp_path / "qa.json"
    qa_path.write_text(
        json.dumps({"files": {"cases": {"path": str(cases_path)}}}),
        encoding="utf-8",
    )

    selected = module.load_selected_cases(
        qa_path,
        limit=1,
        skip=0,
        selection="all",
        identity_file=identities_path,
    )

    assert [row["identity_key"] for row in selected] == ["owner__repo::CVE-2099-0002"]


def test_selected_anchor_file_overrides_dataset_anchor(tmp_path: Path):
    module = load_module()
    selected_path = tmp_path / "selected_cases.jsonl"
    selected_path.write_text(
        json.dumps(
            {
                "identity_key": "owner__repo::CVE-2099-0001",
                "anchor_id": "recalled::1",
                "file": "src/Recalled.java",
                "start_line": 31,
                "end_line": 80,
                "symbol": "Recalled.audit",
                "span_kind": "sliding_window",
                "rank": 1,
                "score": 0.42,
                "retrieval_source": "mechanical_slice_embedding_recall",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    identities, anchors = module.load_selected_anchor_file(selected_path)
    anchor = module.choose_anchor(
        sample_case(),
        anchor_index=0,
        selected_anchors=anchors,
    )

    assert identities == ["owner__repo::CVE-2099-0001"]
    assert anchor["anchor_id"] == "recalled::1"
    assert anchor["file"] == "src/Recalled.java"
    assert anchor["rank"] == 1
    assert anchor["retrieval_source"] == "mechanical_slice_embedding_recall"


def test_selected_anchor_file_guideline_flows_into_case(tmp_path: Path):
    module = load_module()
    selected_path = tmp_path / "selected_cases.jsonl"
    selected_path.write_text(
        json.dumps(
            {
                "identity_key": "owner__repo::CVE-2099-0001",
                "anchor_id": "recalled::1",
                "file": "src/Recalled.java",
                "start_line": 31,
                "end_line": 80,
                "guideline": "Audit a refined mechanism guideline.",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    _, anchors = module.load_selected_anchor_file(selected_path)
    case = sample_case()
    module.choose_anchor(case, anchor_index=0, selected_anchors=anchors)

    assert module.build_guideline(case).splitlines()[1] == (
        "Guideline: Audit a refined mechanism guideline."
    )


def test_guideline_overrides_apply_by_identity_or_case_id(tmp_path: Path):
    module = load_module()
    override_path = tmp_path / "guidelines.jsonl"
    override_path.write_text(
        json.dumps(
            {
                "identity_key": "owner__repo::CVE-2099-0001",
                "guideline_text": "Audit identity-key guideline.",
            }
        )
        + "\n"
        + json.dumps(
            {
                "case_id": "case::2",
                "retrieval_guideline": "Audit case-id guideline.",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    case_a = sample_case()
    case_b = sample_case() | {
        "identity_key": "owner__repo::CVE-2099-0002",
        "new_unified_case_id": "case::2",
    }

    count = module.apply_guideline_overrides(
        [case_a, case_b],
        module.load_guideline_overrides(override_path),
    )

    assert count == 2
    assert module.build_guideline(case_a).splitlines()[1] == (
        "Guideline: Audit identity-key guideline."
    )
    assert module.build_guideline(case_b).splitlines()[1] == (
        "Guideline: Audit case-id guideline."
    )


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
    normalized_prompt = " ".join(prompt.split())
    assert "investigation entry, not proof" in normalized_prompt
    assert "not a boundary on repository reading" in normalized_prompt
    assert "concrete sensitive operation" in normalized_prompt
    assert "PoC agent should observe or instrument" in normalized_prompt
    assert "exact file:line locations" in normalized_prompt
    assert "Do not return unknown" in normalized_prompt


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
    normalized_prompt = " ".join(prompt.split())
    assert "Decision value must be either risk or no-risk" in normalized_prompt
    assert "The Confidence value" in normalized_prompt


def test_build_guideline_does_not_specialize_broad_type_from_description():
    module = load_module()
    case = sample_case()
    case["classification"] = {
        "primary_hcvr_type": "iris",
        "cwe_ids": [],
        "hcvr_types": ["iris"],
    }
    case["vulnerability"] = {
        "id": "CVE-2099-0003",
        "description": "A user controlled endpoint can flow into a JNDI LDAP lookup.",
    }

    guideline = module.build_guideline(case)
    query_body = guideline.split("Guideline:", 1)[1].split("Case description:", 1)[0]

    assert "known security-relevant code path" in query_body
    assert "JNDI" not in query_body
    assert "LDAP" not in query_body
    assert "Case description: A user controlled endpoint" in guideline


def test_build_guideline_prefers_explicit_retrieval_guideline():
    module = load_module()
    case = sample_case()
    case["classification"] = {
        "primary_hcvr_type": "iris",
        "cwe_ids": [],
        "hcvr_types": ["iris"],
    }
    case["retrieval_guideline"] = (
        "Audit whether remote JMX connector creation drops the authentication "
        "environment before exposing a management endpoint."
    )
    case["vulnerability"] = {"id": "CVE-2099-0006", "description": ""}

    guideline = module.build_guideline(case)

    assert "remote JMX connector creation drops the authentication environment" in guideline
    assert "known security-relevant code path" not in guideline


def test_build_guideline_keeps_specific_track_template():
    module = load_module()
    case = sample_case()
    case["classification"] = {
        "primary_hcvr_type": "authorization_bypass",
        "cwe_ids": ["CWE-863"],
        "hcvr_types": ["authorization_bypass"],
    }
    case["vulnerability"] = {
        "id": "CVE-2099-0004",
        "description": "The advisory mentions JNDI only as unrelated deployment context.",
    }

    guideline = module.build_guideline(case)

    assert "authorization decision" in guideline
    assert "JNDI" not in guideline.split("Guideline:", 1)[1].split("Case description:", 1)[0]


def test_build_guideline_uses_cwe_for_unknown_type():
    module = load_module()
    case = sample_case()
    case["classification"] = {
        "primary_hcvr_type": "custom_unknown",
        "cwe_ids": ["CWE-918"],
        "hcvr_types": ["custom_unknown"],
    }
    case["vulnerability"] = {"id": "CVE-2099-0005", "description": ""}

    guideline = module.build_guideline(case)

    assert "outbound network requests" in guideline
