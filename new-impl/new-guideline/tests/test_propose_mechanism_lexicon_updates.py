from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "propose_mechanism_lexicon_updates.py"


def load_module():
    spec = importlib.util.spec_from_file_location("propose_mechanism_lexicon_updates", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def test_split_rows_generate_review_only_new_mechanism_proposals():
    module = load_module()
    summary, proposals = module.build_proposals(
        backlog_rows=[
            {
                "guideline_id": "gl_split",
                "mechanism_id": "mech_old",
                "recommended_action": "split_mechanism_boundary",
                "split_suggestions": [
                    "LDAP filter injection through unescaped values",
                    "Authorization fallback bypass through null policy resolution",
                ],
                "candidate_guideline_text": "Split this group into distinct mechanisms.",
                "example_misses": ["repo::CVE-1"],
            }
        ],
        existing_mechanisms={"mech_old": {"mechanism_id": "mech_old"}},
        max_items=None,
    )

    assert summary["proposal_kind_counts"] == {"candidate_new_mechanism": 2}
    assert {row["release_ready"] for row in proposals} == {False}
    assert all(row["review_status"] == "needs_human_source_validation" for row in proposals)
    assert all(row["candidate_mechanism_id"].startswith("candidate_mech_") for row in proposals)


def test_clean_recall_miss_generates_recall_investigation_not_lexicon_edit():
    module = load_module()
    _, proposals = module.build_proposals(
        backlog_rows=[
            {
                "guideline_id": "gl_clean",
                "mechanism_id": "mech_clean",
                "recommended_action": "inspect_embedding_candidate_or_query_mismatch",
                "attention": ["embedding_or_candidate_recall_attention"],
                "assigned_case_count": 3,
                "primary_hit_count": 0,
            }
        ],
        existing_mechanisms={"mech_clean": {"mechanism_id": "mech_clean"}},
        max_items=None,
    )

    assert len(proposals) == 1
    assert proposals[0]["proposal_kind"] == "recall_investigation_task"
    assert proposals[0]["review_status"] == "needs_same_identity_recall_debug"
    assert proposals[0]["release_ready"] is False


def test_cli_writes_proposals(tmp_path: Path):
    backlog = tmp_path / "backlog.jsonl"
    lexicon = tmp_path / "lexicon.json"
    output = tmp_path / "proposals"
    write_jsonl(
        backlog,
        [
            {
                "guideline_id": "gl_revise",
                "mechanism_id": "mech_old",
                "mechanism_name": "old mechanism",
                "recommended_action": "revise_mechanism_text_from_evidence",
                "candidate_guideline_text": "Trace safer mechanism evidence.",
            }
        ],
    )
    lexicon.write_text(json.dumps({"mechanisms": [{"mechanism_id": "mech_old"}]}), encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--revision-backlog",
            str(backlog),
            "--lexicon",
            str(lexicon),
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
    assert summary["proposal_kind_counts"] == {"candidate_mechanism_revision": 1}
    assert (output / "lexicon_proposals.tsv").is_file()
    assert "not a guideline release" in (output / "README.md").read_text(encoding="utf-8")
