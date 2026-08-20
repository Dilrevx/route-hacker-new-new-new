from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "fuse_recall_rank_tables.py"


def load_module():
    spec = importlib.util.spec_from_file_location("fuse_recall_rank_tables", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def anchor(file: str, start: int, rank: int, *, known: bool = False) -> dict:
    return {
        "file": file,
        "start_line": start,
        "end_line": start + 10,
        "span_kind": "sliding_window",
        "symbol": "",
        "rank": rank,
        "score": 1.0 / rank,
        "known_anchor_overlap": known,
    }


def test_fuse_tables_requires_same_identity_set():
    module = load_module()

    try:
        module.fuse_tables(
            left_rows=[{"identity_key": "case-a", "top_anchors": []}],
            right_rows=[{"identity_key": "case-b", "top_anchors": []}],
            left_label="left",
            right_label="right",
            left_weight=1.0,
            right_weight=1.0,
            rrf_k=60.0,
            per_source_cap=100,
            budgets=[10],
        )
    except ValueError as error:
        assert "identity sets differ" in str(error)
    else:
        raise AssertionError("expected identity mismatch to fail")


def test_fuse_tables_combines_complementary_anchor_ranks():
    module = load_module()
    fused_rows, summary = module.fuse_tables(
        left_rows=[
            {
                "identity_key": "case-a",
                "candidate_count": 3,
                "top_anchors": [
                    anchor("a.py", 1, 1),
                    anchor("vuln.py", 10, 2, known=True),
                ],
            }
        ],
        right_rows=[
            {
                "identity_key": "case-a",
                "candidate_count": 3,
                "top_anchors": [
                    anchor("b.py", 1, 1),
                    anchor("vuln.py", 10, 2, known=True),
                ],
            }
        ],
        left_label="left",
        right_label="right",
        left_weight=1.0,
        right_weight=1.0,
        rrf_k=60.0,
        per_source_cap=100,
        budgets=[1, 2, 3],
    )

    assert len(fused_rows) == 1
    fused = fused_rows[0]
    assert fused["best_known_anchor_rank"] == 1
    assert fused["top_anchors"][0]["known_anchor_overlap"]
    assert fused["top_anchors"][0]["source_ranks"] == {"left": 2, "right": 2}
    assert summary["metrics"]["hit_count_at_1"] == 1


def test_fuse_tables_respects_per_source_cap():
    module = load_module()
    fused_rows, summary = module.fuse_tables(
        left_rows=[
            {
                "identity_key": "case-a",
                "top_anchors": [
                    anchor("safe.py", 1, 1),
                    anchor("vuln.py", 10, 2, known=True),
                ],
            }
        ],
        right_rows=[
            {
                "identity_key": "case-a",
                "top_anchors": [
                    anchor("other.py", 1, 1),
                    anchor("vuln.py", 10, 2, known=True),
                ],
            }
        ],
        left_label="left",
        right_label="right",
        left_weight=1.0,
        right_weight=1.0,
        rrf_k=60.0,
        per_source_cap=1,
        budgets=[10],
    )

    assert fused_rows[0]["best_known_anchor_rank"] is None
    assert summary["metrics"]["hit_count_at_10"] == 0


def test_selected_anchor_row_matches_recall_selected_shape():
    module = load_module()
    case_result = {
        "identity_key": "case-a",
        "case_id": "case::a",
        "repo_url": "https://example.test/repo.git",
        "repo_key": "example__repo",
        "checkout_revision": "abc123",
        "hcvr_type": "authorization_bypass",
        "top_anchors": [
            anchor("safe.py", 1, 1),
            anchor("vuln.py", 10, 2, known=True),
        ],
    }

    selected = module.selected_anchor_row(case_result, 2)

    assert selected is not None
    assert selected["identity_key"] == "case-a"
    assert selected["repo_url"] == "https://example.test/repo.git"
    assert selected["checkout_revision"] == "abc123"
    assert selected["file"] == "vuln.py"
