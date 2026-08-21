from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "recall_guideline_anchors.py"


def load_module():
    sys.path.insert(0, str(SCRIPT.parent))
    spec = importlib.util.spec_from_file_location("recall_guideline_anchors", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class FakeEmbedder:
    @property
    def model_id(self) -> str:
        return "fake"

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        vectors = []
        for text in texts:
            if "baseline guideline" in text or "baseline-only candidate" in text:
                vectors.append([1.0, 0.0])
            elif "override guideline" in text or "override-only candidate" in text:
                vectors.append([0.0, 1.0])
            else:
                vectors.append([0.0, 0.0])
        return vectors

    def embed_queries(self, texts: list[str]) -> list[list[float]]:
        return self.embed_texts(texts)

    def embed_codes(self, texts: list[str]) -> list[list[float]]:
        return self.embed_texts(texts)


def test_baseline_plus_override_ranks_by_best_query_score():
    module = load_module()
    candidates = [
        {
            "anchor_id": "a",
            "file": "A.java",
            "start_line": 1,
            "end_line": 10,
            "span_kind": "sliding_window",
            "symbol": "",
            "text": "baseline-only candidate",
        },
        {
            "anchor_id": "b",
            "file": "B.java",
            "start_line": 1,
            "end_line": 10,
            "span_kind": "sliding_window",
            "symbol": "",
            "text": "override-only candidate",
        },
    ]

    top, _ = module.rank_candidates(
        embedder=FakeEmbedder(),
        query_items=[
            {"label": "baseline", "text": "baseline guideline"},
            {"label": "override", "text": "override guideline"},
        ],
        candidates=candidates,
        batch_size=2,
        text_max_chars=4000,
        top_k=2,
    )

    assert [row["anchor_id"] for row in top] == ["a", "b"]
    assert top[0]["query_label"] == "baseline"
    assert top[1]["query_label"] == "override"
    assert top[0]["query_scores"] == {"baseline": 1.0, "override": 0.0}
    assert top[1]["query_scores"] == {"baseline": 0.0, "override": 1.0}


def test_selected_anchor_uses_winning_query_guideline():
    module = load_module()
    row = {
        "identity_key": "case-a",
        "case_id": "case::a",
        "repo_url": "https://example.test/repo.git",
        "checkout_revision": "abc123",
        "hcvr_type": "authorization_bypass",
        "snapshot": "/tmp/snapshot",
        "guideline": "override guideline",
        "guideline_queries": [
            {"label": "baseline", "text": "baseline guideline"},
            {"label": "override", "text": "override guideline"},
        ],
        "top_anchors": [
            {
                "anchor_id": "a",
                "file": "A.java",
                "start_line": 1,
                "end_line": 10,
                "rank": 1,
                "query_label": "baseline",
            }
        ],
    }

    selected = module.selected_anchor_row(row, 1)

    assert selected is not None
    assert selected["guideline"] == "baseline guideline"
    assert selected["guideline_query_label"] == "baseline"
