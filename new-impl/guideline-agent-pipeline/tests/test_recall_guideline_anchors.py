from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "recall_guideline_anchors.py"


def load_module():
    script_dir = str(SCRIPT.parent)
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)
    spec = importlib.util.spec_from_file_location("recall_guideline_anchors", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class FakeEmbedder:
    model_id = "fake-embedding"

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        vectors = []
        for text in texts:
            lowered = text.lower()
            if "dangeroussink" in lowered or "authorization" in lowered:
                vectors.append([1.0, 0.0])
            else:
                vectors.append([0.0, 1.0])
        return vectors


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
                "anchor_id": "anchor::truth",
                "file": "src/App.java",
                "start_line": 4,
                "end_line": 5,
                "symbol": "",
                "span_kind": "hunk",
            }
        ],
    }


def test_slice_snapshot_and_embedding_rank_hits_known_anchor(tmp_path: Path):
    module = load_module()
    snapshot = tmp_path / "snapshot"
    source = snapshot / "src" / "App.java"
    source.parent.mkdir(parents=True)
    source.write_text(
        "\n".join(
            [
                "class App {",
                "  void safe() {",
                "    System.out.println(\"safe\");",
                "  }",
                "  void update() {",
                "    dangerousSink();",
                "  }",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    case = sample_case()
    candidates = module.slice_snapshot(
        case=case,
        snapshot=snapshot,
        suffixes={".java"},
        window_lines=3,
        stride_lines=3,
        max_file_bytes=10000,
        max_files=100,
        max_candidates=100,
    )
    ranked = module.rank_candidates(
        embedder=FakeEmbedder(),
        query_text=module.build_guideline(case),
        candidates=candidates,
        batch_size=4,
        text_max_chars=4000,
        top_k=2,
    )
    for row in ranked:
        row["known_anchor_overlap"] = module.anchor_hit(row, case["recall_anchors"])

    assert ranked[0]["file"] == "src/App.java"
    assert ranked[0]["start_line"] == 4
    assert ranked[0]["known_anchor_overlap"] is True
    selected = {"identity_key": case["identity_key"], **ranked[0]}
    assert selected["anchor_id"].startswith("recalled_anchor::")


def test_selected_anchor_row_uses_requested_rank():
    module = load_module()
    result = {
        "identity_key": "owner__repo::CVE-2099-0001",
        "case_id": "case::1",
        "repo_url": "https://github.com/owner/repo.git",
        "checkout_revision": "a" * 40,
        "hcvr_type": "authorization_bypass",
        "snapshot": "/tmp/snapshot",
        "top_anchors": [
            {
                "rank": 1,
                "anchor_id": "recalled_anchor::1",
                "file": "A.java",
                "start_line": 1,
                "end_line": 10,
                "score": 0.2,
            },
            {
                "rank": 2,
                "anchor_id": "recalled_anchor::2",
                "file": "B.java",
                "start_line": 20,
                "end_line": 30,
                "score": 0.1,
            },
        ],
    }
    selected = module.selected_anchor_row(result, 2)
    assert selected is not None
    assert selected["anchor_id"] == "recalled_anchor::2"
    assert selected["snapshot"] == "/tmp/snapshot"
