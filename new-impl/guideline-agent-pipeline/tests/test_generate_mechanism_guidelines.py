from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "generate_mechanism_guidelines.py"
LEXICON = Path(__file__).parents[1] / "guidelines" / "mechanism_lexicon.seed.json"
FIXTURE_DIR = Path(__file__).parent / "fixtures" / "mechanism_guidelines"


def load_module():
    spec = importlib.util.spec_from_file_location("generate_mechanism_guidelines", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )


def broad_cluster() -> dict:
    return json.loads((FIXTURE_DIR / "refined_clusters.json").read_text(encoding="utf-8"))


def structured_rows() -> list[dict]:
    return [
        json.loads(line)
        for line in (FIXTURE_DIR / "structured_cves.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_broad_cluster_is_split_by_member_mechanism():
    module = load_module()
    lexicon = module.load_lexicon(LEXICON)
    items = list(module.iter_work_items(broad_cluster()))
    structured = {row["cve_id"]: row for row in structured_rows()}

    candidates, grouped, _ = module.group_items_by_mechanism(
        items,
        structured,
        lexicon,
        min_score=2.0,
    )

    assert len(candidates) == 2
    assert set(grouped) == {
        "cluster_0007__mech_jndi_untrusted_lookup_target",
        "cluster_0007__mech_ssrf_webhook_url_fetch",
    }
    assert all(row["source_kind"] == "cluster_fallback_mechanism_split" for row in candidates)
    assert all(row["group_scope"] == "cluster-mechanism" for row in candidates)


def test_global_mechanism_grouping_is_available_for_ablation():
    module = load_module()
    lexicon = module.load_lexicon(LEXICON)
    payload = broad_cluster()
    payload["clusters"].append({**payload["clusters"][0], "cluster_id": 8})
    items = list(module.iter_work_items(payload))
    structured = {row["cve_id"]: row for row in structured_rows()}

    _, default_grouped, _ = module.group_items_by_mechanism(
        items,
        structured,
        lexicon,
        min_score=2.0,
    )
    _, global_grouped, _ = module.group_items_by_mechanism(
        items,
        structured,
        lexicon,
        min_score=2.0,
        group_scope="mechanism",
    )

    assert len(default_grouped) == 4
    assert set(global_grouped) == {
        "mech_jndi_untrusted_lookup_target",
        "mech_ssrf_webhook_url_fetch",
    }


def test_cli_writes_guidelines_and_case_sidecar(tmp_path: Path):
    clusters = tmp_path / "clusters.json"
    structured = tmp_path / "structured.jsonl"
    cases = tmp_path / "cases.jsonl"
    output = tmp_path / "release"
    write_json(clusters, broad_cluster())
    write_jsonl(structured, structured_rows())
    cases.write_text((FIXTURE_DIR / "cases.jsonl").read_text(encoding="utf-8"), encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--clusters",
            str(clusters),
            "--structured",
            str(structured),
            "--lexicon",
            str(LEXICON),
            "--cases-file",
            str(cases),
            "--output-dir",
            str(output),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    summary = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    assert summary["guideline_count"] == 2
    assert summary["group_scope"] == "cluster-mechanism"
    assert summary["override_count"] == 2
    overrides = [
        json.loads(line)
        for line in (output / "guideline_overrides.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert {row["mechanism_id"] for row in overrides} == {
        "mech_jndi_untrusted_lookup_target",
        "mech_ssrf_webhook_url_fetch",
    }
    jndi_guideline = next(
        row["retrieval_guideline"]
        for row in overrides
        if row["mechanism_id"] == "mech_jndi_untrusted_lookup_target"
    )
    assert "JNDI" in jndi_guideline
    assert "webhook" not in jndi_guideline.lower()
