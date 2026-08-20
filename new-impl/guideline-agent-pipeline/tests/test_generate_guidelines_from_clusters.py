from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "generate_guidelines_from_clusters.py"


def load_module():
    spec = importlib.util.spec_from_file_location("generate_guidelines_from_clusters", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def cve(cve_id: str, *, root: str = "missing owner validation") -> dict:
    return {
        "cve_id": cve_id,
        "vuln_type": "authorization",
        "root_cause": root,
        "code_layer": "authentication_authorization",
        "scope": "cross_function",
        "abstract_pattern": "request object id reaches update without owner check",
        "data_flow": "HTTP parameter to repository update",
        "trigger_condition": "authenticated caller chooses another resource",
        "fix_strategy": "compare resource owner with authenticated principal",
        "impact": "unauthorized resource mutation",
    }


def cluster_payload() -> dict:
    return {
        "method": "traditional",
        "clusters": [
            {
                "cluster_id": 7,
                "cluster_name": "missing object scoped authorization",
                "cluster_summary": "Object identifiers reach sensitive effects without ownership checks.",
                "members": ["CVE-1", "CVE-2", "CVE-3"],
                "representative_cve": "CVE-1",
                "sub_patterns": [
                    {
                        "name": "missing owner comparison",
                        "root_cause": "resource owner is not compared with caller",
                        "fix_strategy": "add owner comparison before mutation",
                        "members": ["CVE-1"],
                    },
                    {
                        "name": "tenant scope omitted",
                        "root_cause": "tenant filter is missing from lookup",
                        "fix_strategy": "bind lookup to tenant and caller",
                        "members": ["CVE-2"],
                    },
                ],
            }
        ],
        "noise": ["CVE-99"],
    }


def test_build_generation_tasks_splits_multiple_subpatterns_and_fallback():
    module = load_module()
    structured = {"CVE-1": cve("CVE-1"), "CVE-2": cve("CVE-2"), "CVE-3": cve("CVE-3")}

    tasks = module.build_generation_tasks(cluster_payload(), structured)

    assert [task.guideline_id for task in tasks] == ["gl_0001", "gl_0002", "gl_0003"]
    assert [task.cve_ids for task in tasks] == [["CVE-1"], ["CVE-2"], ["CVE-1", "CVE-2", "CVE-3"]]


def test_deterministic_release_and_case_sidecar(tmp_path: Path):
    module = load_module()
    clusters = cluster_payload()
    structured = {"CVE-1": cve("CVE-1"), "CVE-2": cve("CVE-2"), "CVE-3": cve("CVE-3")}
    template = "cluster {{ cluster_id }} {{ cluster_name }}\n{{ representatives }}"

    guidelines, prompts, meta = module.build_guidelines(
        clusters,
        structured,
        prompt_template=template,
        model_used="test",
        concurrency=1,
        chat=None,
        deterministic=True,
    )

    assert len(prompts) == 3
    assert meta["source_fingerprint"] == module.build_source_fingerprint(["CVE-1", "CVE-2", "CVE-3", "CVE-99"])
    assert len(guidelines) == 3
    assert all(guideline["guideline_text"] for guideline in guidelines)

    output = tmp_path / "release"
    paths = module.write_release(output, guidelines, metadata={"source_fingerprint": meta["source_fingerprint"], "model_used": "test"})
    assert Path(paths["latest"]).exists()
    index = json.loads((output / "guidelines" / "index.json").read_text(encoding="utf-8"))
    assert index["total"] == 3

    cases = tmp_path / "cases.jsonl"
    cases.write_text(
        json.dumps({"identity_key": "owner__repo::CVE-1", "new_unified_case_id": "case::1", "vulnerability": {"id": "CVE-1"}})
        + "\n"
        + json.dumps({"identity_key": "owner__repo::CVE-X", "new_unified_case_id": "case::x", "vulnerability": {"id": "CVE-X"}})
        + "\n",
        encoding="utf-8",
    )
    sidecar = tmp_path / "guideline_overrides.jsonl"
    count = module.export_case_sidecar(sidecar, guidelines=guidelines, cases_file=cases)

    rows = [json.loads(line) for line in sidecar.read_text(encoding="utf-8").splitlines()]
    assert count == 1
    assert rows[0]["identity_key"] == "owner__repo::CVE-1"
    assert rows[0]["guideline_id"] == "gl_0001"
    assert rows[0]["guideline_text"]


def test_sanitize_guideline_removes_known_project_specific_tokens():
    module = load_module()
    text = "Check CVE-2024-12345 in github.com/acme/app at src/Main.java line 42 before the sink."

    sanitized = module.sanitize_guideline_text(text)

    assert "CVE-2024-12345" not in sanitized
    assert "github.com/acme/app" not in sanitized
    assert "src/Main.java" not in sanitized
    assert "line 42" not in sanitized
