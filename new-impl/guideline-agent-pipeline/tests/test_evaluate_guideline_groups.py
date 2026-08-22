from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "evaluate_guideline_groups.py"


def load_module():
    spec = importlib.util.spec_from_file_location("evaluate_guideline_groups", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")


def guideline(
    guideline_id: str,
    *,
    cves: list[str],
    mechanism_id: str = "mech_object_owner_scope_missing_authz",
) -> dict:
    return {
        "guideline_id": guideline_id,
        "guideline_group_key": f"cluster_0001__{mechanism_id}",
        "guideline_text": "Trace resource IDs into protected object operations.",
        "mechanism": {
            "mechanism_id": mechanism_id,
            "name": "missing object-owner or tenant-scope authorization",
            "family": "authorization",
            "source_shape": "attacker-selected resource identifiers",
            "sink_shape": "sensitive object operations",
            "missing_guard": "object ownership is not checked",
            "typical_fix": "bind authorization to the selected object",
        },
        "cve_ids": cves,
    }


def case(identity: str, cve: str, hcvr: str, cwes: list[str]) -> dict:
    return {
        "identity_key": identity,
        "new_unified_case_id": f"case::{identity}",
        "vulnerability": {"id": cve, "aliases": []},
        "classification": {"primary_hcvr_type": hcvr, "cwe_ids": cwes},
    }


def build_release(tmp_path: Path, payloads: list[dict], overrides: list[dict]) -> Path:
    release = tmp_path / "release"
    for payload in payloads:
        write_json(release / "guidelines" / f"{payload['guideline_id']}.json", payload)
    write_json(
        release / "index.json",
        {
            "items": [
                {
                    "guideline_id": payload["guideline_id"],
                    "file_name": f"{payload['guideline_id']}.json",
                }
                for payload in payloads
            ]
        },
    )
    write_jsonl(release / "guideline_overrides.jsonl", overrides)
    write_jsonl(release / "mechanism_candidates.jsonl", [])
    return release


def test_evaluate_release_flags_mixed_groups_without_recall_rank(tmp_path: Path):
    module = load_module()
    cases_file = tmp_path / "cases.jsonl"
    write_jsonl(
        cases_file,
        [
            case("case-a", "CVE-1", "authorization_bypass", ["CWE-862"]),
            case("case-b", "CVE-2", "ssrf", ["CWE-918"]),
        ],
    )
    release = build_release(
        tmp_path,
        [guideline("gl_mech_0001", cves=["CVE-1", "CVE-2"])],
        [
            {
                "identity_key": "case-a",
                "case_id": "case::case-a",
                "guideline_ids": ["gl_mech_0001"],
                "cve_ids": ["CVE-1"],
            },
            {
                "identity_key": "case-b",
                "case_id": "case::case-b",
                "guideline_ids": ["gl_mech_0001"],
                "cve_ids": ["CVE-2"],
            },
        ],
    )

    summary, group_rows, assignments = module.evaluate_release(
        release_dir=release,
        cases_file=cases_file,
        min_purity=0.67,
        singleton_soft_cap=1,
    )

    assert summary["assigned_unique_case_count"] == 2
    assert summary["mixed_hcvr_group_count"] == 1
    assert summary["mixed_cwe_group_count"] == 1
    assert group_rows[0]["flags"] == ["mixed_hcvr", "mixed_cwe"]
    assert {row["identity_key"] for row in assignments} == {"case-a", "case-b"}
    assert all("rank" not in row for row in assignments)


def test_evaluate_release_accepts_pure_actionable_group(tmp_path: Path):
    module = load_module()
    cases_file = tmp_path / "cases.jsonl"
    write_jsonl(
        cases_file,
        [
            case("case-a", "CVE-1", "authorization_bypass", ["CWE-862"]),
            case("case-b", "CVE-2", "authorization_bypass", ["CWE-862"]),
        ],
    )
    release = build_release(
        tmp_path,
        [guideline("gl_mech_0001", cves=["CVE-1", "CVE-2"])],
        [
            {
                "identity_key": "case-a",
                "case_id": "case::case-a",
                "guideline_ids": ["gl_mech_0001"],
                "cve_ids": ["CVE-1"],
            },
            {
                "identity_key": "case-b",
                "case_id": "case::case-b",
                "guideline_ids": ["gl_mech_0001"],
                "cve_ids": ["CVE-2"],
            },
        ],
    )

    summary, group_rows, _ = module.evaluate_release(
        release_dir=release,
        cases_file=cases_file,
        min_purity=0.67,
        singleton_soft_cap=1,
    )

    assert summary["mixed_hcvr_group_count"] == 0
    assert summary["mixed_cwe_group_count"] == 0
    assert summary["weighted_primary_hcvr_purity"] == 1.0
    assert summary["weighted_cwe_purity"] == 1.0
    assert group_rows[0]["flags"] == []


def test_evaluate_release_excludes_source_only_groups_from_purity(tmp_path: Path):
    module = load_module()
    cases_file = tmp_path / "cases.jsonl"
    write_jsonl(cases_file, [case("case-a", "CVE-1", "authorization_bypass", ["CWE-862"])])
    release = build_release(
        tmp_path,
        [
            guideline("gl_mech_0001", cves=["CVE-1"]),
            guideline("gl_mech_0002", cves=["CVE-NOT-IN-DATASET"]),
        ],
        [
            {
                "identity_key": "case-a",
                "case_id": "case::case-a",
                "guideline_ids": ["gl_mech_0001"],
                "cve_ids": ["CVE-1"],
            }
        ],
    )

    summary, group_rows, assignments = module.evaluate_release(
        release_dir=release,
        cases_file=cases_file,
        min_purity=0.67,
        singleton_soft_cap=0,
    )

    assert summary["guideline_count"] == 2
    assert summary["evaluated_group_count"] == 1
    assert summary["source_only_group_count"] == 1
    assert summary["source_only_no_case_metadata_count"] == 1
    assert summary["weighted_primary_hcvr_purity"] == 1.0
    assert summary["weighted_cwe_purity"] == 1.0
    assert len(assignments) == 1
    source_only = [row for row in group_rows if row["guideline_id"] == "gl_mech_0002"][0]
    assert source_only["flags"] == ["source_only_no_case_metadata"]


def test_write_judge_pack_for_flagged_groups(tmp_path: Path):
    module = load_module()
    group_rows = [
        {
            "guideline_id": "gl_mech_0001",
            "guideline_group_key": "cluster_0001__mech_a",
            "mechanism_id": "mech_a",
            "mechanism_name": "mechanism A",
            "mechanism_family": "authz",
            "assigned_case_count": 2,
            "source_cve_count": 2,
            "metadata_cve_count": 2,
            "primary_hcvr_majority": "authorization_bypass",
            "primary_hcvr_purity": 0.5,
            "cwe_majority": "CWE-862",
            "cwe_purity": 0.5,
            "flags": ["mixed_hcvr"],
            "guideline_text": "Trace object use without object authorization.",
            "cluster_summary": "Mixed authorization cases.",
            "judge_case_examples": [{"identity_key": "case-a", "cve_ids": ["CVE-1"]}],
        },
        {
            "guideline_id": "gl_mech_0002",
            "guideline_group_key": "cluster_0002__mech_b",
            "mechanism_id": "mech_b",
            "mechanism_name": "mechanism B",
            "mechanism_family": "ssrf",
            "assigned_case_count": 1,
            "source_cve_count": 1,
            "metadata_cve_count": 1,
            "primary_hcvr_majority": "ssrf",
            "primary_hcvr_purity": 1.0,
            "cwe_majority": "CWE-918",
            "cwe_purity": 1.0,
            "flags": [],
            "guideline_text": "Trace outbound fetches.",
            "cluster_summary": "SSRF cases.",
            "judge_case_examples": [{"identity_key": "case-b", "cve_ids": ["CVE-2"]}],
        },
    ]

    judge_dir = tmp_path / "judge"
    module.write_judge_pack(judge_dir, group_rows=group_rows, group_filter="flagged", max_groups=10)

    rows = [json.loads(line) for line in (judge_dir / "judge_inputs.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [row["guideline_id"] for row in rows] == ["gl_mech_0001"]
    assert (judge_dir / "prompts" / "gl_mech_0001.md").is_file()
    assert (judge_dir / "judge_rubric.v1.md").is_file()
    assert "Return JSON only" in (judge_dir / "prompts" / "gl_mech_0001.md").read_text(encoding="utf-8")
    assert "Guideline Semantic Judge Rubric" in (judge_dir / "prompts" / "gl_mech_0001.md").read_text(encoding="utf-8")
    assert "judgment criteria can be reviewed and versioned" in (judge_dir / "README.md").read_text(encoding="utf-8")
    runner = (judge_dir / "run_traex_judge.sh").read_text(encoding="utf-8")
    assert "TRAE_JUDGE_CONCURRENCY" in runner
    assert 'OUT_DIR="${1:-judge_outputs}"' in runner
    assert 'xargs -n 1 -P "$CONCURRENCY"' in runner
    assert runner.index('OUT_DIR="${1:-judge_outputs}"') < runner.index("export OUT_DIR")
