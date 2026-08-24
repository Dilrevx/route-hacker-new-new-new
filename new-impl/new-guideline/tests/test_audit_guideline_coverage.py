from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "audit_guideline_coverage.py"


def load_module():
    spec = importlib.util.spec_from_file_location("audit_guideline_coverage", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def case(identity: str, cwe_ids: list[str] | None = None) -> dict:
    vuln_id = identity.split("::", 1)[1]
    return {
        "identity_key": identity,
        "new_unified_case_id": f"case::{vuln_id.lower()}",
        "vulnerability": {"id": vuln_id, "aliases": []},
        "classification": {
            "primary_hcvr_type": "test_type",
            "hcvr_types": ["test_type"],
            "cwe_ids": cwe_ids or [],
            "classification_sources": [{"source_family": "fixture"}],
        },
    }


def test_load_identities_accepts_complete_qa_receipt_json(tmp_path):
    module = load_module()
    receipt = tmp_path / "qa.json"
    receipt.write_text(
        (
            '{"unique_identity_count":2,'
            '"added_identities":["repo__one::CVE-2099-0001","repo__two::GHSA-AAAA-BBBB-CCCC"]}'
        ),
        encoding="utf-8",
    )

    assert module.load_identities(receipt) == [
        "repo__one::CVE-2099-0001",
        "repo__two::GHSA-AAAA-BBBB-CCCC",
    ]


def test_load_identities_uses_sibling_full_allowlist_for_rebalance_receipt(tmp_path):
    module = load_module()
    receipt = tmp_path / "qa.json"
    receipt.write_text(
        '{"unique_identity_count":2,"added_identities":["repo__added::CVE-2099-0003"]}',
        encoding="utf-8",
    )
    allowlist = tmp_path / "hcvr_new_unified_fix_revision_paper_eval_review.v2.jsonl"
    allowlist.write_text(
        '{"identity_key":"repo__one::CVE-2099-0001"}\n'
        '{"identity_key":"repo__two::GHSA-AAAA-BBBB-CCCC"}\n',
        encoding="utf-8",
    )

    assert module.load_identities(receipt) == [
        "repo__one::CVE-2099-0001",
        "repo__two::GHSA-AAAA-BBBB-CCCC",
    ]


def test_load_cases_accepts_json_cases_array(tmp_path):
    module = load_module()
    cases_path = tmp_path / "cases.json"
    cases_path.write_text(
        '{"cases":[{"identity_key":"repo__one::CVE-2099-0001"},{"identity_key":"repo__two::CVE-2099-0002"}]}',
        encoding="utf-8",
    )

    assert sorted(module.load_cases(cases_path)) == [
        "repo__one::CVE-2099-0001",
        "repo__two::CVE-2099-0002",
    ]


def test_audit_coverage_separates_intake_noise_release_and_advisory_gaps():
    module = load_module()
    identities = [
        "repo__covered::CVE-2099-0001",
        "repo__absent::CVE-2099-0002",
        "repo__noise::CVE-2099-0003",
        "repo__review::CVE-2099-0004",
        "repo__ghsa::GHSA-AAAA-BBBB-CCCC",
    ]
    cases = {identity: case(identity) for identity in identities}

    summary, rows = module.audit_coverage(
        identities=identities,
        cases=cases,
        raw_records={
            "CVE-2099-0001": {"cve_id": "CVE-2099-0001", "cwe_id": "CWE-79"},
            "CVE-2099-0003": {"cve_id": "CVE-2099-0003", "cwe_id": "CWE-362"},
            "CVE-2099-0004": {"cve_id": "CVE-2099-0004", "cwe_id": "CWE-863"},
        },
        structured_records={
            "CVE-2099-0001": {"cve_id": "CVE-2099-0001", "cwe_chain": ["CWE-79"]},
            "CVE-2099-0003": {"cve_id": "CVE-2099-0003", "cwe_chain": ["CWE-362"]},
            "CVE-2099-0004": {"cve_id": "CVE-2099-0004", "cwe_chain": ["CWE-863"]},
        },
        cluster_members={"CVE-2099-0001": [{}], "CVE-2099-0004": [{}]},
        cluster_noise={"CVE-2099-0003"},
        candidate_members={"CVE-2099-0001", "CVE-2099-0004"},
        review_queue={
            "CVE-2099-0004": [
                {
                    "release_status": {
                        "blockers": ["pending_mechanism_needs_review"],
                    }
                }
            ]
        },
        sidecars={
            "primary": {
                "repo__covered::CVE-2099-0001": {
                    "identity_key": "repo__covered::CVE-2099-0001",
                    "guideline_text": "Audit XSS.",
                }
            }
        },
        primary_sidecar="primary",
    )

    by_identity = {row["identity_key"]: row for row in rows}
    assert summary["coverage_by_sidecar"] == {"primary": 1}
    assert summary["coverage_upper_bounds"] == {
        "current_primary_sidecar": 1,
        "if_review_queue_released_for_current_candidates": 2,
        "if_noise_singletons_released_from_current_raw_structured": 3,
        "if_all_cve_ids_ingested": 4,
        "if_cve_and_ghsa_supported": 5,
    }
    assert by_identity["repo__covered::CVE-2099-0001"]["coverage_category"] == "covered_by_primary_sidecar"
    assert by_identity["repo__absent::CVE-2099-0002"]["coverage_category"] == (
        "missing_from_cve_clustering_raw_structured"
    )
    assert by_identity["repo__noise::CVE-2099-0003"]["coverage_category"] == (
        "present_in_raw_but_cluster_noise"
    )
    assert by_identity["repo__review::CVE-2099-0004"]["coverage_category"] == (
        "clustered_but_review_only_release_gate"
    )
    assert by_identity["repo__ghsa::GHSA-AAAA-BBBB-CCCC"]["coverage_category"] == (
        "ghsa_or_non_cve_no_cvelist_join"
    )
