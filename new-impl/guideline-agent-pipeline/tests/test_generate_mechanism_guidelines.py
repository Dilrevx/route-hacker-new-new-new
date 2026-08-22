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
    assert {row["mechanism_ids"][0] for row in overrides} == {
        "mech_jndi_untrusted_lookup_target",
        "mech_ssrf_webhook_url_fetch",
    }
    jndi_guideline = next(
        row["retrieval_guideline"]
        for row in overrides
        if row["mechanism_ids"] == ["mech_jndi_untrusted_lookup_target"]
    )
    assert "JNDI" in jndi_guideline
    assert "webhook" not in jndi_guideline.lower()


def test_guideline_text_uses_mechanism_guard_without_generic_binding_boilerplate():
    module = load_module()
    authz = module.Mechanism(
        mechanism_id="mech_object_owner_scope_missing_authz",
        name="missing object-owner or tenant-scope authorization",
        family="authorization",
        aliases=(),
        keywords=(),
        source_shape="attacker-selected object IDs",
        sink_shape="sensitive resource mutations",
        missing_guard="the authorization decision is not bound to the exact resource being mutated",
        typical_fix="bind the checked resource identity to the mutation",
    )
    sql = module.Mechanism(
        mechanism_id="mech_sql_dynamic_query",
        name="dynamic SQL construction from untrusted values",
        family="injection",
        aliases=(),
        keywords=(),
        source_shape="attacker-controlled query fields",
        sink_shape="SQL statement construction",
        missing_guard="values are concatenated into SQL syntax before parameter binding",
        typical_fix="use bound parameters or strict allowlists for structural SQL fragments",
    )

    authz_text = module.build_guideline_text(authz, 2)
    sql_text = module.build_guideline_text(sql, 2)

    assert "same source-to-sink path" in authz_text
    assert "bound to the exact resource" in authz_text
    assert "same resource, principal, destination, or object" not in authz_text
    assert "same resource, principal, destination, or object" not in sql_text
    assert "bound parameters" in sql_text


def test_pending_review_guidelines_are_not_recall_overrides_by_default(tmp_path: Path):
    module = load_module()
    item = module.WorkItem(
        cluster_id=77,
        cluster_name="Unclassified mechanism",
        cluster_summary="A narrow issue that does not match the current mechanism lexicon.",
        sub_pattern_name="Novel parser state confusion",
        sub_pattern_root_cause="Parser state is confused after a rare transition.",
        sub_pattern_fix_strategy="Validate the parser state before the transition.",
        members=("CVE-2099-7701",),
        source_kind="sub_pattern",
    )
    mechanism = module.pending_mechanism(item, "novel parser state confusion")
    case_lookup = {
        "CVE-2099-7701": [
            {
                "identity_key": "example__project::CVE-2099-7701",
                "new_unified_case_id": "case::pending",
                "vulnerability": {"id": "CVE-2099-7701"},
            }
        ]
    }
    output = tmp_path / "release"

    summary = module.write_outputs(
        output_dir=output,
        candidates=[
            {
                "status": "pending_review",
                "mechanism_id": mechanism.mechanism_id,
            }
        ],
        grouped={"cluster_0077__pending": [item]},
        mechanisms_by_group={"cluster_0077__pending": mechanism},
        clustering={"method": "test"},
        case_lookup=case_lookup,
        group_scope="cluster-mechanism",
    )

    assert summary["guideline_count"] == 1
    assert summary["pending_review_count"] == 1
    assert summary["override_count"] == 0
    assert summary["pending_overrides_included"] is False
    assert (output / "guidelines" / "gl_mech_0001.json").is_file()
    assert not (output / "guideline_overrides.jsonl").exists()


def test_pending_review_overrides_can_be_included_for_ablation(tmp_path: Path):
    module = load_module()
    item = module.WorkItem(
        cluster_id=78,
        cluster_name="Unclassified mechanism",
        cluster_summary="A narrow issue that does not match the current mechanism lexicon.",
        sub_pattern_name="Novel parser state confusion",
        sub_pattern_root_cause="Parser state is confused after a rare transition.",
        sub_pattern_fix_strategy="Validate the parser state before the transition.",
        members=("CVE-2099-7801",),
        source_kind="sub_pattern",
    )
    mechanism = module.pending_mechanism(item, "novel parser state confusion")
    case_lookup = {
        "CVE-2099-7801": [
            {
                "identity_key": "example__project::CVE-2099-7801",
                "new_unified_case_id": "case::pending",
                "vulnerability": {"id": "CVE-2099-7801"},
            }
        ]
    }
    output = tmp_path / "release"

    summary = module.write_outputs(
        output_dir=output,
        candidates=[
            {
                "status": "pending_review",
                "mechanism_id": mechanism.mechanism_id,
            }
        ],
        grouped={"cluster_0078__pending": [item]},
        mechanisms_by_group={"cluster_0078__pending": mechanism},
        clustering={"method": "test"},
        case_lookup=case_lookup,
        group_scope="cluster-mechanism",
        include_pending_overrides=True,
    )

    assert summary["override_count"] == 1
    assert summary["pending_overrides_included"] is True
    overrides = [
        json.loads(line)
        for line in (output / "guideline_overrides.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert overrides[0]["identity_key"] == "example__project::CVE-2099-7801"


def test_sub_pattern_evidence_takes_precedence_over_broad_cluster_summary():
    module = load_module()
    lexicon = module.load_lexicon(LEXICON)
    structured = {
        "CVE-2099-2001": {
            "cve_id": "CVE-2099-2001",
            "vuln_type": "missing validation of target namespace identifiers in bulk sync operation",
            "root_cause": (
                "The request body contains syncToNamespaces resource identifiers "
                "that are not validated to match the appId and namespaceName path "
                "parameters, allowing a path-scoped permission check to be bypassed."
            ),
            "abstract_pattern": (
                "User-supplied resource identifiers in a bulk operation are not "
                "bound to the resource identified by path parameters."
            ),
            "data_flow": "HTTP body syncToNamespaces -> NamespaceSyncModel -> syncItems mutation",
            "trigger_condition": "Authenticated request with mismatched body namespace targets.",
            "fix_strategy": "Validate every body namespace target against the path parameters.",
            "impact": "Modify a namespace not covered by the path-scoped authorization decision.",
        }
    }
    item = module.WorkItem(
        cluster_id=34,
        cluster_name="Missing authorization checks in web endpoints",
        cluster_summary=(
            "HTTP endpoints lack authentication guards, permission annotations, "
            "object-level ownership checks, and other broad authorization controls."
        ),
        sub_pattern_name="Missing validation of resource identifiers against path parameters",
        sub_pattern_root_cause=(
            "Request body resource identifiers are not validated to match URL path parameters."
        ),
        sub_pattern_fix_strategy="Validate each body-selected target against the path parameters.",
        members=("CVE-2099-2001",),
        source_kind="sub_pattern",
    )

    attributed = module.attributed_work_items(item, structured, lexicon, min_score=2.0)

    assert len(attributed) == 1
    _, mechanism, status, _, _ = attributed[0]
    assert status == "active"
    assert mechanism.mechanism_id == "mech_request_body_resource_mismatch_authz"


def test_xml_external_entity_mechanism_wins_over_deserialization_for_parser_evidence():
    module = load_module()
    lexicon = module.load_lexicon(LEXICON)
    structured = {
        "CVE-2099-3001": {
            "cve_id": "CVE-2099-3001",
            "vuln_type": "XML external entity processing in report parser",
            "root_cause": (
                "A default DocumentBuilderFactory parses attacker supplied XML "
                "without disabling DTD processing, external general entities, "
                "or external parameter entities."
            ),
            "abstract_pattern": "Untrusted XML reaches a parser that resolves external entities.",
            "data_flow": "uploaded XML report -> DocumentBuilderFactory -> DocumentBuilder.parse",
            "trigger_condition": "The XML document contains a DOCTYPE with an external entity.",
            "fix_strategy": "Disable DOCTYPE and external entity resolution on the parser factory.",
            "impact": "Local file disclosure or SSRF through XML entity resolution.",
        }
    }
    item = module.WorkItem(
        cluster_id=1,
        cluster_name="XML processing bugs",
        cluster_summary=(
            "XML parser bugs include XXE, XMLDecoder deserialization, XSLT extension "
            "function abuse, and other XML-processing problems."
        ),
        sub_pattern_name="Unsafe XML parser external entity resolution",
        sub_pattern_root_cause="Default parser allows external entity resolution.",
        sub_pattern_fix_strategy="Disable DTD and external entities.",
        members=("CVE-2099-3001",),
        source_kind="sub_pattern",
    )

    attributed = module.attributed_work_items(item, structured, lexicon, min_score=2.0)

    assert len(attributed) == 1
    _, mechanism, status, _, matches = attributed[0]
    assert status == "active"
    assert mechanism.mechanism_id == "mech_xml_external_entity_resolution"
    assert "documentbuilderfactory" in matches
