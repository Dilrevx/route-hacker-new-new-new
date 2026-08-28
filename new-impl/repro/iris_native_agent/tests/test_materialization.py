from pathlib import Path
import runpy


def test_scripts_are_present():
    root = Path(__file__).resolve().parents[1] / "scripts"
    assert (root / "serve_agent_openai.py").is_file()
    assert (root / "materialize_iris_case.py").is_file()
    assert (root / "prepare_current_v2_iris_queue.py").is_file()
    assert (root / "run_native_iris_case.py").is_file()
    assert (root / "run_native_iris_batch.py").is_file()
    assert (root / "summarize_native_iris_metrics.py").is_file()


def test_batch_attempt_id_is_namespaced():
    module = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts" / "run_native_iris_batch.py"))
    assert module["safe_name"]("flash-a1") == "flash-a1"
    assert module["safe_name"]("v8:case") == "v8_case"


def test_batch_summary_counts_verified_statistics(tmp_path):
    module = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts" / "run_native_iris_batch.py"))
    ledger = tmp_path / "receipts.jsonl"
    ledger.write_text(
        '{"status":"completed_verified","elapsed_seconds":3,"iris_statistics":{"candidate_apis":5,"vanilla_paths":2}}\n'
        '{"status":"failed_or_incomplete","elapsed_seconds":9,"iris_statistics":{"candidate_apis":99}}\n'
    )
    summary = module["summarize_receipts"](ledger)
    assert summary["completed_verified_count"] == 1
    assert summary["verified_totals"]["elapsed_seconds"] == 3
    assert summary["verified_totals"]["candidate_apis"] == 5
    assert summary["verified_totals"]["vanilla_paths"] == 2


def test_batch_accepts_strict_admission_rows():
    module = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts" / "run_native_iris_batch.py"))
    assert module["is_iris_ready_row"](
        {
            "schema_version": "iris213_full_strict_native_admission.v1",
            "official_iris_admission": {
                "exact_source_receipt": True,
                "fix_info_present": True,
                "native_query_supported": True,
                "package_names_present": True,
                "project_info_present": True,
            },
        }
    )
    assert not module["is_iris_ready_row"](
        {
            "schema_version": "iris213_full_strict_native_admission.v1",
            "official_iris_admission": {
                "exact_source_receipt": True,
                "fix_info_present": False,
                "native_query_supported": True,
                "package_names_present": True,
                "project_info_present": True,
            },
        }
    )
