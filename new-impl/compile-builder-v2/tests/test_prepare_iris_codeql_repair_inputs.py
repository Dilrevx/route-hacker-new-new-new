from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "prepare_iris_codeql_repair_inputs.py"


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def test_prepare_binds_v8_receipts_to_current_iris_case_id(tmp_path: Path) -> None:
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    archive = tmp_path / "source.tar.gz"
    archive.write_bytes(b"exact")
    revision = "abc123"
    manifest = tmp_path / "manifest.jsonl"
    failed = tmp_path / "failed.jsonl"
    source = tmp_path / "source.jsonl"
    output = tmp_path / "output"
    write_jsonl(
        manifest,
        [
            {
                "case_id": "case::current",
                "identity_key": "org__repo::CVE-1",
                "project_slug": "repo_CVE-1_1.0",
                "cve_id": "CVE-1",
                "cwe_id": "CWE-022",
                "iris_query": "cwe-022wLLM",
                "input_status": {
                    "codeql_db_status": "codeql_db_failed",
                    "blockers": ["codeql_db_not_created"],
                },
            }
        ],
    )
    write_jsonl(
        failed,
        [
            {
                "case_id": "v8:repo_CVE-1_1.0",
                "project_slug": "repo_CVE-1_1.0",
                "status": "codeql_db_failed",
                "resolved_buggy_commit": revision,
                "source_dir": str(source_dir),
                "planned_codeql_database_command": ["codeql", "database", "create"],
            }
        ],
    )
    write_jsonl(
        source,
        [
            {
                "case_id": "v8:repo_CVE-1_1.0",
                "project_slug": "repo_CVE-1_1.0",
                "source_dir": str(source_dir),
                "resolved_buggy_commit": revision,
                "status": "source_materialized_exact_archive_snapshot",
                "contract": {"exact_declared_buggy_commit_only": True},
                "archive_result": {
                    "archive_path": str(archive),
                    "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                    "archive_url": f"https://example.test/source/{revision}",
                },
            }
        ],
    )

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--iris-manifest",
            str(manifest),
            "--failed-receipts",
            str(failed),
            "--source-receipts",
            str(source),
            "--output-dir",
            str(output),
            "--expected-candidate-count",
            "1",
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    prepared_failed = json.loads((output / "failed_receipts.jsonl").read_text())
    prepared_source = json.loads((output / "source_receipts.jsonl").read_text())
    prepared_ledger = json.loads((output / "prior_ledger.jsonl").read_text())
    summary = json.loads((output / "summary.json").read_text())
    assert prepared_failed["case_id"] == "case::current"
    assert prepared_source["case_id"] == "case::current"
    assert prepared_failed["upstream_receipt_binding"]["upstream_case_id"].startswith("v8:")
    assert prepared_ledger["case_id"] == "case::current"
    assert summary["eligible_count"] == 1


def test_prepare_excludes_cases_with_native_iris_metadata_blockers(tmp_path: Path) -> None:
    manifest = tmp_path / "manifest.jsonl"
    failed = tmp_path / "failed.jsonl"
    source = tmp_path / "source.jsonl"
    output = tmp_path / "output"
    write_jsonl(
        manifest,
        [
            {
                "case_id": "case::blocked",
                "project_slug": "blocked",
                "input_status": {
                    "codeql_db_status": "codeql_db_failed",
                    "blockers": [
                        "project_slug_missing_in_clean_iris_project_info",
                        "codeql_db_not_created",
                    ],
                },
            }
        ],
    )
    write_jsonl(failed, [])
    write_jsonl(source, [])

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--iris-manifest",
            str(manifest),
            "--failed-receipts",
            str(failed),
            "--source-receipts",
            str(source),
            "--output-dir",
            str(output),
            "--expected-candidate-count",
            "0",
        ],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads((output / "summary.json").read_text())["eligible_count"] == 0
