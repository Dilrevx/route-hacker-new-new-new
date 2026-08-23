#!/usr/bin/env python3
"""Run IRIS's pinned official CodeQL baseline in a materialized case workspace."""
from __future__ import annotations

import argparse
import contextlib
import importlib
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def read_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def official_codeql_query(native_query: str) -> str:
    if not native_query.startswith("cwe-") or not native_query.endswith("wLLM"):
        raise ValueError(f"unsupported native IRIS query name: {native_query}")
    return f"{native_query.removesuffix('wLLM')}wCodeQL"


def codeql_cwe_directory(native_query: str) -> str:
    official_query = official_codeql_query(native_query)
    return f"CWE-{official_query[4:7]}"


def run_command(command: list[str], cwd: Path, stdout_path: Path, stderr_path: Path) -> int:
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        return subprocess.run(command, cwd=cwd, stdout=stdout, stderr=stderr, check=False).returncode


def required_path_errors(workspace: Path, project_slug: str) -> list[str]:
    expected = {
        "CodeQL executable": workspace / "codeql" / "codeql",
        "CodeQL database": workspace / "data" / "codeql-dbs" / project_slug,
        "project source": workspace / "data" / "project-sources" / project_slug,
        "IRIS metadata": workspace / "data" / "fix_info.csv",
        "IRIS evaluator": workspace / "src" / "modules" / "evaluation_pipeline.py",
        "class-location query": workspace / "src" / "queries" / "fetch_class_locs.ql",
        "method-location query": workspace / "src" / "queries" / "fetch_func_locs.ql",
    }
    return [f"missing {label}: {path}" for label, path in expected.items() if not path.exists()]


def create_location_query_pack(workspace: Path, run_root: Path) -> Path:
    """Create an isolated official-query pack for evaluator location lookups."""
    pack_root = run_root / "location_queries"
    if pack_root.exists():
        shutil.rmtree(pack_root)
    query_source_root = workspace / "src" / "queries"
    shutil.copytree(query_source_root, pack_root)
    (pack_root / "qlpack.yml").write_text(
        "name: iris-native-traex/location-queries\n"
        "version: 0.0.0\n"
        "dependencies:\n"
        "  codeql/java-all: 7.7.1\n",
        encoding="utf-8",
    )
    return pack_root


@contextlib.contextmanager
def workspace_imports(workspace: Path):
    original_path = list(sys.path)
    original_src = sys.modules.get("src")
    sys.path.insert(0, str(workspace))
    for name in list(sys.modules):
        if name == "src" or name.startswith("src."):
            del sys.modules[name]
    try:
        yield
    finally:
        for name in list(sys.modules):
            if name == "src" or name.startswith("src."):
                del sys.modules[name]
        if original_src is not None:
            sys.modules["src"] = original_src
        sys.path[:] = original_path


def evaluate(
    workspace: Path,
    project_slug: str,
    sarif_path: Path,
    class_locations: Path,
    function_locations: Path,
) -> dict[str, Any]:
    with workspace_imports(workspace):
        pandas = importlib.import_module("pandas")
        evaluator_module = importlib.import_module("src.modules.evaluation_pipeline")
        fixed_methods = pandas.read_csv(workspace / "data" / "fix_info.csv")
        project_fixed_methods = fixed_methods[fixed_methods["project_slug"] == project_slug]
        evaluator = evaluator_module.EvaluationPipeline(
            project_fixed_methods=project_fixed_methods,
            class_locs_path=str(class_locations),
            func_locs_path=str(function_locations),
            project_source_code_dir=str(workspace / "data" / "project-sources" / project_slug),
            query_output_result_sarif_path=str(sarif_path),
            final_output_json_path=None,
            project_logger=None,
        )
        return evaluator.evaluate_sarif_result(str(sarif_path))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()

    workspace = args.workspace.resolve()
    materialization = read_json(workspace / "materialization.json")
    case = materialization["case"]
    project_slug = str(case["project_slug"])
    native_query = str(case["iris_query"])
    baseline_query = official_codeql_query(native_query)
    cwe_directory = codeql_cwe_directory(native_query)
    output_dir = args.output_dir.resolve()
    summary_path = output_dir / "summary.json"
    if summary_path.exists() and not args.overwrite:
        raise SystemExit(f"summary already exists; use --overwrite: {summary_path}")

    errors = required_path_errors(workspace, project_slug)
    if errors:
        raise SystemExit("; ".join(errors))

    codeql = workspace / "codeql" / "codeql"
    database = workspace / "data" / "codeql-dbs" / project_slug
    query_root = (
        workspace
        / "codeql"
        / "qlpacks"
        / "codeql"
        / "java-queries"
        / str(materialization["codeql_bundle"]["iris_codeql_query_version"])
        / "Security"
        / "CWE"
        / cwe_directory
    )
    if not query_root.is_dir():
        raise SystemExit(f"missing pinned official CodeQL query directory: {query_root}")

    output_dir.mkdir(parents=True, exist_ok=True)
    artifacts_dir = output_dir / "artifacts"
    artifacts_dir.mkdir(exist_ok=True)
    sarif_path = artifacts_dir / "results.sarif"
    location_query_pack = create_location_query_pack(workspace, artifacts_dir)
    class_bqrs = artifacts_dir / "class_locations.bqrs"
    class_locations = artifacts_dir / "class_locations.csv"
    function_bqrs = artifacts_dir / "function_locations.bqrs"
    function_locations = artifacts_dir / "function_locations.csv"
    started = time.monotonic()

    commands = {
        "baseline_analyze": [
            str(codeql),
            "database",
            "analyze",
            "--rerun",
            "--format=sarif-latest",
            f"--output={sarif_path}",
            str(database),
            str(query_root),
        ],
        "class_locations_query": [
            str(codeql),
            "query",
            "run",
            f"--database={database}",
            f"--output={class_bqrs}",
            "--",
            str(location_query_pack / "fetch_class_locs.ql"),
        ],
        "class_locations_decode": [
            str(codeql),
            "bqrs",
            "decode",
            str(class_bqrs),
            "--format=csv",
            f"--output={class_locations}",
        ],
        "function_locations_query": [
            str(codeql),
            "query",
            "run",
            f"--database={database}",
            f"--output={function_bqrs}",
            "--",
            str(location_query_pack / "fetch_func_locs.ql"),
        ],
        "function_locations_decode": [
            str(codeql),
            "bqrs",
            "decode",
            str(function_bqrs),
            "--format=csv",
            f"--output={function_locations}",
        ],
    }
    return_codes: dict[str, int] = {}
    for name, command in commands.items():
        return_codes[name] = run_command(
            command,
            workspace,
            output_dir / f"{name}.stdout.txt",
            output_dir / f"{name}.stderr.txt",
        )
        if return_codes[name] != 0:
            break

    evaluation: dict[str, Any] | None = None
    completed = all(code == 0 for code in return_codes.values()) and len(return_codes) == len(commands)
    if completed:
        try:
            evaluation = evaluate(
                workspace,
                project_slug,
                sarif_path,
                class_locations,
                function_locations,
            )
        except Exception as error:
            completed = False
            (output_dir / "evaluation.error.txt").write_text(f"{error!r}\n", encoding="utf-8")

    summary = {
        "schema_version": "iris_native_traex_official_codeql_baseline.v1",
        "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "status": "completed_verified" if completed and evaluation is not None else "failed",
        "verified_completion": completed and evaluation is not None,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "case": case,
        "run_id": args.run_id,
        "official_codeql_query": baseline_query,
        "official_codeql_query_directory": str(query_root),
        "codeql_database": str(database),
        "commands": commands,
        "return_codes": return_codes,
        "artifacts": {
            "sarif": str(sarif_path),
            "location_query_pack": str(location_query_pack),
            "class_locations": str(class_locations),
            "function_locations": str(function_locations),
        },
        "evaluation": evaluation,
    }
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["verified_completion"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
