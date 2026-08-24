#!/usr/bin/env python3
"""Run IRIS's pinned official CodeQL baseline in a materialized case workspace."""
from __future__ import annotations

import argparse
import contextlib
import importlib
import json
import re
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


def config_query_version(workspace: Path) -> str:
    config = workspace / "src" / "config.py"
    text = config.read_text(encoding="utf-8")
    match = re.search(r"^CODEQL_QUERY_VERSION\s*=\s*['\"]([^'\"]+)['\"]", text, re.MULTILINE)
    if not match:
        raise ValueError(f"cannot find CODEQL_QUERY_VERSION in {config}")
    return match.group(1)


def iris_codeql_query_version(workspace: Path, materialization: dict[str, Any]) -> str:
    bundle = materialization.get("codeql_bundle")
    if isinstance(bundle, dict) and bundle.get("iris_codeql_query_version"):
        return str(bundle["iris_codeql_query_version"])
    return config_query_version(workspace)


def candidate_query_pack_roots(workspace: Path, materialization: dict[str, Any]) -> list[Path]:
    roots = [workspace / "codeql"]
    for action in materialization.get("actions") or []:
        if not isinstance(action, dict):
            continue
        for key in ("source", "destination"):
            value = action.get(key)
            if value:
                roots.append(Path(str(value)))
    for parent in [workspace, *workspace.parents]:
        bundles = parent / "official-codeql-bundles"
        if bundles.is_dir():
            roots.extend(path for path in sorted(bundles.glob("codeql-*")) if path.is_dir())
    deduped = []
    seen = set()
    for root in roots:
        resolved = root.resolve()
        if resolved not in seen:
            seen.add(resolved)
            deduped.append(root)
    return deduped


def qlpacks_root_for_query_root(query_root: Path) -> Path:
    return query_root.parents[5]


def qlpack_has_workspace_dependency(path: Path) -> bool:
    if not path.is_file():
        return False
    return "${workspace}" in path.read_text(encoding="utf-8")


def query_root_dependency_score(query_root: Path) -> int:
    qlpacks_root = qlpacks_root_for_query_root(query_root)
    required = [
        qlpacks_root / "codeql" / "java-all" / "7.7.1" / "qlpack.yml",
        qlpacks_root / "codeql" / "controlflow" / "2.0.16" / "qlpack.yml",
        qlpacks_root / "codeql" / "dataflow" / "2.0.16" / "qlpack.yml",
        qlpacks_root / "codeql" / "suite-helpers" / "1.0.32" / "qlpack.yml",
        qlpacks_root / "codeql" / "util" / "2.0.19" / "qlpack.yml",
    ]
    return sum(path.is_file() and not qlpack_has_workspace_dependency(path) for path in required)


def query_root_selection_key(query_root: Path) -> tuple[int, int, float]:
    qlpacks_root = qlpacks_root_for_query_root(query_root)
    java_queries_pack = query_root.parents[2] / "qlpack.yml"
    score = query_root_dependency_score(query_root)
    pack_count = len(list((qlpacks_root / "codeql").glob("*/*/qlpack.yml")))
    query_pack_is_self_contained = int(
        java_queries_pack.is_file() and not qlpack_has_workspace_dependency(java_queries_pack)
    )
    return (score, query_pack_is_self_contained, pack_count, qlpacks_root.stat().st_mtime)


def official_query_source_root(
    workspace: Path,
    materialization: dict[str, Any],
    query_version: str,
    cwe_directory: str,
) -> Path:
    candidates = []
    for root in candidate_query_pack_roots(workspace, materialization):
        query_root = (
            root
            / "qlpacks"
            / "codeql"
            / "java-queries"
            / query_version
            / "Security"
            / "CWE"
            / cwe_directory
        )
        if query_root.is_dir():
            candidates.append(query_root)
    if candidates:
        return max(candidates, key=query_root_selection_key)
    searched = ", ".join(str(path) for path in candidate_query_pack_roots(workspace, materialization))
    raise FileNotFoundError(
        f"missing pinned official CodeQL query directory for {cwe_directory}@{query_version}; "
        f"searched roots: {searched}"
    )


def create_official_query_pack(query_root: Path, run_root: Path, query_version: str) -> Path:
    """Copy the selected official CWE query set into a path safe for CodeQL CLI parsing."""

    pack_root = run_root / "official_query_pack"
    if pack_root.exists():
        shutil.rmtree(pack_root)
    source_pack_root = query_root.parents[2]
    relative_query = Path("Security") / "CWE" / query_root.name
    destination = pack_root / relative_query
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(query_root, destination)
    # The original Action qlpack may use ${workspace} dependencies. This copied
    # pack intentionally lives outside that workspace, so pin explicit versions
    # and pass the original qlpacks root via --additional-packs at execution time.
    (pack_root / "qlpack.yml").write_text(
        "name: iris-native-traex/official-query-pack\n"
        "version: 0.0.0\n"
        "dependencies:\n"
        "  codeql/java-all: 7.7.1\n"
        "  codeql/suite-helpers: 1.0.32\n"
        "  codeql/util: 2.0.19\n",
        encoding="utf-8",
    )
    (pack_root / "query-source.json").write_text(
        json.dumps(
            {
                "source": str(query_root),
                "source_pack_root": str(source_pack_root),
                "query_version": query_version,
                "relative_query": str(relative_query),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return destination


def resolve_codeql_executable(codeql: Path) -> Path:
    """Use the real CodeQL CLI when a materialized workspace provides a wrapper."""

    try:
        text = codeql.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return codeql
    except OSError:
        return codeql
    match = re.search(r'^SOURCE_CODEQL="([^"]+)"', text, re.MULTILINE)
    if not match:
        return codeql
    source_codeql = Path(match.group(1))
    if source_codeql.is_file():
        return source_codeql
    return codeql


def path_argument(path: Path) -> str:
    text = str(path)
    if ":" in text or "@" in text:
        return f"path:{text}"
    return text


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
    query_version = iris_codeql_query_version(workspace, materialization)
    output_dir = args.output_dir.resolve()
    summary_path = output_dir / "summary.json"
    if summary_path.exists() and not args.overwrite:
        raise SystemExit(f"summary already exists; use --overwrite: {summary_path}")

    errors = required_path_errors(workspace, project_slug)
    if errors:
        raise SystemExit("; ".join(errors))

    codeql = resolve_codeql_executable(workspace / "codeql" / "codeql")
    database = workspace / "data" / "codeql-dbs" / project_slug
    query_root = official_query_source_root(
        workspace,
        materialization,
        query_version,
        cwe_directory,
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    artifacts_dir = output_dir / "artifacts"
    artifacts_dir.mkdir(exist_ok=True)
    sarif_path = artifacts_dir / "results.sarif"
    runnable_query_root = create_official_query_pack(query_root, artifacts_dir, query_version)
    additional_packs = qlpacks_root_for_query_root(query_root)
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
            "--additional-packs",
            str(additional_packs),
            "--format=sarif-latest",
            f"--output={sarif_path}",
            str(database),
            path_argument(runnable_query_root),
        ],
        "class_locations_query": [
            str(codeql),
            "query",
            "run",
            "--additional-packs",
            str(additional_packs),
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
            "--additional-packs",
            str(additional_packs),
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
        "official_codeql_runnable_query_directory": str(runnable_query_root),
        "official_codeql_additional_packs": str(additional_packs),
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
