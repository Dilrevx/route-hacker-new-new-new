#!/usr/bin/env python3
"""Materialize one isolated IRIS-shaped root from an audited layout receipt."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


METADATA_FILES = (
    "project_info.csv",
    "build_info.csv",
    "build_cmds.csv",
    "fix_info.csv",
    "fix_info_source_sink.csv",
    "source_sink_detect.csv",
)


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"non-object receipt at {path}:{line_no}")
        rows.append(value)
    return rows


def symlink_exact(source: Path, destination: Path) -> dict[str, str]:
    if not source.exists():
        raise FileNotFoundError(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        raise RuntimeError(f"refusing to replace existing path: {destination}")
    destination.symlink_to(source, target_is_directory=source.is_dir())
    return {"source": str(source), "destination": str(destination), "kind": "symlink"}


def find_case(rows: list[dict[str, Any]], case_selector: str) -> dict[str, Any]:
    matches = [
        row
        for row in rows
        if row.get("case_id") == case_selector or row.get("project_slug") == case_selector
    ]
    if len(matches) != 1:
        raise ValueError(f"expected exactly one receipt for {case_selector}, found {len(matches)}")
    row = matches[0]
    if not is_iris_ready_row(row):
        raise ValueError(f"case is not IRIS-ready: {row.get('status')} blockers={row.get('blockers')}")
    return row


def is_iris_ready_row(row: dict[str, Any]) -> bool:
    if row.get("status") == "iris_shadow_root_ready":
        return True
    if row.get("status") in {"native_iris_ready", "current_v2_native_iris_ready"}:
        return True
    if row.get("schema_version") == "iris213_full_strict_native_admission.v1":
        admission = row.get("official_iris_admission") or {}
        required = (
            "exact_source_receipt",
            "fix_info_present",
            "native_query_supported",
            "package_names_present",
            "project_info_present",
        )
        return all(admission.get(key) is True for key in required)
    return False


def add_traex_model_aliases(gpt_model_path: Path) -> dict[str, str]:
    """Add transport aliases to the copied IRIS GPT adapter, never shared inputs."""

    source = gpt_model_path.read_text(encoding="utf-8")
    aliases = (
        '    "gpt-traex-flash": "DeepSeek-V4-Flash",\n'
        '    "gpt-traex-pro": "DeepSeek-V4-Pro",\n'
    )
    if '"gpt-traex-flash"' not in source:
        marker = "}\n_OPENAI_DEFAULT_PARAMS"
        if marker not in source:
            raise RuntimeError(f"cannot find GPT model registry marker in {gpt_model_path}")
        source = source.replace(marker, aliases + "}\n_OPENAI_DEFAULT_PARAMS", 1)
    header_marker = (
        'default_headers={\n'
        '                "X-Iris-Run-Id": os.getenv("IRIS_TRAEX_RUN_ID", ""),\n'
        '                "X-Iris-Case-Id": os.getenv("IRIS_TRAEX_CASE_ID", ""),\n'
        '            }'
    )
    legacy_client_marker = "self.client = OpenAI(api_key=api_key)"
    legacy_client_replacement = (
        'self.client = OpenAI(\n'
        '            api_key=api_key,\n'
        f'            {header_marker},\n'
        '        )'
    )
    base_url_client_marker = (
        "self.client = OpenAI(api_key=api_key, base_url=base_url, timeout=timeout) "
        "if base_url else OpenAI(api_key=api_key, timeout=timeout)"
    )
    base_url_client_replacement = (
        "self.client = OpenAI(\n"
        "            api_key=api_key,\n"
        "            base_url=base_url,\n"
        "            timeout=timeout,\n"
        f"            {header_marker},\n"
        "        ) if base_url else OpenAI(\n"
        "            api_key=api_key,\n"
        "            timeout=timeout,\n"
        f"            {header_marker},\n"
        "        )"
    )
    if "X-Iris-Run-Id" in source:
        pass
    elif base_url_client_marker in source:
        source = source.replace(base_url_client_marker, base_url_client_replacement, 1)
    elif legacy_client_marker in source:
        source = source.replace(legacy_client_marker, legacy_client_replacement, 1)
    else:
        raise RuntimeError(f"cannot add bridge attribution headers to {gpt_model_path}")
    gpt_model_path.write_text(source, encoding="utf-8")
    return {
        "path": str(gpt_model_path),
        "kind": "copied_iris_gpt_transport_aliases",
        "aliases": "gpt-traex-flash,gpt-traex-pro",
        "bridge_attribution_headers": "X-Iris-Run-Id,X-Iris-Case-Id",
        "sha256": sha256_path(gpt_model_path),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipts", type=Path, required=True)
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--clean-iris-root", type=Path, required=True)
    parser.add_argument("--codeql-dir", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--overwrite-empty-workspace", action="store_true")
    args = parser.parse_args()

    rows = read_jsonl(args.receipts)
    case = find_case(rows, args.case_id)
    workspace = args.workspace.resolve()
    if workspace.exists():
        if not args.overwrite_empty_workspace:
            raise SystemExit(f"workspace already exists: {workspace}")
        if any(workspace.iterdir()):
            raise SystemExit(f"workspace is not empty: {workspace}")
    workspace.mkdir(parents=True, exist_ok=True)

    clean_root = args.clean_iris_root.resolve()
    src_source = clean_root / "src"
    if not src_source.is_dir():
        raise SystemExit(f"missing clean IRIS src: {src_source}")
    codeql_dir = args.codeql_dir.resolve()
    if not (codeql_dir / "codeql").is_file():
        raise SystemExit(f"missing CodeQL executable: {codeql_dir / 'codeql'}")

    copied_ignored = shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo")
    shutil.copytree(src_source, workspace / "src", ignore=copied_ignored, symlinks=True)
    actions: list[dict[str, str]] = [
        {
            "source": str(src_source),
            "destination": str(workspace / "src"),
            "kind": "copied_clean_iris_src",
        },
        symlink_exact(codeql_dir, workspace / "codeql"),
        add_traex_model_aliases(workspace / "src" / "models" / "gpt.py"),
    ]
    (workspace / "data" / "project-sources").mkdir(parents=True)
    (workspace / "data" / "codeql-dbs").mkdir(parents=True)
    (workspace / "data" / "package-names").mkdir(parents=True)
    (workspace / "output").mkdir()
    (workspace / "log").mkdir()

    for name in METADATA_FILES:
        source = clean_root / "data" / name
        if source.is_file():
            actions.append(symlink_exact(source, workspace / "data" / name))
    for name in ("dep_configs.json", "dep_configs.linux_x64.json"):
        source = clean_root / name
        if source.is_file():
            actions.append(symlink_exact(source, workspace / name))

    inputs = case.get("input_paths") or {}
    source_dir = Path(str(inputs.get("source") or inputs.get("source_dir") or ""))
    db_dir = Path(str(inputs.get("codeql_db") or inputs.get("codeql_db_dir") or ""))
    package_file = Path(str(inputs.get("package_names") or inputs.get("package_names_file") or ""))
    slug = str(case["project_slug"])
    if not str(source_dir) or not str(db_dir) or not str(package_file):
        raise SystemExit(
            "ready receipt must provide input_paths.source, input_paths.codeql_db, "
            "and input_paths.package_names"
        )
    actions.extend(
        (
            symlink_exact(source_dir, workspace / "data" / "project-sources" / slug),
            # IRIS passes data/codeql-dbs/<slug> directly to `codeql database`.
            # The audited receipt already points at that database root.
            symlink_exact(db_dir, workspace / "data" / "codeql-dbs" / slug),
            symlink_exact(package_file, workspace / "data" / "package-names" / f"{slug}.txt"),
        )
    )
    manifest = {
        "schema_version": "iris_native_traex_materialization.v1",
        "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "status": "ready",
        "case": {
            key: case.get(key)
            for key in ("case_id", "case_index", "project_slug", "cve_id", "cwe_id", "cwe_id_normalized", "iris_query")
        },
        "workspace": str(workspace),
        "clean_iris_root": str(clean_root),
        "clean_iris_src_sha256": sha256_path(workspace / "src" / "iris.py"),
        "codeql_dir": str(codeql_dir),
        "receipt_path": str(args.receipts.resolve()),
        "receipt_sha256": sha256_path(args.receipts),
        "actions": actions,
        "contract": {
            "isolated_workspace": True,
            "clean_iris_src_copied": True,
            "only_local_source_change_is_gpt_transport_aliases": True,
            "case_source_and_db_linked_from_receipt": True,
            "no_iris_execution": True,
            "no_llm_call": True,
        },
    }
    output = workspace / "materialization.json"
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
