#!/usr/bin/env python3
"""Materialize one isolated IRIS-shaped root from an audited layout receipt."""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
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
        if row.get("case_id") == case_selector
        or row.get("identity_key") == case_selector
        or row.get("project_slug") == case_selector
    ]
    if len(matches) != 1:
        raise ValueError(f"expected exactly one receipt for {case_selector}, found {len(matches)}")
    return matches[0]


def validate_manifest_row(row: dict[str, Any]) -> dict[str, Any]:
    required = ("identity_key", "project_slug", "iris_query", "input_paths")
    missing = [key for key in required if not row.get(key)]
    if missing:
        raise ValueError(f"manifest row is missing required fields: {', '.join(missing)}")
    inputs = row["input_paths"]
    if not isinstance(inputs, dict):
        raise ValueError("manifest input_paths must be an object")
    input_missing = [key for key in ("source", "codeql_db", "package_names") if not inputs.get(key)]
    if input_missing:
        raise ValueError(
            "manifest input_paths is missing required fields: " + ", ".join(input_missing)
        )
    revisions = row.get("revisions")
    if not isinstance(revisions, dict) or not revisions.get("v2_checkout_revision"):
        raise ValueError("manifest revisions.v2_checkout_revision is required")
    return row


def validate_input_paths(case: dict[str, Any]) -> dict[str, str]:
    inputs = case["input_paths"]
    paths = {
        "source": Path(str(inputs["source"])).resolve(),
        "codeql_db": Path(str(inputs["codeql_db"])).resolve(),
        "package_names": Path(str(inputs["package_names"])).resolve(),
    }
    if not paths["source"].is_dir():
        raise FileNotFoundError(f"source directory does not exist: {paths['source']}")
    if not paths["codeql_db"].is_dir():
        raise FileNotFoundError(f"CodeQL database directory does not exist: {paths['codeql_db']}")
    if not paths["package_names"].is_file():
        raise FileNotFoundError(f"package-name file does not exist: {paths['package_names']}")
    return {key: str(value) for key, value in paths.items()}


def codeql_cli_version(codeql_dir: Path) -> str:
    command = [str(codeql_dir / "codeql"), "version"]
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    if completed.returncode != 0:
        raise RuntimeError(
            f"CodeQL version probe failed ({completed.returncode}): "
            f"{completed.stderr.strip()[-500:]}"
        )
    match = re.search(r"release\s+([0-9]+(?:\.[0-9]+){1,2})", completed.stdout)
    if not match:
        raise RuntimeError(f"cannot parse CodeQL release from: {completed.stdout!r}")
    return match.group(1)


def query_pack_version(clean_root: Path) -> str:
    config = (clean_root / "src" / "config.py").read_text(encoding="utf-8")
    match = re.search(r'^CODEQL_QUERY_VERSION\s*=\s*"([^"]+)"', config, flags=re.MULTILINE)
    if not match:
        raise RuntimeError("cannot find CODEQL_QUERY_VERSION in clean IRIS src/config.py")
    return match.group(1)


def qlpack_value(path: Path, key: str) -> str | None:
    match = re.search(
        rf"^\s*{re.escape(key)}:\s*([^\s#]+)",
        path.read_text(encoding="utf-8"),
        flags=re.MULTILINE,
    )
    return match.group(1) if match else None


def validated_source_overlay(codeql_dir: Path, cli_version: str) -> dict[str, Any] | None:
    """Return provenance for a matching official CodeQL source-tag overlay."""

    manifest_path = codeql_dir / ".iris_codeql_source_overlay.json"
    if not manifest_path.is_file():
        return None
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"invalid CodeQL source overlay manifest: {manifest_path}") from exc
    if not isinstance(manifest, dict):
        raise RuntimeError(f"CodeQL source overlay manifest is not an object: {manifest_path}")
    if manifest.get("kind") != "github_codeql_source_tag_overlay":
        raise RuntimeError(f"unrecognized CodeQL source overlay kind: {manifest_path}")
    source_root = Path(str(manifest.get("source_root") or ""))
    source_tag = manifest.get("source_tag")
    if not source_root.is_dir() or not isinstance(source_tag, dict):
        raise RuntimeError(f"incomplete CodeQL source overlay manifest: {manifest_path}")
    tag = str(source_tag.get("tag") or "")
    expected_tag = f"codeql-cli/v{cli_version}"
    expected_commit = str(source_tag.get("commit") or "")
    if tag != expected_tag or not expected_commit:
        raise RuntimeError(
            "CodeQL source overlay tag does not match installed CLI: "
            f"expected {expected_tag}, found {tag or '<missing>'}"
        )
    completed = subprocess.run(
        ["git", "-C", str(source_root), "rev-parse", "--verify", f"{tag}^{{commit}}"],
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0 or completed.stdout.strip() != expected_commit:
        raise RuntimeError(
            "CodeQL source overlay tag commit cannot be revalidated: "
            f"{source_root} {tag}"
        )
    current = subprocess.run(
        ["git", "-C", str(source_root), "rev-parse", "HEAD"],
        text=True,
        capture_output=True,
        check=False,
    )
    if current.returncode != 0 or current.stdout.strip() != expected_commit:
        raise RuntimeError(
            "CodeQL source overlay checkout no longer matches its recorded official tag: "
            f"{source_root}"
        )
    return {
        "manifest": str(manifest_path),
        "sha256": sha256_path(manifest_path),
        "source_root": str(source_root),
        "source_tag": {"tag": tag, "commit": expected_commit},
    }


def compile_source_overlay_probe(codeql_dir: Path, query_pack: Path) -> dict[str, str]:
    """Compile one official query so a source-pack projection cannot be metadata-only."""

    candidates = sorted((query_pack / "Security" / "CWE").glob("CWE-*/*.ql"))
    if not candidates:
        raise RuntimeError(
            "CodeQL source overlay has no official Java CWE query available for compile probing: "
            f"{query_pack}"
        )
    probe = candidates[0]
    completed = subprocess.run(
        [str(codeql_dir / "codeql"), "query", "compile", str(probe)],
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "CodeQL source overlay cannot compile an official Java CWE query: "
            f"{probe}; {completed.stderr.strip()[-1500:]}"
        )
    return {"query": str(probe), "status": "compiled"}


def validate_codeql_bundle(clean_root: Path, codeql_dir: Path) -> dict[str, Any]:
    """Require Action-bundle packs or a matching official source-tag overlay."""

    executable = codeql_dir / "codeql"
    if not executable.is_file():
        raise FileNotFoundError(f"missing CodeQL executable: {executable}")
    cli_version = codeql_cli_version(codeql_dir)
    required_query_version = query_pack_version(clean_root)
    query_pack = codeql_dir / "qlpacks" / "codeql" / "java-queries" / required_query_version
    query_pack_file = query_pack / "qlpack.yml"
    if not query_pack_file.is_file():
        raise RuntimeError(
            "CodeQL Action bundle is missing the IRIS-required java-queries pack "
            f"codeql/java-queries@{required_query_version}: {query_pack_file}"
        )
    compatible_java_all = []
    java_all_root = codeql_dir / "qlpacks" / "codeql" / "java-all"
    if java_all_root.is_dir():
        for pack_file in sorted(java_all_root.glob("*/qlpack.yml")):
            if qlpack_value(pack_file, "cliVersion") == cli_version:
                compatible_java_all.append(
                    {
                        "version": qlpack_value(pack_file, "version"),
                        "path": str(pack_file.parent),
                    }
                )
    source_overlay = validated_source_overlay(codeql_dir, cli_version)
    if source_overlay and query_pack_file.is_file():
        compatible_java_all = compatible_java_all or [
            {
                "version": qlpack_value(java_all_root / "7.7.1" / "qlpack.yml", "version"),
                "path": str(java_all_root / "7.7.1"),
            }
        ]
    if not compatible_java_all:
        raise RuntimeError(
            "CodeQL Action bundle lacks a codeql/java-all pack compatible with "
            f"CLI {cli_version}; expected a qlpack buildMetadata.cliVersion match"
        )
    compile_probe = (
        compile_source_overlay_probe(codeql_dir, query_pack)
        if source_overlay
        else None
    )
    return {
        "codeql_cli_version": cli_version,
        "iris_codeql_query_version": required_query_version,
        "java_queries_pack": {
            "version": qlpack_value(query_pack_file, "version"),
            "path": str(query_pack),
        },
        "compatible_java_all_packs": compatible_java_all,
        "source_overlay": source_overlay,
        "source_overlay_compile_probe": compile_probe,
    }


def add_traex_model_aliases(gpt_model_path: Path) -> dict[str, str]:
    """Add fault-tolerant TraeX transport to the copied IRIS GPT adapter."""

    source = gpt_model_path.read_text(encoding="utf-8")
    aliases = (
        '    "gpt-traex-flash": "DeepSeek-V4-Flash",\n'
        '    "gpt-traex-pro": "DeepSeek-V4-Pro",\n'
    )
    if '"gpt-traex-flash"' not in source:
        match = re.search(r"(?ms)^_model_name_map = \{(?P<body>.*?)^\}\n_OPENAI_DEFAULT_PARAMS", source)
        if not match:
            raise RuntimeError(f"cannot find GPT model registry marker in {gpt_model_path}")
        body = match.group("body")
        if body and not body.rstrip().endswith(","):
            body = body.rstrip() + ",\n"
        source = source[: match.start("body")] + body + aliases + source[match.end("body") :]
    client_marker = "self.client = OpenAI(api_key=api_key)"
    client_replacement = (
        'self.client = OpenAI(\n'
        '            api_key=api_key,\n'
        '            default_headers={\n'
        '                "X-Iris-Run-Id": os.getenv("IRIS_TRAEX_RUN_ID", ""),\n'
        '                "X-Iris-Case-Id": os.getenv("IRIS_TRAEX_CASE_ID", ""),\n'
        '            },\n'
        '        )'
    )
    if client_marker in source:
        source = source.replace(client_marker, client_replacement, 1)
    elif "X-Iris-Run-Id" not in source:
        raise RuntimeError(f"cannot add bridge attribution headers to {gpt_model_path}")
    if "def _create_completion_with_retry" not in source:
        if "import json\n" not in source:
            source = source.replace("import os\n", "import json\nimport os\n", 1)
        if "import time\n" not in source:
            source = source.replace("import os\n", "import os\nimport time\n", 1)
        source = source.replace(
            "self.client.chat.completions.create(",
            "self._create_completion_with_retry(",
        )
        predict_marker = "    def _predict(self, main_prompt, expect_json=False):\n"
        retry_method = """    def _create_completion_with_retry(self, **request_kwargs):
        max_attempts = max(1, int(os.getenv("IRIS_LLM_MAX_ATTEMPTS", "4")))
        retry_delay_seconds = max(0.0, float(os.getenv("IRIS_LLM_RETRY_DELAY_SECONDS", "5")))
        for attempt in range(1, max_attempts + 1):
            try:
                return self.client.chat.completions.create(**request_kwargs)
            except Exception:
                if attempt == max_attempts:
                    raise
                time.sleep(retry_delay_seconds * attempt)

    @staticmethod
    def _requires_json_list_response(main_prompt):
        prompt_text = "\\n".join(
            str(message.get("content", ""))
            for message in main_prompt
            if isinstance(message, dict)
        ).lower()
        return (
            "return the result as a json list" in prompt_text
            or "return the result as a json array" in prompt_text
        )

    @staticmethod
    def _is_json_list_response(response_text):
        if not isinstance(response_text, str):
            return False
        payload = response_text.strip()
        if payload.startswith("```json\\n") and payload.endswith("\\n```"):
            payload = payload[len("```json\\n") : -len("\\n```")]
        try:
            return isinstance(json.loads(payload), list)
        except (json.JSONDecodeError, TypeError):
            return False

    def _retry_json_list_format(self, request_kwargs, first_response):
        max_attempts = max(1, int(os.getenv("IRIS_JSON_LIST_FORMAT_ATTEMPTS", "4")))
        response = first_response
        response_text = response.choices[0].message.content
        if self._is_json_list_response(response_text):
            return response
        correction = {
            "role": "user",
            "content": (
                "Format correction: return only a valid JSON array for the original task. "
                "Do not include Markdown fences, explanation, or any surrounding text. "
                "If no items apply, return exactly []."
            ),
        }
        retry_kwargs = dict(request_kwargs)
        retry_kwargs["messages"] = list(request_kwargs["messages"]) + [correction]
        for _ in range(1, max_attempts):
            response = self._create_completion_with_retry(**retry_kwargs)
            response_text = response.choices[0].message.content
            if self._is_json_list_response(response_text):
                break
        return response

"""
        if predict_marker not in source:
            raise RuntimeError(f"cannot add retrying completion transport to {gpt_model_path}")
        source = source.replace(predict_marker, retry_method + predict_marker, 1)
        json_list_retry = """        if self._requires_json_list_response(main_prompt):
            request_kwargs = {
                "model": self.model_id,
                "messages": prompt,
                **_OPENAI_DEFAULT_PARAMS,
            }
            response = self._retry_json_list_format(request_kwargs, response)
"""
        response_markers = (
            "        if response.choices[0].logprobs != None:\n",
            "        response=response.choices[0].message.content\n",
            "        return response.choices[0].message.content\n",
        )
        response_assignment = next(
            (marker for marker in response_markers if marker in source),
            None,
        )
        if response_assignment is None:
            raise RuntimeError(f"cannot add JSON-list retry to {gpt_model_path}")
        source = source.replace(response_assignment, json_list_retry + response_assignment, 1)
    try:
        ast.parse(source, filename=str(gpt_model_path))
    except SyntaxError as exc:
        raise RuntimeError(f"generated GPT transport adapter is invalid Python: {exc}") from exc
    gpt_model_path.write_text(source, encoding="utf-8")
    return {
        "path": str(gpt_model_path),
        "kind": "copied_iris_gpt_transport_adapter",
        "aliases": "gpt-traex-flash,gpt-traex-pro",
        "bridge_attribution_headers": "X-Iris-Run-Id,X-Iris-Case-Id",
        "bounded_transport_retries": "IRIS_LLM_MAX_ATTEMPTS,IRIS_LLM_RETRY_DELAY_SECONDS",
        "bounded_json_list_format_retries": "IRIS_JSON_LIST_FORMAT_ATTEMPTS",
        "sha256": sha256_path(gpt_model_path),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    inputs = parser.add_mutually_exclusive_group()
    inputs.add_argument("--receipts", type=Path)
    inputs.add_argument("--manifest", type=Path)
    parser.add_argument(
        "--validate-codeql-bundle",
        action="store_true",
        help="validate the official CodeQL Action bundle without materializing a case",
    )
    parser.add_argument("--case-id")
    parser.add_argument("--clean-iris-root", type=Path, required=True)
    parser.add_argument("--codeql-dir", type=Path, required=True)
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--overwrite-empty-workspace", action="store_true")
    args = parser.parse_args()

    clean_root = args.clean_iris_root.resolve()
    src_source = clean_root / "src"
    if not src_source.is_dir():
        raise SystemExit(f"missing clean IRIS src: {src_source}")
    codeql_dir = args.codeql_dir.resolve()
    codeql_bundle = validate_codeql_bundle(clean_root, codeql_dir)
    if args.validate_codeql_bundle:
        if args.manifest or args.receipts or args.case_id or args.workspace:
            raise SystemExit(
                "--validate-codeql-bundle cannot be combined with case materialization arguments"
            )
        print(json.dumps(codeql_bundle, indent=2, sort_keys=True))
        return 0
    if not (args.manifest or args.receipts):
        raise SystemExit("one of --manifest or --receipts is required for case materialization")
    if not args.case_id:
        raise SystemExit("--case-id is required for case materialization")
    if not args.workspace:
        raise SystemExit("--workspace is required for case materialization")

    input_path = args.manifest or args.receipts
    rows = read_jsonl(input_path)
    case = find_case(rows, args.case_id)
    if args.manifest:
        case = validate_manifest_row(case)
        validate_input_paths(case)
    workspace = args.workspace.resolve()
    if workspace.exists():
        if not args.overwrite_empty_workspace:
            raise SystemExit(f"workspace already exists: {workspace}")
        if any(workspace.iterdir()):
            raise SystemExit(f"workspace is not empty: {workspace}")
    workspace.mkdir(parents=True, exist_ok=True)

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
    source_dir = Path(str(inputs.get("source") or inputs.get("source_dir") or "")).resolve()
    db_dir = Path(str(inputs.get("codeql_db") or inputs.get("codeql_db_dir") or "")).resolve()
    package_file = Path(str(inputs.get("package_names") or inputs.get("package_names_file") or "")).resolve()
    slug = str(case["project_slug"])
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
            for key in ("case_id", "case_index", "project_slug", "cve_id", "cwe_id_normalized", "iris_query")
        },
        "workspace": str(workspace),
        "clean_iris_root": str(clean_root),
        "clean_iris_src_sha256": sha256_path(workspace / "src" / "iris.py"),
        "codeql_dir": str(codeql_dir),
        "codeql_bundle": codeql_bundle,
        "receipt_path": str(input_path.resolve()),
        "receipt_sha256": sha256_path(input_path),
        "manifest_input": bool(args.manifest),
        "actions": actions,
        "contract": {
            "isolated_workspace": True,
            "clean_iris_src_copied": True,
            "only_local_source_change_is_gpt_transport_aliases": True,
            "case_source_and_db_linked_from_receipt": True,
            "input_paths_validated_before_materialization": bool(args.manifest),
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
