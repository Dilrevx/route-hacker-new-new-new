#!/usr/bin/env python3
"""Run a materialized case through unmodified IRIS stages with artifact gates."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


EXPECTED_ARTIFACTS = (
    "results.sarif",
    "results.csv",
    "results_pp.sarif",
    "../{query}-posthoc-filter/results.sarif",
    "../{query}-posthoc-filter/results.json",
    "../{query}-posthoc-filter/stats.json",
    "../{query}-final/results.json",
)


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def run_process(command: list[str], cwd: Path, env: dict[str, str], timeout_seconds: int) -> tuple[int | None, bool, bytes, bytes]:
    process = subprocess.Popen(
        command,
        cwd=str(cwd),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
        return process.returncode, False, stdout, stderr
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout or b""
        stderr = error.stderr or b""
        os.killpg(process.pid, signal.SIGTERM)
        try:
            next_stdout, next_stderr = process.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            next_stdout, next_stderr = process.communicate()
        return None, True, stdout + (next_stdout or b""), stderr + (next_stderr or b"")


def existing_final_artifacts(workspace: Path, slug: str, run_id: str, query: str) -> dict[str, bool]:
    query_root = workspace / "output" / slug / run_id / query
    return {
        rel.format(query=query): (query_root / rel.format(query=query)).resolve().is_file()
        for rel in EXPECTED_ARTIFACTS
    }


def valid_label_response(path: Path) -> bool:
    """IRIS allows raw JSON lists or one complete fenced list for labelling stages."""

    payload = path.read_text(encoding="utf-8", errors="replace").strip()
    if payload.startswith("```json\n") and payload.endswith("\n```"):
        payload = payload[len("```json\n") : -len("\n```")]
    try:
        return isinstance(json.loads(payload), list)
    except json.JSONDecodeError:
        return False


def audit_label_responses(workspace: Path, slug: str, run_id: str, query: str) -> dict[str, Any]:
    root = workspace / "output" / slug / run_id / "analysis" / query / "logs"
    phases: dict[str, Any] = {}
    all_valid = True
    total = 0
    for phase in ("label_apis", "label_func_params"):
        phase_root = root / phase
        prompts = sorted(phase_root.glob("raw_user_prompt_*.txt")) if phase_root.is_dir() else []
        responses = []
        for prompt in prompts:
            suffix = prompt.name.removeprefix("raw_user_prompt_")
            response = phase_root / f"raw_llm_response_{suffix}"
            detail = {
                "prompt": str(prompt.relative_to(workspace)),
                "response": str(response.relative_to(workspace)),
                "exists": response.is_file(),
                "valid_json_list": response.is_file() and valid_label_response(response),
            }
            responses.append(detail)
        phase_valid = all(item["exists"] and item["valid_json_list"] for item in responses)
        total += len(responses)
        all_valid = all_valid and phase_valid
        phases[phase] = {"prompt_count": len(prompts), "valid": phase_valid, "responses": responses}
    return {"total_dispatched_prompt_count": total, "all_valid": all_valid, "phases": phases}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--llm", choices=("gpt-traex-flash", "gpt-traex-pro"), default="gpt-traex-flash")
    parser.add_argument("--bridge-url", required=True)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--num-threads", type=int, default=1)
    parser.add_argument("--label-api-batch-size", type=int, default=30)
    parser.add_argument("--label-func-param-batch-size", type=int, default=20)
    parser.add_argument("--timeout-seconds", type=int, default=3600)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    workspace = args.workspace.resolve()
    materialization = read_json(workspace / "materialization.json")
    case = materialization["case"]
    slug = str(case["project_slug"])
    query = str(case["iris_query"])
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    project_output = workspace / "output" / slug / args.run_id
    common_output = workspace / "output" / "common" / args.run_id
    if project_output.exists() or common_output.exists():
        raise SystemExit("run-id collides with existing project/common output; choose a fresh --run-id")

    command = [
        args.python,
        "src/iris.py",
        "--query",
        query,
        "--run-id",
        args.run_id,
        "--llm",
        args.llm,
        "--num-threads",
        str(args.num_threads),
        "--label-api-batch-size",
        str(args.label_api_batch_size),
        "--label-func-param-batch-size",
        str(args.label_func_param_batch_size),
        slug,
    ]
    env = dict(os.environ)
    env.update(
        {
            "OPENAI_API_KEY": "traex-local-bridge",
            "OPENAI_BASE_URL": args.bridge_url.rstrip("/") + "/v1",
            "IRIS_LLM_MAX_ATTEMPTS": env.get("IRIS_LLM_MAX_ATTEMPTS", "2"),
        }
    )
    started = time.monotonic()
    returncode, timed_out, stdout, stderr = run_process(command, workspace, env, args.timeout_seconds)
    elapsed_seconds = round(time.monotonic() - started, 3)
    (output_dir / "stdout.txt").write_bytes(stdout)
    (output_dir / "stderr.txt").write_bytes(stderr)

    artifacts = existing_final_artifacts(workspace, slug, args.run_id, query)
    label_audit = audit_label_responses(workspace, slug, args.run_id, query)
    verified = returncode == 0 and not timed_out and all(artifacts.values()) and label_audit["all_valid"]
    summary = {
        "schema_version": "iris_native_traex_run.v1",
        "created_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "status": "completed_verified" if verified else ("timeout" if timed_out else "failed_or_incomplete"),
        "native_iris_contract": {
            "entrypoint": "src/iris.py",
            "stages_required": [
                "candidate API extraction",
                "LLM source/sink/taint-propagator labelling",
                "LLM function-parameter labelling",
                "project-specific CodeQL query generation",
                "CodeQL vulnerability query",
                "IRIS postprocessing",
                "LLM posthoc filtering",
                "IRIS evaluation",
            ],
            "skipped_stages": [],
            "llm_transport_only_adaptation": True,
        },
        "case": case,
        "workspace": str(workspace),
        "materialization_sha256": sha256_path(workspace / "materialization.json"),
        "command": command,
        "returncode": returncode,
        "timed_out": timed_out,
        "elapsed_seconds": elapsed_seconds,
        "llm": {
            "iris_model_name": args.llm,
            "transport": "local_traex_openai_bridge",
            "bridge_url": args.bridge_url,
        },
        "artifact_gate": {"all_required_artifacts_present": all(artifacts.values()), "artifacts": artifacts},
        "label_response_audit": label_audit,
        "verified_completion": verified,
        "stdio": {
            "stdout_path": str(output_dir / "stdout.txt"),
            "stderr_path": str(output_dir / "stderr.txt"),
            "stdout_sha256": sha256_path(output_dir / "stdout.txt"),
            "stderr_sha256": sha256_path(output_dir / "stderr.txt"),
        },
    }
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if verified else 3


if __name__ == "__main__":
    raise SystemExit(main())
