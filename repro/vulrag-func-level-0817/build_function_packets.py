#!/usr/bin/env python3
"""Build function-level VulRAG packets from the HCVR new unified dataset.

This is an offline input construction tool. It may read dataset anchors to
recover the vulnerable function boundary, but the emitted runtime packet keeps
model-facing fields truth-free and function-level.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import importlib
import json
import os
import re
import shutil
import subprocess
import tarfile
from pathlib import Path
from typing import Any, Iterable


LANGUAGE_BY_SUFFIX = {
    ".cs": "csharp",
    ".go": "go",
    ".java": "java",
    ".js": "javascript",
    ".php": "php",
    ".py": "python",
    ".rb": "ruby",
    ".ts": "typescript",
    ".tsx": "tsx",
}
FUNCTION_NODE_TYPES = {
    "csharp": {
        "anonymous_method_expression",
        "constructor_declaration",
        "local_function_statement",
        "method_declaration",
        "parenthesized_lambda_expression",
        "simple_lambda_expression",
    },
    "go": {"func_literal", "function_declaration", "method_declaration"},
    "java": {"constructor_declaration", "lambda_expression", "method_declaration"},
    "javascript": {
        "arrow_function",
        "function_declaration",
        "function_expression",
        "generator_function",
        "generator_function_declaration",
        "method_definition",
    },
    "php": {
        "anonymous_function",
        "arrow_function",
        "function_definition",
        "method_declaration",
    },
    "python": {"function_definition", "lambda"},
    "ruby": {"lambda", "method", "singleton_method"},
    "tsx": {
        "arrow_function",
        "function_declaration",
        "function_expression",
        "generator_function",
        "generator_function_declaration",
        "method_definition",
    },
    "typescript": {
        "arrow_function",
        "function_declaration",
        "function_expression",
        "generator_function",
        "generator_function_declaration",
        "method_definition",
    },
}
LANGUAGE_BINDINGS = {
    "csharp": ("tree_sitter_c_sharp", "language"),
    "go": ("tree_sitter_go", "language"),
    "java": ("tree_sitter_java", "language"),
    "javascript": ("tree_sitter_javascript", "language"),
    "php": ("tree_sitter_php", "language_php"),
    "python": ("tree_sitter_python", "language"),
    "ruby": ("tree_sitter_ruby", "language"),
    "tsx": ("tree_sitter_typescript", "language_tsx"),
    "typescript": ("tree_sitter_typescript", "language_typescript"),
}


FORBIDDEN_RUNTIME_KEYS = {
    "anchor",
    "anchors",
    "cwe_id",
    "fix_revision",
    "ground_truth",
    "patch",
    "patched_code",
    "root_cause",
    "target_location",
    "vulnerability_id",
}


@dataclasses.dataclass(frozen=True)
class FunctionSpan:
    relative_path: str
    start_line: int
    end_line: int
    kind: str
    name: str
    code: str
    source_sha256: str


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"expected object at {path}:{line_number}")
            rows.append(value)
    return rows


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(cmd: list[str], cwd: Path | None = None, timeout_seconds: int | None = None) -> None:
    subprocess.run(cmd, cwd=cwd, check=True, timeout=timeout_seconds)


def ensure_checkout(
    repo_url: str,
    revision: str,
    repo_cache: Path,
    work_root: Path,
    case_id: str,
    source_timeout_seconds: int,
) -> Path:
    repo_cache.mkdir(parents=True, exist_ok=True)
    work_root.mkdir(parents=True, exist_ok=True)
    cache_key = sha256_bytes(repo_url.encode())[:16]
    bare = repo_cache / f"{cache_key}.git"
    if not bare.exists():
        run(["git", "init", "--quiet", "--bare", str(bare)], timeout_seconds=source_timeout_seconds)
        run(["git", "-C", str(bare), "remote", "add", "origin", repo_url], timeout_seconds=source_timeout_seconds)
    probe = subprocess.run(
        ["git", "-C", str(bare), "cat-file", "-e", f"{revision}^{{commit}}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if probe.returncode != 0:
        run(
            ["git", "-C", str(bare), "fetch", "--quiet", "--no-tags", "--depth=1", "origin", revision],
            timeout_seconds=source_timeout_seconds,
        )
    run(
        ["git", "-C", str(bare), "update-ref", "refs/heads/vulrag-source", revision],
        timeout_seconds=source_timeout_seconds,
    )

    repo = work_root / case_id / "repo"
    if repo.exists():
        head = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        if head.returncode == 0 and head.stdout.strip() == revision:
            return repo
        shutil.rmtree(repo)
    repo.parent.mkdir(parents=True, exist_ok=True)
    run(["git", "clone", "--quiet", "--no-checkout", str(bare), str(repo)], timeout_seconds=source_timeout_seconds)
    run(["git", "-C", str(repo), "checkout", "--quiet", "--detach", revision], timeout_seconds=source_timeout_seconds)
    run(["git", "-C", str(repo), "remote", "set-url", "origin", repo_url], timeout_seconds=source_timeout_seconds)
    return repo


def find_existing_repo(
    existing_input_root: Path | None,
    case_id: str,
    revision: str,
    existing_case_id: str | None = None,
) -> Path | None:
    if existing_input_root is None:
        return None
    repo = existing_input_root / (existing_case_id or case_id) / "repo"
    if not repo.exists():
        return None
    head = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if head.returncode == 0 and head.stdout.strip() == revision:
        return repo
    return None


def repo_url_from_key(repo_key: str) -> str:
    if "__" not in repo_key:
        raise ValueError(f"cannot derive GitHub URL from repo_key={repo_key!r}")
    owner, repo = repo_key.split("__", 1)
    return f"https://github.com/{owner}/{repo}.git"


def line_offsets(text: str) -> list[int]:
    offsets = [0]
    for match in re.finditer(r"\n", text):
        offsets.append(match.end())
    return offsets


def line_for_offset(offsets: list[int], offset: int) -> int:
    lo, hi = 0, len(offsets)
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if offsets[mid] <= offset:
            lo = mid
        else:
            hi = mid
    return lo + 1


def strip_comments_and_strings(text: str) -> str:
    result = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if ch == "/" and nxt == "/":
            while i < n and text[i] != "\n":
                result.append(" ")
                i += 1
            continue
        if ch == "/" and nxt == "*":
            result.extend("  ")
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                result.append("\n" if text[i] == "\n" else " ")
                i += 1
            if i + 1 < n:
                result.extend("  ")
                i += 2
            continue
        if ch in {"\"", "'"}:
            quote = ch
            result.append(" ")
            i += 1
            while i < n:
                result.append("\n" if text[i] == "\n" else " ")
                if text[i] == "\\":
                    i += 2
                    if i <= n:
                        result.append(" ")
                    continue
                if text[i] == quote:
                    i += 1
                    break
                i += 1
            continue
        result.append(ch)
        i += 1
    return "".join(result)


def find_matching_open(clean_text: str, open_offset: int) -> int | None:
    depth = 0
    for i in range(open_offset, len(clean_text)):
        if clean_text[i] == "{":
            depth += 1
        elif clean_text[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return None


def guess_signature_name(signature: str) -> tuple[str, str] | None:
    compact = " ".join(signature.strip().split())
    if not compact or compact.startswith(("if ", "for ", "while ", "switch ", "catch ", "try ", "else ")):
        return None
    if "=" in compact and not re.search(r"\bnew\s+\w+\s*\(", compact):
        return None
    match = re.search(r"([A-Za-z_$][\w$]*)\s*\([^;{}]*\)\s*(?:throws\s+[^{]+)?$", compact)
    if not match:
        return None
    name = match.group(1)
    kind = "constructor_declaration" if re.search(rf"\bclass\s+{re.escape(name)}\b", compact) else "method_declaration"
    return kind, name


def method_candidates(text: str) -> Iterable[FunctionSpan]:
    clean = strip_comments_and_strings(text)
    offsets = line_offsets(text)
    for open_match in re.finditer(r"\{", clean):
        open_offset = open_match.start()
        close_offset = find_matching_open(clean, open_offset)
        if close_offset is None:
            continue
        prefix_start = max(clean.rfind("\n", 0, open_offset), clean.rfind(";", 0, open_offset), clean.rfind("}", 0, open_offset)) + 1
        signature = clean[prefix_start:open_offset]
        guessed = guess_signature_name(signature)
        if guessed is None:
            continue
        kind, name = guessed
        start_line = line_for_offset(offsets, prefix_start)
        end_line = line_for_offset(offsets, close_offset)
        lines = text.splitlines()
        code = "\n".join(lines[start_line - 1 : end_line])
        yield FunctionSpan(
            relative_path="",
            start_line=start_line,
            end_line=end_line,
            kind=kind,
            name=name,
            code=code,
            source_sha256=sha256_bytes(code.encode()),
        )


def get_offline_parser(language: str) -> Any:
    from tree_sitter import Language, Parser

    module_name, binding_name = LANGUAGE_BINDINGS[language]
    module = importlib.import_module(module_name)
    grammar = Language(getattr(module, binding_name)())
    try:
        return Parser(grammar)
    except TypeError:
        parser = Parser()
        parser.language = grammar
        return parser


def resolve_function(repo: Path, relative_path: str, start_line: int, end_line: int) -> FunctionSpan | None:
    source_path = repo / relative_path
    language = LANGUAGE_BY_SUFFIX.get(source_path.suffix.lower())
    if not source_path.exists() or language is None:
        return None
    text = source_path.read_text(encoding="utf-8", errors="replace")
    try:
        parser = get_offline_parser(language)
        source = text.encode("utf-8")
        tree = parser.parse(source)
        candidates: list[FunctionSpan] = []
        stack = [tree.root_node]
        while stack:
            node = stack.pop()
            stack.extend(reversed(node.children))
            if node.type not in FUNCTION_NODE_TYPES[language]:
                continue
            node_start_line = node.start_point.row + 1
            node_end_line = node.end_point.row + 1
            if node_end_line < start_line or node_start_line > end_line:
                continue
            name_node = node.child_by_field_name("name")
            name = (
                source[name_node.start_byte : name_node.end_byte].decode("utf-8", errors="replace")
                if name_node is not None
                else f"<{node.type}>"
            )
            code = source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")
            candidates.append(
                FunctionSpan(
                    relative_path=relative_path,
                    start_line=node_start_line,
                    end_line=node_end_line,
                    kind=node.type,
                    name=name,
                    code=code,
                    source_sha256=sha256_bytes(code.encode()),
                )
            )
        if candidates:
            anchor_midpoint = (start_line + end_line) / 2
            return min(
                candidates,
                key=lambda item: (
                    -(
                        min(item.end_line, end_line)
                        - max(item.start_line, start_line)
                        + 1
                    ),
                    abs(((item.start_line + item.end_line) / 2) - anchor_midpoint),
                    item.end_line - item.start_line,
                ),
            )
    except (ImportError, RuntimeError, TypeError, ValueError):
        if language != "java":
            return None

    best: FunctionSpan | None = None
    for candidate in method_candidates(text):
        if candidate.end_line < start_line or candidate.start_line > end_line:
            continue
        if best is None:
            best = candidate
            continue
        candidate_overlap = min(candidate.end_line, end_line) - max(candidate.start_line, start_line) + 1
        best_overlap = min(best.end_line, end_line) - max(best.start_line, start_line) + 1
        if (candidate_overlap, -(candidate.end_line - candidate.start_line)) > (
            best_overlap,
            -(best.end_line - best.start_line),
        ):
            best = candidate
    if best is None:
        return None
    return dataclasses.replace(best, relative_path=relative_path)


def build_case_index(cases_path: Path) -> dict[str, dict[str, Any]]:
    index = {}
    for row in read_jsonl(cases_path):
        identity = row.get("identity_key")
        if identity:
            index[identity] = row
    return index


def build_existing_case_index(queue_path: Path | None) -> dict[str, str]:
    if queue_path is None:
        return {}
    return {
        row["identity_key"]: row["case_id"]
        for row in read_jsonl(queue_path)
        if row.get("identity_key") and row.get("case_id")
    }


def build_archive_index(archive_index_path: Path | None) -> dict[str, Path]:
    if archive_index_path is None:
        return {}
    return {
        row["identity_key"]: Path(row["source_path"])
        for row in read_jsonl(archive_index_path)
        if row.get("identity_key") and row.get("source_path")
    }


def extract_archive(
    archive: Path,
    work_root: Path,
    case_id: str,
    relative_paths: set[str],
) -> Path | None:
    if not archive.is_file():
        return None
    destination = work_root / case_id / "archive"
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive) as handle:
        pending = set(relative_paths)
        for member in handle:
            if not member.isfile():
                continue
            relative_path = next(
                (
                    candidate
                    for candidate in pending
                    if member.name == candidate
                    or member.name.endswith(f"/{candidate}")
                ),
                None,
            )
            if relative_path is None:
                continue
            source = handle.extractfile(member)
            if source is None:
                continue
            target = destination / relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read())
            pending.remove(relative_path)
            if not pending:
                break
    return destination if any(path.is_file() for path in destination.rglob("*")) else None


def find_verified_tree(
    verified_tree_root: Path | None,
    repo_key: str,
    vulnerability_id: str,
) -> Path | None:
    if verified_tree_root is None or not verified_tree_root.is_dir():
        return None
    prefix = f"{repo_key}_{vulnerability_id}_"
    matches = sorted(
        path for path in verified_tree_root.iterdir() if path.is_dir() and path.name.startswith(prefix)
    )
    return matches[0] if matches else None


def make_runtime_packet(row: dict[str, Any], function: FunctionSpan) -> dict[str, Any]:
    packet = {
        "case_id": row["case_id"],
        "created_by": "repro/vulrag-func-level-0817/build_function_packets.py",
        "function": dataclasses.asdict(function),
        "input_scope": "function_conditioned_multilanguage_adaptation",
        "project_group": row["repo_key"].split("__", 1)[-1],
        "project_slug": f'{row["repo_key"]}_{row["vulnerability_id"]}',
        "schema_version": "vulrag_func_level_0817.runtime_packet.v1",
        "source_revision": row["checkout_revision"],
    }
    for key in packet:
        if key in FORBIDDEN_RUNTIME_KEYS:
            raise ValueError(f"forbidden runtime key leaked: {key}")
    return packet


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allowlist", required=True, type=Path)
    parser.add_argument("--cases", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument(
        "--unresolved-out",
        type=Path,
        default=None,
        help="Per-case unresolved ledger (default: <out>.unresolved.jsonl).",
    )
    parser.add_argument("--run-root", required=True, type=Path)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--max-functions-per-case", type=int, default=1)
    parser.add_argument("--source-timeout-seconds", type=int, default=300)
    parser.add_argument(
        "--existing-input-root",
        type=Path,
        default=None,
        help="Optional existing batch inputs root containing case_XXX/repo checkouts.",
    )
    parser.add_argument(
        "--existing-queue",
        type=Path,
        default=None,
        help="Queue that maps identity_key to case_id under --existing-input-root.",
    )
    parser.add_argument(
        "--archive-index",
        type=Path,
        default=None,
        help="JSONL mapping identity_key to an existing source archive.",
    )
    parser.add_argument(
        "--verified-tree-root",
        type=Path,
        default=None,
        help="Fallback root containing extracted repo_vulnerability_version trees.",
    )
    args = parser.parse_args()
    unresolved_out = args.unresolved_out or args.out.with_name(
        f"{args.out.stem}.unresolved.jsonl"
    )

    case_index = build_case_index(args.cases)
    existing_case_index = build_existing_case_index(args.existing_queue)
    archive_index = build_archive_index(args.archive_index)
    rows = read_jsonl(args.allowlist)
    if args.limit is not None:
        rows = rows[: args.limit]

    repo_cache = args.run_root / "repo-cache"
    work_root = args.run_root / "work"
    args.out.parent.mkdir(parents=True, exist_ok=True)

    emitted = 0
    unresolved = 0
    unresolved_rows: list[dict[str, Any]] = []
    with args.out.open("w", encoding="utf-8") as handle:
        for rank, row in enumerate(rows, start=1):
            identity = row["identity_key"]
            case = case_index.get(identity)
            if not case:
                unresolved += 1
                unresolved_rows.append(
                    {
                        "case_id": f"case_{rank:03d}",
                        "identity_key": identity,
                        "reason": "case_missing_from_dataset_index",
                    }
                )
                continue
            repo_key = row["repo_key"]
            repo_url = row.get("repo_url") or repo_url_from_key(repo_key)
            case_id = f"case_{rank:03d}"
            print(f"prepare {case_id} {repo_key} {row['checkout_revision'][:12]}", flush=True)
            runtime_row = {
                "case_id": case_id,
                "repo_key": repo_key,
                "vulnerability_id": row["vulnerability_id"],
                "checkout_revision": row["checkout_revision"],
            }
            repo = find_existing_repo(
                args.existing_input_root,
                case_id,
                row["checkout_revision"],
                existing_case_index.get(identity),
            )
            if repo is None:
                repo = extract_archive(
                    archive_index.get(identity, Path()),
                    work_root,
                    case_id,
                    {
                        str(anchor.get("file"))
                        for anchor in case.get("recall_anchors") or []
                        if Path(str(anchor.get("file") or "")).suffix.lower()
                        in LANGUAGE_BY_SUFFIX
                    },
                )
                if repo is not None:
                    print(f"reuse_source_archive {case_id} {repo}", flush=True)
            if repo is None:
                repo = find_verified_tree(
                    args.verified_tree_root,
                    repo_key,
                    row["vulnerability_id"],
                )
                if repo is not None:
                    print(f"reuse_verified_tree {case_id} {repo}", flush=True)
            if repo is None:
                try:
                    repo = ensure_checkout(
                        repo_url,
                        row["checkout_revision"],
                        repo_cache,
                        work_root,
                        case_id,
                        args.source_timeout_seconds,
                    )
                except subprocess.TimeoutExpired:
                    print(f"source_timeout {case_id} {repo_url}", flush=True)
                    unresolved += 1
                    unresolved_rows.append(
                        {
                            "case_id": case_id,
                            "identity_key": identity,
                            "reason": "source_timeout",
                        }
                    )
                    continue
                except subprocess.CalledProcessError as exc:
                    print(f"source_failed {case_id} {repo_url} exit={exc.returncode}", flush=True)
                    unresolved += 1
                    unresolved_rows.append(
                        {
                            "case_id": case_id,
                            "identity_key": identity,
                            "reason": "source_checkout_failed",
                        }
                    )
                    continue
            else:
                print(f"reuse_existing_repo {case_id} {repo}", flush=True)
            seen_functions: set[tuple[str, int, int]] = set()
            selected = 0
            for anchor in case.get("recall_anchors") or []:
                relative_path = str(anchor.get("file") or "")
                start_line = int(anchor.get("start_line") or 0)
                end_line = int(anchor.get("end_line") or start_line)
                if Path(relative_path).suffix.lower() not in LANGUAGE_BY_SUFFIX or start_line <= 0:
                    continue
                function = resolve_function(repo, relative_path, start_line, end_line)
                if function is None:
                    continue
                key = (function.relative_path, function.start_line, function.end_line)
                if key in seen_functions:
                    continue
                seen_functions.add(key)
                packet = make_runtime_packet(runtime_row, function)
                output = {
                    "identity_key": identity,
                    "private_provenance": {
                        "anchor_id": anchor.get("anchor_id"),
                        "anchor_file": relative_path,
                        "anchor_start_line": start_line,
                        "anchor_end_line": end_line,
                        "anchor_span_kind": anchor.get("span_kind"),
                    },
                    "runtime_packet": packet,
                }
                handle.write(json.dumps(output, ensure_ascii=False, sort_keys=True) + "\n")
                emitted += 1
                selected += 1
                if selected >= args.max_functions_per_case:
                    break
            if selected == 0:
                unresolved += 1
                unresolved_rows.append(
                    {
                        "case_id": case_id,
                        "identity_key": identity,
                        "reason": "no_containing_function_resolved",
                        "supported_anchor_count": sum(
                            1
                            for anchor in case.get("recall_anchors") or []
                            if Path(str(anchor.get("file") or "")).suffix.lower()
                            in LANGUAGE_BY_SUFFIX
                        ),
                    }
                )

    unresolved_out.parent.mkdir(parents=True, exist_ok=True)
    with unresolved_out.open("w", encoding="utf-8") as handle:
        for row in unresolved_rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    print(
        json.dumps(
            {
                "emitted": emitted,
                "out": str(args.out),
                "unresolved_cases": unresolved,
                "unresolved_out": str(unresolved_out),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
