#!/usr/bin/env python3
"""Build Dataset A for repo-level no-trace TOCTOU retrieval.

Dataset A is deliberately source-centric: it creates generic code views from
the whole repository and labels positives by case anchors. It does not inject
TOCTOU-specific feature signatures into candidate text.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


JAVA_SUFFIXES = {".java"}
C_CPP_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}
SCRIPT_SUFFIXES = {".go", ".js", ".jsx", ".php", ".py", ".ts", ".tsx"}
GENERIC_TEXT_SUFFIXES = {
    ".in",
    ".init",
    ".sh",
    ".bash",
    ".pl",
    ".rb",
    ".txt",
    ".result",
    ".conf",
    ".cfg",
}
SOURCE_SUFFIXES = JAVA_SUFFIXES | C_CPP_SUFFIXES
WINDOW_SUFFIXES = SOURCE_SUFFIXES | SCRIPT_SUFFIXES | GENERIC_TEXT_SUFFIXES
DEFAULT_EXCLUDE_DIRS = {
    ".git",
    ".gradle",
    ".idea",
    ".mvn",
    "build",
    "target",
    "out",
    "node_modules",
    "vendor",
}

JAVA_KEYWORDS = {
    "abstract",
    "assert",
    "boolean",
    "break",
    "byte",
    "case",
    "catch",
    "char",
    "class",
    "const",
    "continue",
    "default",
    "do",
    "double",
    "else",
    "enum",
    "extends",
    "final",
    "finally",
    "float",
    "for",
    "goto",
    "if",
    "implements",
    "import",
    "instanceof",
    "int",
    "interface",
    "long",
    "native",
    "new",
    "null",
    "package",
    "private",
    "protected",
    "public",
    "return",
    "short",
    "static",
    "strictfp",
    "super",
    "switch",
    "synchronized",
    "this",
    "throw",
    "throws",
    "transient",
    "true",
    "try",
    "void",
    "volatile",
    "while",
}
C_CPP_KEYWORDS = {
    "alignas",
    "alignof",
    "and",
    "asm",
    "auto",
    "bitand",
    "bitor",
    "bool",
    "break",
    "case",
    "catch",
    "char",
    "class",
    "const",
    "constexpr",
    "continue",
    "decltype",
    "default",
    "delete",
    "do",
    "double",
    "else",
    "enum",
    "explicit",
    "extern",
    "false",
    "float",
    "for",
    "friend",
    "goto",
    "if",
    "inline",
    "int",
    "long",
    "mutable",
    "namespace",
    "new",
    "noexcept",
    "not",
    "nullptr",
    "operator",
    "or",
    "override",
    "private",
    "protected",
    "public",
    "register",
    "return",
    "short",
    "signed",
    "sizeof",
    "static",
    "struct",
    "switch",
    "template",
    "this",
    "throw",
    "true",
    "try",
    "typedef",
    "typename",
    "union",
    "unsigned",
    "using",
    "virtual",
    "void",
    "volatile",
    "while",
    "xor",
}
SYMBOL_KEEP_WORDS = JAVA_KEYWORDS | C_CPP_KEYWORDS

IDENT_RE = re.compile(r"\b[A-Za-z_$][A-Za-z0-9_$]*\b")
PATH_TOKEN_RE = re.compile(r"\b(?:[A-Za-z0-9_.+-]+/)+[A-Za-z0-9_.+-]+\b")
URL_TOKEN_RE = re.compile(r"https?://\S+")
CVE_CWE_TOKEN_RE = re.compile(r"\b(?:CVE|CWE)-\d+(?:-\d+)?\b", re.IGNORECASE)
STRING_LITERAL_RE = re.compile(
    r"(?P<prefix>\b[rRuUbBfF]*)"
    r"(?P<string>\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*')"
)
COMMENT_RE = re.compile(r"//.*?$|/\*.*?\*/", re.MULTILINE | re.DOTALL)
METHOD_NAME_RE = re.compile(
    r"\b(?P<name>[A-Za-z_$][\w$]*)\s*\([^;{}]*\)\s*(?:throws\s+[^{;]+)?\{"
)
C_CPP_DECL_NAME_RE = re.compile(
    r"(?P<name>~?[A-Za-z_][A-Za-z0-9_]*|operator\s*[^\s(]+)\s*"
    r"\([^;{}]*\)\s*"
    r"(?:(?:const|volatile|override|final)\s*)?"
    r"(?:noexcept(?:\s*\([^)]*\))?\s*)?"
    r"(?:->\s*[A-Za-z_][A-Za-z0-9_:<>,\s*&\[\]]*)?$"
)


@dataclass
class Anchor:
    file: str = ""
    function: str = ""
    start_line: int = 0
    end_line: int = 0
    anchor_source: str = ""


@dataclass
class Case:
    case_id: str
    cve_id: str
    repo_key: str
    evidence_level: str
    subtype: str
    query_text: str
    repo_path: str = ""
    anchors: list[Anchor] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class CodeView:
    view_type: str
    rel_file: str
    symbol: str
    start_line: int
    end_line: int
    text: str


def source_advisory_id(case: Case) -> str:
    """Return the public advisory identity without inventing a CVE."""

    raw = case.raw or {}
    return str(raw.get("source_advisory_id") or case.cve_id or raw.get("ghsa_id") or "")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def norm_path(path: str) -> str:
    return (path or "").replace("\\", "/").lstrip("./").lstrip("/")


def method_leaf(name: str) -> str:
    text = (name or "").strip()
    text = text.split("(", 1)[0]
    text = text.split("#")[-1]
    text = text.split("::")[-1]
    return text.split(".")[-1]


def line_number_at(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def find_matching_brace(text: str, open_idx: int) -> int:
    depth = 0
    i = open_idx
    in_string = ""
    escaped = False
    in_line_comment = False
    in_block_comment = False
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
            i += 1
            continue
        if in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                i += 2
            else:
                i += 1
            continue
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == in_string:
                in_string = ""
            i += 1
            continue
        if ch == "/" and nxt == "/":
            in_line_comment = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            in_block_comment = True
            i += 2
            continue
        if ch in {"'", '"'}:
            in_string = ch
            i += 1
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return len(text) - 1


def strip_comments_for_signature(text: str) -> str:
    return COMMENT_RE.sub(lambda m: " " * (m.end() - m.start()), text)


def extract_java_methods(text: str) -> list[CodeView]:
    searchable = strip_comments_for_signature(text)
    views: list[CodeView] = []
    seen_ranges: set[tuple[int, int]] = set()

    lines = searchable.splitlines(keepends=True)
    offsets: list[int] = []
    pos = 0
    for line in lines:
        offsets.append(pos)
        pos += len(line)

    for line_idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or "(" not in stripped:
            continue
        # Java signatures often span a few lines; cap the join to avoid
        # regex backtracking over whole files during repository-scale scans.
        signature = ""
        open_idx = -1
        match: re.Match[str] | None = None
        for extra in range(0, min(6, len(lines) - line_idx)):
            signature += lines[line_idx + extra].strip() + " "
            if "{" not in signature:
                continue
            match = METHOD_NAME_RE.search(signature)
            if match is None:
                break
            if match.group("name") in JAVA_KEYWORDS:
                break
            prefix = signature[: match.start("name")]
            if not any(mod in prefix.split() for mod in ("public", "protected", "private", "static", "final", "synchronized", "abstract", "default")):
                break
            open_line_idx = line_idx + extra
            open_col = lines[open_line_idx].find("{")
            if open_col < 0:
                break
            open_idx = offsets[open_line_idx] + open_col
            break
        if match is None or open_idx < 0:
            continue
        end_idx = find_matching_brace(searchable, open_idx)
        start_line = line_idx + 1
        end_line = line_number_at(searchable, end_idx)
        if end_line < start_line:
            continue
        key = (start_line, end_line)
        if key in seen_ranges:
            continue
        seen_ranges.add(key)
        snippet = text[offsets[line_idx] : end_idx + 1]
        views.append(
            CodeView(
                view_type="function",
                rel_file="",
                symbol=match.group("name"),
                start_line=start_line,
                end_line=end_line,
                text=snippet.strip(),
            )
        )
    return views


def parse_c_cpp_function_name(signature_before_brace: str) -> str | None:
    signature = " ".join(signature_before_brace.strip().split())
    if not signature or ";" in signature:
        return None
    match = C_CPP_DECL_NAME_RE.search(signature)
    if match is None:
        return None
    name = match.group("name").replace(" ", "")
    if name.lstrip("~") in C_CPP_KEYWORDS:
        return None
    prefix = signature[: match.start("name")].strip()
    if not prefix:
        return None
    prefix_tail = prefix.split()[-1].strip("*&:") if prefix.split() else ""
    if prefix_tail in {"if", "for", "while", "switch", "catch", "return"}:
        return None
    return name


def extract_c_cpp_functions(text: str) -> list[CodeView]:
    searchable = strip_comments_for_signature(text)
    views: list[CodeView] = []
    seen_ranges: set[tuple[int, int]] = set()

    lines = searchable.splitlines(keepends=True)
    offsets: list[int] = []
    pos = 0
    for line in lines:
        offsets.append(pos)
        pos += len(line)

    for line_idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "(" not in stripped:
            continue
        signature = ""
        open_idx = -1
        symbol = ""
        for extra in range(0, min(8, len(lines) - line_idx)):
            part = lines[line_idx + extra].strip()
            if not part:
                continue
            signature = f"{signature} {part}".strip()
            if "{" not in signature:
                continue
            before_brace = signature.split("{", 1)[0]
            if ";" in before_brace:
                break
            symbol = parse_c_cpp_function_name(before_brace) or ""
            if not symbol:
                break
            open_line_idx = line_idx + extra
            open_col = lines[open_line_idx].find("{")
            if open_col < 0:
                break
            open_idx = offsets[open_line_idx] + open_col
            break
        if not symbol or open_idx < 0:
            continue
        end_idx = find_matching_brace(searchable, open_idx)
        start_line = line_idx + 1
        end_line = line_number_at(searchable, end_idx)
        if end_line < start_line:
            continue
        key = (start_line, end_line)
        if key in seen_ranges:
            continue
        seen_ranges.add(key)
        snippet = text[offsets[line_idx] : end_idx + 1]
        views.append(
            CodeView(
                view_type="function",
                rel_file="",
                symbol=symbol,
                start_line=start_line,
                end_line=end_line,
                text=snippet.strip(),
            )
        )
    return views


def extract_functions_for_path(path: Path, text: str) -> list[CodeView]:
    if path.suffix in JAVA_SUFFIXES:
        return extract_java_methods(text)
    if path.suffix in C_CPP_SUFFIXES:
        return extract_c_cpp_functions(text)
    return []


def sliding_windows(
    text: str,
    *,
    window_lines: int,
    stride_lines: int,
) -> list[CodeView]:
    lines = text.splitlines()
    if not lines:
        return []
    if len(lines) <= window_lines:
        return [
            CodeView(
                view_type="window",
                rel_file="",
                symbol="",
                start_line=1,
                end_line=len(lines),
                text="\n".join(lines).strip(),
            )
        ]
    views: list[CodeView] = []
    start = 0
    while start < len(lines):
        end = min(start + window_lines, len(lines))
        snippet = "\n".join(lines[start:end]).strip()
        if snippet:
            views.append(
                CodeView(
                    view_type="window",
                    rel_file="",
                    symbol="",
                    start_line=start + 1,
                    end_line=end,
                    text=snippet,
                )
            )
        if end == len(lines):
            break
        start += max(1, stride_lines)
    return views


def mask_symbols(text: str) -> str:
    def replace(match: re.Match[str]) -> str:
        token = match.group(0)
        if token in SYMBOL_KEEP_WORDS:
            return token
        return "ID"

    return IDENT_RE.sub(replace, text)


def _previous_nonspace(text: str, idx: int) -> str:
    pos = idx - 1
    while pos >= 0 and text[pos].isspace():
        pos -= 1
    return text[pos] if pos >= 0 else ""


def _next_nonspace(text: str, idx: int) -> str:
    pos = idx
    while pos < len(text) and text[pos].isspace():
        pos += 1
    return text[pos] if pos < len(text) else ""


def _previous_identifier(text: str, idx: int) -> str:
    prefix = text[:idx]
    matches = list(IDENT_RE.finditer(prefix))
    return matches[-1].group(0) if matches else ""


def _line_prefix(text: str, idx: int) -> str:
    line_start = text.rfind("\n", 0, idx) + 1
    return text[line_start:idx].strip()


def _looks_like_command_position(text: str, start: int, end: int) -> bool:
    prefix = _line_prefix(text, start)
    if prefix:
        return False
    next_char = _next_nonspace(text, end)
    if next_char in {"", "=", ":", ".", "("}:
        return False
    return True


def _looks_like_declaration_name(text: str, start: int) -> bool:
    prefix = _line_prefix(text, start)
    previous = _previous_identifier(text, start)
    if previous in {"def", "function", "class", "interface", "struct", "enum"}:
        return True
    if not prefix:
        return False
    if any(op in prefix for op in ("=", "(", "[", ".", "->", "return", "if", "while", "for")):
        return False
    tokens = IDENT_RE.findall(prefix.replace("*", " ").replace("&", " "))
    return bool(tokens)


def mask_api_shape(text: str) -> str:
    """Mask local symbols while preserving generic operation/API shape.

    This view is meant for embedding ablations where fully replacing every
    identifier destroys script/text-window semantics such as `os.path.islink`.
    It still masks paths, string literals, and most local variables.
    """

    masked = URL_TOKEN_RE.sub("URL", text)
    masked = PATH_TOKEN_RE.sub("PATH", masked)
    masked = STRING_LITERAL_RE.sub("STR", masked)

    def replace(match: re.Match[str]) -> str:
        token = match.group(0)
        if token in SYMBOL_KEEP_WORDS:
            return token
        start, end = match.span()
        prev_char = _previous_nonspace(masked, start)
        next_char = _next_nonspace(masked, end)
        is_member = prev_char == "." or next_char == "."
        is_call = next_char == "(" and not _looks_like_declaration_name(masked, start)
        is_command = _looks_like_command_position(masked, start, end)
        if is_member or is_call or is_command:
            return token
        return "ID"

    return IDENT_RE.sub(replace, masked)


def looks_like_query_symbol(token: str) -> bool:
    return (
        "_" in token
        or "$" in token
        or "::" in token
        or any(ch.isdigit() for ch in token)
        or any(token[i].islower() and token[i + 1].isupper() for i in range(len(token) - 1))
    )


def mask_query_symbols(text: str) -> str:
    masked = URL_TOKEN_RE.sub("URL", text)
    masked = CVE_CWE_TOKEN_RE.sub("ID", masked)
    masked = PATH_TOKEN_RE.sub("PATH", masked)

    def replace(match: re.Match[str]) -> str:
        token = match.group(0)
        if looks_like_query_symbol(token):
            return "ID"
        return token

    return IDENT_RE.sub(replace, masked)


def iter_source_files(repo_path: Path, *, max_file_bytes: int) -> Iterable[Path]:
    for path in sorted(repo_path.rglob("*")):
        if not path.is_file():
            continue
        rel_parts = set(path.relative_to(repo_path).parts[:-1])
        if rel_parts & DEFAULT_EXCLUDE_DIRS:
            continue
        if path.suffix not in WINDOW_SUFFIXES:
            continue
        try:
            if path.stat().st_size > max_file_bytes:
                continue
        except OSError:
            continue
        yield path


def prioritized_source_files(
    repo_path: Path,
    *,
    max_file_bytes: int,
    cases: list[Case],
) -> list[Path]:
    paths = list(iter_source_files(repo_path, max_file_bytes=max_file_bytes))
    anchor_files = [
        norm_path(anchor.file)
        for case in cases
        for anchor in case.anchors
        if anchor.file
    ]
    if not anchor_files:
        return paths

    def priority(path: Path) -> tuple[int, str]:
        rel = norm_path(str(path.relative_to(repo_path)))
        is_anchor = any(anchor_file_matches(rel, anchor_file) for anchor_file in anchor_files)
        return (0 if is_anchor else 1, rel)

    return sorted(paths, key=priority)


def find_repo(repo_key: str, repo_roots: list[Path]) -> Path | None:
    for root in repo_roots:
        candidate = root / repo_key
        if candidate.is_dir():
            return candidate
    return None


def build_query_text(row: dict[str, Any]) -> str:
    q = row.get("query_fields") or {}
    parts = [
        f"CVE={row.get('cve_id') or ''}",
        f"CWE={','.join(row.get('cwe') or [])}",
        f"SUBTYPE={row.get('subtype') or ''}",
        f"DESCRIPTION={q.get('description') or ''}",
        f"ROOT_CAUSE={q.get('root_cause') or ''}",
        f"ABSTRACT_PATTERN={q.get('abstract_pattern') or ''}",
        f"DATA_FLOW={q.get('data_flow') or ''}",
        f"FIX_SUMMARY={q.get('fix_summary') or ''}",
    ]
    return "\n".join(part for part in parts if part.split("=", 1)[-1])


def load_cases(path: Path, *, limit_cases: int = 0) -> list[Case]:
    cases: list[Case] = []
    for row in read_jsonl(path):
        anchors = [
            Anchor(
                file=norm_path(anchor.get("file") or ""),
                function=str(anchor.get("function") or ""),
                start_line=int(anchor.get("start_line") or 0),
                end_line=int(anchor.get("end_line") or 0),
                anchor_source=str(anchor.get("anchor_source") or ""),
            )
            for anchor in row.get("positive_anchors") or []
            if anchor.get("file") or anchor.get("function")
        ]
        cases.append(
            Case(
                case_id=str(row.get("case_id") or ""),
                cve_id=str(row.get("cve_id") or ""),
                repo_key=str(row.get("repo_key") or ""),
                evidence_level=str(row.get("evidence_level") or ""),
                subtype=str(row.get("subtype") or ""),
                query_text=build_query_text(row),
                repo_path=str(row.get("repo_path") or ""),
                anchors=anchors,
                raw=row,
            )
        )
        if limit_cases and len(cases) >= limit_cases:
            break
    return cases


def anchor_file_matches(rel_file: str, anchor_file: str) -> bool:
    rel = norm_path(rel_file)
    anchor = norm_path(anchor_file)
    return bool(rel and anchor and (rel.endswith(anchor) or anchor.endswith(rel)))


def line_ranges_overlap(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    if a_start <= 0 or b_start <= 0:
        return True
    if a_end <= 0:
        a_end = a_start
    if b_end <= 0:
        b_end = b_start
    return max(a_start, b_start) <= min(a_end, b_end)


def positive_cases_for_view(
    view: CodeView,
    cases: list[Case],
) -> list[tuple[Case, Anchor]]:
    positives: list[tuple[Case, Anchor]] = []
    for case in cases:
        for anchor in case.anchors:
            if anchor.file and not anchor_file_matches(view.rel_file, anchor.file):
                continue
            if (
                view.view_type == "function"
                and anchor.function
                and method_leaf(anchor.function) != method_leaf(view.symbol)
            ):
                continue
            if not line_ranges_overlap(
                view.start_line,
                view.end_line,
                anchor.start_line,
                anchor.end_line,
            ):
                continue
            positives.append((case, anchor))
            break
    return positives


def candidate_text(repo_key: str, view: CodeView) -> str:
    header = [
        f"REPO={repo_key}",
        f"VIEW={view.view_type}",
        f"FILE={view.rel_file}",
        f"SYMBOL={view.symbol}",
        f"LINES={view.start_line}-{view.end_line}",
        "[SOURCE]",
    ]
    return "\n".join(header + [view.text])


def stable_id(*parts: str) -> str:
    digest = hashlib.sha1("::".join(parts).encode("utf-8")).hexdigest()[:12]
    return digest


def build_dataset(
    *,
    cases: list[Case],
    repo_roots: list[Path],
    output_dir: Path,
    max_file_bytes: int,
    window_lines: int,
    stride_lines: int,
    max_repos: int = 0,
    max_files_per_repo: int = 0,
    verbose: bool = False,
) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    cases_by_repo: dict[tuple[str, str], list[Case]] = defaultdict(list)
    for case in cases:
        if case.repo_key:
            cases_by_repo[(case.repo_key, case.repo_path)].append(case)

    candidate_output_path = output_dir / "dataset_a_candidates.jsonl"
    candidate_file = candidate_output_path.open("w", encoding="utf-8")
    candidate_count = 0
    positive_candidate_count = 0
    by_view: Counter[str] = Counter()
    coverage_rows: list[dict[str, Any]] = []
    query_rows: list[dict[str, Any]] = []
    repos_seen = 0

    for repo_key, case_repo_path in sorted(cases_by_repo):
        if max_repos and repos_seen >= max_repos:
            break
        repo_cases = cases_by_repo[(repo_key, case_repo_path)]
        repo_path = Path(case_repo_path) if case_repo_path else None
        if repo_path is not None and not repo_path.is_absolute():
            repo_path = Path.cwd() / repo_path
        if repo_path is None or not repo_path.is_dir():
            repo_path = find_repo(repo_key, repo_roots)
        if repo_path is None:
            for case in repo_cases:
                coverage_rows.append(
                    {
                        "case_id": case.case_id,
                        "cve_id": case.cve_id,
                        "repo_key": repo_key,
                        "repo_present": False,
                        "candidate_count": 0,
                        "positive_candidate_count": 0,
                        "positive_view_types": {},
                        "covered": False,
                    }
                )
            continue
        repos_seen += 1

        repo_candidate_count = 0
        repo_file_count = 0
        positives_by_case: dict[str, list[str]] = defaultdict(list)
        positive_view_types: dict[str, Counter[str]] = defaultdict(Counter)
        for source_path in prioritized_source_files(
            repo_path,
            max_file_bytes=max_file_bytes,
            cases=repo_cases,
        ):
            if max_files_per_repo and repo_file_count >= max_files_per_repo:
                break
            repo_file_count += 1
            rel_file = norm_path(str(source_path.relative_to(repo_path)))
            try:
                text = source_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            views = extract_functions_for_path(source_path, text)
            views.extend(
                sliding_windows(
                    text,
                    window_lines=window_lines,
                    stride_lines=stride_lines,
                )
            )
            for idx, view in enumerate(views):
                if not view.text:
                    continue
                view.rel_file = rel_file
                positives = positive_cases_for_view(view, repo_cases)
                candidate_id = "dataset-a::{}::{}::{}::{}".format(
                    repo_key,
                    view.view_type,
                    stable_id(rel_file, view.view_type, str(view.start_line), view.symbol),
                    idx,
                )
                pos_case_ids = [case.case_id for case, _ in positives]
                pos_cve_ids = [case.cve_id for case, _ in positives]
                pos_source_advisory_ids = [source_advisory_id(case) for case, _ in positives]
                for case, _ in positives:
                    positives_by_case[case.case_id].append(candidate_id)
                    positive_view_types[case.case_id][view.view_type] += 1
                raw_text = candidate_text(repo_key, view)
                candidate_row = {
                    "candidate_id": candidate_id,
                    "repo_key": repo_key,
                    "repo_path": str(repo_path),
                    "view_type": view.view_type,
                    "file": rel_file,
                    "symbol": view.symbol,
                    "start_line": view.start_line,
                    "end_line": view.end_line,
                    "text": raw_text,
                    "text_symbol_masked": mask_symbols(raw_text),
                    "text_api_shape_masked": mask_api_shape(raw_text),
                    "is_positive": bool(positives),
                    "positive_case_ids": pos_case_ids,
                    "positive_cve_ids": pos_cve_ids,
                    "positive_source_advisory_ids": pos_source_advisory_ids,
                }
                candidate_file.write(json.dumps(candidate_row, ensure_ascii=False) + "\n")
                by_view[view.view_type] += 1
                candidate_count += 1
                if positives:
                    positive_candidate_count += 1
                repo_candidate_count += 1

        if verbose:
            print(
                json.dumps(
                    {
                        "repo_key": repo_key,
                        "files": repo_file_count,
                        "candidates": repo_candidate_count,
                        "cases": len(repo_cases),
                        "covered_cases": sum(1 for case in repo_cases if positives_by_case.get(case.case_id)),
                    },
                    ensure_ascii=False,
                ),
                flush=True,
            )

        for case in repo_cases:
            ids = positives_by_case.get(case.case_id, [])
            coverage_rows.append(
                {
                    "case_id": case.case_id,
                    "cve_id": case.cve_id,
                    "ghsa_id": str((case.raw or {}).get("ghsa_id") or ""),
                    "source_advisory_id": source_advisory_id(case),
                    "repo_key": repo_key,
                    "repo_present": True,
                    "candidate_count": repo_candidate_count,
                    "positive_candidate_count": len(ids),
                    "positive_view_types": dict(positive_view_types.get(case.case_id, Counter())),
                    "covered": bool(ids),
                }
            )

    for case in cases:
        query_rows.append(
            {
                "query_id": f"query::{case.case_id}",
                "case_id": case.case_id,
                "cve_id": case.cve_id,
                "ghsa_id": str((case.raw or {}).get("ghsa_id") or ""),
                "source_advisory_id": source_advisory_id(case),
                "repo_key": case.repo_key,
                "evidence_level": case.evidence_level,
                "subtype": case.subtype,
                "text": case.query_text,
                "text_symbol_masked": mask_query_symbols(case.query_text),
                "text_api_shape_masked": mask_query_symbols(case.query_text),
            }
        )

    candidate_file.close()
    write_jsonl(output_dir / "dataset_a_queries.jsonl", query_rows)
    write_jsonl(output_dir / "dataset_a_case_coverage.jsonl", coverage_rows)

    covered = [row for row in coverage_rows if row["covered"]]
    repo_present = [row for row in coverage_rows if row["repo_present"]]
    candidate_counts = [row["candidate_count"] for row in coverage_rows if row["repo_present"]]
    positive_counts = [row["positive_candidate_count"] for row in coverage_rows if row["repo_present"]]
    summary = {
        "case_count": len(cases),
        "query_count": len(query_rows),
        "repo_count": len(cases_by_repo),
        "repo_present_cases": len(repo_present),
        "covered_cases": len(covered),
        "coverage_rate": (len(covered) / len(cases)) if cases else 0.0,
        "candidate_count": candidate_count,
        "positive_candidate_count": positive_candidate_count,
        "candidate_view_types": dict(by_view.most_common()),
        "mean_candidates_per_present_case": (
            sum(candidate_counts) / len(candidate_counts) if candidate_counts else 0.0
        ),
        "mean_positives_per_present_case": (
            sum(positive_counts) / len(positive_counts) if positive_counts else 0.0
        ),
    }
    manifest = {
        "dataset": "toctou_dataset_a_no_trace",
        "repo_roots": [str(path) for path in repo_roots],
        "max_file_bytes": max_file_bytes,
        "max_files_per_repo": max_files_per_repo,
        "window_lines": window_lines,
        "stride_lines": stride_lines,
        "source_suffixes": sorted(SOURCE_SUFFIXES),
        "generic_text_suffixes": sorted(GENERIC_TEXT_SUFFIXES),
        "window_suffixes": sorted(WINDOW_SUFFIXES),
        "summary": summary,
    }
    (output_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    write_report(output_dir / "report.md", manifest)
    return manifest


def write_report(path: Path, manifest: dict[str, Any]) -> None:
    summary = manifest["summary"]
    lines = [
        "# TOCTOU Dataset A No-Trace Candidate Build",
        "",
        "## Scope",
        f"- Cases: {summary['case_count']}",
        f"- Repos: {summary['repo_count']}",
        f"- Repo-present cases: {summary['repo_present_cases']}",
        f"- Covered cases: {summary['covered_cases']}",
        f"- Coverage rate: {summary['coverage_rate']:.1%}",
        f"- Candidates: {summary['candidate_count']}",
        f"- Positive candidates: {summary['positive_candidate_count']}",
        "",
        "## Candidate Views",
    ]
    for view_type, count in summary["candidate_view_types"].items():
        lines.append(f"- {view_type}: {count}")
    lines.extend(
        [
            "",
            "## Notes",
            "- Candidate text is generated from full-repository source views only.",
            "- No TOCTOU/check-use feature signatures are injected into candidate text.",
            "- `text_symbol_masked` is emitted for symbol-replacement ablation.",
            "- `text_api_shape_masked` preserves generic API/member/call shape while masking local symbols and literal values.",
            "- Positives are anchor overlaps, not proof that the view alone contains all exploit evidence.",
        ]
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", type=Path, default=Path("."))
    ap.add_argument(
        "--case-manifest",
        default="output/eval_dataset_audit/toctou_local_v6/strict_check_use_cases.jsonl",
    )
    ap.add_argument(
        "--repo-root",
        action="append",
        default=None,
    )
    ap.add_argument("--output-dir", default="output/toctou_dataset_a/strict_v1")
    ap.add_argument("--limit-cases", type=int, default=0)
    ap.add_argument("--max-repos", type=int, default=0)
    ap.add_argument("--max-files-per-repo", type=int, default=0)
    ap.add_argument("--max-file-bytes", type=int, default=512_000)
    ap.add_argument("--window-lines", type=int, default=80)
    ap.add_argument("--stride-lines", type=int, default=40)
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    root = args.root
    cases = load_cases(root / args.case_manifest, limit_cases=args.limit_cases)
    repo_root_values = args.repo_root or [
        "output/intermediates/pipeline-repos",
        "output/intermediates/benchmark-repos",
    ]
    repo_roots = [root / value for value in repo_root_values]
    manifest = build_dataset(
        cases=cases,
        repo_roots=repo_roots,
        output_dir=root / args.output_dir,
        max_file_bytes=args.max_file_bytes,
        window_lines=args.window_lines,
        stride_lines=args.stride_lines,
        max_repos=args.max_repos,
        max_files_per_repo=args.max_files_per_repo,
        verbose=args.verbose,
    )
    print(json.dumps(manifest, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
