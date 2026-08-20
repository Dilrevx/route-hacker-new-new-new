#!/usr/bin/env python3
"""Generate legacy cve_clustering-style guidelines from refined CVE clusters.

This is a standalone migration of the old Route-Hacker guideline generation
stage. It keeps the old artifact contract:

    output_dir/
      latest.json
      guidelines/
        index.json
        gl_0001.json
        ...

It also writes a recall sidecar when a Unified V2 cases file is provided, so
`recall_guideline_anchors.py --guideline-file` can consume the generated
guidelines without mutating the dataset.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable


DEFAULT_PROMPT = Path(__file__).parents[1] / "prompts" / "generate_guideline.md"
DEFAULT_BUDGETS = (30, 50, 100, 150, 200, 300, 500)
FENCE_RE = re.compile(r"^```[a-zA-Z0-9]*\s*|\s*```$", re.MULTILINE)
PROJECT_SPECIFIC_RE = re.compile(
    r"(?i)"
    r"("
    r"CVE-\d{4}-\d{4,7}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|"
    r"\b(?:github\.com|gitlab\.com)/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\b|"
    r"[A-Za-z0-9_/.-]+\.(?:java|py|js|ts|tsx|jsx|go|c|cc|cpp|h|hpp|php|rb)|"
    r"\bline\s+\d+\b"
    r")"
)
TEXT_FIELDS = (
    "root_cause",
    "abstract_pattern",
    "data_flow",
    "trigger_condition",
    "fix_strategy",
    "vuln_type",
    "impact",
)
STOP_WORDS = {
    "the",
    "a",
    "an",
    "is",
    "are",
    "was",
    "were",
    "be",
    "been",
    "being",
    "have",
    "has",
    "had",
    "do",
    "does",
    "did",
    "will",
    "would",
    "could",
    "should",
    "may",
    "might",
    "can",
    "shall",
    "to",
    "of",
    "in",
    "for",
    "on",
    "with",
    "at",
    "by",
    "from",
    "as",
    "into",
    "through",
    "during",
    "before",
    "after",
    "and",
    "or",
    "not",
    "but",
    "if",
    "then",
    "when",
    "where",
    "which",
    "this",
    "that",
    "these",
    "those",
    "user",
    "code",
    "data",
    "file",
    "method",
    "function",
    "class",
    "object",
    "value",
    "result",
    "case",
    "using",
    "without",
}


@dataclass(frozen=True)
class GuidelineTask:
    guideline_id: str
    cluster: dict[str, Any]
    sub_pattern: dict[str, Any] | None
    cve_ids: list[str]
    representatives: list[dict[str, Any]]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def build_source_fingerprint(cve_ids: Iterable[str]) -> str:
    digest = hashlib.sha256()
    for cve_id in sorted(set(cve_ids)):
        digest.update(str(cve_id).encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def extract_json_object(text: str) -> dict[str, Any]:
    cleaned = FENCE_RE.sub("", text).strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end != -1 and end > start:
        return json.loads(cleaned[start : end + 1])
    raise ValueError(f"no JSON object in response: {text[:200]!r}")


def load_structured_index(path: Path) -> dict[str, dict[str, Any]]:
    rows = list(read_jsonl(path)) if path.suffix.lower() == ".jsonl" else read_json(path)
    if isinstance(rows, dict):
        if "records" in rows:
            rows = rows["records"]
        elif "items" in rows:
            rows = rows["items"]
        else:
            rows = list(rows.values())
    index: dict[str, dict[str, Any]] = {}
    for row in rows:
        if isinstance(row, dict) and row.get("cve_id"):
            index[str(row["cve_id"])] = row
    if not index:
        raise ValueError(f"structured input has no cve_id records: {path}")
    return index


def load_clustering(path: Path) -> dict[str, Any]:
    payload = read_json(path)
    if not isinstance(payload, dict):
        raise ValueError(f"clustering input must be a JSON object: {path}")
    if not isinstance(payload.get("clusters"), list):
        raise ValueError(f"clustering input missing clusters list: {path}")
    return payload


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def unique_ordered(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def cluster_members(cluster: dict[str, Any]) -> list[str]:
    return unique_ordered(str(value) for value in as_list(cluster.get("members")) if value)


def subpattern_members(sub_pattern: dict[str, Any]) -> list[str]:
    return unique_ordered(str(value) for value in as_list(sub_pattern.get("members")) if value)


def pick_representatives(
    cluster: dict[str, Any],
    structured: dict[str, dict[str, Any]],
    *,
    member_subset: list[str] | None = None,
    limit: int,
) -> list[dict[str, Any]]:
    target = member_subset if member_subset is not None else cluster_members(cluster)
    ordered: list[str] = []
    representative = str(cluster.get("representative_cve") or "")
    if representative in structured and representative in set(target):
        ordered.append(representative)
    for sub_pattern in as_list(cluster.get("sub_patterns")):
        if isinstance(sub_pattern, dict):
            ordered.extend(subpattern_members(sub_pattern))
    ordered.extend(target)
    return [structured[cve_id] for cve_id in unique_ordered(ordered) if cve_id in structured][:limit]


def build_generation_tasks(
    clustering: dict[str, Any],
    structured: dict[str, dict[str, Any]],
    *,
    representatives_per_task: int = 3,
) -> list[GuidelineTask]:
    tasks: list[GuidelineTask] = []
    for cluster in sorted(as_list(clustering.get("clusters")), key=lambda row: int(row.get("cluster_id", 0))):
        if not isinstance(cluster, dict):
            continue
        members = cluster_members(cluster)
        sub_patterns = [sp for sp in as_list(cluster.get("sub_patterns")) if isinstance(sp, dict)]
        if sub_patterns and len(sub_patterns) > 1:
            for sub_pattern in sub_patterns:
                sp_members = subpattern_members(sub_pattern)
                representatives = pick_representatives(
                    cluster,
                    structured,
                    member_subset=sp_members,
                    limit=representatives_per_task,
                )
                if representatives:
                    tasks.append(
                        GuidelineTask(
                            guideline_id=f"gl_{len(tasks) + 1:04d}",
                            cluster=cluster,
                            sub_pattern=sub_pattern,
                            cve_ids=sp_members,
                            representatives=representatives,
                        )
                    )
            covered = {cve_id for sp in sub_patterns for cve_id in subpattern_members(sp)}
            if set(members) - covered:
                representatives = pick_representatives(
                    cluster,
                    structured,
                    member_subset=members,
                    limit=representatives_per_task,
                )
                if representatives:
                    tasks.append(
                        GuidelineTask(
                            guideline_id=f"gl_{len(tasks) + 1:04d}",
                            cluster=cluster,
                            sub_pattern=None,
                            cve_ids=members,
                            representatives=representatives,
                        )
                    )
        else:
            representatives = pick_representatives(
                cluster,
                structured,
                member_subset=members,
                limit=representatives_per_task,
            )
            if representatives:
                tasks.append(
                    GuidelineTask(
                        guideline_id=f"gl_{len(tasks) + 1:04d}",
                        cluster=cluster,
                        sub_pattern=None,
                        cve_ids=members,
                        representatives=representatives,
                    )
                )
    return tasks


def render_subpatterns(task: GuidelineTask) -> str:
    sub_patterns = [task.sub_pattern] if task.sub_pattern else as_list(task.cluster.get("sub_patterns"))
    lines: list[str] = []
    for sub_pattern in sub_patterns:
        if not isinstance(sub_pattern, dict):
            continue
        lines.extend(
            [
                f"Sub-pattern: {sub_pattern.get('name') or 'unnamed'}",
                f"root_cause: {sub_pattern.get('root_cause') or ''}",
                f"fix_strategy: {sub_pattern.get('fix_strategy') or ''}",
                f"members: {', '.join(subpattern_members(sub_pattern))}",
                "",
            ]
        )
    return "\n".join(lines).strip() or "No explicit sub-patterns."


def render_representatives(task: GuidelineTask) -> str:
    lines: list[str] = []
    for record in task.representatives:
        lines.extend(
            [
                f"- {record.get('cve_id')} ({record.get('vuln_type') or ''}, "
                f"layer={record.get('code_layer') or ''}, scope={record.get('scope') or ''})",
                f"  abstract_pattern: {record.get('abstract_pattern') or ''}",
                f"  root_cause: {record.get('root_cause') or ''}",
                f"  data_flow: {record.get('data_flow') or ''}",
                f"  trigger_condition: {record.get('trigger_condition') or ''}",
                f"  fix_strategy: {record.get('fix_strategy') or ''}",
            ]
        )
    return "\n".join(lines)


def render_prompt(template: str, task: GuidelineTask) -> str:
    cluster = task.cluster
    label = str(cluster.get("cluster_name") or f"cluster_{cluster.get('cluster_id', 0)}")
    if task.sub_pattern:
        label = f"{label} - {task.sub_pattern.get('name') or 'sub_pattern'}"
    replacements = {
        "{{ cluster_id }}": str(cluster.get("cluster_id", 0)),
        "{{ cluster_name }}": label,
        "{{ cluster_summary }}": str(cluster.get("cluster_summary") or ""),
        "{{ sub_patterns }}": render_subpatterns(task),
        "{{ representatives }}": render_representatives(task),
    }
    out = template
    for key, value in replacements.items():
        out = out.replace(key, value)
    out = out.replace("{% sub_patterns %}", "")
    out = out.replace("{% representatives %}", "")
    return out.strip() + "\n"


def extract_tags(structured: dict[str, dict[str, Any]], cve_ids: list[str], *, max_tags: int = 24) -> list[str]:
    counts: dict[str, int] = {}
    for cve_id in cve_ids:
        record = structured.get(cve_id) or {}
        for field in TEXT_FIELDS:
            text = str(record.get(field) or "")
            for word in re.findall(r"[a-z0-9][a-z0-9_-]*[a-z0-9]|[a-z0-9]", text.lower()):
                if len(word) >= 3 and word not in STOP_WORDS:
                    counts[word] = counts.get(word, 0) + 1
    return [
        word
        for word, _ in sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:max_tags]
    ]


def sanitize_guideline_text(text: str) -> str:
    text = FENCE_RE.sub("", text).strip()
    text = PROJECT_SPECIFIC_RE.sub("", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def deterministic_guideline(task: GuidelineTask) -> str:
    cluster = task.cluster
    sub_pattern = task.sub_pattern or {}
    root_cause = str(sub_pattern.get("root_cause") or cluster.get("cluster_summary") or "").strip()
    fix_strategy = str(sub_pattern.get("fix_strategy") or "").strip()
    representatives = " ".join(
        " ".join(str(record.get(field) or "") for field in TEXT_FIELDS)
        for record in task.representatives
    )
    terms = " ".join(extract_tags({r["cve_id"]: r for r in task.representatives if r.get("cve_id")}, [r["cve_id"] for r in task.representatives if r.get("cve_id")], max_tags=10))
    text = (
        "Audit code paths matching this root-cause pattern: "
        f"{root_cause or representatives}. "
        "Trace attacker-controlled input, resource identity, parser state, or "
        "execution context into the sensitive operation described by the pattern, "
        "and verify whether the required validation, authorization, isolation, "
        "or state precondition is present before the effect. "
        f"Use the fix strategy as a guard shape to look for, without treating it as proof: {fix_strategy}. "
        f"Prioritize semantically related code involving these concepts: {terms}."
    )
    return sanitize_guideline_text(text)


class OpenAICompatibleChatClient:
    def __init__(
        self,
        *,
        base_url: str,
        model: str,
        api_key: str | None,
        timeout: int,
        max_retries: int,
        temperature: float,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max(1, max_retries)
        self.temperature = temperature
        self.usage = {
            "total_calls": 0,
            "total_prompt_tokens": 0,
            "total_completion_tokens": 0,
            "total_tokens": 0,
        }

    def __call__(self, prompt: str) -> str:
        payload = json.dumps(
            {
                "model": self.model,
                "temperature": self.temperature,
                "messages": [{"role": "user", "content": prompt}],
            }
        ).encode("utf-8")
        last_error: Exception | None = None
        for attempt in range(1, self.max_retries + 1):
            request = urllib.request.Request(
                f"{self.base_url}/chat/completions",
                data=payload,
                headers={"Content-Type": "application/json", "Connection": "close"},
                method="POST",
            )
            if self.api_key:
                request.add_header("Authorization", f"Bearer {self.api_key}")
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    body = response.read().decode("utf-8")
                data = json.loads(body)
                usage = data.get("usage") or {}
                self.usage["total_calls"] += 1
                self.usage["total_prompt_tokens"] += int(usage.get("prompt_tokens") or 0)
                self.usage["total_completion_tokens"] += int(usage.get("completion_tokens") or 0)
                self.usage["total_tokens"] += int(usage.get("total_tokens") or 0)
                return str(data["choices"][0]["message"]["content"])
            except urllib.error.HTTPError as error:
                detail = error.read().decode("utf-8", errors="replace")
                last_error = RuntimeError(f"chat completion HTTP {error.code}: {detail[:1000]}")
                if error.code < 500 or attempt >= self.max_retries:
                    raise last_error from error
            except (TimeoutError, urllib.error.URLError, KeyError, json.JSONDecodeError) as error:
                last_error = error
                if attempt >= self.max_retries:
                    raise RuntimeError(f"chat completion failed after {attempt} attempt(s): {error}") from error
            time.sleep(min(2.0 * attempt, 10.0))
        raise RuntimeError(f"chat completion failed: {last_error}")


def generate_guideline_payload(
    task: GuidelineTask,
    *,
    structured: dict[str, dict[str, Any]],
    clustering: dict[str, Any],
    source_fingerprint: str,
    model_used: str,
    response_text: str,
) -> dict[str, Any]:
    payload = extract_json_object(response_text)
    guideline_text = sanitize_guideline_text(str(payload.get("guideline_text") or ""))
    if not guideline_text:
        raise ValueError(f"empty guideline_text for {task.guideline_id}")
    cluster = task.cluster
    return {
        "guideline_id": task.guideline_id,
        "guideline_text": guideline_text,
        "source_cluster_id": int(cluster.get("cluster_id", 0)),
        "source_method": str(clustering.get("method") or "traditional"),
        "source_fingerprint": source_fingerprint,
        "cve_ids": task.cve_ids,
        "cluster_summary": str(cluster.get("cluster_summary") or ""),
        "sub_patterns": [task.sub_pattern] if task.sub_pattern else as_list(cluster.get("sub_patterns")),
        "representative_cve": str((task.representatives[0] or {}).get("cve_id") or ""),
        "model_used": model_used,
        "tags": extract_tags(structured, task.cve_ids),
        "embeddings": {},
        "schema_version": "1.0",
        "created_at": utc_now(),
    }


def build_guidelines(
    clustering: dict[str, Any],
    structured: dict[str, dict[str, Any]],
    *,
    prompt_template: str,
    model_used: str,
    concurrency: int,
    chat: Callable[[str], str] | None,
    deterministic: bool,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    all_cve_ids = set(str(value) for value in as_list(clustering.get("noise")) if value)
    for cluster in as_list(clustering.get("clusters")):
        if isinstance(cluster, dict):
            all_cve_ids.update(cluster_members(cluster))
    source_fingerprint = build_source_fingerprint(all_cve_ids)
    tasks = build_generation_tasks(clustering, structured)

    prompt_rows = [
        {
            "guideline_id": task.guideline_id,
            "source_cluster_id": task.cluster.get("cluster_id"),
            "cve_ids": task.cve_ids,
            "sub_pattern_name": (task.sub_pattern or {}).get("name"),
            "prompt": render_prompt(prompt_template, task),
        }
        for task in tasks
    ]
    if chat is None and not deterministic:
        return [], prompt_rows, {
            "source_fingerprint": source_fingerprint,
            "task_count": len(tasks),
            "generated_count": 0,
        }

    def generate_one(task: GuidelineTask) -> dict[str, Any]:
        if deterministic:
            response = json.dumps({"guideline_text": deterministic_guideline(task)})
        else:
            assert chat is not None
            response = chat(render_prompt(prompt_template, task))
        return generate_guideline_payload(
            task,
            structured=structured,
            clustering=clustering,
            source_fingerprint=source_fingerprint,
            model_used=model_used,
            response_text=response,
        )

    guidelines: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, concurrency)) as executor:
        future_to_task = {executor.submit(generate_one, task): task for task in tasks}
        for future in concurrent.futures.as_completed(future_to_task):
            task = future_to_task[future]
            try:
                guidelines.append(future.result())
            except Exception as exc:  # noqa: BLE001
                guidelines.append(
                    {
                        "guideline_id": task.guideline_id,
                        "state": "failed",
                        "error": str(exc),
                        "source_cluster_id": task.cluster.get("cluster_id"),
                        "cve_ids": task.cve_ids,
                    }
                )
    guidelines.sort(key=lambda row: row["guideline_id"])
    success = [row for row in guidelines if row.get("state") != "failed"]
    return success, prompt_rows, {
        "source_fingerprint": source_fingerprint,
        "task_count": len(tasks),
        "generated_count": len(success),
        "failed_count": len(guidelines) - len(success),
        "failed": [row for row in guidelines if row.get("state") == "failed"],
    }


def write_release(output_dir: Path, guidelines: list[dict[str, Any]], *, metadata: dict[str, Any]) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    items_dir = output_dir / "guidelines"
    items_dir.mkdir(parents=True, exist_ok=True)
    items: list[dict[str, Any]] = []
    for guideline in guidelines:
        file_name = f"{guideline['guideline_id']}.json"
        write_json(items_dir / file_name, guideline)
        items.append(
            {
                "guideline_id": guideline["guideline_id"],
                "file_name": file_name,
                "source_cluster_id": guideline.get("source_cluster_id"),
                "source_method": guideline.get("source_method"),
                "cve_count": len(guideline.get("cve_ids") or []),
                "representative_cve": guideline.get("representative_cve") or "",
                "size": len(guideline.get("cve_ids") or []),
                "top_tags": (guideline.get("tags") or [])[:8],
                "cluster_summary_preview": str(guideline.get("cluster_summary") or "")[:200],
            }
        )
    now = utc_now()
    source_fingerprint = metadata.get("source_fingerprint") or (
        guidelines[0].get("source_fingerprint") if guidelines else ""
    )
    index = {
        "schema_version": "1.0",
        "created_at": now,
        "source_fingerprint": source_fingerprint,
        "model_used": metadata.get("model_used") or "",
        "total": len(items),
        "items": items,
    }
    if metadata.get("token_usage"):
        index["token_usage"] = metadata["token_usage"]
    write_json(items_dir / "index.json", index)
    latest = {
        "schema_version": "1.0",
        "created_at": now,
        "latest_index": "guidelines/index.json",
        "source_fingerprint": source_fingerprint,
    }
    write_json(output_dir / "latest.json", latest)
    return {"index": str(items_dir / "index.json"), "latest": str(output_dir / "latest.json")}


def case_cve_ids(case: dict[str, Any]) -> list[str]:
    values: list[str] = []
    identity = str(case.get("identity_key") or "")
    if "::" in identity:
        values.append(identity.rsplit("::", 1)[-1])
    vuln = case.get("vulnerability") or {}
    for key in ("id", "cve_id"):
        if vuln.get(key):
            values.append(str(vuln[key]))
    values.extend(str(value) for value in as_list(vuln.get("aliases")) if value)
    values.extend(str(value) for value in as_list(case.get("aliases")) if value)
    return unique_ordered(values)


def export_case_sidecar(
    path: Path,
    *,
    guidelines: list[dict[str, Any]],
    cases_file: Path,
) -> int:
    guideline_by_cve: dict[str, dict[str, Any]] = {}
    for guideline in guidelines:
        for cve_id in guideline.get("cve_ids") or []:
            guideline_by_cve.setdefault(str(cve_id), guideline)
    rows: list[dict[str, Any]] = []
    for case in read_jsonl(cases_file):
        identity = case.get("identity_key")
        if not identity:
            continue
        guideline = None
        for cve_id in case_cve_ids(case):
            guideline = guideline_by_cve.get(cve_id)
            if guideline:
                break
        if guideline is None:
            continue
        rows.append(
            {
                "identity_key": identity,
                "case_id": case.get("new_unified_case_id") or case.get("case_id"),
                "guideline_id": guideline["guideline_id"],
                "guideline_text": guideline["guideline_text"],
                "source_cluster_id": guideline.get("source_cluster_id"),
                "source_fingerprint": guideline.get("source_fingerprint"),
            }
        )
    write_jsonl(path, rows)
    return len(rows)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    root.add_argument("--clusters", type=Path, required=True)
    root.add_argument("--structured", type=Path, required=True)
    root.add_argument("--output-dir", type=Path, required=True)
    root.add_argument("--prompt-template", type=Path, default=DEFAULT_PROMPT)
    root.add_argument("--cases-file", type=Path)
    root.add_argument("--sidecar-output", type=Path)
    root.add_argument("--concurrency", type=int, default=5)
    root.add_argument("--model", default=os.environ.get("HCVR_GUIDELINE_MODEL", "DeepSeek-V4-Pro"))
    root.add_argument("--openai-base-url", default=os.environ.get("OPENAI_BASE_URL", ""))
    root.add_argument("--api-key-env", default="OPENAI_API_KEY")
    root.add_argument("--request-timeout", type=int, default=120)
    root.add_argument("--max-retries", type=int, default=3)
    root.add_argument("--temperature", type=float, default=0.0)
    root.add_argument("--dry-run-prompts", action="store_true")
    root.add_argument("--deterministic", action="store_true")
    return root


def main() -> None:
    args = parser().parse_args()
    clustering = load_clustering(args.clusters)
    structured = load_structured_index(args.structured)
    template = args.prompt_template.read_text(encoding="utf-8")

    chat: OpenAICompatibleChatClient | None = None
    if not args.dry_run_prompts and not args.deterministic:
        if not args.openai_base_url:
            raise SystemExit("--openai-base-url or OPENAI_BASE_URL is required unless --dry-run-prompts or --deterministic is used")
        chat = OpenAICompatibleChatClient(
            base_url=args.openai_base_url,
            model=args.model,
            api_key=os.environ.get(args.api_key_env),
            timeout=args.request_timeout,
            max_retries=args.max_retries,
            temperature=args.temperature,
        )

    guidelines, prompt_rows, meta = build_guidelines(
        clustering,
        structured,
        prompt_template=template,
        model_used=args.model if not args.deterministic else "deterministic_legacy_template_v1",
        concurrency=args.concurrency,
        chat=chat,
        deterministic=args.deterministic,
    )
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(output_dir / "generation_tasks.jsonl", prompt_rows)

    release_paths: dict[str, Any] = {}
    if args.dry_run_prompts:
        state = "dry_run_prompts"
    else:
        token_usage = chat.usage if chat else None
        release_paths = write_release(
            output_dir,
            guidelines,
            metadata={
                "source_fingerprint": meta["source_fingerprint"],
                "model_used": args.model if not args.deterministic else "deterministic_legacy_template_v1",
                "token_usage": token_usage,
            },
        )
        state = "completed"

    sidecar_count = 0
    sidecar_output = args.sidecar_output
    if not args.dry_run_prompts and args.cases_file is not None:
        sidecar_output = sidecar_output or (output_dir / "guideline_overrides.jsonl")
        sidecar_count = export_case_sidecar(
            sidecar_output,
            guidelines=guidelines,
            cases_file=args.cases_file,
        )

    summary = {
        "schema_version": "legacy_cve_cluster_guideline_generation.v1",
        "created_at": utc_now(),
        "state": state,
        "inputs": {
            "clusters": str(args.clusters.resolve()),
            "structured": str(args.structured.resolve()),
            "cases_file": str(args.cases_file.resolve()) if args.cases_file else None,
            "prompt_template": str(args.prompt_template.resolve()),
        },
        "outputs": {
            **release_paths,
            "generation_tasks": str(output_dir / "generation_tasks.jsonl"),
            "sidecar": str(sidecar_output.resolve()) if sidecar_output else None,
        },
        "model_used": args.model if not args.deterministic else "deterministic_legacy_template_v1",
        "concurrency": args.concurrency,
        "source_fingerprint": meta["source_fingerprint"],
        "task_count": meta["task_count"],
        "generated_count": meta["generated_count"],
        "failed_count": meta.get("failed_count", 0),
        "sidecar_case_count": sidecar_count,
        "boundary": {
            "uses_target_locations": False,
            "uses_retrieval_ranks": False,
            "uses_known_anchor_labels": False,
            "query_side_only": True,
        },
        "token_usage": chat.usage if chat else None,
        "failures": meta.get("failed", []),
    }
    write_json(output_dir / "summary.json", summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
