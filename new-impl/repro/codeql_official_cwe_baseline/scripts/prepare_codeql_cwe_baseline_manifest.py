#!/usr/bin/env python3
"""Prepare a case manifest for the official CodeQL CWE baseline.

The unified dataset is the source of case identity and ground-truth anchors.
The CodeQL DB run is the source of executable database paths. CWE labels are
kept explicit and source-attributed because some dataset snapshots intentionally
do not carry complete CWE metadata.
"""

from __future__ import annotations

import argparse
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any


CWE_RE = re.compile(r"\bCWE[-_ ]?(\d+)\b", re.IGNORECASE)
VULN_RE = re.compile(r"(CVE-\d{4}-\d{4,}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})", re.IGNORECASE)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unified-cases", required=True, type=Path)
    parser.add_argument("--paper-eval-review", required=True, type=Path)
    parser.add_argument("--db-task-jsonl", required=True, action="append", type=Path)
    parser.add_argument(
        "--db-marker-list",
        type=Path,
        help="Optional text file containing DB directories or codeql-database.yml paths known to exist.",
    )
    parser.add_argument(
        "--assume-db-task-usable",
        action="store_true",
        help="Treat every task with a db_dir as usable. Prefer --db-marker-list when running off-host.",
    )
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--cwe-cache", type=Path)
    parser.add_argument("--offline", action="store_true", help="Do not call OSV/NVD for missing CWE labels.")
    parser.add_argument("--skip-nvd", action="store_true", help="Use OSV only for online CWE lookup.")
    parser.add_argument("--request-delay", type=float, default=0.25)
    parser.add_argument("--request-timeout", type=float, default=10.0)
    parser.add_argument("--progress-every", type=int, default=10)
    return parser.parse_args()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def normalize_cwe(value: Any) -> str | None:
    match = CWE_RE.search(str(value or ""))
    if not match:
        return None
    return f"CWE-{int(match.group(1))}"


def cwe_sort_key(value: str) -> tuple[int, str]:
    cwe = normalize_cwe(value)
    return (int(cwe.split("-")[1]) if cwe else 10**9, value)


def collect_dataset_cwes(case: dict[str, Any]) -> tuple[list[str], list[str]]:
    cwes: set[str] = set()
    sources: list[str] = []
    classification = case.get("classification") or {}
    for raw in classification.get("cwe_ids") or []:
        cwe = normalize_cwe(raw)
        if cwe:
            cwes.add(cwe)
            sources.append("dataset.classification.cwe_ids")
    for source in classification.get("classification_sources") or []:
        if not isinstance(source, dict):
            continue
        cwe = normalize_cwe(source.get("value"))
        if cwe:
            cwes.add(cwe)
            sources.append(f"dataset.classification_sources:{source.get('source_family', '')}")
    return sorted(cwes, key=cwe_sort_key), sorted(set(sources))


def collect_vuln_ids(identity_key: str, case: dict[str, Any]) -> list[str]:
    ids: set[str] = set(VULN_RE.findall(identity_key))
    vuln = case.get("vulnerability") or {}
    for value in [vuln.get("id"), *(vuln.get("aliases") or [])]:
        for match in VULN_RE.findall(str(value or "")):
            ids.add(match.upper())
    for anchor in case.get("recall_anchors") or []:
        provenance = anchor.get("provenance") or {}
        for key in ("advisory_urls", "fix_commit_urls"):
            for value in provenance.get(key) or []:
                for match in VULN_RE.findall(str(value or "")):
                    ids.add(match.upper())
        for value in (provenance.get("rationale"), provenance.get("source_path"), provenance.get("review_id")):
            for match in VULN_RE.findall(str(value or "")):
                ids.add(match.upper())
    return sorted(ids)


def load_cache(path: Path) -> dict[str, Any]:
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return {}


def save_cache(path: Path, cache: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(cache, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def fetch_json(url: str, timeout: float) -> dict[str, Any]:
    req = urllib.request.Request(url, headers={"User-Agent": "hcvr-codeql-official-cwe-baseline"})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def fetch_osv(vuln_id: str, timeout: float) -> tuple[list[str], dict[str, Any]]:
    data = fetch_json(f"https://api.osv.dev/v1/vulns/{urllib.parse.quote(vuln_id)}", timeout)
    cwes: set[str] = set()
    database_specific = data.get("database_specific") or {}
    for raw in database_specific.get("cwe_ids") or []:
        cwe = normalize_cwe(raw)
        if cwe:
            cwes.add(cwe)
    for raw in data.get("aliases") or []:
        cwe = normalize_cwe(raw)
        if cwe:
            cwes.add(cwe)
    return sorted(cwes, key=cwe_sort_key), {"summary": data.get("summary"), "modified": data.get("modified")}


def fetch_nvd(cve_id: str, timeout: float) -> tuple[list[str], dict[str, Any]]:
    data = fetch_json("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + urllib.parse.quote(cve_id), timeout)
    cwes: set[str] = set()
    for vuln in data.get("vulnerabilities") or []:
        cve = vuln.get("cve") or {}
        for weakness in cve.get("weaknesses") or []:
            for desc in weakness.get("description") or []:
                cwe = normalize_cwe(desc.get("value"))
                if cwe:
                    cwes.add(cwe)
    return sorted(cwes, key=cwe_sort_key), {"totalResults": data.get("totalResults")}


def lookup_external_cwes(
    vuln_ids: list[str],
    cache: dict[str, Any],
    offline: bool,
    skip_nvd: bool,
    delay: float,
    timeout: float,
    cache_path: Path,
) -> tuple[list[str], list[str]]:
    cwes: set[str] = set()
    sources: list[str] = []
    for vuln_id in vuln_ids:
        key = vuln_id.upper()
        if key not in cache:
            cache[key] = {"cwe_ids": [], "attempts": []}
        cached = cache[key]
        for raw in cached.get("cwe_ids") or []:
            cwe = normalize_cwe(raw)
            if cwe:
                cwes.add(cwe)
        if cached.get("cwe_ids") or offline:
            if cached.get("cwe_ids"):
                sources.append(f"cache:{cached.get('source', 'unknown')}")
            continue

        attempts: list[dict[str, Any]] = []
        fetchers = [("osv", fetch_osv)]
        if not skip_nvd:
            fetchers.append(("nvd", fetch_nvd))
        for source_name, fetcher in fetchers:
            if source_name == "nvd" and not key.startswith("CVE-"):
                continue
            try:
                found, meta = fetcher(key, timeout)
                attempts.append({"source": source_name, "ok": True, "cwe_ids": found, "meta": meta})
                if found:
                    cache[key] = {"cwe_ids": found, "source": source_name, "attempts": attempts}
                    save_cache(cache_path, cache)
                    cwes.update(found)
                    sources.append(source_name)
                    break
            except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
                attempts.append({"source": source_name, "ok": False, "error": repr(exc)})
            time.sleep(max(delay, 0.0))
        else:
            cache[key] = {"cwe_ids": [], "source": "unresolved", "attempts": attempts}
            save_cache(cache_path, cache)
    return sorted(cwes, key=cwe_sort_key), sorted(set(sources))


def load_db_markers(path: Path | None) -> set[str]:
    if not path:
        return set()
    markers: set[str] = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        value = line.strip()
        if not value:
            continue
        if value.endswith("/codeql-database.yml"):
            value = str(Path(value).parent)
        markers.add(value)
    return markers


def load_usable_dbs(paths: list[Path], marker_list: set[str], assume_usable: bool) -> dict[str, dict[str, Any]]:
    usable: dict[str, dict[str, Any]] = {}
    for path in paths:
        for task in read_jsonl(path):
            identity = task.get("identity_key")
            db_dir = Path(task.get("db_dir") or "")
            if not identity or not db_dir:
                continue
            usable_now = (
                assume_usable
                or str(db_dir) in marker_list
                or str(db_dir / "codeql-database.yml") in marker_list
                or (db_dir / "codeql-database.yml").exists()
            )
            if usable_now:
                usable[identity] = {
                    "identity_key": identity,
                    "codeql_language": task.get("codeql_language") or "",
                    "db_dir": str(db_dir),
                    "source_root": task.get("source_root") or "",
                    "task_id": task.get("task_id") or "",
                    "admission_status": task.get("admission_status") or "",
                }
    return usable


def main() -> None:
    args = parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    cache_path = args.cwe_cache or args.out_dir / "cwe_cache.json"
    cache = load_cache(cache_path)

    selected_rows = read_jsonl(args.paper_eval_review)
    selected_ids = [row["identity_key"] for row in selected_rows]
    cases = {case["identity_key"]: case for case in read_jsonl(args.unified_cases)}
    usable_dbs = load_usable_dbs(args.db_task_jsonl, load_db_markers(args.db_marker_list), args.assume_db_task_usable)

    rows: list[dict[str, Any]] = []
    for index, selected in enumerate(selected_rows, 1):
        identity = selected["identity_key"]
        case = cases.get(identity, {})
        db = usable_dbs.get(identity)
        dataset_cwes, dataset_sources = collect_dataset_cwes(case)
        vuln_ids = collect_vuln_ids(identity, case)
        external_cwes: list[str] = []
        external_sources: list[str] = []
        if not dataset_cwes:
            external_cwes, external_sources = lookup_external_cwes(
                vuln_ids,
                cache,
                args.offline,
                args.skip_nvd,
                args.request_delay,
                args.request_timeout,
                cache_path,
            )
        cwes = dataset_cwes or external_cwes
        row = {
            "identity_key": identity,
            "new_unified_case_id": case.get("new_unified_case_id", ""),
            "repo_key": selected.get("repo_key") or identity.split("::", 1)[0],
            "vulnerability_id": selected.get("vulnerability_id") or (identity.split("::", 1)[1] if "::" in identity else ""),
            "vuln_ids_for_lookup": vuln_ids,
            "paper_eval_decision": selected.get("paper_eval_decision", ""),
            "checkout_revision": selected.get("checkout_revision") or (case.get("revisions") or {}).get("checkout_revision", ""),
            "fix_revision": selected.get("candidate_fix_revision") or (case.get("revisions") or {}).get("fix_revision", ""),
            "repo_url": ((case.get("repository") or {}).get("repo_url")) or "",
            "codeql_db_usable": bool(db),
            "codeql_language": (db or {}).get("codeql_language", ""),
            "db_dir": (db or {}).get("db_dir", ""),
            "source_root": (db or {}).get("source_root", ""),
            "cwe_ids": cwes,
            "cwe_source": "dataset" if dataset_cwes else ("external" if external_cwes else "missing"),
            "cwe_source_detail": dataset_sources or external_sources,
            "anchor_count": len(case.get("recall_anchors") or []),
            "recall_anchors": case.get("recall_anchors") or [],
        }
        row["eval_in_current_db_denominator"] = row["codeql_db_usable"]
        rows.append(row)
        if args.progress_every and index % args.progress_every == 0:
            print(
                json.dumps(
                    {
                        "progress": index,
                        "total": len(selected_rows),
                        "identity_key": identity,
                        "cwe_source": row["cwe_source"],
                        "cwe_ids": row["cwe_ids"],
                        "codeql_db_usable": row["codeql_db_usable"],
                    },
                    ensure_ascii=False,
                ),
                flush=True,
            )

    save_cache(cache_path, cache)
    write_jsonl(args.out_dir / "current_143_manifest.jsonl", rows)
    eval_rows = [row for row in rows if row["eval_in_current_db_denominator"]]
    write_jsonl(args.out_dir / "current_143_with_usable_codeql_db_manifest.jsonl", eval_rows)
    write_jsonl(args.out_dir / "current_143_missing_codeql_db_manifest.jsonl", [row for row in rows if not row["codeql_db_usable"]])

    summary = {
        "selected_current_cases": len(selected_ids),
        "unique_selected_current_cases": len(set(selected_ids)),
        "db_usable_for_current_cases": len(eval_rows),
        "current_cases_missing_db": len(rows) - len(eval_rows),
        "usable_db_not_in_current_dataset": len(set(usable_dbs) - set(selected_ids)),
        "decision_counts": dict(Counter(row["paper_eval_decision"] for row in rows)),
        "language_counts_for_current_usable_dbs": dict(Counter(row["codeql_language"] for row in eval_rows)),
        "cwe_source_counts_for_current_usable_dbs": dict(Counter(row["cwe_source"] for row in eval_rows)),
        "cases_missing_cwe_for_current_usable_dbs": sum(1 for row in eval_rows if not row["cwe_ids"]),
        "cwe_counts_for_current_usable_dbs": dict(Counter(cwe for row in eval_rows for cwe in row["cwe_ids"])),
        "inputs": {
            "unified_cases": str(args.unified_cases),
            "paper_eval_review": str(args.paper_eval_review),
            "db_task_jsonl": [str(p) for p in args.db_task_jsonl],
            "db_marker_list": str(args.db_marker_list) if args.db_marker_list else "",
            "cwe_cache": str(cache_path),
        },
    }
    (args.out_dir / "manifest_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
