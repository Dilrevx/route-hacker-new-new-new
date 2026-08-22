#!/usr/bin/env python3
"""Generate mechanism-level retrieval guidelines from refined CVE clusters.

This is an offline guideline release tool. It consumes cve_clustering-style
cluster artifacts, attributes each cluster/sub-pattern to a mechanism, and
emits reviewable guidelines plus a recall/audit sidecar. It deliberately keeps
the mechanism logic out of online repository recall.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


GROUP_SCOPES = ("mechanism", "cluster-mechanism", "sub-pattern")
RELEASE_MIN_MEMBER_SUPPORT_RATE = 1.0
RELEASE_MIN_EVIDENCE_ROLES = 2

TEXT_FIELDS = (
    "vuln_type",
    "root_cause",
    "abstract_pattern",
    "data_flow",
    "trigger_condition",
    "fix_strategy",
    "impact",
)

EVIDENCE_ROLE_FIELDS = (
    "source_shape",
    "sink_shape",
    "missing_guard",
    "typical_fix",
)

STOP_WORDS = {
    "able",
    "about",
    "after",
    "also",
    "and",
    "any",
    "are",
    "before",
    "being",
    "between",
    "both",
    "can",
    "case",
    "class",
    "code",
    "could",
    "data",
    "does",
    "due",
    "during",
    "each",
    "file",
    "for",
    "from",
    "function",
    "had",
    "has",
    "have",
    "into",
    "its",
    "may",
    "method",
    "more",
    "most",
    "new",
    "not",
    "object",
    "only",
    "other",
    "over",
    "result",
    "should",
    "some",
    "such",
    "than",
    "that",
    "the",
    "then",
    "these",
    "this",
    "through",
    "too",
    "under",
    "user",
    "using",
    "value",
    "very",
    "was",
    "were",
    "when",
    "where",
    "which",
    "while",
    "with",
    "without",
    "would",
}

EVIDENCE_STOP_WORDS = STOP_WORDS | {
    "absent",
    "accepted",
    "access",
    "add",
    "allow",
    "before",
    "bind",
    "bound",
    "check",
    "checked",
    "constrain",
    "constrained",
    "controlled",
    "decision",
    "effect",
    "enforce",
    "enforced",
    "equivalent",
    "exact",
    "fail",
    "guard",
    "input",
    "inputs",
    "missing",
    "operation",
    "operations",
    "required",
    "safe",
    "sensitive",
    "trusted",
    "untrusted",
    "validate",
    "validated",
    "validation",
    "values",
}


@dataclass(frozen=True)
class Mechanism:
    mechanism_id: str
    name: str
    family: str
    aliases: tuple[str, ...]
    keywords: tuple[str, ...]
    required_keywords: tuple[tuple[str, ...], ...]
    source_shape: str
    sink_shape: str
    missing_guard: str
    typical_fix: str


@dataclass(frozen=True)
class WorkItem:
    cluster_id: int
    cluster_name: str
    cluster_summary: str
    sub_pattern_name: str
    sub_pattern_root_cause: str
    sub_pattern_fix_strategy: str
    members: tuple[str, ...]
    source_kind: str


@dataclass(frozen=True)
class EvidenceSupport:
    supported: bool
    role_hits: dict[str, tuple[str, ...]]
    role_count: int
    lexicon_score: float
    lexicon_matches: tuple[str, ...]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def slugify(text: str, *, prefix: str = "mech") -> str:
    value = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
    value = re.sub(r"_+", "_", value)
    return f"{prefix}_{value[:80] or 'unknown'}"


def guideline_group_key(item: WorkItem, mechanism: Mechanism, group_scope: str) -> str:
    if group_scope == "mechanism":
        return mechanism.mechanism_id
    cluster_key = f"cluster_{item.cluster_id:04d}"
    if group_scope == "cluster-mechanism":
        return f"{cluster_key}__{mechanism.mechanism_id}"
    if group_scope == "sub-pattern":
        sub_pattern_key = slugify(item.sub_pattern_name or item.cluster_name, prefix="sub_pattern")
        return f"{cluster_key}__{sub_pattern_key}__{mechanism.mechanism_id}"
    raise ValueError(f"unknown group scope: {group_scope}")


def load_lexicon(path: Path) -> list[Mechanism]:
    payload = read_json(path)
    if isinstance(payload, dict):
        raw_items = payload.get("mechanisms", [])
    elif isinstance(payload, list):
        raw_items = payload
    else:
        raw_items = []
    mechanisms: list[Mechanism] = []
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        mechanism_id = str(item.get("mechanism_id") or "").strip()
        name = str(item.get("name") or "").strip()
        if not mechanism_id or not name:
            continue
        mechanisms.append(
            Mechanism(
                mechanism_id=mechanism_id,
                name=name,
                family=str(item.get("family") or "").strip(),
                aliases=tuple(str(v).strip() for v in item.get("aliases") or [] if str(v).strip()),
                keywords=tuple(str(v).strip().lower() for v in item.get("keywords") or [] if str(v).strip()),
                required_keywords=parse_required_keywords(item.get("required_keywords")),
                source_shape=str(item.get("source_shape") or "").strip(),
                sink_shape=str(item.get("sink_shape") or "").strip(),
                missing_guard=str(item.get("missing_guard") or "").strip(),
                typical_fix=str(item.get("typical_fix") or "").strip(),
            )
        )
    if not mechanisms:
        raise ValueError(f"lexicon has no mechanisms: {path}")
    return mechanisms


def parse_required_keywords(raw: Any) -> tuple[tuple[str, ...], ...]:
    groups: list[tuple[str, ...]] = []
    if not raw:
        return ()
    if not isinstance(raw, list):
        raise ValueError("required_keywords must be a list of strings or string lists")
    for value in raw:
        if isinstance(value, str):
            terms = (value.strip().lower(),)
        elif isinstance(value, list):
            terms = tuple(str(item).strip().lower() for item in value if str(item).strip())
        else:
            raise ValueError("required_keywords entries must be strings or string lists")
        if terms:
            groups.append(terms)
    return tuple(groups)


def merge_lexicons(paths: list[Path]) -> list[Mechanism]:
    mechanisms: list[Mechanism] = []
    seen: set[str] = set()
    duplicates: list[str] = []
    for path in paths:
        for mechanism in load_lexicon(path):
            if mechanism.mechanism_id in seen:
                duplicates.append(mechanism.mechanism_id)
                continue
            seen.add(mechanism.mechanism_id)
            mechanisms.append(mechanism)
    if duplicates:
        raise ValueError(f"duplicate mechanism_id across lexicons: {sorted(duplicates)[:10]}")
    return mechanisms


def load_structured(path: Path) -> dict[str, dict[str, Any]]:
    return {row["cve_id"]: row for row in read_jsonl(path) if row.get("cve_id")}


def normalize_members(values: Iterable[Any]) -> tuple[str, ...]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        cve_id = str(value or "").strip()
        if cve_id and cve_id not in seen:
            out.append(cve_id)
            seen.add(cve_id)
    return tuple(out)


def iter_work_items(clustering: dict[str, Any]) -> Iterable[WorkItem]:
    for raw_cluster in clustering.get("clusters") or []:
        if not isinstance(raw_cluster, dict):
            continue
        cluster_id = int(raw_cluster.get("cluster_id") or 0)
        cluster_name = str(raw_cluster.get("cluster_name") or "").strip()
        cluster_summary = str(raw_cluster.get("cluster_summary") or "").strip()
        cluster_members = normalize_members(raw_cluster.get("members") or [])
        sub_patterns = raw_cluster.get("sub_patterns") or []
        emitted_members: set[str] = set()
        if isinstance(sub_patterns, list):
            for sp_index, sp in enumerate(sub_patterns, start=1):
                if not isinstance(sp, dict):
                    continue
                members = normalize_members(sp.get("members") or [])
                if not members:
                    continue
                emitted_members.update(members)
                yield WorkItem(
                    cluster_id=cluster_id,
                    cluster_name=cluster_name,
                    cluster_summary=cluster_summary,
                    sub_pattern_name=str(sp.get("name") or f"sub_pattern_{sp_index}").strip(),
                    sub_pattern_root_cause=str(sp.get("root_cause") or "").strip(),
                    sub_pattern_fix_strategy=str(sp.get("fix_strategy") or "").strip(),
                    members=members,
                    source_kind="sub_pattern",
                )
        uncovered = tuple(cve_id for cve_id in cluster_members if cve_id not in emitted_members)
        if uncovered or not sub_patterns:
            yield WorkItem(
                cluster_id=cluster_id,
                cluster_name=cluster_name,
                cluster_summary=cluster_summary,
                sub_pattern_name=cluster_name or f"cluster_{cluster_id}",
                sub_pattern_root_cause="",
                sub_pattern_fix_strategy="",
                members=uncovered or cluster_members,
                source_kind="cluster_fallback",
            )


def record_text(record: dict[str, Any]) -> str:
    parts: list[str] = []
    for field in TEXT_FIELDS:
        value = record.get(field)
        if isinstance(value, list):
            parts.extend(str(item) for item in value)
        elif value:
            parts.append(str(value))
    keywords = record.get("keywords")
    if isinstance(keywords, dict):
        parts.extend(str(value) for value in keywords.values() if value)
    return "\n".join(parts)


def work_item_text(item: WorkItem, structured: dict[str, dict[str, Any]]) -> str:
    parts = [item.cluster_name]
    if item.source_kind == "cluster_fallback":
        parts.append(item.cluster_summary)
    parts.extend(
        [
            item.sub_pattern_name,
            item.sub_pattern_root_cause,
            item.sub_pattern_fix_strategy,
        ]
    )
    for cve_id in item.members:
        if cve_id in structured:
            parts.append(record_text(structured[cve_id]))
    return "\n".join(part for part in parts if part)


def token_set(text: str) -> set[str]:
    return {
        token
        for token in re.findall(r"[a-z0-9][a-z0-9_.-]*[a-z0-9]|[a-z0-9]", text.lower())
        if len(token) >= 3 and token not in STOP_WORDS
    }


def phrase_present(phrase: str, text: str) -> bool:
    phrase = phrase.lower().strip()
    if not phrase:
        return False
    if re.search(r"[^a-z0-9]", phrase):
        return phrase in text.lower()
    return phrase in token_set(text)


def score_mechanism(text: str, mechanism: Mechanism) -> tuple[float, list[str]]:
    lowered = text.lower()
    for required_group in mechanism.required_keywords:
        if not any(phrase_present(keyword, lowered) for keyword in required_group):
            return 0.0, []
    matches: list[str] = []
    score = 0.0
    for keyword in mechanism.keywords:
        if phrase_present(keyword, lowered):
            matches.append(keyword)
            score += 3.0 if " " in keyword or "." in keyword else 1.0
    for alias in mechanism.aliases:
        if phrase_present(alias, lowered):
            matches.append(alias)
            score += 4.0
    family_tokens = token_set(mechanism.family.replace("_", " "))
    overlap = token_set(lowered) & family_tokens
    score += 0.25 * len(overlap)
    return score, sorted(set(matches))


def ranked_mechanisms(
    text: str,
    lexicon: list[Mechanism],
    *,
    min_score: float,
) -> list[tuple[Mechanism, float, list[str]]]:
    scored = []
    for mechanism in lexicon:
        score, matches = score_mechanism(text, mechanism)
        if score >= min_score:
            scored.append((mechanism, score, matches))
    scored.sort(key=lambda item: (-item[1], item[0].mechanism_id))
    return scored


def best_mechanism(text: str, lexicon: list[Mechanism], *, min_score: float) -> tuple[Mechanism | None, float, list[str]]:
    ranked = ranked_mechanisms(text, lexicon, min_score=0.0)
    if not ranked:
        return None, 0.0, []
    mechanism, score, matches = ranked[0]
    if score < min_score:
        return None, score, matches
    return mechanism, score, matches


def evidence_terms(text: str) -> set[str]:
    return token_set(text) - EVIDENCE_STOP_WORDS


def role_evidence_hits(role_text: str, evidence_text: str) -> tuple[str, ...]:
    role_terms = evidence_terms(role_text)
    evidence = evidence_terms(evidence_text)
    return tuple(sorted(role_terms & evidence))


def evidence_support(
    record: dict[str, Any] | None,
    mechanism: Mechanism,
    *,
    lexicon_score: float,
    lexicon_matches: list[str],
    min_roles: int = 2,
    min_terms_per_role: int = 2,
) -> EvidenceSupport:
    if not record:
        return EvidenceSupport(
            supported=False,
            role_hits={},
            role_count=0,
            lexicon_score=lexicon_score,
            lexicon_matches=tuple(lexicon_matches),
        )
    text = record_text(record)
    # Required-keyword constraints must be satisfied by the member CVE evidence
    # itself. Cluster and sub-pattern text can propose a mechanism, but should
    # not make a member releasable when its own structured evidence is thin.
    member_score, member_matches = score_mechanism(text, mechanism)
    if member_score <= 0.0:
        return EvidenceSupport(
            supported=False,
            role_hits={},
            role_count=0,
            lexicon_score=member_score,
            lexicon_matches=tuple(member_matches),
        )
    role_hits: dict[str, tuple[str, ...]] = {}
    for field in EVIDENCE_ROLE_FIELDS:
        hits = role_evidence_hits(str(getattr(mechanism, field) or ""), text)
        if len(hits) >= min_terms_per_role:
            role_hits[field] = hits
    role_count = len(role_hits)
    supported = role_count >= min_roles and bool({"sink_shape", "missing_guard"} & set(role_hits))
    return EvidenceSupport(
        supported=supported,
        role_hits=role_hits,
        role_count=role_count,
        lexicon_score=member_score,
        lexicon_matches=tuple(member_matches),
    )


def aggregate_evidence_support(
    supports: list[EvidenceSupport],
    *,
    score: float,
    matches: list[str],
) -> EvidenceSupport:
    role_hits: dict[str, set[str]] = defaultdict(set)
    for support in supports:
        for role, hits in support.role_hits.items():
            role_hits[role].update(hits)
    aggregated = {role: tuple(sorted(hits)) for role, hits in sorted(role_hits.items())}
    return EvidenceSupport(
        supported=bool(supports) and all(support.supported for support in supports),
        role_hits=aggregated,
        role_count=len(aggregated),
        lexicon_score=score,
        lexicon_matches=tuple(matches),
    )


def top_terms(text: str, *, limit: int = 8) -> list[str]:
    counts = Counter(token for token in token_set(text))
    return [token for token, _ in counts.most_common(limit)]


def pending_mechanism(item: WorkItem, text: str) -> Mechanism:
    name = item.sub_pattern_name or item.cluster_name or "unclassified vulnerability mechanism"
    terms = top_terms(text, limit=12)
    return Mechanism(
        mechanism_id=slugify(f"cluster {item.cluster_id} {name}", prefix="pending_mech"),
        name=name,
        family="pending_review",
        aliases=tuple(terms[:6]),
        keywords=tuple(terms),
        required_keywords=(),
        source_shape="attacker-influenced inputs, resource identities, state values, or configuration described by the member CVEs",
        sink_shape="the sensitive operation or security boundary described by the member CVEs",
        missing_guard="the required validation, authorization, isolation, state check, or binding is absent or not connected to the sensitive effect",
        typical_fix=item.sub_pattern_fix_strategy or "add the required guard and bind it to the exact sensitive effect",
    )


def with_members(item: WorkItem, members: Iterable[str], source_kind: str) -> WorkItem:
    return WorkItem(
        cluster_id=item.cluster_id,
        cluster_name=item.cluster_name,
        cluster_summary=item.cluster_summary,
        sub_pattern_name=item.sub_pattern_name,
        sub_pattern_root_cause=item.sub_pattern_root_cause,
        sub_pattern_fix_strategy=item.sub_pattern_fix_strategy,
        members=normalize_members(members),
        source_kind=source_kind,
    )


def attributed_work_items(
    item: WorkItem,
    structured: dict[str, dict[str, Any]],
    lexicon: list[Mechanism],
    *,
    min_score: float,
) -> list[tuple[WorkItem, Mechanism, str, float, list[str], EvidenceSupport | None]]:
    """Split a cluster/sub-pattern into mechanism-homogeneous work items.

    The cluster remains the source neighborhood, but the emitted guideline
    granularity is driven by per-member mechanism attribution. This lets one
    broad cluster yield separate JNDI, webhook SSRF, and redirect SSRF
    guidelines when its members point to different mechanisms.
    """
    buckets: dict[str, dict[str, Any]] = {}
    pending_members: list[str] = []

    for member in item.members:
        member_item = with_members(item, [member], item.source_kind)
        text = work_item_text(member_item, structured)
        selected: tuple[Mechanism, float, list[str], EvidenceSupport] | None = None
        for mechanism, score, matches in ranked_mechanisms(text, lexicon, min_score=min_score):
            support = evidence_support(
                structured.get(member),
                mechanism,
                lexicon_score=score,
                lexicon_matches=matches,
            )
            if support.supported:
                selected = (mechanism, score, matches, support)
                break
        if selected is None:
            pending_members.append(member)
            continue
        mechanism, score, matches, support = selected
        bucket = buckets.setdefault(
            mechanism.mechanism_id,
            {"mechanism": mechanism, "members": [], "scores": [], "matches": set(), "supports": []},
        )
        bucket["members"].append(member)
        bucket["scores"].append(score)
        bucket["matches"].update(matches)
        bucket["supports"].append(support)

    total_buckets = len(buckets) + (1 if pending_members else 0)
    split_kind = item.source_kind if total_buckets <= 1 else f"{item.source_kind}_mechanism_split"

    output: list[tuple[WorkItem, Mechanism, str, float, list[str], EvidenceSupport | None]] = []
    for bucket in buckets.values():
        members = bucket["members"]
        score = sum(bucket["scores"]) / len(bucket["scores"])
        matches = sorted(bucket["matches"])
        output.append(
            (
                with_members(item, members, split_kind),
                bucket["mechanism"],
                "active",
                score,
                matches,
                aggregate_evidence_support(bucket["supports"], score=score, matches=matches),
            )
        )
    if pending_members:
        pending_item = with_members(item, pending_members, split_kind)
        text = work_item_text(pending_item, structured)
        output.append((pending_item, pending_mechanism(pending_item, text), "pending_review", 0.0, [], None))
    return output


def group_items_by_mechanism(
    items: list[WorkItem],
    structured: dict[str, dict[str, Any]],
    lexicon: list[Mechanism],
    *,
    min_score: float,
    group_scope: str = "cluster-mechanism",
) -> tuple[list[dict[str, Any]], dict[str, list[WorkItem]], dict[str, Mechanism]]:
    if group_scope not in GROUP_SCOPES:
        raise ValueError(f"group_scope must be one of {', '.join(GROUP_SCOPES)}")
    grouped: dict[str, list[WorkItem]] = defaultdict(list)
    mechanisms_by_group: dict[str, Mechanism] = {}
    candidates: list[dict[str, Any]] = []
    for item in items:
        for attributed_item, mechanism, status, score, matches, support in attributed_work_items(
            item,
            structured,
            lexicon,
            min_score=min_score,
        ):
            group_key = guideline_group_key(attributed_item, mechanism, group_scope)
            mechanisms_by_group[group_key] = mechanism
            grouped[group_key].append(attributed_item)
            candidates.append(
                {
                    "guideline_group_key": group_key,
                    "group_scope": group_scope,
                    "cluster_id": attributed_item.cluster_id,
                    "cluster_name": attributed_item.cluster_name,
                    "sub_pattern_name": attributed_item.sub_pattern_name,
                    "source_kind": attributed_item.source_kind,
                    "member_count": len(attributed_item.members),
                    "members": list(attributed_item.members),
                    "mechanism_id": mechanism.mechanism_id,
                    "mechanism_name": mechanism.name,
                    "mechanism_family": mechanism.family,
                    "status": status,
                    "alignment_score": round(score, 3),
                    "matched_terms": matches,
                    "evidence_role_count": support.role_count if support else 0,
                    "evidence_role_hits": {
                        role: list(hits) for role, hits in (support.role_hits if support else {}).items()
                    },
                    "evidence_supported": bool(support.supported) if support else False,
                }
            )
    return candidates, grouped, mechanisms_by_group


def build_guideline_text(mechanism: Mechanism, member_count: int) -> str:
    return (
        f"Trace {mechanism.source_shape} into {mechanism.sink_shape}. "
        f"Report code paths where {mechanism.missing_guard}. "
        f"Confirm that the required guard is enforced on the same source-to-sink path before the sensitive effect. "
        f"Treat this as a reusable mechanism-level pattern derived from {member_count} historical CVE example(s), not as a project-specific signature. "
        f"A safe implementation should {mechanism.typical_fix}."
    )


def preview_text(text: str, limit: int = 240) -> str:
    if len(text) <= limit:
        return text
    return text[:limit].rstrip()


def build_guideline_payload(
    *,
    guideline_id: str,
    guideline_group_key: str,
    group_scope: str,
    mechanism: Mechanism,
    items: list[WorkItem],
    release_status: dict[str, Any],
    source_method: str,
    source_fingerprint: str,
) -> dict[str, Any]:
    member_ids = sorted({member for item in items for member in item.members})
    cluster_ids = sorted({item.cluster_id for item in items})
    sub_patterns = [
        {
            "cluster_id": item.cluster_id,
            "name": item.sub_pattern_name,
            "root_cause": item.sub_pattern_root_cause,
            "fix_strategy": item.sub_pattern_fix_strategy,
            "members": list(item.members),
        }
        for item in items
    ]
    return {
        "guideline_id": guideline_id,
        "guideline_group_key": guideline_group_key,
        "guideline_text": build_guideline_text(mechanism, len(member_ids)),
        "group_scope": group_scope,
        "mechanism": {
            "mechanism_id": mechanism.mechanism_id,
            "name": mechanism.name,
            "family": mechanism.family,
            "aliases": list(mechanism.aliases),
            "required_keywords": [list(group) for group in mechanism.required_keywords],
            "source_shape": mechanism.source_shape,
            "sink_shape": mechanism.sink_shape,
            "missing_guard": mechanism.missing_guard,
            "typical_fix": mechanism.typical_fix,
        },
        "source_cluster_ids": cluster_ids,
        "source_method": source_method,
        "source_fingerprint": source_fingerprint,
        "release_status": release_status,
        "cve_ids": member_ids,
        "cluster_summary": " / ".join(sorted({item.cluster_summary for item in items if item.cluster_summary}))[:1000],
        "sub_patterns": sub_patterns,
        "representative_cve": member_ids[0] if member_ids else "",
        "model_used": "cluster_assisted_mechanism_attribution.v1",
        "tags": [mechanism.family, mechanism.mechanism_id, *list(mechanism.aliases[:4])],
        "embeddings": {},
        "schema_version": "hcvr_audit_guideline.v2",
        "created_at": utc_now(),
    }


def group_candidate_rows(candidates: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    by_group: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in candidates:
        by_group[str(row.get("guideline_group_key") or "")].append(row)
    return by_group


def release_status_for_group(mechanism: Mechanism, candidate_rows: list[dict[str, Any]]) -> dict[str, Any]:
    total_members = sum(int(row.get("member_count") or 0) for row in candidate_rows)
    supported_members = sum(
        int(row.get("member_count") or 0)
        for row in candidate_rows
        if row.get("status") == "active" and row.get("evidence_supported")
    )
    unsupported_members = sorted(
        {
            str(member)
            for row in candidate_rows
            if not (row.get("status") == "active" and row.get("evidence_supported"))
            for member in row.get("members") or []
            if str(member or "")
        }
    )
    role_counts = [
        int(row.get("evidence_role_count") or 0)
        for row in candidate_rows
        if row.get("status") == "active" and row.get("evidence_supported")
    ]
    support_rate = supported_members / total_members if total_members else 0.0
    blockers: list[str] = []
    is_pending = mechanism.family == "pending_review" or mechanism.mechanism_id.startswith("pending_mech_")
    if is_pending:
        blockers.append("pending_mechanism_needs_review")
    if total_members <= 0:
        blockers.append("no_members")
    if supported_members <= 0:
        blockers.append("no_member_level_evidence_support")
    elif support_rate < RELEASE_MIN_MEMBER_SUPPORT_RATE:
        blockers.append("partial_member_level_evidence_support")
    if role_counts and min(role_counts) < RELEASE_MIN_EVIDENCE_ROLES:
        blockers.append("insufficient_evidence_role_coverage")
    return {
        "release_ready": not blockers,
        "status": "release_ready" if not blockers else "review_only",
        "blockers": blockers,
        "member_support_rate": round(support_rate, 4),
        "supported_member_count": supported_members,
        "total_member_count": total_members,
        "unsupported_members": unsupported_members,
        "min_evidence_role_count": min(role_counts) if role_counts else 0,
    }


def load_case_lookup(path: Path | None) -> dict[str, list[dict[str, Any]]]:
    if path is None:
        return {}
    by_cve: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in read_jsonl(path):
        vuln = row.get("vulnerability") or {}
        ids = [vuln.get("id"), *(vuln.get("aliases") or [])]
        for value in ids:
            cve_id = str(value or "").strip()
            if cve_id:
                by_cve[cve_id].append(row)
    return by_cve


def write_outputs(
    *,
    output_dir: Path,
    candidates: list[dict[str, Any]],
    grouped: dict[str, list[WorkItem]],
    mechanisms_by_group: dict[str, Mechanism],
    clustering: dict[str, Any],
    case_lookup: dict[str, list[dict[str, Any]]],
    group_scope: str,
    include_pending_guidelines: bool = False,
    include_pending_overrides: bool = False,
) -> dict[str, Any]:
    if output_dir.exists() and any(output_dir.iterdir()):
        raise FileExistsError(f"refusing to overwrite non-empty output directory: {output_dir}")
    guidelines_dir = output_dir / "guidelines"
    guidelines_dir.mkdir(parents=True, exist_ok=True)
    source_method = str(clustering.get("method") or "unknown")
    all_members = sorted({member for rows in grouped.values() for item in rows for member in item.members})
    fingerprint = sha256_text("\n".join(all_members))

    guideline_rows: list[dict[str, Any]] = []
    review_queue_rows: list[dict[str, Any]] = []
    override_map: dict[str, dict[str, Any]] = {}
    candidate_rows_by_group = group_candidate_rows(candidates)
    if include_pending_overrides:
        include_pending_guidelines = True
    guideline_index = 0
    for idx, group_key in enumerate(sorted(grouped), start=1):
        mechanism = mechanisms_by_group[group_key]
        release_status = release_status_for_group(mechanism, candidate_rows_by_group.get(group_key, []))
        emit_guideline = bool(release_status["release_ready"]) or include_pending_guidelines
        if not emit_guideline:
            member_ids = sorted({member for item in grouped[group_key] for member in item.members})
            review_queue_rows.append(
                {
                    "review_id": f"review_mech_{idx:04d}",
                    "guideline_group_key": group_key,
                    "guideline_text": build_guideline_text(mechanism, len(member_ids)),
                    "mechanism": {
                        "mechanism_id": mechanism.mechanism_id,
                        "name": mechanism.name,
                        "family": mechanism.family,
                        "source_shape": mechanism.source_shape,
                        "sink_shape": mechanism.sink_shape,
                        "missing_guard": mechanism.missing_guard,
                        "typical_fix": mechanism.typical_fix,
                    },
                    "source_cluster_ids": sorted({item.cluster_id for item in grouped[group_key]}),
                    "cve_ids": member_ids,
                    "cluster_summary": " / ".join(
                        sorted({item.cluster_summary for item in grouped[group_key] if item.cluster_summary})
                    )[:1000],
                    "release_status": release_status,
                    "candidate_rows": candidate_rows_by_group.get(group_key, []),
                }
            )
            continue
        guideline_index += 1
        guideline_id = f"gl_mech_{guideline_index:04d}"
        payload = build_guideline_payload(
            guideline_id=guideline_id,
            guideline_group_key=group_key,
            group_scope=group_scope,
            mechanism=mechanism,
            items=grouped[group_key],
            release_status=release_status,
            source_method=source_method,
            source_fingerprint=fingerprint,
        )
        guideline_file = guidelines_dir / f"{guideline_id}.json"
        write_json(guideline_file, payload)
        is_pending = mechanism.family == "pending_review" or mechanism.mechanism_id.startswith("pending_mech_")
        guideline_rows.append(
            {
                "guideline_id": guideline_id,
                "guideline_group_key": group_key,
                "file_name": guideline_file.name,
                "mechanism_id": mechanism.mechanism_id,
                "mechanism_name": mechanism.name,
                "mechanism_family": mechanism.family,
                "release_ready": release_status["release_ready"],
                "release_blockers": release_status["blockers"],
                "member_support_rate": release_status["member_support_rate"],
                "source_cluster_ids": payload["source_cluster_ids"],
                "cve_count": len(payload["cve_ids"]),
                "top_tags": payload["tags"][:8],
                "guideline_preview": preview_text(payload["guideline_text"]),
            }
        )
        if (is_pending or not release_status["release_ready"]) and not include_pending_overrides:
            continue
        for cve_id in payload["cve_ids"]:
            for case in case_lookup.get(cve_id, []):
                key = str(case.get("identity_key") or case.get("new_unified_case_id") or "")
                if not key:
                    continue
                row = override_map.setdefault(
                    key,
                    {
                        "identity_key": case.get("identity_key"),
                        "case_id": case.get("new_unified_case_id"),
                        "cve_ids": [],
                        "guideline_ids": [],
                        "mechanism_ids": [],
                        "mechanism_names": [],
                        "retrieval_guidelines": [],
                    },
                )
                row["cve_ids"].append(cve_id)
                row["guideline_ids"].append(guideline_id)
                row["mechanism_ids"].append(mechanism.mechanism_id)
                row["mechanism_names"].append(mechanism.name)
                row["retrieval_guidelines"].append(payload["guideline_text"])

    override_rows: list[dict[str, Any]] = []
    for row in override_map.values():
        for field in ("cve_ids", "guideline_ids", "mechanism_ids", "mechanism_names", "retrieval_guidelines"):
            row[field] = list(dict.fromkeys(row[field]))
        row["retrieval_guideline"] = "\n\n".join(row.pop("retrieval_guidelines"))
        override_rows.append(row)

    active = sum(1 for row in candidates if row["status"] == "active")
    pending = sum(1 for row in candidates if row["status"] == "pending_review")
    release_ready_guidelines = sum(1 for row in guideline_rows if row["release_ready"])
    review_only_guidelines = len(guideline_rows) - release_ready_guidelines
    summary = {
        "schema_version": "hcvr_mechanism_guideline_release.v1",
        "created_at": utc_now(),
        "source_method": source_method,
        "source_fingerprint": fingerprint,
        "group_scope": group_scope,
        "work_item_count": len(candidates),
        "active_attribution_count": active,
        "pending_review_count": pending,
        "guideline_count": len(guideline_rows),
        "release_ready_guideline_count": release_ready_guidelines,
        "review_only_guideline_count": review_only_guidelines,
        "review_queue_count": len(review_queue_rows),
        "override_count": len(override_rows),
        "pending_guidelines_included": include_pending_guidelines,
        "pending_overrides_included": include_pending_overrides,
        "files": {
            "mechanism_candidates": "mechanism_candidates.jsonl",
            "review_queue": "review_queue.jsonl" if review_queue_rows else None,
            "guideline_overrides": "guideline_overrides.jsonl" if override_rows else None,
            "index": "index.json",
        },
    }
    write_jsonl(output_dir / "mechanism_candidates.jsonl", candidates)
    if review_queue_rows:
        write_jsonl(output_dir / "review_queue.jsonl", review_queue_rows)
    if override_rows:
        write_jsonl(output_dir / "guideline_overrides.jsonl", override_rows)
    write_json(output_dir / "index.json", {"summary": summary, "items": guideline_rows})
    write_json(output_dir / "summary.json", summary)
    write_readme(output_dir, summary, guideline_rows, candidates)
    return summary


def write_readme(
    output_dir: Path,
    summary: dict[str, Any],
    guideline_rows: list[dict[str, Any]],
    candidates: list[dict[str, Any]],
) -> None:
    lines = [
        "# Mechanism Guideline Release",
        "",
        "This directory was generated by `generate_mechanism_guidelines.py`.",
        "It is an offline cluster-assisted mechanism-attribution artifact, not an online source-code keyword scanner.",
        "",
        "## Summary",
        "",
        f"- Work items: {summary['work_item_count']}",
        f"- Guidelines: {summary['guideline_count']}",
        f"- Group scope: `{summary['group_scope']}`",
        f"- Active lexicon attributions: {summary['active_attribution_count']}",
        f"- Pending review attributions: {summary['pending_review_count']}",
        f"- Release-ready guidelines: {summary['release_ready_guideline_count']}",
        f"- Review-only guidelines in index: {summary['review_only_guideline_count']}",
        f"- Review queue rows outside index: {summary['review_queue_count']}",
        f"- Recall sidecar rows: {summary['override_count']}",
        f"- Pending review included in guideline index: {summary['pending_guidelines_included']}",
        f"- Pending review included in recall sidecar: {summary['pending_overrides_included']}",
        "",
        "## Guideline Preview",
        "",
    ]
    for row in guideline_rows[:10]:
        lines.extend(
            [
                f"### {row['guideline_id']} - {row['mechanism_name']}",
                "",
                f"- Mechanism: `{row['mechanism_id']}`",
                f"- Group: `{row['guideline_group_key']}`",
                f"- Family: `{row['mechanism_family']}`",
                f"- Release ready: `{row['release_ready']}`",
                f"- CVEs: {row['cve_count']}",
                f"- Preview: {row['guideline_preview']}",
                "",
            ]
        )
    pending = [row for row in candidates if row["status"] == "pending_review"]
    if pending:
        lines.extend(["## Pending Review", ""])
        lines.append(
            "Pending rows are review-only by default. They stay in `mechanism_candidates.jsonl` "
            "and `review_queue.jsonl`, but are not emitted into `guidelines/`, `index.json`, "
            "or `guideline_overrides.jsonl` unless the ablation flags are used."
        )
        lines.append("")
        for row in pending[:20]:
            cluster_id = row.get("cluster_id", "unknown")
            sub_pattern_name = row.get("sub_pattern_name") or row.get("mechanism_name") or "unknown"
            lines.append(
                f"- cluster {cluster_id} / {sub_pattern_name}: "
                f"{row.get('mechanism_name', 'unknown')} ({row.get('member_count', 0)} CVE)"
            )
        lines.append("")
    output_dir.joinpath("README.md").write_text("\n".join(lines), encoding="utf-8")


def generate(args: argparse.Namespace) -> dict[str, Any]:
    clustering = read_json(args.clusters)
    structured = load_structured(args.structured)
    lexicon = merge_lexicons([args.lexicon, *args.extra_lexicon])
    items = list(iter_work_items(clustering))
    if not items:
        raise ValueError(f"no cluster or sub-pattern work items in {args.clusters}")
    candidates, grouped, mechanisms_by_group = group_items_by_mechanism(
        items,
        structured,
        lexicon,
        min_score=args.min_score,
        group_scope=args.group_scope,
    )
    return write_outputs(
        output_dir=args.output_dir,
        candidates=candidates,
        grouped=grouped,
        mechanisms_by_group=mechanisms_by_group,
        clustering=clustering,
        case_lookup=load_case_lookup(args.cases_file),
        group_scope=args.group_scope,
        include_pending_guidelines=args.include_pending_guidelines,
        include_pending_overrides=args.include_pending_overrides,
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--clusters", type=Path, required=True, help="Refined cve_clustering ClusteringOutput JSON.")
    parser.add_argument("--structured", type=Path, required=True, help="Structured CVE JSONL used by the clustering run.")
    parser.add_argument(
        "--lexicon",
        type=Path,
        default=Path(__file__).parents[1] / "guidelines" / "mechanism_lexicon.seed.json",
        help="Versioned mechanism lexicon JSON.",
    )
    parser.add_argument(
        "--extra-lexicon",
        type=Path,
        action="append",
        default=[],
        help="Additional review-approved mechanism lexicon JSON. May be repeated.",
    )
    parser.add_argument("--cases-file", type=Path, help="Optional HCVR case JSONL used to emit guideline_overrides.jsonl.")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--min-score", type=float, default=2.0, help="Minimum lexicon alignment score for active attribution.")
    parser.add_argument(
        "--include-pending-guidelines",
        action="store_true",
        help=(
            "Also write pending_review mechanisms into guidelines/ and index.json for review ablations. "
            "By default, pending groups stay in mechanism_candidates.jsonl/review_queue.jsonl only."
        ),
    )
    parser.add_argument(
        "--include-pending-overrides",
        action="store_true",
        help=(
            "Also emit pending_review guidelines into guideline_overrides.jsonl. "
            "This implies --include-pending-guidelines. By default, pending groups stay "
            "outside the release index and recall sidecars to avoid query pollution."
        ),
    )
    parser.add_argument(
        "--group-scope",
        choices=GROUP_SCOPES,
        default="cluster-mechanism",
        help=(
            "Guideline grouping boundary. The default keeps clustering as the local "
            "evidence neighborhood and splits mechanisms per source cluster; "
            "'mechanism' reproduces the old global same-mechanism aggregation."
        ),
    )
    args = parser.parse_args()
    summary = generate(args)
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
