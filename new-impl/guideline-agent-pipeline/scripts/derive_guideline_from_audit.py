#!/usr/bin/env python3
"""Derive a retrieval guideline from a free-form risk audit report."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DECISION_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?(?:\*\*)?Decision(?:\*\*)?\s*:\s*"
    r"(?:\*\*)?(risk|no-risk)(?:\*\*)?\s*$"
)
CONFIDENCE_RE = re.compile(
    r"(?im)^\s*(?:[-*]\s*)?(?:\*\*)?Confidence(?:\*\*)?\s*:\s*"
    r"(?:\*\*)?(0(?:\.\d+)?|1(?:\.0+)?)(?:\*\*)?\s*$"
)

PROJECT_SPECIFIC_RE = re.compile(
    r"(?i)"
    r"(openmeetings|RoomWebService|BaseWebService|RoomMapper|RoomDao|InviteDao|"
    r"performCall|User\.Right\.SOAP|SOAP|roomId|room|invite|invitation|sid|"
    r"[A-Za-z0-9_/.-]+\.java|line\s+\d+|\b\d{2,5}\b)"
)

GUIDELINE_TEMPLATES = {
    "interface_permission_object_effect": (
        "Find endpoints where a caller-level permission authorizes access to an "
        "interface, API, service, or transport, but the sensitive effect uses a "
        "request-supplied object identifier and does not verify that the current "
        "principal has object-level permission for that specific object. Treat "
        "creation, modification, sharing, deletion, invitation, membership, "
        "ownership, or capability issuance as sensitive effects when they bind "
        "another principal or object. The audit should confirm that the same "
        "principal and object are carried from the authorization decision to the "
        "effect, rather than relying only on a broad API/session permission."
    ),
    "generic_object_authorization": (
        "Find endpoints where a request names a mutable application object and "
        "then performs a sensitive effect on that object without a correct "
        "authorization decision for the current principal and the requested "
        "object. The audit should distinguish broad login, API, role, or session "
        "checks from object-scoped permission checks, and should verify that the "
        "authorization decision is propagated to the exact object affected by the "
        "effect."
    ),
}


@dataclass(frozen=True)
class ParsedAudit:
    decision: str
    confidence: float
    body: str


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def parse_audit_report(text: str) -> ParsedAudit:
    decisions = DECISION_RE.findall(text)
    confidences = CONFIDENCE_RE.findall(text)
    if not decisions:
        raise ValueError("audit report is missing a machine-readable Decision footer")
    if not confidences:
        raise ValueError("audit report is missing a machine-readable Confidence footer")
    body = DECISION_RE.sub("", text)
    body = CONFIDENCE_RE.sub("", body).strip()
    return ParsedAudit(
        decision=decisions[-1].lower(),
        confidence=float(confidences[-1]),
        body=body,
    )


def classify_pattern(body: str) -> str:
    lowered = body.lower()
    broad_permission = any(
        token in lowered
        for token in (
            "soap",
            "api",
            "interface",
            "service-level",
            "transport",
            "caller-level",
            "session",
        )
    )
    object_effect = any(
        token in lowered
        for token in (
            "object-level",
            "object scoped",
            "room",
            "roomid",
            "invite",
            "invitation",
            "request-supplied",
            "specific object",
        )
    )
    if broad_permission and object_effect:
        return "interface_permission_object_effect"
    return "generic_object_authorization"


def redact_project_specifics(text: str) -> str:
    text = PROJECT_SPECIFIC_RE.sub("", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def extract_evidence_preview(body: str) -> str:
    sentences = re.split(r"(?<=[.!?。！？])\s+", body)
    kept: list[str] = []
    for sentence in sentences:
        lowered = sentence.lower()
        if any(token in lowered for token in ("authorization", "permission", "sensitive", "risk")):
            redacted = redact_project_specifics(sentence)
            if redacted:
                kept.append(redacted)
        if len(kept) == 3:
            break
    return " ".join(kept)[:600]


def yaml_quote(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def write_yaml_track(path: Path, *, track_id: str, display_name: str, guideline_text: str, metadata: dict[str, Any]) -> None:
    lines = [
        "tracks:",
        f"  - track_id: {track_id}",
        f"    display_name: {yaml_quote(display_name)}",
        f"    guideline_text: {yaml_quote(guideline_text)}",
        "    metadata:",
    ]
    for key in sorted(metadata):
        value = metadata[key]
        if isinstance(value, (int, float)):
            rendered = str(value)
        else:
            rendered = yaml_quote(str(value))
        lines.append(f"      {key}: {rendered}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def guideline_json(track_id: str, guideline_text: str, parsed: ParsedAudit, pattern_id: str, evidence_preview: str) -> dict[str, Any]:
    report_hash = sha256_text(parsed.body)
    return {
        "guideline_id": track_id,
        "guideline_text": guideline_text,
        "source_cluster_id": 0,
        "source_method": "llm_native",
        "source_fingerprint": report_hash,
        "cve_ids": [],
        "cluster_summary": evidence_preview,
        "sub_patterns": [],
        "representative_cve": "",
        "model_used": "audit_report_derived_deterministic_v1",
        "tags": [
            "authorization",
            "object_scope",
            "interface_permission",
            pattern_id,
        ],
        "embeddings": {},
        "schema_version": "1.0",
        "created_at": utc_now(),
    }


def derive(args: argparse.Namespace) -> dict[str, Any]:
    report_path = args.audit_report.resolve()
    output_dir = args.output_dir.resolve()
    if output_dir.exists() and any(output_dir.iterdir()):
        raise FileExistsError(f"refusing to overwrite non-empty output directory: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)

    text = report_path.read_text(encoding="utf-8")
    parsed = parse_audit_report(text)
    if parsed.decision != "risk":
        raise ValueError("only risk audit reports can seed a new retrieval guideline")
    if parsed.confidence < args.min_confidence:
        raise ValueError(
            f"audit confidence {parsed.confidence:.2f} is below threshold {args.min_confidence:.2f}"
        )

    pattern_id = classify_pattern(parsed.body)
    guideline_text = GUIDELINE_TEMPLATES[pattern_id]
    evidence_preview = extract_evidence_preview(parsed.body)
    track = args.track_id

    tracks_path = output_dir / "guideline_tracks.yaml"
    metadata = {
        "derived_from_report": str(report_path),
        "audit_decision": parsed.decision,
        "audit_confidence": parsed.confidence,
        "pattern_id": pattern_id,
        "source_report_sha256": sha256_text(text),
        "leakage_policy": "project names, file names, line numbers, and concrete functions are excluded from guideline_text",
    }
    write_yaml_track(
        tracks_path,
        track_id=track,
        display_name="Object-scoped authorization after broad interface permission",
        guideline_text=guideline_text,
        metadata=metadata,
    )

    guidelines_dir = output_dir / "cve_clustering_guidelines" / "guidelines"
    guidelines_dir.mkdir(parents=True, exist_ok=True)
    guideline_payload = guideline_json(track, guideline_text, parsed, pattern_id, evidence_preview)
    guideline_file = guidelines_dir / f"{track}.json"
    guideline_file.write_text(
        json.dumps(guideline_payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    index = {
        "schema_version": "1.0",
        "created_at": utc_now(),
        "source_fingerprint": guideline_payload["source_fingerprint"],
        "model_used": guideline_payload["model_used"],
        "total": 1,
        "items": [
            {
                "guideline_id": track,
                "file_name": guideline_file.name,
                "source_cluster_id": 0,
                "source_method": "llm_native",
                "cve_count": 0,
                "representative_cve": "",
                "size": 0,
                "top_tags": guideline_payload["tags"][:8],
                "cluster_summary_preview": evidence_preview[:200],
            }
        ],
    }
    index_path = output_dir / "cve_clustering_guidelines" / "index.json"
    index_path.write_text(json.dumps(index, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    latest = {
        "schema_version": "1.0",
        "created_at": utc_now(),
        "latest_index": "index.json",
        "source_fingerprint": guideline_payload["source_fingerprint"],
    }
    latest_path = output_dir / "cve_clustering_guidelines" / "latest.json"
    latest_path.write_text(json.dumps(latest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    summary = {
        "schema_version": "openmeetings_audit_derived_guideline_v1",
        "created_at": utc_now(),
        "track_id": track,
        "guideline_text": guideline_text,
        "pattern_id": pattern_id,
        "audit_decision": parsed.decision,
        "audit_confidence": parsed.confidence,
        "inputs": {
            "audit_report": str(report_path),
            "audit_report_sha256": sha256_text(text),
        },
        "outputs": {
            "guideline_tracks": str(tracks_path),
            "cve_clustering_latest": str(latest_path),
            "cve_clustering_index": str(index_path),
            "cve_clustering_guideline": str(guideline_file),
        },
        "boundary": {
            "uses_target_locations": False,
            "guideline_text_contains_project_identifiers": False,
            "requires_risk_decision": True,
            "minimum_confidence": args.min_confidence,
        },
    }
    (output_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    root.add_argument("--audit-report", type=Path, required=True)
    root.add_argument("--output-dir", type=Path, required=True)
    root.add_argument(
        "--track-id",
        default="object_scoped_authorization_after_interface_permission",
    )
    root.add_argument("--min-confidence", type=float, default=0.50)
    return root


def main() -> None:
    args = parser().parse_args()
    summary = derive(args)
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
