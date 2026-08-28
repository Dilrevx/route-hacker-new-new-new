from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


SCRIPT = (
    Path(__file__).parents[1]
    / "scripts"
    / "derive_guideline_from_audit.py"
)


def load_module():
    spec = importlib.util.spec_from_file_location("derive_openmeetings_guideline", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def risk_report() -> str:
    return """
The anchor in BaseWebService.java leads to RoomWebService.hash() line 563.
performCall(sid, User.Right.SOAP, ...) checks SOAP/interface permission, but
the sensitive effect creates an invitation for a request-supplied roomId. The
RoomMapper.get() path loads the Room and inviteDao.update(i) persists the
invitation without proving object-level permission for that specific room.

Decision: risk
Confidence: 0.84
""".lstrip()


def test_derives_retrieval_yaml_and_cve_clustering_artifact(tmp_path: Path):
    module = load_module()
    report = tmp_path / "rank-0005.md"
    report.write_text(risk_report(), encoding="utf-8")
    output = tmp_path / "derived"

    args = type(
        "Args",
        (),
        {
            "audit_report": report,
            "output_dir": output,
            "track_id": "openmeetings_invitation_object_authorization",
            "min_confidence": 0.5,
        },
    )()
    summary = module.derive(args)

    tracks = (output / "guideline_tracks.yaml").read_text(encoding="utf-8")
    guideline = summary["guideline_text"]
    assert "track_id: openmeetings_invitation_object_authorization" in tracks
    assert "request-supplied object identifier" in guideline
    assert "object-level permission" in guideline
    for leaked in (
        "OpenMeetings",
        "RoomWebService",
        "BaseWebService",
        "RoomMapper",
        "inviteDao",
        "SOAP",
        "roomId",
        ".java",
        "563",
    ):
        assert leaked not in guideline

    latest = json.loads(
        (output / "cve_clustering_guidelines" / "latest.json").read_text(encoding="utf-8")
    )
    index = json.loads(
        (output / "cve_clustering_guidelines" / latest["latest_index"]).read_text(
            encoding="utf-8"
        )
    )
    item = index["items"][0]
    payload = json.loads(
        (output / "cve_clustering_guidelines" / "guidelines" / item["file_name"]).read_text(
            encoding="utf-8"
        )
    )
    assert payload["guideline_id"] == "openmeetings_invitation_object_authorization"
    assert payload["guideline_text"] == guideline
    assert payload["source_method"] == "llm_native"
    assert "interface_permission_object_effect" in payload["tags"]


def test_rejects_no_risk_report(tmp_path: Path):
    module = load_module()
    report = tmp_path / "rank-0001.md"
    report.write_text(
        """
This anchor delegates authorization to a resource layer and no concrete missing
object authorization decision is proven.

Decision: no-risk
Confidence: 0.72
""".lstrip(),
        encoding="utf-8",
    )
    output = tmp_path / "derived"
    args = type(
        "Args",
        (),
        {
            "audit_report": report,
            "output_dir": output,
            "track_id": "x",
            "min_confidence": 0.5,
        },
    )()
    try:
        module.derive(args)
    except ValueError as exc:
        assert "only risk audit reports" in str(exc)
    else:
        raise AssertionError("no-risk report should not seed a guideline")


def test_requires_machine_readable_footer():
    module = load_module()
    try:
        module.parse_audit_report("risk maybe, confidence high")
    except ValueError as exc:
        assert "Decision" in str(exc)
    else:
        raise AssertionError("missing footer should fail")
