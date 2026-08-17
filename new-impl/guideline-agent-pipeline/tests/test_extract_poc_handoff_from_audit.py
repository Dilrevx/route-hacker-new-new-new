from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


SCRIPT = Path(__file__).parents[1] / "scripts" / "extract_poc_handoff_from_audit.py"


def load_module():
    spec = importlib.util.spec_from_file_location("extract_poc_handoff", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_extract_file_lines_deduplicates_supported_source_locations():
    module = load_module()
    locations = module.extract_file_lines(
        "Check src/App.java:42 and then src/App.java:42. "
        "Effect is backend/routers/files.py line 640."
    )
    assert locations == [
        {"file": "src/App.java", "line": 42},
        {"file": "backend/routers/files.py", "line": 640},
    ]


def test_build_handoff_rows_keeps_only_completed_risk_reports(tmp_path: Path):
    module = load_module()
    report = tmp_path / "risk.md"
    report.write_text(
        "Missing check at src/App.java:42; sensitive effect at src/App.java:57.\n"
        "Decision: risk\nConfidence: 0.91\n",
        encoding="utf-8",
    )
    audit_index = tmp_path / "audit_index.jsonl"
    rows = [
        {
            "identity_key": "owner__repo::CVE-1",
            "case_id": "case::1",
            "hcvr_type": "authorization_bypass",
            "repo_url": "https://github.com/owner/repo.git",
            "checkout_revision": "a" * 40,
            "anchor_id": "anchor::1",
            "file": "src/App.java",
            "start_line": 40,
            "end_line": 60,
            "state": "completed",
            "decision": "risk",
            "confidence": 0.91,
            "report": str(report),
            "events": str(tmp_path / "events.jsonl"),
        },
        {
            "identity_key": "owner__repo::CVE-2",
            "state": "completed",
            "decision": "no-risk",
            "report": str(report),
        },
    ]
    audit_index.write_text(
        "".join(json.dumps(row) + "\n" for row in rows),
        encoding="utf-8",
    )
    handoff = module.build_handoff_rows(audit_index)
    assert len(handoff) == 1
    assert handoff[0]["identity_key"] == "owner__repo::CVE-1"
    assert handoff[0]["candidate_instrumentation_locations"] == [
        {"file": "src/App.java", "line": 42},
        {"file": "src/App.java", "line": 57},
    ]
