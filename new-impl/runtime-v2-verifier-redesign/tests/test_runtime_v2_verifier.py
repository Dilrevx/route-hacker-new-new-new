from __future__ import annotations

import urllib.error
from pathlib import Path
from unittest.mock import patch

from gca.runtime_v2.verifier import RuntimeVerifier


def test_probe_retries_transient_failure_until_ready(tmp_path: Path) -> None:
    verifier = RuntimeVerifier(probe_poll_seconds=0.001)
    results = iter(
        [
            {"type": "http", "passed": False, "error": "connection reset"},
            {"type": "http", "passed": True, "status": 200},
        ]
    )
    verifier._run_probe_once = lambda **_: next(results)  # type: ignore[method-assign]

    result = verifier._run_probe(
        attempt_dir=tmp_path,
        probe={
            "type": "http",
            "url": "http://127.0.0.1:8080/",
            "timeout_seconds": 1,
        },
    )

    assert result["passed"] is True
    assert result["attempts"] == 2
    assert result["elapsed_seconds"] >= 0


def test_http_404_counts_as_reachable_service(tmp_path: Path) -> None:
    verifier = RuntimeVerifier(probe_poll_seconds=0.001)
    error = urllib.error.HTTPError(
        "http://127.0.0.1:8080/",
        404,
        "not found",
        {},
        None,
    )

    with patch("urllib.request.urlopen", side_effect=error):
        result = verifier._run_probe(
            attempt_dir=tmp_path,
            probe={
                "type": "http",
                "url": "http://127.0.0.1:8080/",
                "timeout_seconds": 0.01,
            },
        )

    assert result["passed"] is True
    assert result["status"] == 404
    assert result["attempts"] == 1
