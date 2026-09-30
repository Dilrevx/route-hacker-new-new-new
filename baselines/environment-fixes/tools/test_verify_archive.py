import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import export_legacy
import verify_archive as verify


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "file.txt").write_bytes(b"recipe\n")
        self.entry = {"path": "file.txt", "bytes": 7,
                      "sha256": hashlib.sha256(b"recipe\n").hexdigest()}

    def test_valid(self):
        self.assertEqual(verify.verify_entries(self.root, [self.entry]), {"files": 1, "bytes": 7})

    def test_mutation_detected(self):
        (self.root / "file.txt").write_bytes(b"broken\n")
        with self.assertRaisesRegex(ValueError, "Hash mismatch"):
            verify.verify_entries(self.root, [self.entry])

    def test_missing_detected(self):
        with self.assertRaisesRegex(ValueError, "Missing"):
            verify.verify_entries(self.root, [dict(self.entry, path="missing")])

    def test_duplicate_detected(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            verify.verify_entries(self.root, [self.entry, self.entry])

    def test_path_traversal(self):
        for name in ("../file.txt", "/file.txt", "a/../../file.txt", "a\\b", "./file.txt", ""):
            with self.subTest(name=name), self.assertRaises(ValueError):
                verify.safe_path(self.root, name)

    def test_symlink_rejected(self):
        (self.root / "link").symlink_to(self.root / "file.txt")
        with self.assertRaisesRegex(ValueError, "Symlink"):
            verify.safe_path(self.root, "link")

    def test_invalid_size(self):
        with self.assertRaisesRegex(ValueError, "Invalid size"):
            verify.verify_entries(self.root, [dict(self.entry, bytes=True)])

    def test_duplicate_json(self):
        path = self.root / "bad.json"
        path.write_text('{"a":1,"a":2}')
        with self.assertRaisesRegex(ValueError, "Duplicate JSON"):
            verify.read_json(path)

    def test_legacy_member_paths(self):
        self.assertEqual(str(export_legacy.safe_member("./repo/rev/Dockerfile")), "repo/rev/Dockerfile")
        for name in ("../repo/rev/Dockerfile", "/repo/rev/Dockerfile", "repo/rev/key.pem"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                export_legacy.safe_member(name)

    def test_numeric_not_commit(self):
        self.assertIn("not_resolved", export_legacy.identifier_kind("42"))

    def held_fixture(self):
        entries = [{"sha256": f"{i:064x}", "reason": "held"} for i in range(95)]
        for row in entries[2:]:
            row["source_provenance"] = "historical/input"
        return {"not_included": 95, "files": entries}

    def test_held_public_intersection(self):
        with self.assertRaisesRegex(ValueError, "Withheld content"):
            verify.validate_held(self.held_fixture(), [{"sha256": f"{0:064x}"}])

    def test_sensitive_held_metadata(self):
        held = self.held_fixture()
        held["files"][0]["source_provenance"] = "unexpected-sensitive-name"
        with self.assertRaisesRegex(ValueError, "Sensitive held metadata"):
            verify.validate_held(held, [])

    def test_held_valid(self):
        verify.validate_held(self.held_fixture(), [{"sha256": f"{100:064x}"}])

    def status_fixture(self):
        return [
            {"case_id": "superset-cve2017-18342", "origin_label": "superset_base_and_patched_control"},
            {"case_id": "superset-cve2020-14343", "origin_label": "superset_base_and_patched_control"},
            {"case_id": "apache_pulsar__CVE-2021-44228__source_inserted", "recorded_verdicts": [
                {"source_record": "runtime-source-runner-verify.json", "recorded": {"status": "TP_RUNTIME_VERIFIED_SOURCE_RUNNER"}},
                {"source_record": "runtime-source-verify.json", "recorded": {"status": "FAILED"}},
            ]},
        ]

    def test_pulsar_failure_not_overwritten(self):
        cases = self.status_fixture()
        cases[-1]["recorded_verdicts"][-1]["recorded"]["status"] = "TP_CONFIRMED"
        with self.assertRaisesRegex(ValueError, "Pulsar runtime failure"):
            verify.validate_source_runtime_status(cases)

    def test_pulsar_runner_not_runtime(self):
        cases = self.status_fixture()
        cases[-1]["recorded_verdicts"].pop()
        with self.assertRaisesRegex(ValueError, "Pulsar runtime failure"):
            verify.validate_source_runtime_status(cases)

    def test_superset_origin_preserved(self):
        cases = self.status_fixture()
        cases[0]["origin_label"] = "unrelated"
        with self.assertRaisesRegex(ValueError, "Superset control"):
            verify.validate_source_runtime_status(cases)

    def test_status_valid(self):
        verify.validate_source_runtime_status(self.status_fixture())

    def test_unlisted_payload_rejected(self):
        (self.root / "files").mkdir()
        (self.root / "files/held").write_text("not public")
        with self.assertRaisesRegex(ValueError, "Payload contains"):
            verify.verify_payload_coverage(self.root, "files", [])


if __name__ == "__main__":
    unittest.main()
