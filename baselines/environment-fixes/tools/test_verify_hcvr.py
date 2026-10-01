import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import verify_hcvr


class HcvrArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.case = {"case_id": "example", "new_execution_performed": False, "records": [
            {"source": {"source_id": "src1", "pointer": "/0"},
             "historical_status": {"status": "database_repaired"},
             "evidence_level": "recorded_database_repaired", "new_execution_performed": False}]}
        self.index = {"case_count": 1, "record_count": 1, "cases": [
            {"case_id": "example", "path": "cases/example.json", "record_count": 1,
             "evidence_counts": {"recorded_database_repaired": 1}}]}

    def write(self, rel, value):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))

    def seal(self):
        self.write("cases/example.json", self.case)
        self.write("case-index.json", self.index)
        self.write("source-provenance.json", {"sources": [
            {"source_id": "src1", "source_relative_path": "v10/receipt.json",
             "bytes": 2, "sha256": "0" * 64}]})
        entries = []
        for path in sorted(self.root.rglob("*.json")):
            if path.name == "file-manifest.json":
                continue
            data = path.read_bytes()
            entries.append({"path": path.relative_to(self.root).as_posix(), "bytes": len(data),
                            "sha256": hashlib.sha256(data).hexdigest()})
        self.write("file-manifest.json", {"files": entries})

    def test_valid(self):
        self.seal()
        self.assertEqual(verify_hcvr.verify(self.root)["records"], 1)

    def test_unbound_source(self):
        self.case["records"][0]["source"]["source_id"] = "missing"
        self.seal()
        with self.assertRaisesRegex(ValueError, "Unbound"):
            verify_hcvr.verify(self.root)

    def test_success_count_cannot_change(self):
        self.case["records"][0]["evidence_level"] = "failed"
        self.seal()
        with self.assertRaisesRegex(ValueError, "Evidence count"):
            verify_hcvr.verify(self.root)

    def test_historical_not_fresh(self):
        self.case["new_execution_performed"] = True
        self.seal()
        with self.assertRaisesRegex(ValueError, "Historical result"):
            verify_hcvr.verify(self.root)

    def test_unlisted_payload(self):
        self.seal()
        self.write("extra.json", {})
        with self.assertRaisesRegex(ValueError, "coverage"):
            verify_hcvr.verify(self.root)

    def test_manifest_mutation(self):
        self.seal()
        self.write("cases/example.json", {})
        with self.assertRaises(ValueError):
            verify_hcvr.verify(self.root)

    def test_unbound_duplicate_source(self):
        self.case["records"][0]["duplicate_source_references"] = [{"source_id": "missing", "pointer": "/1"}]
        self.seal()
        with self.assertRaisesRegex(ValueError, "Unbound duplicate"):
            verify_hcvr.verify(self.root)

    def test_nested_verification_not_hidden(self):
        self.seal()
        self.write("cases/verification.json", {})
        with self.assertRaisesRegex(ValueError, "coverage"):
            verify_hcvr.verify(self.root)


if __name__ == "__main__":
    unittest.main()
