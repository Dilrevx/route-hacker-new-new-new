"""Adversarial unit tests for the archive verifier (standard library only)."""

import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import verify_baseline as verifier


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.file = self.root / "p3c64/example.json"
        self.file.parent.mkdir()
        self.file.write_bytes(b'{"a": 1}\n')
        self.entry = {"path": "p3c64/example.json", "bytes": self.file.stat().st_size,
                      "sha256": verifier.sha256(self.file)}
        self.manifest = self.root / "archive-manifest.json"
        self.save([self.entry])

    def save(self, entries):
        self.manifest.write_text(json.dumps({"schema_version": "test.v1", "files": entries}), encoding="utf-8")

    def test_valid_manifest(self):
        result = verifier.verify_manifest(self.root, self.manifest)
        self.assertEqual(result["file_count"], 1)
        self.assertEqual(result["bytes"], self.entry["bytes"])

    def test_same_length_hash_tampering(self):
        self.file.write_bytes(b'{"a": 2}\n')
        with self.assertRaisesRegex(verifier.VerificationError, "SHA-256"):
            verifier.verify_manifest(self.root, self.manifest)

    def test_size_tampering(self):
        self.file.write_bytes(b"changed")
        with self.assertRaisesRegex(verifier.VerificationError, "bytes"):
            verifier.verify_manifest(self.root, self.manifest)

    def test_missing_file(self):
        self.file.unlink()
        with self.assertRaisesRegex(verifier.VerificationError, "missing archive file"):
            verifier.verify_manifest(self.root, self.manifest)

    def test_unlisted_file(self):
        (self.file.parent / "extra").write_bytes(b"extra")
        with self.assertRaisesRegex(verifier.VerificationError, "coverage mismatch"):
            verifier.verify_manifest(self.root, self.manifest)

    def test_duplicate_path(self):
        self.save([self.entry, self.entry])
        with self.assertRaisesRegex(verifier.VerificationError, "duplicate manifest path"):
            verifier.verify_manifest(self.root, self.manifest)

    def test_unsafe_paths(self):
        for name in ("../secret", "/tmp/secret", "p3c64/../secret", "p3c64//example.json",
                     "p3c64/./example.json", "p3c64\\secret", "C:/secret", "other/example", "", "."):
            with self.subTest(name=name), self.assertRaises(verifier.VerificationError):
                verifier.safe_archive_path(self.root, name)

    def test_symlink_file(self):
        linked = self.file.parent / "link"
        linked.symlink_to(self.file)
        with self.assertRaisesRegex(verifier.VerificationError, "symlink"):
            verifier.safe_archive_path(self.root, "p3c64/link")

    def test_symlink_directory(self):
        (self.root / "helpers").symlink_to(self.file.parent, target_is_directory=True)
        with self.assertRaisesRegex(verifier.VerificationError, "symlink"):
            verifier.verify_manifest(self.root, self.manifest)

    def test_bad_digest_or_size_types(self):
        for override in ({"sha256": "bad"}, {"bytes": True}, {"bytes": -1}):
            with self.subTest(override=override):
                self.save([{**self.entry, **override}])
                with self.assertRaises(verifier.VerificationError):
                    verifier.verify_manifest(self.root, self.manifest)

    def test_manifest_totals_are_checked_when_present(self):
        for field, value in (("file_count", 2), ("bytes", self.entry["bytes"] + 1),
                             ("file_count", True), ("bytes", float(self.entry["bytes"]))):
            with self.subTest(field=field, value=value):
                manifest = {"schema_version": "test.v1", "files": [self.entry], field: value}
                self.manifest.write_text(json.dumps(manifest), encoding="utf-8")
                with self.assertRaisesRegex(verifier.VerificationError, f"manifest total {field}"):
                    verifier.verify_manifest(self.root, self.manifest)

    def test_correct_manifest_totals_pass(self):
        manifest = {"schema_version": "test.v1", "files": [self.entry],
                    "file_count": 1, "bytes": self.entry["bytes"]}
        self.manifest.write_text(json.dumps(manifest), encoding="utf-8")
        self.assertEqual(verifier.verify_manifest(self.root, self.manifest)["file_count"], 1)

    def test_cli_failure_is_json_nonzero_and_does_not_write(self):
        before = set(self.root.rglob("*"))
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            status = verifier.main(["--baseline-root", str(self.root)])
        self.assertEqual(status, 1)
        self.assertEqual(json.loads(stream.getvalue())["status"], "failed")
        self.assertEqual(before, set(self.root.rglob("*")))


class RankTests(unittest.TestCase):
    @staticmethod
    def row(name="case1", rank=2):
        return {"case_id": name, "candidate_count": 10, "B0_rank": rank,
                "B0_hit_at_1": rank is not None and rank <= 1,
                "B0_hit_at_5": rank is not None and rank <= 5,
                "B0_hit_at_10": rank is not None and rank <= 10}

    def calculate(self, rows):
        return verifier.rank_metrics(rows, "B0_rank", "B0_", (1, 5, 10))

    def test_null_rank_is_miss_but_in_denominator(self):
        result = self.calculate([self.row(), self.row("case2", None)])
        self.assertEqual(result["case_count"], 2)
        self.assertEqual(result["cases_with_hit"], 1)
        self.assertEqual(result["R@5"], 0.5)
        self.assertEqual(result["MRR"], 0.25)

    def test_invalid_ranks(self):
        for value in (0, -1, 11, 1.0, "1", True, float("nan"), float("inf")):
            row = self.row()
            row["B0_rank"] = value
            with self.subTest(value=value), self.assertRaisesRegex(verifier.VerificationError, "rank must be"):
                self.calculate([row])

    def test_missing_rank_not_null(self):
        row = self.row()
        del row["B0_rank"]
        with self.assertRaisesRegex(verifier.VerificationError, "missing rank field"):
            self.calculate([row])

    def test_invalid_candidate_counts(self):
        for count in (0, -1, True, "10", 10.0, None):
            row = self.row()
            row["candidate_count"] = count
            with self.subTest(count=count), self.assertRaisesRegex(verifier.VerificationError, "candidate_count"):
                self.calculate([row])

    def test_duplicate_case(self):
        with self.assertRaisesRegex(verifier.VerificationError, "duplicate case_id"):
            self.calculate([self.row(), self.row()])

    def test_flags_disagree_with_rank(self):
        row = self.row()
        row["B0_hit_at_5"] = False
        with self.assertRaisesRegex(verifier.VerificationError, "B0_hit_at_5"):
            self.calculate([row])

    def test_integer_flags_rejected(self):
        row = self.row()
        row["B0_hit_at_5"] = 1
        with self.assertRaises(verifier.VerificationError):
            self.calculate([row])

    def test_missing_flag_rejected(self):
        row = self.row()
        del row["B0_hit_at_5"]
        with self.assertRaisesRegex(verifier.VerificationError, "missing B0_hit_at_5"):
            self.calculate([row])

    def test_mrr_disagreement(self):
        row = self.row()
        row["mrr_contribution"] = 1.0
        with self.assertRaisesRegex(verifier.VerificationError, "mrr_contribution"):
            self.calculate([row])

    def test_empty_ledger(self):
        with self.assertRaises(verifier.VerificationError):
            self.calculate([])

    def test_percentiles(self):
        result = verifier.percentiles([10, 1, 4, 2])
        self.assertEqual(result["min"], 1.0)
        self.assertEqual(result["p50"], 3.0)
        self.assertAlmostEqual(result["p90"], 8.2)

    def test_json_rejects_duplicate_keys_and_nonfinite_values(self):
        for text in ('{"x": 1, "x": 2}', '{"x": NaN}', '{"x": Infinity}'):
            with self.subTest(text=text), self.assertRaises(verifier.VerificationError):
                verifier.parse_json(text, "fixture")


class Fixed143ReportTests(unittest.TestCase):
    """Mutate report objects in memory; never write to the archived reports."""

    @classmethod
    def setUpClass(cls):
        cls.repository = Path(__file__).resolve().parents[3]
        cls.directory = cls.repository / verifier.FIXED_REPORT
        cls.summary = verifier.read_json(cls.directory / "summary.json")
        cls.comparison = verifier.read_json(cls.directory / "qwen4b_comparison.json")
        cls.real_read_json = staticmethod(verifier.read_json)

    def altered_reports(self, summary=None, comparison=None):
        def read(path):
            if path == self.directory / "summary.json" and summary is not None:
                return summary
            if path == self.directory / "qwen4b_comparison.json" and comparison is not None:
                return comparison
            return self.real_read_json(path)
        return mock.patch.object(verifier, "read_json", side_effect=read)

    def test_empty_missing_duplicate_and_incomplete_budgets_rejected(self):
        for budgets in ([], None, [30, 50, 100, 200, 300, 500, 500],
                        [30, 50, 100, 200, 300], [30, 50, 100, 150, 200, 300, 500]):
            comparison = copy.deepcopy(self.comparison)
            if budgets is None:
                del comparison["budgets"]
            else:
                comparison["budgets"] = budgets
            with self.subTest(budgets=budgets), self.altered_reports(comparison=comparison):
                with self.assertRaisesRegex(verifier.VerificationError, "comparison budgets"):
                    verifier.verify_fixed143(self.repository)

    def test_each_summary_recall_or_hit_count_is_checked(self):
        for prefix in ("hit_count_at_", "known_anchor_hit_at_"):
            for k in verifier.FIXED_COMPARISON_KS:
                summary = copy.deepcopy(self.summary)
                summary["metrics"][f"{prefix}{k}"] = 999
                with self.subTest(key=f"{prefix}{k}"), self.altered_reports(summary=summary):
                    with self.assertRaisesRegex(verifier.VerificationError, "fixed143 summary"):
                        verifier.verify_fixed143(self.repository)

    def test_empty_budgets_cannot_hide_corrupt_summary(self):
        summary = copy.deepcopy(self.summary)
        comparison = copy.deepcopy(self.comparison)
        comparison["budgets"] = []
        for key in summary["metrics"]:
            if key.startswith(("hit_count_at_", "known_anchor_hit_at_")):
                summary["metrics"][key] = 999
        with self.altered_reports(summary=summary, comparison=comparison):
            with self.assertRaises(verifier.VerificationError):
                verifier.verify_fixed143(self.repository)


class RestrictedWeightTests(unittest.TestCase):
    def test_old_torch_does_not_fall_back_to_unrestricted_pickle(self):
        fake = SimpleNamespace(load=mock.Mock(side_effect=TypeError("unknown weights_only")))
        with mock.patch.dict(sys.modules, {"torch": fake}):
            with self.assertRaisesRegex(verifier.VerificationError, "restricted weights-only loading failed"):
                verifier.check_weights(Path("model.pt"))
        fake.load.assert_called_once_with(Path("model.pt"), map_location="cpu", weights_only=True)

    def test_unexpected_keys_rejected(self):
        fake = SimpleNamespace(load=mock.Mock(return_value={"wrong_key": 1}))
        with mock.patch.dict(sys.modules, {"torch": fake}):
            with self.assertRaisesRegex(verifier.VerificationError, "unexpected checkpoint keys"):
                verifier.check_weights(Path("model.pt"))

    def test_shape_dtype_and_finiteness_checks(self):
        shapes = {"query_projection.first.weight": (128, 1024),
                  "query_projection.first.bias": (128,),
                  "query_projection.output.weight": (1024, 128),
                  "query_projection.output.bias": (1024,)}
        for change in ("shape", "dtype", "nonfinite", "valid"):
            state = {key: SimpleNamespace(shape=shape, dtype="float32") for key, shape in shapes.items()}
            if change == "shape":
                state["query_projection.first.bias"].shape = (127,)
            if change == "dtype":
                state["query_projection.first.bias"].dtype = "float64"
            fake = SimpleNamespace(load=mock.Mock(return_value=state), is_tensor=lambda value: True,
                                   float32="float32",
                                   isfinite=lambda value: SimpleNamespace(all=lambda: change != "nonfinite"))
            with self.subTest(change=change), mock.patch.dict(sys.modules, {"torch": fake}):
                if change == "valid":
                    self.assertEqual(verifier.check_weights(Path("model.pt"))["status"], "passed")
                else:
                    with self.assertRaises(verifier.VerificationError):
                        verifier.check_weights(Path("model.pt"))

    def test_both_checkpoint_hashes_checked(self):
        root = Path("archive")
        expected = {root / item["path"]: item["sha256"] for item in verifier.CHECKPOINTS.values()}
        with mock.patch.object(verifier, "sha256", side_effect=expected.__getitem__) as digest:
            result = verifier.verify_checkpoint_hashes(root)
        self.assertEqual(set(result), {"P3C16", "P3C64"})
        self.assertEqual(set(call.args[0] for call in digest.call_args_list), set(expected))

    def test_each_checkpoint_hash_tampering_fails(self):
        root = Path("archive")
        for changed in ("P3C16", "P3C64"):
            expected = {root / item["path"]: item["sha256"] for item in verifier.CHECKPOINTS.values()}
            expected[root / verifier.CHECKPOINTS[changed]["path"]] = "0" * 64
            with self.subTest(changed=changed), mock.patch.object(verifier, "sha256", side_effect=expected.__getitem__):
                with self.assertRaisesRegex(verifier.VerificationError, changed):
                    verifier.verify_checkpoint_hashes(root)

    def test_weight_option_checks_both_files(self):
        root = Path("archive")
        with mock.patch.object(verifier, "check_weights", return_value={"status": "passed"}) as check:
            result = verifier.check_archived_weights(root)
        self.assertEqual(result["status"], "passed")
        self.assertEqual(set(result["checkpoints"]), {"P3C16", "P3C64"})
        self.assertEqual(set(call.args[0] for call in check.call_args_list),
                         {root / item["path"] for item in verifier.CHECKPOINTS.values()})

    def test_failure_of_either_checkpoint_fails_combined_check(self):
        root = Path("archive")
        for changed in ("P3C16", "P3C64"):
            def check(path):
                if path == root / verifier.CHECKPOINTS[changed]["path"]:
                    raise verifier.VerificationError("invalid tensor")
                return {"status": "passed"}
            with self.subTest(changed=changed), mock.patch.object(verifier, "check_weights", side_effect=check):
                with self.assertRaisesRegex(verifier.VerificationError, changed):
                    verifier.check_archived_weights(root)


if __name__ == "__main__":
    unittest.main()
