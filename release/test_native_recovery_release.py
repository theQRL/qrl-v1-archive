"""Small synthetic checks for the native supplement's publication gate."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import native_recovery_release as release


def write_json(path: Path, obj: dict) -> None:
    path.write_text(json.dumps(obj, sort_keys=True) + "\n")


def make_tar(path: Path, contents: bytes) -> None:
    digest = hashlib.sha256(contents).hexdigest()
    files = {
        "state/000001.ldb": contents,
        "state.sha256": f"{digest}  ./000001.ldb\n".encode(),
    }
    with tarfile.open(path, "w:") as archive:
        directory = tarfile.TarInfo("state/")
        directory.type = tarfile.DIRTYPE
        directory.mode = 0o700
        directory.uid = 501
        directory.gid = 777
        directory.uname = "source-owner"
        directory.gname = "source-group"
        directory.mtime = 1_700_000_000
        archive.addfile(directory)
        for name, data in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            member.mode = 0o644
            member.uid = 501
            member.gid = 777
            member.uname = "source-owner"
            member.gname = "source-group"
            member.mtime = 1_700_000_000
            archive.addfile(member, io.BytesIO(data))


class NativeReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.s1 = self.root / "s1.tar"
        self.testnet3 = self.root / "testnet3.tar"
        make_tar(self.s1, b"S1 test state")
        make_tar(self.testnet3, b"testnet3 test state")
        original = release.SOURCE_INFO
        release.SOURCE_INFO = {
            "s1": {"version": "test", "tar_sha256": release._digest(self.s1)[1]},
            "testnet3": {"version": "test", "tar_sha256": release._digest(self.testnet3)[1]},
        }
        self.addCleanup(setattr, release, "SOURCE_INFO", original)
        self.normalized_dir = self.root / "normalized"
        release.normalize(argparse.Namespace(tag=release.TAG, s1_tar=self.s1,
                                             testnet3_tar=self.testnet3,
                                             output=self.normalized_dir))
        self.s1_normalized = self.normalized_dir / "s1-normalized.tar"
        self.testnet3_normalized = self.normalized_dir / "testnet3-normalized.tar"
        self.normalization_report = self.normalized_dir / "native-normalization-report.json"
        self.parent = self.root / "parent-manifest.json"
        write_json(self.parent, {"schema": "theqrl.release-manifest.v1",
                                 "product": release.PRODUCT, "tag": release.PARENT_TAG,
                                 "context": release.ARTIFACT_CONTEXT, "artifacts": []})
        self.native = self.root / "native-report.json"
        write_json(self.native, {"command": "compare-native-state", "status": "PASS",
                                 "result": {"native_state_agreement_verified": True,
                                            "exact_native_state_bytes_equal": True,
                                            "anchors": {"terminal_height": release.HEIGHT,
                                                        "terminal_hash": release.HASH,
                                                        "genesis_hash": release.GENESIS}}})
        parent_hash = release._digest(self.parent)[1]
        native_hash = release._digest(self.native)[1]
        old_parent = release.PARENT_MANIFEST_SHA256
        old_native = release.NATIVE_COMPARISON_SHA256
        release.PARENT_MANIFEST_SHA256 = parent_hash
        release.NATIVE_COMPARISON_SHA256 = native_hash
        self.addCleanup(setattr, release, "PARENT_MANIFEST_SHA256", old_parent)
        self.addCleanup(setattr, release, "NATIVE_COMPARISON_SHA256", old_native)
        self.review = self.root / "review.json"
        self.raw_audit = self.root / "raw-byte-audit.json"
        self.classification = self.root / "source-classification.json"
        subjects = [
            {"label": "s1", "distributed_sha256": release._digest(self.s1_normalized)[1]},
            {"label": "testnet3", "distributed_sha256": release._digest(self.testnet3_normalized)[1]},
        ]
        write_json(self.raw_audit, {"status": "PASS", "subjects": subjects})
        write_json(self.classification, {"schema": "synthetic.source-classification.v1",
                                         "publication_status": "SYNTHETIC_ONLY"})
        self.output = self.root / "release"
        self.restricted = self.root / "restricted.json"

    def args(self):
        return argparse.Namespace(
            tag=release.TAG, output=self.output, mode="reviewed_plaintext",
            s1_tar=self.s1, testnet3_tar=self.testnet3,
            s1_normalized_tar=self.s1_normalized,
            testnet3_normalized_tar=self.testnet3_normalized,
            normalization_report=self.normalization_report,
            native_report=self.native, parent_manifest=self.parent,
            publication_review=self.review, restricted_report=self.restricted,
            raw_byte_audit=self.raw_audit,
            source_classification=self.classification,
        )

    def approve(self):
        write_json(self.review, {
            "schema": release.REVIEW_SCHEMA, "tag": release.TAG,
            "mode": "reviewed_plaintext", "decision": "APPROVED_PUBLIC_PLAINTEXT",
            "subjects": [
                {"label": "s1", "distributed_sha256": release._digest(self.s1_normalized)[1]},
                {"label": "testnet3", "distributed_sha256": release._digest(self.testnet3_normalized)[1]},
            ],
            "custody_subjects": [
                {"label": "s1", "custody_sha256": release._digest(self.s1)[1]},
                {"label": "testnet3", "custody_sha256": release._digest(self.testnet3)[1]},
            ],
            "reviewer_role": "synthetic fixture only",
            "reviewed_at_utc": "2026-10-16T00:00:00Z",
            "evidence": {
                "raw_byte_audit_sha256": release._digest(self.raw_audit)[1],
                "source_classification_sha256": release._digest(self.classification)[1],
                "normalization_report_sha256": release._digest(self.normalization_report)[1],
            },
        })

    def test_missing_review_stages_no_parts(self):
        with self.assertRaises((release.ReleaseError, release.ArchiveError)):
            release.prepare(self.args())
        self.assertFalse(self.output.exists())

    def test_headers_normalized_and_native_bytes_unchanged(self):
        self.assertNotEqual(release._digest(self.s1)[1],
                            release._digest(self.s1_normalized)[1])
        release.normalized_headers(self.s1_normalized)
        self.assertEqual(release.content_view(release.source_manifest(self.s1)),
                         release.content_view(release.source_manifest(self.s1_normalized)))

    def test_changed_audit_evidence_stages_no_parts(self):
        self.approve()
        write_json(self.raw_audit, {"status": "FAIL", "subjects": []})
        with self.assertRaises(release.ReleaseError):
            release.prepare(self.args())
        self.assertFalse(self.output.exists())

    def test_reviewed_parts_verify_and_tamper_fails(self):
        self.approve()
        result = release.prepare(self.args())
        self.assertTrue(result["prepared_verified"])
        self.assertEqual(result["mode"], "reviewed_plaintext")
        self.assertEqual(release.verify_prepared(
            self.output, review_path=self.review,
            raw_audit_path=self.raw_audit,
            classification_path=self.classification,
            normalization_report_path=self.normalization_report), result)
        part = self.output / "payload" / "s1-native-backup.part-0000"
        with part.open("r+b") as stream:
            stream.seek(-1, 2)
            last = stream.read(1)[0]
            stream.seek(-1, 2)
            stream.write(bytes([last ^ 1]))
        with self.assertRaises(release.ReleaseError):
            release.verify_prepared(self.output, review_path=self.review,
                                    raw_audit_path=self.raw_audit,
                                    classification_path=self.classification,
                                    normalization_report_path=self.normalization_report)

    def test_public_file_inventory_must_match_reassembled_tar(self):
        self.approve()
        release.prepare(self.args())
        payload = self.output / "payload"
        file_path = payload / "native-file-inventory.json"
        inventory_path = payload / "native-recovery-inventory.json"
        file_inventory = release.read_json(file_path)
        file_inventory["sources"][0]["files"][0]["sha3_256"] = "0" * 64
        file_path.write_bytes(release.encoded(file_inventory))
        inventory = release.read_json(inventory_path)
        size, sha256, sha3 = release._digest(file_path)
        inventory["file_inventory_sha256"] = sha256
        entry = next(item for item in inventory["payloads"]
                     if item["filename"] == file_path.name)
        entry.update({"size": size, "sha256": sha256, "sha3_256": sha3})
        inventory_path.write_bytes(release.encoded(inventory))
        with self.assertRaisesRegex(release.ReleaseError,
                                    "distributed native tar members differ"):
            release.verify_prepared(self.output)


if __name__ == "__main__":
    unittest.main()
