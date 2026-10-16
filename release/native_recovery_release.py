#!/usr/bin/env python3
"""Prepare and verify an immutable native-state supplement for the testnet snapshot.

This tool never encrypts data or decides that a database is safe to publish.
It requires an exact-byte operator review before it stages any distributable
parts. Its action manifest follows actions-mldsa-sign v3 without extensions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from qrl_archive.errors import ArchiveError
from qrl_archive.snapshot_release import (
    ARTIFACT_CONTEXT, FIXED_QRLFT_COMMIT, KEY_SHA256, MANIFEST_CONTEXT,
    PRODUCT, SECURITY_COMMIT, SIGNATURE_HEX_LENGTH, _build_fixed_qrlft,
    _digest, _read_json, _verify_qrlft,
)


SCHEMA = "qrl.v1.archive.native-recovery-supplement.v1"
REVIEW_SCHEMA = "qrl.v1.archive.native-publication-review.v1"
FILE_INVENTORY_SCHEMA = "qrl.v1.archive.native-file-inventory.v1"
NORMALIZATION_SCHEMA = "qrl.v1.archive.native-header-normalization.v1"
TAG = "testnet-snapshot-h1620000-8d7d8a30-native-r1"
OBJECT_PREFIX = f"testnet/native-recovery/{TAG}"
PARENT_TAG = "testnet-snapshot-h1620000-8d7d8a30-r1"
PARENT_MANIFEST_SHA256 = "b81739b982cdd4cd3082463598fac85b48e0fdf4fc887f1fea36dc40437a6e4b"
NATIVE_COMPARISON_SHA256 = "a39957150a37fdead79880e50979e282153f4ad91164365f491535f33cededa2"
HEIGHT = 1_620_000
HASH = "8d7d8a30d928d52e74dd68f453d99604e5c8290c3df88d182353d4abcc8c0300"
GENESIS = "d6765d6e0af7e8b25bac587279999e16bbb0bd3038445934e2d9f3b24a89041e"
PART_BYTES = 64 * 1024 * 1024
HEADER_POLICY = {
    "format": "ustar", "order": "state_directory_then_lexical_state_files_then_state_sha256",
    "uid": 0, "gid": 0, "uname": "", "gname": "", "mtime": 0,
    "file_mode": 0o600, "directory_mode": 0o700,
}
SOURCE_INFO = {
    "s1": {"version": "4.0.11", "tar_sha256": "d15b900dd58ed2208c8cc1f87e80bbae8e186e25ee95a14bcc8598fdce09ee8f"},
    "testnet3": {"version": "4.0.1", "tar_sha256": "7552d7c9c0783a710104a3b4ec3090d0791e863fffeba6e57449281bafda285b"},
}
RESERVED = {"manifest.json", "manifest.json.sig", "signatures.txt"}
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")


class ReleaseError(Exception):
    pass


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ReleaseError(message)


def encoded(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"


def regular(path: Path) -> None:
    require(not path.is_symlink() and path.is_file(), f"missing or linked file: {path.name}")
    with path.open("rb") as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), f"not a regular file: {path.name}")


def digest_stream(stream) -> tuple[int, str, str]:
    sha256, sha3 = hashlib.sha256(), hashlib.sha3_256()
    size = 0
    while chunk := stream.read(1024 * 1024):
        sha256.update(chunk)
        sha3.update(chunk)
        size += len(chunk)
    return size, sha256.hexdigest(), sha3.hexdigest()


def read_json(path: Path) -> dict:
    _, value = _read_json(path)
    return value


def source_manifest(tar_path: Path) -> dict:
    """Validate the source tar and its embedded state.sha256 without extraction."""
    regular(tar_path)
    with tarfile.open(tar_path, mode="r:") as archive:
        return scan_tar_archive(archive)


def scan_tar_archive(archive: tarfile.TarFile, *, normalized: bool = False) -> dict:
    """Check native members, optionally enforcing the public header contract."""
    members: list[dict] = []
    names: set[str] = set()
    ordered_names: list[str] = []
    seen_root = False
    internal_manifest: bytes | None = None
    for member in archive:
        require(member.name not in names, "duplicate tar member")
        names.add(member.name)
        is_root = member.name.rstrip("/") == "state"
        ordered_names.append("state/" if is_root else member.name)
        if normalized:
            require(member.uid == 0 and member.gid == 0
                    and member.uname == "" and member.gname == ""
                    and member.mtime == 0 and not member.pax_headers,
                    "distributed tar exposes source header metadata")
            require(member.mode == (0o700 if is_root else 0o600),
                    "distributed tar has an unexpected member mode")
        if is_root:
            require(member.isdir(), "state root must be a directory")
            seen_root = True
            continue
        require(member.isfile(), "tar has a link or non-file member")
        require(member.pax_headers == {}, "tar has extended metadata")
        require(member.name == "state.sha256" or (
            member.name.startswith("state/") and
            SAFE_NAME.fullmatch(member.name[6:]) is not None),
            "tar has an unsafe or unexpected path")
        stream = archive.extractfile(member)
        require(stream is not None, "cannot read tar member")
        with stream:
            if member.name == "state.sha256":
                internal_manifest = stream.read(2_000_001)
                require(len(internal_manifest) <= 2_000_000, "state manifest is too large")
                require(len(internal_manifest) == member.size,
                        "embedded state manifest size differs")
                continue
            size, sha256, sha3 = digest_stream(stream)
        require(size == member.size, "tar member size differs from bytes")
        members.append({"path": member.name, "size": size,
                        "mode": member.mode & 0o7777,
                        "sha256": sha256, "sha3_256": sha3})
    if normalized:
        expected_order = ["state/"] + sorted(
            name for name in ordered_names if name.startswith("state/")
            and name != "state/") + ["state.sha256"]
        require(ordered_names == expected_order,
                "distributed tar member order differs from normalization policy")
    require(seen_root and internal_manifest is not None and members,
            "tar lacks state directory, state files or embedded manifest")
    expected: dict[str, str] = {}
    try:
        lines = internal_manifest.decode("ascii").splitlines()
    except UnicodeError as error:
        raise ReleaseError("state manifest is not ASCII") from error
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  \./([A-Za-z0-9][A-Za-z0-9._-]*)", line)
        require(match is not None, "state manifest has an invalid line")
        path = "state/" + match.group(2)
        require(path not in expected, "state manifest repeats a path")
        expected[path] = match.group(1)
    actual = {entry["path"]: entry["sha256"] for entry in members}
    require(actual == expected, "embedded state manifest differs from tar members")
    members.sort(key=lambda entry: entry["path"])
    return {"files": members, "state_manifest_sha256": hashlib.sha256(internal_manifest).hexdigest()}


class OrderedPartsReader:
    """Present fixed-size release parts as one read-only sequential tar stream."""

    def __init__(self, paths: list[Path]):
        self.paths = iter(paths)
        self.current = None

    def read(self, size: int = -1) -> bytes:
        require(size >= 0, "unbounded read of native parts is forbidden")
        pieces = []
        remaining = size
        while remaining:
            if self.current is None:
                try:
                    path = next(self.paths)
                except StopIteration:
                    break
                regular(path)
                self.current = path.open("rb")
            piece = self.current.read(remaining)
            if piece:
                pieces.append(piece)
                remaining -= len(piece)
            else:
                self.current.close()
                self.current = None
        return b"".join(pieces)

    def close(self) -> None:
        if self.current is not None:
            self.current.close()
            self.current = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def scan_parts(paths: list[Path]) -> dict:
    with OrderedPartsReader(paths) as stream:
        with tarfile.open(fileobj=stream, mode="r|") as archive:
            return scan_tar_archive(archive, normalized=True)


def content_view(scan: dict) -> list[dict]:
    return [{key: item[key] for key in ("path", "size", "sha256", "sha3_256")}
            for item in scan["files"]]


def normalized_headers(tar_path: Path) -> None:
    """Reject owner, timestamp, mode, format or ordering drift."""
    with tarfile.open(tar_path, mode="r:") as archive:
        members = archive.getmembers()
        names = ["state/" if member.isdir() and member.name.rstrip("/") == "state"
                 else member.name for member in members]
        expected = ["state/"] + sorted(
            name for name in names if name.startswith("state/")
            and name != "state/") + ["state.sha256"]
        require(names == expected,
                "normalized tar member order differs")
        for member in members:
            require(member.uid == 0 and member.gid == 0
                    and member.uname == "" and member.gname == ""
                    and member.mtime == 0 and not member.pax_headers,
                    "normalized tar still exposes source metadata")
            expected_mode = 0o700 if member.isdir() else 0o600
            require(member.mode == expected_mode,
                    "normalized tar mode differs")


def normalize_one(label: str, custody_tar: Path, destination: Path) -> dict:
    custody_size, custody_sha256, custody_sha3 = _digest(custody_tar)
    require(custody_sha256 == SOURCE_INFO[label]["tar_sha256"],
            f"{label} custody tar differs from pinned SHA-256")
    custody_scan = source_manifest(custody_tar)
    with tarfile.open(custody_tar, mode="r:") as original:
        members = {member.name.rstrip("/") if member.isdir() else member.name: member
                   for member in original.getmembers()}
        ordered_names = ["state"] + [item["path"] for item in custody_scan["files"]] + ["state.sha256"]
        require(set(members) == set(ordered_names),
                "custody tar has an unexpected member")
        with tarfile.open(destination, mode="x:", format=tarfile.USTAR_FORMAT) as normalized:
            for name in ordered_names:
                original_member = members[name]
                output_name = "state/" if name == "state" else name
                new_member = tarfile.TarInfo(output_name)
                new_member.type = tarfile.DIRTYPE if name == "state" else tarfile.REGTYPE
                new_member.size = 0 if name == "state" else original_member.size
                new_member.mode = 0o700 if name == "state" else 0o600
                new_member.uid = new_member.gid = new_member.mtime = 0
                new_member.uname = new_member.gname = ""
                if name == "state":
                    normalized.addfile(new_member)
                else:
                    stream = original.extractfile(original_member)
                    require(stream is not None, "cannot read custody tar member")
                    with stream:
                        normalized.addfile(new_member, stream)
    normalized_headers(destination)
    published_scan = source_manifest(destination)
    require(content_view(custody_scan) == content_view(published_scan)
            and custody_scan["state_manifest_sha256"] == published_scan["state_manifest_sha256"],
            "normalization changed native state or embedded state manifest bytes")
    published_size, published_sha256, published_sha3 = _digest(destination)
    return {"label": label,
            "custody_tar": {"size": custody_size, "sha256": custody_sha256,
                            "sha3_256": custody_sha3},
            "published_tar": {"size": published_size, "sha256": published_sha256,
                              "sha3_256": published_sha3},
            "file_count": len(custody_scan["files"]),
            "state_manifest_sha256": custody_scan["state_manifest_sha256"],
            "member_content_equal": True, "headers_normalized": True}


def normalize(args: argparse.Namespace) -> dict:
    os.umask(0o077)
    require(args.tag == TAG, "this tool only normalizes the pinned testnet custody tars")
    require(not args.output.exists(), "normalization output already exists")
    args.output.mkdir(parents=True, exist_ok=False)
    subjects = []
    for label, custody_tar in (("s1", args.s1_tar), ("testnet3", args.testnet3_tar)):
        destination = args.output / f"{label}-normalized.tar"
        subjects.append(normalize_one(label, custody_tar, destination))
    report = {"schema": NORMALIZATION_SCHEMA, "tag": TAG, "status": "PASS",
              "header_policy": HEADER_POLICY, "subjects": subjects}
    report_path = args.output / "native-normalization-report.json"
    report_path.write_bytes(encoded(report))
    return {"status": "NORMALIZED_PRIVATE_REVIEW_PENDING", "tag": TAG,
            "report_sha256": _digest(report_path)[1],
            "subjects": [{"label": entry["label"],
                          "custody_sha256": entry["custody_tar"]["sha256"],
                          "published_sha256": entry["published_tar"]["sha256"]}
                         for entry in subjects]}


def source_anchors(report_path: Path) -> str:
    report = read_json(report_path)
    result = report.get("result", {})
    anchors = result.get("anchors", {})
    require(report.get("command") == "compare-native-state" and report.get("status") == "PASS"
            and result.get("native_state_agreement_verified") is True
            and result.get("exact_native_state_bytes_equal") is True
            and anchors.get("terminal_height") == HEIGHT
            and anchors.get("terminal_hash") == HASH
            and anchors.get("genesis_hash") == GENESIS,
            "native comparison report does not attest this cutoff")
    digest = _digest(report_path)[1]
    require(digest == NATIVE_COMPARISON_SHA256,
            "native comparison report differs from signed parent payload")
    return digest


def parent_identity(parent_manifest: Path) -> str:
    manifest = read_json(parent_manifest)
    require(manifest.get("schema") == "theqrl.release-manifest.v1"
            and manifest.get("product") == PRODUCT
            and manifest.get("tag") == PARENT_TAG
            and manifest.get("context") == ARTIFACT_CONTEXT,
            "parent manifest has wrong release identity")
    digest = _digest(parent_manifest)[1]
    require(digest == PARENT_MANIFEST_SHA256,
            "parent manifest differs from published signed snapshot")
    return digest


def review_identity(review_path: Path, subjects: list[dict],
                    custody_subjects: list[dict], raw_audit_path: Path,
                    classification_path: Path,
                    normalization_report_path: Path) -> tuple[str, dict]:
    review = read_json(review_path)
    evidence = {
        "raw_byte_audit_sha256": _digest(raw_audit_path)[1],
        "source_classification_sha256": _digest(classification_path)[1],
        "normalization_report_sha256": _digest(normalization_report_path)[1],
    }
    audit = read_json(raw_audit_path)
    require(audit.get("status") == "PASS" and audit.get("subjects") == subjects,
            "raw-byte audit does not pass for exact published tar hashes")
    read_json(classification_path)
    timestamp = review.get("reviewed_at_utc", "")
    try:
        parsed_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as error:
        raise ReleaseError("publication review timestamp is invalid") from error
    require(review.get("schema") == REVIEW_SCHEMA
            and review.get("mode") == "reviewed_plaintext"
            and review.get("decision") == "APPROVED_PUBLIC_PLAINTEXT"
            and review.get("tag") == TAG
            and review.get("subjects") == subjects
            and review.get("custody_subjects") == custody_subjects
            and review.get("evidence") == evidence
            and isinstance(review.get("reviewer_role"), str)
            and bool(review["reviewer_role"])
            and isinstance(timestamp, str) and timestamp.endswith("Z")
            and parsed_time.tzinfo == timezone.utc,
            "publication review does not approve exact distributed bytes")
    return _digest(review_path)[1], evidence


def add_payload(payload: Path, path: Path, role: str, object_path: str) -> dict:
    size, sha256, sha3 = _digest(path)
    return {"filename": path.name, "role": role, "object_path": object_path,
            "size": size, "sha256": sha256, "sha3_256": sha3}


def split(source: Path, payload: Path, label: str) -> tuple[dict, list[dict]]:
    size, whole_sha256, whole_sha3 = _digest(source)
    require(size > 0, "distributed backup is empty")
    parts: list[dict] = []
    with source.open("rb") as reader:
        number = 0
        while chunk := reader.read(PART_BYTES):
            name = f"{label}-native-backup.part-{number:04d}"
            destination = payload / name
            with destination.open("xb") as writer:
                writer.write(chunk)
            parts.append(add_payload(payload, destination, "native_backup_part",
                                     f"native/{label}/{name}"))
            number += 1
    require(sum(part["size"] for part in parts) == size, "part sizes differ from whole")
    whole = {"size": size, "sha256": whole_sha256, "sha3_256": whole_sha3,
             "part_filenames": [part["filename"] for part in parts]}
    return whole, parts


def prepare(args: argparse.Namespace) -> dict:
    os.umask(0o077)
    require(args.tag == TAG, "this tool only prepares the pinned testnet native supplement")
    require(args.mode == "reviewed_plaintext",
            "encrypted publication is not enabled for this supplement")
    require(not args.restricted_report.resolve().is_relative_to(args.output.resolve()),
            "restricted plaintext inventory cannot be placed inside public release")
    require(args.output != args.restricted_report and not args.output.exists(),
            "release output already exists or overlaps restricted report")
    require(not args.restricted_report.exists(), "restricted report already exists")
    regular(args.publication_review)
    regular(args.raw_byte_audit)
    regular(args.source_classification)
    regular(args.normalization_report)
    custody_paths = {"s1": args.s1_tar, "testnet3": args.testnet3_tar}
    published_paths = {"s1": args.s1_normalized_tar,
                       "testnet3": args.testnet3_normalized_tar}
    custody: dict[str, dict] = {}
    published: dict[str, dict] = {}
    file_sources = []
    expected_normalization_subjects = []
    for label in sorted(SOURCE_INFO):
        custody_size, custody_sha256, custody_sha3 = _digest(custody_paths[label])
        require(custody_sha256 == SOURCE_INFO[label]["tar_sha256"],
                f"{label} custody tar differs from pinned SHA-256")
        custody_scan = source_manifest(custody_paths[label])
        custody[label] = {"size": custody_size, "sha256": custody_sha256,
                          "sha3_256": custody_sha3}
        normalized_headers(published_paths[label])
        published_size, published_sha256, published_sha3 = _digest(published_paths[label])
        published_scan = source_manifest(published_paths[label])
        require(content_view(custody_scan) == content_view(published_scan)
                and custody_scan["state_manifest_sha256"] == published_scan["state_manifest_sha256"],
                "published tar changes native state bytes")
        published[label] = {"size": published_size, "sha256": published_sha256,
                            "sha3_256": published_sha3}
        file_sources.append({"label": label, "custody_tar": custody[label],
                             "published_tar": published[label],
                             "state_manifest_sha256": published_scan["state_manifest_sha256"],
                             "files": published_scan["files"]})
        expected_normalization_subjects.append({
            "label": label, "custody_tar": custody[label],
            "published_tar": published[label],
            "file_count": len(published_scan["files"]),
            "state_manifest_sha256": published_scan["state_manifest_sha256"],
            "member_content_equal": True, "headers_normalized": True,
        })
    normalization_report = read_json(args.normalization_report)
    require(normalization_report == {"schema": NORMALIZATION_SCHEMA, "tag": TAG,
                                     "status": "PASS", "header_policy": HEADER_POLICY,
                                     "subjects": expected_normalization_subjects},
            "normalization report differs from independently checked public tar bytes")
    subjects = [{"label": label, "distributed_sha256": published[label]["sha256"]}
                for label in sorted(SOURCE_INFO)]
    custody_subjects = [{"label": label, "custody_sha256": custody[label]["sha256"]}
                        for label in sorted(SOURCE_INFO)]
    review_sha256, evidence = review_identity(
        args.publication_review, subjects, custody_subjects,
        args.raw_byte_audit, args.source_classification,
        args.normalization_report)
    parent_sha256 = parent_identity(args.parent_manifest)
    native_sha256 = source_anchors(args.native_report)
    file_inventory = {"schema": FILE_INVENTORY_SCHEMA, "tag": TAG,
                      "sources": file_sources}
    file_inventory_bytes = encoded(file_inventory)
    file_inventory_sha256 = hashlib.sha256(file_inventory_bytes).hexdigest()
    args.restricted_report.parent.mkdir(parents=True, exist_ok=True)
    with args.restricted_report.open("xb") as writer:
        writer.write(file_inventory_bytes)
    os.chmod(args.restricted_report, 0o600)
    args.output.mkdir(parents=True, exist_ok=False)
    payload = args.output / "payload"
    payload.mkdir()
    entries: list[dict] = []
    file_manifest = payload / "native-file-inventory.json"
    file_manifest.write_bytes(file_inventory_bytes)
    entries.append(add_payload(payload, file_manifest, "native_file_inventory",
                               file_manifest.name))
    public_normalization_report = payload / "native-normalization-report.json"
    public_normalization_report.write_bytes(args.normalization_report.read_bytes())
    entries.append(add_payload(payload, public_normalization_report,
                               "native_header_normalization_report",
                               public_normalization_report.name))
    sources: list[dict] = []
    for label in sorted(SOURCE_INFO):
        whole, parts = split(published_paths[label], payload, label)
        require(all(whole[key] == published[label][key]
                    for key in ("size", "sha256", "sha3_256")),
                "distributed file changed while splitting")
        entries.extend(parts)
        sources.append({"label": label,
                        "node_version": SOURCE_INFO[label]["version"],
                        "custody_tar": custody[label],
                        "distribution": {"kind": "header_normalized_plaintext_tar", **whole},
                        "state_file_count": len(file_sources[sorted(SOURCE_INFO).index(label)]["files"])})
    notice = payload / "NATIVE-RECOVERY-NOTICE.md"
    notice.write_text(
        "# QRL v1 testnet native-state supplement\n\n"
        f"Release: `{TAG}`. Parent snapshot: `{PARENT_TAG}`.\n\n"
        f"These two independently captured, cleanly stopped QRL node states are fixed at "
        f"testnet block {HEIGHT}, hash `{HASH}`. The public testnet continues beyond "
        "this point. This supplement is not a terminal archive or permission to stop a node.\n\n"
        "Verify the action manifest and signatures with the pinned QRL release public key, "
        "then verify all ordered parts and each reassembled object's SHA-256 and SHA3-256 "
        "against `native-recovery-inventory.json`. Tar headers were normalized; "
        "native file bytes and the embedded state manifest match the stopped custody tars. "
        "Only a disposable writable copy may "
        "be opened by LevelDB. A matching QRL runtime and an isolated cold-restore test "
        "are separate requirements; this release does not claim that test has passed.\n"
    )
    entries.append(add_payload(payload, notice, "notice", notice.name))
    publication = {"mode": "reviewed_plaintext", "review_schema": REVIEW_SCHEMA,
                   "review_sha256": review_sha256,
                   "review_decision": "APPROVED_PUBLIC_PLAINTEXT",
                   "subjects": subjects, "custody_subjects": custody_subjects,
                   "evidence": evidence}
    inventory = {
        "schema": SCHEMA, "release_class": "LIVE_TESTNET_SNAPSHOT_NATIVE_RECOVERY_SUPPLEMENT",
        "product": PRODUCT, "tag": TAG, "object_prefix": OBJECT_PREFIX,
        "parent_release": {"tag": PARENT_TAG, "manifest_sha256": parent_sha256},
        "snapshot": {"network_id": "testnet", "genesis_hash": GENESIS,
                     "height": HEIGHT, "hash": HASH, "terminal": False},
        "signing": {"public_key_sha256": KEY_SHA256,
                    "artifact_context": ARTIFACT_CONTEXT,
                    "manifest_context": MANIFEST_CONTEXT},
        "publication": publication, "native_comparison_report_sha256": native_sha256,
        "file_inventory_sha256": file_inventory_sha256,
        "normalization_report_sha256": _digest(public_normalization_report)[1],
        "header_policy": HEADER_POLICY,
        "part_bytes_max": PART_BYTES, "sources": sources,
        "payloads": sorted(entries, key=lambda entry: entry["filename"]),
        "verification_scope": {
            "native_tar_member_sha256_and_sha3_256_checked_at_prepare": True,
            "source_state_manifests_checked_at_prepare": True,
            "post_upload_download_verified": False,
            "clean_host_cold_restore_verified": False,
            "historical_consensus_replayed": False,
        },
    }
    (payload / "native-recovery-inventory.json").write_bytes(encoded(inventory))
    return verify_prepared(args.output, review_path=args.publication_review,
                           raw_audit_path=args.raw_byte_audit,
                           classification_path=args.source_classification,
                           normalization_report_path=args.normalization_report,
                           restricted_path=args.restricted_report)


def verify_prepared(release: Path, *, review_path: Path | None = None,
                    raw_audit_path: Path | None = None,
                    classification_path: Path | None = None,
                    normalization_report_path: Path | None = None,
                    restricted_path: Path | None = None) -> dict:
    payload = release / "payload"
    require(payload.is_dir() and not payload.is_symlink(), "payload directory missing or linked")
    regular(payload / "native-recovery-inventory.json")
    inventory = read_json(payload / "native-recovery-inventory.json")
    require(inventory.get("schema") == SCHEMA and inventory.get("tag") == TAG
            and inventory.get("product") == PRODUCT
            and inventory.get("snapshot") == {"network_id": "testnet", "genesis_hash": GENESIS,
                                               "height": HEIGHT, "hash": HASH, "terminal": False}
            and inventory.get("signing") == {"public_key_sha256": KEY_SHA256,
                                              "artifact_context": ARTIFACT_CONTEXT,
                                              "manifest_context": MANIFEST_CONTEXT}
            and inventory.get("part_bytes_max") == PART_BYTES
            and inventory.get("header_policy") == HEADER_POLICY
            and inventory.get("object_prefix") == OBJECT_PREFIX,
            "supplement identity differs")
    entries = inventory.get("payloads")
    require(isinstance(entries, list) and entries == sorted(entries, key=lambda x: x["filename"]),
            "payload inventory is missing or unsorted")
    listed = {item["filename"] for item in entries}
    require(len(listed) == len(entries) and
            {p.name for p in payload.iterdir()} == listed | {"native-recovery-inventory.json"},
            "payload set differs from signed inventory")
    for item in entries:
        name = item["filename"]
        require(SAFE_NAME.fullmatch(name) is not None and name not in RESERVED,
                "unsafe payload filename")
        regular(payload / name)
        size, sha256, sha3 = _digest(payload / name)
        require((size, sha256, sha3) == (item["size"], item["sha256"], item["sha3_256"]),
                f"payload differs: {name}")
        require(item["object_path"] in (name, f"native/s1/{name}", f"native/testnet3/{name}"),
                "unsafe object path")
        if item["role"] == "native_backup_part":
            require(0 < size <= PART_BYTES, "native part exceeds bound")
    require(inventory.get("parent_release", {}).get("tag") == PARENT_TAG
            and inventory["parent_release"].get("manifest_sha256") == PARENT_MANIFEST_SHA256
            and inventory.get("native_comparison_report_sha256") == NATIVE_COMPARISON_SHA256,
            "parent release binding is malformed")
    sources = inventory.get("sources")
    require(isinstance(sources, list) and [s.get("label") for s in sources] == sorted(SOURCE_INFO),
            "native source list differs")
    mode = inventory.get("publication", {}).get("mode")
    require(mode == "reviewed_plaintext", "publication mode is not approved plaintext")
    observed_subjects = []
    custody_subjects = []
    public_scans: dict[str, dict] = {}
    for source in sources:
        label = source["label"]
        require(source.get("node_version") == SOURCE_INFO[label]["version"],
                "source runtime version differs")
        whole = source.get("distribution", {})
        names = whole.get("part_filenames")
        require(whole.get("kind") == "header_normalized_plaintext_tar"
                and isinstance(names, list) and names,
                "native source distribution missing")
        custody_tar = source.get("custody_tar", {})
        require(custody_tar.get("sha256") == SOURCE_INFO[label]["tar_sha256"]
                and isinstance(custody_tar.get("size"), int)
                and HEX64.fullmatch(custody_tar.get("sha3_256", "")),
                "custody tar binding differs")
        require(len(names) <= 64, "native source has too many parts")
        require(names == [f"{label}-native-backup.part-{n:04d}" for n in range(len(names))],
                "native part order differs")
        sha256, sha3 = hashlib.sha256(), hashlib.sha3_256()
        size = 0
        for name in names:
            entry = next((item for item in entries if item["filename"] == name), None)
            require(entry is not None and entry["role"] == "native_backup_part"
                    and entry["object_path"] == f"native/{label}/{name}",
                    "native part missing from payload inventory")
            with (payload / name).open("rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    sha256.update(chunk)
                    sha3.update(chunk)
                    size += len(chunk)
        require((size, sha256.hexdigest(), sha3.hexdigest()) ==
                (whole.get("size"), whole.get("sha256"), whole.get("sha3_256")),
                "reassembled native object digest differs")
        public_scans[label] = scan_parts([payload / name for name in names])
        observed_subjects.append({"label": label, "distributed_sha256": whole["sha256"]})
        custody_subjects.append({"label": label, "custody_sha256": custody_tar["sha256"]})
    expected_names = {"NATIVE-RECOVERY-NOTICE.md", "native-file-inventory.json",
                      "native-normalization-report.json"}
    for source in sources:
        expected_names.update(source["distribution"]["part_filenames"])
    require(listed == expected_names, "supplement has an unexpected payload")
    notice_entry = next(item for item in entries
                        if item["filename"] == "NATIVE-RECOVERY-NOTICE.md")
    require(notice_entry["role"] == "notice"
            and notice_entry["object_path"] == "NATIVE-RECOVERY-NOTICE.md",
            "supplement notice mapping differs")
    file_entry = next(item for item in entries
                      if item["filename"] == "native-file-inventory.json")
    require(file_entry["role"] == "native_file_inventory"
            and file_entry["object_path"] == "native-file-inventory.json"
            and file_entry["sha256"] == inventory.get("file_inventory_sha256"),
            "native file inventory mapping differs")
    normalization_entry = next(item for item in entries
                               if item["filename"] == "native-normalization-report.json")
    require(normalization_entry["role"] == "native_header_normalization_report"
            and normalization_entry["object_path"] == "native-normalization-report.json"
            and normalization_entry["sha256"] == inventory.get("normalization_report_sha256"),
            "native normalization report mapping differs")
    file_inventory = read_json(payload / "native-file-inventory.json")
    require(file_inventory.get("schema") == FILE_INVENTORY_SCHEMA
            and file_inventory.get("tag") == TAG
            and [entry.get("label") for entry in file_inventory.get("sources", [])]
                == sorted(SOURCE_INFO),
            "native file inventory identity differs")
    for file_source, source in zip(file_inventory["sources"], sources, strict=True):
        require(file_source.get("custody_tar") == source["custody_tar"]
                and file_source.get("published_tar") ==
                    {key: source["distribution"][key]
                     for key in ("size", "sha256", "sha3_256")}
                and len(file_source.get("files", [])) == source["state_file_count"]
                and all(item.get("mode") == 0o600 for item in file_source["files"]),
                "native per-file inventory differs from source")
        require(file_source.get("files") == public_scans[source["label"]]["files"]
                and file_source.get("state_manifest_sha256") ==
                    public_scans[source["label"]]["state_manifest_sha256"],
                "distributed native tar members differ from signed per-file inventory")
    normalization_report = read_json(payload / "native-normalization-report.json")
    expected_normalization_subjects = [
        {"label": file_source["label"],
         "custody_tar": file_source["custody_tar"],
         "published_tar": file_source["published_tar"],
         "file_count": len(file_source["files"]),
         "state_manifest_sha256": file_source["state_manifest_sha256"],
         "member_content_equal": True, "headers_normalized": True}
        for file_source in file_inventory["sources"]
    ]
    require(normalization_report == {"schema": NORMALIZATION_SCHEMA, "tag": TAG,
                                     "status": "PASS", "header_policy": HEADER_POLICY,
                                     "subjects": expected_normalization_subjects},
            "public normalization report differs from signed native files")
    publication = inventory["publication"]
    require(publication.get("review_schema") == REVIEW_SCHEMA
            and publication.get("review_decision") == "APPROVED_PUBLIC_PLAINTEXT"
            and publication.get("subjects") == observed_subjects
            and publication.get("custody_subjects") == custody_subjects
            and HEX64.fullmatch(publication.get("review_sha256", "")),
            "publication review binding differs")
    evidence = publication.get("evidence", {})
    require(set(evidence) == {"raw_byte_audit_sha256", "source_classification_sha256",
                              "normalization_report_sha256"}
            and all(HEX64.fullmatch(value) for value in evidence.values()),
            "publication evidence digests missing")
    require(evidence["normalization_report_sha256"] == inventory["normalization_report_sha256"],
            "review does not bind the public normalization report")
    require(set(publication) == {"mode", "review_schema", "review_sha256",
                                 "review_decision", "subjects", "custody_subjects",
                                 "evidence"},
            "publication fields differ from approved plaintext contract")
    if review_path is not None:
        require(raw_audit_path is not None and classification_path is not None
                and normalization_report_path is not None,
                "private review requires audit, source and normalization reports")
        require(_digest(review_path)[1] == publication["review_sha256"],
                "private publication review digest differs")
        _, checked_evidence = review_identity(
            review_path, observed_subjects, custody_subjects, raw_audit_path,
            classification_path, normalization_report_path)
        require(checked_evidence == evidence, "publication evidence digests differ")
        require(_digest(normalization_report_path)[1] ==
                inventory["normalization_report_sha256"],
                "private normalization report differs from public payload")
    if restricted_path is not None:
        require(_digest(restricted_path)[1] == inventory["file_inventory_sha256"],
                "private working copy of file inventory differs")
    return {"schema": SCHEMA, "tag": TAG, "height": HEIGHT, "hash": HASH,
            "mode": mode, "payload_count": len(entries) + 1,
            "prepared_verified": True, "signed_verified": False}


def verify_signed(release: Path, key: Path, qrlft: Path,
                  *, review_path: Path | None = None,
                  raw_audit_path: Path | None = None,
                  classification_path: Path | None = None,
                  normalization_report_path: Path | None = None) -> dict:
    result = verify_prepared(release, review_path=review_path,
                             raw_audit_path=raw_audit_path,
                             classification_path=classification_path,
                             normalization_report_path=normalization_report_path)
    require(_digest(key)[1] == KEY_SHA256, "trusted public key differs from theQRL/security")
    manifest_path = release / "manifest.json"
    signature_path = release / "manifest.json.sig"
    signatures_path = release / "signatures.txt"
    regular(manifest_path)
    manifest = read_json(manifest_path)
    require(set(manifest) == {"schema", "product", "tag", "context", "artifacts"},
            "action manifest fields differ")
    require(manifest["schema"] == "theqrl.release-manifest.v1"
            and manifest["product"] == PRODUCT and manifest["tag"] == TAG
            and manifest["context"] == ARTIFACT_CONTEXT,
            "action manifest release identity differs")
    regular(signature_path)
    signature = signature_path.read_text(encoding="ascii").strip()
    require(re.fullmatch(rf"[0-9a-fA-F]{{{SIGNATURE_HEX_LENGTH}}}", signature) is not None,
            "manifest signature encoding differs")
    _verify_qrlft(qrlft, manifest_path, key, MANIFEST_CONTEXT, sigfile=signature_path)
    payload = release / "payload"
    expected = []
    for path in payload.iterdir():
        size, sha256, _ = _digest(path)
        expected.append({"filename": path.name, "size": size, "sha256": sha256})
    expected.sort(key=lambda item: item["filename"])
    require(manifest["artifacts"] == expected, "action manifest payload set or digest differs")
    regular(signatures_path)
    signatures = {}
    for line in signatures_path.read_text(encoding="ascii").splitlines():
        signature, separator, path = line.partition(" ")
        require(bool(separator) and path.startswith("payload/") and path.count("/") == 1,
                "signature list has an invalid path")
        name = path[8:]
        require(name not in signatures and re.fullmatch(
            rf"[0-9a-fA-F]{{{SIGNATURE_HEX_LENGTH}}}", signature) is not None,
            "signature list has a duplicate or malformed signature")
        signatures[name] = signature
    require(set(signatures) == {entry["filename"] for entry in expected},
            "artifact signatures do not cover manifest")
    for entry in expected:
        _verify_qrlft(qrlft, payload / entry["filename"], key,
                      ARTIFACT_CONTEXT, signature=signatures[entry["filename"]])
    result.update({"signed_verified": True, "trusted_key_sha256": KEY_SHA256,
                   "security_commit": SECURITY_COMMIT,
                   "signature_count": len(signatures) + 1,
                   "manifest_sha256": _digest(manifest_path)[1],
                   "manifest_signature_sha256": _digest(signature_path)[1],
                   "signatures_sha256": _digest(signatures_path)[1],
                   "inventory_sha256": _digest(payload / "native-recovery-inventory.json")[1]})
    return result


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)
    normalization = commands.add_parser("normalize")
    normalization.add_argument("--tag", required=True)
    normalization.add_argument("--s1-tar", type=Path, required=True)
    normalization.add_argument("--testnet3-tar", type=Path, required=True)
    normalization.add_argument("--output", type=Path, required=True)
    make = commands.add_parser("prepare")
    make.add_argument("--tag", required=True)
    make.add_argument("--output", type=Path, required=True)
    make.add_argument("--mode", choices=("reviewed_plaintext",), required=True)
    make.add_argument("--s1-tar", type=Path, required=True)
    make.add_argument("--testnet3-tar", type=Path, required=True)
    make.add_argument("--s1-normalized-tar", type=Path, required=True)
    make.add_argument("--testnet3-normalized-tar", type=Path, required=True)
    make.add_argument("--normalization-report", type=Path, required=True)
    make.add_argument("--native-report", type=Path, required=True)
    make.add_argument("--parent-manifest", type=Path, required=True)
    make.add_argument("--publication-review", type=Path, required=True)
    make.add_argument("--raw-byte-audit", type=Path, required=True)
    make.add_argument("--source-classification", type=Path, required=True)
    make.add_argument("--restricted-report", type=Path, required=True)
    check = commands.add_parser("verify-prepared")
    check.add_argument("release", type=Path)
    check.add_argument("--review-file", type=Path)
    check.add_argument("--raw-byte-audit", type=Path)
    check.add_argument("--source-classification", type=Path)
    check.add_argument("--normalization-report", type=Path)
    check.add_argument("--restricted-report", type=Path)
    signed = commands.add_parser("verify-signed")
    signed.add_argument("release", type=Path)
    signed.add_argument("--trusted-key", type=Path, required=True)
    signed.add_argument("--qrlft-repo", type=Path, required=True)
    signed.add_argument("--review-file", type=Path)
    signed.add_argument("--raw-byte-audit", type=Path)
    signed.add_argument("--source-classification", type=Path)
    signed.add_argument("--normalization-report", type=Path)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "normalize":
            result = normalize(args)
        elif args.command == "prepare":
            result = prepare(args)
        elif args.command == "verify-prepared":
            result = verify_prepared(args.release, review_path=args.review_file,
                                     raw_audit_path=args.raw_byte_audit,
                                     classification_path=args.source_classification,
                                     normalization_report_path=args.normalization_report,
                                     restricted_path=args.restricted_report)
        else:
            with tempfile.TemporaryDirectory(prefix="qrl-native-verifier-") as directory:
                qrlft = _build_fixed_qrlft(args.qrlft_repo, Path(directory),
                                           commit=FIXED_QRLFT_COMMIT)
                result = verify_signed(args.release, args.trusted_key, qrlft,
                                       review_path=args.review_file,
                                       raw_audit_path=args.raw_byte_audit,
                                       classification_path=args.source_classification,
                                       normalization_report_path=args.normalization_report)
            result["qrlft_source_commit"] = FIXED_QRLFT_COMMIT
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ReleaseError, ArchiveError, OSError, KeyError, TypeError, ValueError,
            tarfile.TarError) as error:
        print(f"native recovery supplement: {error}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
