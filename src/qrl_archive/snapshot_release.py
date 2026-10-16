"""Prepare and verify a signed, nonterminal QRL v1 testnet snapshot.

This module deliberately uses the action v2 manifest without changing its
schema. The extra network and SHA3-256 assertions live in the signed inventory.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .block_stream_v1 import verify_archive
from .comparison import compare_archives
from .errors import ArchiveError, IntegrityError, PublicationError, SourceError, UsageError


PRODUCT = "qrl-v1-testnet-archive"
ARTIFACT_CONTEXT = PRODUCT + "-release-signatures"
MANIFEST_CONTEXT = PRODUCT + "-release-manifest"
INVENTORY_SCHEMA = "qrl.v1.archive.snapshot-inventory.v1"
DERIVED_INVENTORY_SCHEMA = "qrl.v1.archive.snapshot-inventory.v2"
RELEASE_CLASS = "LIVE_TESTNET_SNAPSHOT"
SQLITE_PART_BYTES = 16 * 1024 * 1024
KEY_SHA256 = "8cf05c32a7cb69dfe27e5137b27baedf4ab0008a0684f36e59aa2553ff8f0c5f"
SECURITY_COMMIT = "2aef08563f4d177fb2773215a30d86029ed519f7"
FIXED_QRLFT_COMMIT = "ed1f29f3e4743ba2f1429154ae31549c37e3a357"
SIGNATURE_HEX_LENGTH = 9254
TAG_PATTERN = re.compile(r"testnet-snapshot-h(0|[1-9][0-9]*)-([0-9a-f]{8,16})-r[1-9][0-9]*\Z")
HEX_32 = re.compile(r"[0-9a-f]{64}\Z")
OBJECT_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
RESERVED_RELEASE_NAMES = {"manifest.json", "manifest.json.sig", "signatures.txt"}
QUERY_SUBDIRECTORIES = {("blocks", "height"), ("blocks", "hash"),
                        ("transactions", "hash")}


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise IntegrityError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_json(path: Path) -> tuple[bytes, dict]:
    if path.is_symlink() or not path.is_file():
        raise SourceError(f"missing or linked file: {path.name}")
    try:
        raw = path.read_bytes()
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (OSError, UnicodeError, ValueError) as error:
        raise SourceError(f"cannot read JSON file: {path.name}") from error
    if not isinstance(obj, dict):
        raise IntegrityError(f"JSON root is not an object: {path.name}")
    return raw, obj


def _json_bytes(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"


def _digest(path: Path) -> tuple[int, str, str]:
    if path.is_symlink() or not path.is_file():
        raise SourceError(f"missing or linked file: {path.name}")
    sha256 = hashlib.sha256()
    sha3 = hashlib.sha3_256()
    size = 0
    with path.open("rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise SourceError(f"not a regular file: {path.name}")
        while chunk := stream.read(1024 * 1024):
            sha256.update(chunk)
            sha3.update(chunk)
            size += len(chunk)
    return size, sha256.hexdigest(), sha3.hexdigest()


def _named_payload(path: Path, role: str, object_path: str | None = None) -> dict:
    size, sha256, sha3 = _digest(path)
    return {"filename": path.name, "role": role, "size": size,
            "sha256": sha256, "sha3_256": sha3,
            "object_path": object_path or path.name}


def _check_object_path(filename: str, object_path: str) -> None:
    if not isinstance(object_path, str) or object_path.startswith("/") or "\\" in object_path:
        raise IntegrityError("unsafe public object path")
    parts = object_path.split("/")
    nested_ok = (
        len(parts) == 1
        or (len(parts) == 2 and parts == ["query", "query-packs-index.json"])
        or (len(parts) == 3 and parts[:2] == ["query", "addresses"])
        or (len(parts) == 3 and parts[:2] == ["derived", "sqlite"]
            and filename.endswith(".part"))
        or (len(parts) == 4 and parts[0] == "query"
            and tuple(parts[1:3]) in QUERY_SUBDIRECTORIES)
    )
    if (not parts or any(part in (".", "..") or OBJECT_COMPONENT.fullmatch(part) is None
                         for part in parts) or parts[-1] != filename
            or filename in RESERVED_RELEASE_NAMES or not nested_ok):
        raise IntegrityError("unsafe public object path")


def _require(condition: bool, reason: str) -> None:
    if not condition:
        raise IntegrityError(reason)


def _utc_timestamp(value: object) -> bool:
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo == timezone.utc
    except ValueError:
        return False


def _anchors(index: dict) -> dict:
    return {
        "network_id": index["network_id"],
        "genesis_hash": index["genesis_hash"],
        "fork_height": index["fork_height"],
        "fork_hash": index["fork_hash"],
        "terminal_height": index["terminal_height"],
        "terminal_hash": index["terminal_hash"],
    }


def _check_identity(index: dict, tag: str) -> None:
    match = TAG_PATTERN.fullmatch(tag)
    if match is None:
        raise UsageError("tag must be testnet-snapshot-hHEIGHT-HASHPREFIX-rREVISION")
    _require(index.get("network_id") == "testnet", "snapshot must use the testnet block stream")
    _require(index.get("block_count") == index.get("terminal_height", -2) + 1,
             "snapshot block count differs from cutoff height")
    _require(match.group(1) == str(index["terminal_height"]), "tag height differs from cutoff")
    _require(index["terminal_hash"].startswith(match.group(2)), "tag hash prefix differs from cutoff")
    for field in ("genesis_hash", "terminal_hash"):
        _require(isinstance(index.get(field), str) and HEX_32.fullmatch(index[field]) is not None,
                 f"invalid {field}")


def _check_reports(compare_report: dict, native_report: dict, comparison: dict,
                   index: dict) -> None:
    _require(compare_report.get("schema") == "qrl.v1.archive.report.v1"
             and compare_report.get("command") == "compare"
             and compare_report.get("status") == "PASS"
             and compare_report.get("exit_code") == 0
             and compare_report.get("result") == comparison,
             "source comparison report does not match a fresh exact-byte comparison")
    _require(comparison["exact_block_bytes_equal"] is True
             and comparison["first_mismatch"] is None,
             "independent canonical exports differ")
    native = native_report.get("result", {})
    _require(native_report.get("schema") == "qrl.v1.archive.report.v1"
             and native_report.get("command") == "compare-native-state"
             and native_report.get("status") == "PASS"
             and native_report.get("exit_code") == 0
             and native.get("schema") == "qrl.v1.archive.native-state-compare.v1"
             and native.get("exact_native_state_bytes_equal") is True
             and native.get("native_state_agreement_verified") is True,
             "native state comparison report is not a passing byte comparison")
    native_anchors = native.get("anchors", {})
    for field in ("genesis_hash", "fork_height", "fork_hash", "terminal_height", "terminal_hash"):
        _require(native_anchors.get(field) == index[field], f"native report {field} differs")
    _require(native_anchors.get("network_id") in ("Final Testnet", "testnet"),
             "native report is for another network")


def _notice(index: dict, tag: str, *, derived: bool = False) -> bytes:
    text = (
        "# Live QRL v1 testnet snapshot\n\n"
        f"Release: `{tag}`\n\n"
        f"This is a point-in-time record of testnet blocks 0 through {index['terminal_height']} "
        f"at hash `{index['terminal_hash']}`. The public testnet continues beyond this "
        "cutoff. This release is not a final network archive, a terminal-block claim, "
        "or approval to shut down any node or miner.\n\n"
        "The canonical block bytes come from two separately captured source nodes "
        "and agree at every height. The current verifier checks structure, links, "
        "uniqueness and both file digests. It does not replay historical consensus "
        "or prove source independence on its own. `shards.json` uses the exporter "
        "field names `terminal_height` and `terminal_hash` for the end of this "
        "bounded export; here they mean snapshot cutoff.\n\n"
    )
    if derived:
        text += (
            "The explorer lookup files are derived from a certified SQLite view "
            "of this same cutoff. Account balances and nonces are observed "
            "native state from two agreeing source captures, not balances "
            "replayed independently from genesis. SQLite snapshot eligibility "
            "does not imply final retirement readiness.\n\n"
        )
    text += (
        "The signed inventory states the precise verification scope. Use the "
        "QRL release public key from the pinned theQRL/security repository, not "
        "a key downloaded only beside this snapshot.\n"
    )
    return text.encode("utf-8")


def _public_live_anchor(path: Path, index: dict) -> dict:
    raw, report = _read_json(path)
    _require(report.get("schema") == "qrl-v1-live-snapshot-anchor-observation-v1"
             and report.get("network_id") in ("Final Testnet", "testnet")
             and report.get("snapshot_height") == index["terminal_height"]
             and report.get("snapshot_block_hash") == index["terminal_hash"]
             and _utc_timestamp(report.get("reported_at_utc")),
             "live anchor report does not match snapshot cutoff")
    observations = report.get("observations")
    _require(isinstance(observations, list) and len(observations) == 2,
             "live anchor requires two observations")
    public_observations = []
    transports = set()
    nodes = set()
    for number, observation in enumerate(observations):
        _require(isinstance(observation, dict), "invalid live anchor observation")
        node = observation.get("node")
        transport = observation.get("transport")
        _require(isinstance(node, str) and node and node not in nodes,
                 "live anchor nodes must be distinct")
        nodes.add(node)
        _require(isinstance(observation.get("head_height"), int)
                 and observation["head_height"] >= index["terminal_height"]
                 and observation.get("historical_height") == index["terminal_height"]
                 and observation.get("historical_block_hash") == index["terminal_hash"],
                 "live anchor node does not retain the cutoff block")
        if transport == "host-key-verified SSH to local QRL gRPC API":
            public_transport = "host_key_verified_ssh_local_grpc"
        elif transport == "public unauthenticated gRPC API":
            public_transport = "public_unauthenticated_grpc"
        else:
            raise IntegrityError("unrecognized live anchor transport")
        transports.add(public_transport)
        public_observations.append({
            "source_label": f"observer-{number + 1}",
            "transport": public_transport,
            "head_height": observation["head_height"],
            "historical_height": observation["historical_height"],
            "historical_block_hash": observation["historical_block_hash"],
        })
    _require(transports == {"host_key_verified_ssh_local_grpc", "public_unauthenticated_grpc"},
             "live anchor lacks both transport classes")
    return {
        "schema": "qrl.v1.archive.public-live-anchor.v1",
        "reported_at_utc": report["reported_at_utc"],
        "network_id": "testnet",
        "snapshot_height": index["terminal_height"],
        "snapshot_hash": index["terminal_hash"],
        "network_remains_live": True,
        "point_in_time_only": True,
        "private_operator_report_sha256": hashlib.sha256(raw).hexdigest(),
        "observations": public_observations,
    }


def _check_snapshot_sqlite(path: Path, report: dict, index: dict,
                           expected_digest: dict | None = None) -> dict:
    """Check the narrower live-snapshot certificate, never retirement readiness."""
    _require(path.name.endswith(".snapshot.sqlite") and ".partial" not in path.name,
             "SQLite is not a certified snapshot file")
    _require(report.get("schema") == "qrl-v1-sqlite-snapshot-certification-v1"
             and report.get("anchors") == _anchors(index)
             and report.get("snapshot_eligible") is True
             and report.get("snapshot_kind") == "live-chain-point-in-time"
             and report.get("balances_observed_at_cutoff") is True
             and report.get("independent_sources_attested_by_operator") is True
             and report.get("chain_derived_tables_equal") is True
             and report.get("consensus_replayed") is False
             and report.get("release_ready") is False,
             "SQLite snapshot certificate is not eligible for this live snapshot")
    native = report.get("native_account_comparison", {})
    structural = report.get("canonical_structural_check", {})
    _require(native.get("schema") == "qrl-v1-native-balance-check-v1"
             and native.get("anchors") == _anchors(index)
             and native.get("all_balances_nonces_and_state_pb_equal") is True
             and native.get("source_independence_verified") is False
             and native.get("consensus_replayed") is False
             and native.get("release_ready") is False
             and native.get("account_count", 0) > 0
             and structural.get("structural_verified") is True
             and structural.get("consensus_verified") is False
             and structural.get("block_count") == index["block_count"]
             and structural.get("transaction_count") == index["transaction_count"],
             "SQLite snapshot certificate evidence differs from cutoff")
    size, sha256, sha3 = _digest(path)
    digest = {"bytes": size, "sha256": sha256, "sha3_256": sha3}
    _require(report.get("file") == digest
             and (expected_digest is None or expected_digest == digest),
             "certified SQLite whole-file digest differs")
    try:
        with sqlite3.connect(f"{path.as_uri()}?mode=ro&immutable=1", uri=True) as db:
            _require(db.execute("PRAGMA integrity_check").fetchone() == ("ok",),
                     "certified SQLite integrity check failed")
            _require(db.execute("PRAGMA foreign_key_check").fetchone() is None,
                     "certified SQLite foreign key check failed")
            meta = dict(db.execute("SELECT key,value FROM archive_meta"))
            _require(all(meta.get(key) == str(value) for key, value in _anchors(index).items())
                     and meta.get("snapshot_eligible") == "true"
                     and meta.get("snapshot_kind") == "live-chain-point-in-time"
                     and meta.get("snapshot_canonical_verification") == "structural-only"
                     and meta.get("snapshot_balance_label") ==
                     "observed-at-cutoff-two-node-agreement"
                     and meta.get("snapshot_source_independence") == "operator-attested"
                     and meta.get("snapshot_account_rows_sha256") == native.get("rows_sha256")
                     and meta.get("snapshot_account_rows_sha3_256") == native.get("rows_sha3_256")
                     and meta.get("release_ready") == "false"
                     and meta.get("consensus_replayed") == "false"
                     and meta.get("balance_source") == "qrl-state-v3-anchored-not-replayed",
                     "certified SQLite metadata differs from snapshot certificate")
            _require(db.execute("SELECT COUNT(*) FROM blocks").fetchone()[0] == index["block_count"]
                     and db.execute("SELECT COUNT(*) FROM transactions").fetchone()[0]
                     == index["transaction_count"]
                     and db.execute("SELECT COUNT(*) FROM final_address_state").fetchone()[0]
                     == native["account_count"],
                     "certified SQLite row counts differ")
    except sqlite3.Error as error:
        raise IntegrityError("certified SQLite cannot be read safely") from error
    return digest


def _check_query_index(query_index: dict, verify_report: dict,
                       snapshot: dict, sqlite_sha256: str,
                       account_count: int, query_index_sha256: str) -> list[dict]:
    _require(query_index.get("schema") == "qrl.v1.archive.query-packs.v1"
             and query_index.get("network") == "testnet"
             and query_index.get("snapshot_kind") == "live-chain-point-in-time"
             and query_index.get("snapshot_balance_label") ==
             "observed-at-cutoff-two-node-agreement"
             and query_index.get("consensus_replayed") is False
             and query_index.get("source_sqlite_sha256") == sqlite_sha256
             and query_index.get("genesis_hash") == snapshot["genesis_hash"]
             and query_index.get("snapshot_height") == snapshot["height"]
             and query_index.get("snapshot_hash") == snapshot["hash"]
             and query_index.get("canonical_stream_sha256") ==
             snapshot["block_stream_sha256"]
             and query_index.get("block_count") == snapshot["block_count"]
             and query_index.get("transaction_count") == snapshot["transaction_count"]
             and query_index.get("height_pack_size") == 1000
             and query_index.get("event_record_bytes") == 54,
             "query pack index differs from canonical snapshot")
    files = query_index.get("files")
    _require(isinstance(files, list) and len(files) > 0,
             "query pack index has no files")
    _require(verify_report.get("schema") == "qrl.v1.archive.query-packs.v1"
             and verify_report.get("status") == "PASS"
             and verify_report.get("release_ready") is False
             and verify_report.get("network") == "testnet"
             and verify_report.get("snapshot_height") == snapshot["height"]
             and verify_report.get("snapshot_hash") == snapshot["hash"]
             and verify_report.get("canonical_stream_sha256") ==
             snapshot["block_stream_sha256"]
             and verify_report.get("source_sqlite_sha256") == sqlite_sha256
             and verify_report.get("query_index_sha256") == query_index_sha256
             and verify_report.get("block_count") == snapshot["block_count"]
             and verify_report.get("transaction_count") == snapshot["transaction_count"]
             and verify_report.get("address_count") == query_index.get("address_count")
             and verify_report.get("event_count") == query_index.get("event_count")
             and verify_report.get("observed_account_state_count") == account_count
             and verify_report.get("sha256_sha3_checked") is True
             and verify_report.get("sqlite_logical_comparison_passed") is True
             and verify_report.get("signed_verified") is False
             and verify_report.get("served_bytes_verified") is False
             and verify_report.get("file_count") == len(files)
             and verify_report.get("total_bytes") == sum(file.get("bytes", 0) for file in files)
             and verify_report.get("max_file_bytes") ==
             max(file.get("bytes", 0) for file in files)
             and verify_report["max_file_bytes"] <= 64 * 1024 * 1024,
             "query pack verification report does not pass this snapshot")
    names = []
    paths = []
    for file in files:
        _require(set(file) == {"path", "bytes", "sha256", "sha3_256"}
                 and isinstance(file["path"], str)
                 and isinstance(file["bytes"], int) and 0 <= file["bytes"] <= 64 * 1024 * 1024
                 and isinstance(file["sha256"], str) and HEX_32.fullmatch(file["sha256"])
                 and isinstance(file["sha3_256"], str) and HEX_32.fullmatch(file["sha3_256"]),
                 "query pack file record is invalid")
        name = Path(file["path"]).name
        _check_object_path(name, f"query/{file['path']}")
        names.append(name)
        paths.append(file["path"])
    _require(len(names) == len(set(names)),
             "query pack basenames must be unique")
    _require(paths == sorted(set(paths)), "query pack paths must be unique and sorted")
    return files


def _add_derived_payloads(payload: Path, objects: list[dict], index: dict,
                          snapshot: dict, sqlite_path: Path, sqlite_report_path: Path,
                          query_dir: Path, query_verify_path: Path) -> dict:
    _require(".partial" not in sqlite_path.name and ".partial" not in query_dir.name,
             "partial derived outputs cannot be packaged")
    _, sqlite_report = _read_json(sqlite_report_path)
    sqlite_digest = _check_snapshot_sqlite(sqlite_path, sqlite_report, index)
    query_index_raw, query_index = _read_json(query_dir / "query-packs-index.json")
    _, query_verify = _read_json(query_verify_path)
    query_files = _check_query_index(query_index, query_verify, snapshot,
                                     sqlite_digest["sha256"],
                                     sqlite_report["native_account_comparison"]["account_count"],
                                     hashlib.sha256(query_index_raw).hexdigest())
    # The query verifier has its own independently computed file digests and
    # logical SQLite comparison. Re-check every staged byte below.
    shutil.copyfile(sqlite_report_path, payload / "snapshot-sqlite-certification.json")
    objects.append(_named_payload(payload / "snapshot-sqlite-certification.json",
                                  "sqlite_snapshot_certification"))
    shutil.copyfile(query_dir / "query-packs-index.json", payload / "query-packs-index.json")
    objects.append(_named_payload(payload / "query-packs-index.json", "query_pack_index",
                                  "query/query-packs-index.json"))
    shutil.copyfile(query_verify_path, payload / "query-packs-verification.json")
    objects.append(_named_payload(payload / "query-packs-verification.json",
                                  "query_pack_verification"))

    parts = []
    with sqlite_path.open("rb") as source:
        number = 0
        while data := source.read(SQLITE_PART_BYTES):
            name = f"snapshot-sqlite-{number:06d}.part"
            part = payload / name
            part.write_bytes(data)
            entry = _named_payload(part, "sqlite_snapshot_part",
                                   f"derived/sqlite/{name}")
            objects.append(entry)
            parts.append({key: entry[key] for key in ("filename", "size", "sha256", "sha3_256")})
            number += 1
    _require(len(parts) == (sqlite_digest["bytes"] + SQLITE_PART_BYTES - 1) // SQLITE_PART_BYTES,
             "SQLite split count differs from whole-file size")
    query_names = []
    for file in query_files:
        source = query_dir / file["path"]
        _require(source.resolve().is_relative_to(query_dir.resolve())
                 and not source.is_symlink() and source.is_file(),
                 "query pack source is missing or linked")
        name = source.name
        _require(not (payload / name).exists(), "query pack basename collides with payload")
        shutil.copyfile(source, payload / name)
        entry = _named_payload(payload / name, "query_pack", f"query/{file['path']}")
        _require((entry["size"], entry["sha256"], entry["sha3_256"]) ==
                 (file["bytes"], file["sha256"], file["sha3_256"]),
                 f"query pack changed during staging: {name}")
        objects.append(entry)
        query_names.append(name)
    return {
        "schema": "qrl.v1.archive.snapshot-derived.v1",
        "sqlite": {
            "whole_file": sqlite_digest,
            "part_size": SQLITE_PART_BYTES,
            "parts": parts,
            "certification_report": "snapshot-sqlite-certification.json",
            "balance_label": "observed-at-cutoff-two-node-agreement",
            "snapshot_eligible": True,
            "consensus_replayed": False,
            "release_ready": False,
        },
        "query_packs": {
            "index": "query-packs-index.json",
            "verification_report": "query-packs-verification.json",
            "file_count": len(query_names),
            "total_bytes": sum(file["bytes"] for file in query_files),
        },
    }


def prepare(canonical: Path, secondary: Path, compare_path: Path,
            native_path: Path, live_anchor_path: Path, output: Path, tag: str,
            *, sqlite_path: Path | None = None, sqlite_report_path: Path | None = None,
            query_dir: Path | None = None, query_verify_path: Path | None = None) -> dict:
    _, index = _read_json(canonical / "shards.json")
    _check_identity(index, tag)
    if output.exists() or not output.parent.is_dir():
        raise UsageError("release output must be a fresh path under an existing directory")
    if canonical.resolve() == secondary.resolve():
        raise UsageError("two distinct source exports are required")
    comparison = compare_archives(canonical, secondary, **_anchors(index))
    _, compare_report = _read_json(compare_path)
    _, native_report = _read_json(native_path)
    _check_reports(compare_report, native_report, comparison, index)
    public_live_anchor = _public_live_anchor(live_anchor_path, index)
    derived_inputs = (sqlite_path, sqlite_report_path, query_dir, query_verify_path)
    if any(value is not None for value in derived_inputs) and not all(
            value is not None for value in derived_inputs):
        raise UsageError("all certified SQLite and query-pack inputs are required together")

    temporary = Path(tempfile.mkdtemp(prefix=".snapshot-release-", dir=output.parent))
    try:
        payload = temporary / "payload"
        payload.mkdir()
        objects: list[dict] = []
        expected_shards = index["shards"]
        _require(isinstance(expected_shards, list) and bool(expected_shards), "empty shard list")
        for shard in expected_shards:
            name = shard["name"]
            _require(isinstance(name, str) and Path(name).name == name and name.endswith(".qrlblk"),
                     "invalid shard filename")
            src = canonical / name
            dst = payload / name
            if src.is_symlink() or not src.is_file():
                raise SourceError(f"missing or linked shard: {name}")
            shutil.copyfile(src, dst)
            entry = _named_payload(dst, "canonical_block_shard")
            _require(all(entry[key] == shard[key] for key in ("size", "sha256", "sha3_256") if key in shard)
                     and entry["size"] == shard["bytes"],
                     f"shard changed during staging: {name}")
            objects.append(entry)
        for src, name, role in (
            (canonical / "shards.json", "shards.json", "canonical_shard_index"),
            (compare_path, "source-comparison.json", "source_comparison_report"),
            (native_path, "native-state-comparison.json", "native_state_comparison_report"),
        ):
            if src.is_symlink() or not src.is_file():
                raise SourceError(f"missing or linked input: {src.name}")
            shutil.copyfile(src, payload / name)
            objects.append(_named_payload(payload / name, role))
        (payload / "SNAPSHOT-NOTICE.md").write_bytes(_notice(
            index, tag, derived=all(value is not None for value in derived_inputs)))
        objects.append(_named_payload(payload / "SNAPSHOT-NOTICE.md", "public_notice"))
        (payload / "live-anchor-summary.json").write_bytes(_json_bytes(public_live_anchor))
        objects.append(_named_payload(payload / "live-anchor-summary.json", "live_anchor_observation"))
        snapshot = {
            "network_id": index["network_id"],
            "genesis_hash": index["genesis_hash"],
            "height": index["terminal_height"],
            "hash": index["terminal_hash"],
            "block_count": index["block_count"],
            "transaction_count": index["transaction_count"],
            "source_run_ids": [comparison["a"]["run_id"], comparison["b"]["run_id"]],
            "block_stream_sha256": comparison["a"]["block_stream_sha256"],
            "block_stream_sha3_256": comparison["a"]["block_stream_sha3_256"],
        }
        derived = None
        if all(value is not None for value in derived_inputs):
            derived = _add_derived_payloads(payload, objects, index, snapshot,
                                            sqlite_path, sqlite_report_path,
                                            query_dir, query_verify_path)
        objects.sort(key=lambda entry: entry["filename"])
        _require(len({entry["filename"] for entry in objects}) == len(objects),
                 "duplicate payload basename")
        _require(len({entry["object_path"] for entry in objects}) == len(objects),
                 "duplicate public object path")

        inventory = {
            "schema": DERIVED_INVENTORY_SCHEMA if derived is not None else INVENTORY_SCHEMA,
            "release_class": RELEASE_CLASS,
            "product": PRODUCT,
            "tag": tag,
            "object_prefix": f"testnet/snapshots/{tag}",
            "trust_root": {
                "security_commit": SECURITY_COMMIT,
                "public_key_sha256": KEY_SHA256,
                "artifact_context": ARTIFACT_CONTEXT,
                "manifest_context": MANIFEST_CONTEXT,
            },
            "snapshot": snapshot,
            "verification_scope": {
                "structural_verified": True,
                "dual_source_exact_bytes_equal": True,
                "native_state_comparison_report_included": True,
                "live_anchor_observation_included": True,
                "source_independence_cryptographically_proven": False,
                "historical_consensus_replayed": False,
                "network_stopped": False,
                "retirement_authorized": False,
            },
            "payloads": objects,
        }
        if derived is not None:
            inventory["derived"] = derived
            inventory["verification_scope"]["snapshot_sqlite_eligible"] = True
            inventory["verification_scope"]["query_packs_verified"] = True
        (payload / "archive-inventory.json").write_bytes(_json_bytes(inventory))
        verify_prepared(temporary)
        for path in payload.iterdir():
            with path.open("rb") as stream:
                os.fsync(stream.fileno())
        descriptor = os.open(payload, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.rename(temporary, output)
        return inventory
    except Exception:
        shutil.rmtree(temporary)
        raise


def verify_prepared(release: Path) -> dict:
    payload = release / "payload"
    _, inventory = _read_json(payload / "archive-inventory.json")
    derived_release = inventory.get("schema") == DERIVED_INVENTORY_SCHEMA
    expected_fields = {"schema", "release_class", "product", "tag",
                       "object_prefix", "trust_root", "snapshot",
                       "verification_scope", "payloads"}
    if derived_release:
        expected_fields.add("derived")
    _require(set(inventory) == expected_fields, "inventory fields differ")
    _require(inventory["schema"] in {INVENTORY_SCHEMA, DERIVED_INVENTORY_SCHEMA}
             and inventory["release_class"] == RELEASE_CLASS
             and inventory["product"] == PRODUCT, "inventory is not a live testnet snapshot")
    _require(inventory["object_prefix"] == f"testnet/snapshots/{inventory['tag']}"
             and inventory["trust_root"] == {
                 "security_commit": SECURITY_COMMIT,
                 "public_key_sha256": KEY_SHA256,
                 "artifact_context": ARTIFACT_CONTEXT,
                 "manifest_context": MANIFEST_CONTEXT,
             }, "object prefix or trust root differs")
    scope = inventory["verification_scope"]
    expected_scope = {
        "structural_verified": True,
        "dual_source_exact_bytes_equal": True,
        "native_state_comparison_report_included": True,
        "live_anchor_observation_included": True,
        "source_independence_cryptographically_proven": False,
        "historical_consensus_replayed": False,
        "network_stopped": False,
        "retirement_authorized": False,
    }
    if derived_release:
        expected_scope.update(snapshot_sqlite_eligible=True, query_packs_verified=True)
    _require(scope == expected_scope, "snapshot verification scope changed")
    entries = inventory["payloads"]
    _require(isinstance(entries, list) and len(entries) >= 5, "missing payload entries")
    names = []
    for entry in entries:
        _require(set(entry) == {"filename", "role", "size", "sha256", "sha3_256",
                                "object_path"},
                 "payload entry fields differ")
        name = entry["filename"]
        _require(isinstance(name, str) and Path(name).name == name
                 and name != "archive-inventory.json", "unsafe payload filename")
        _check_object_path(name, entry["object_path"])
        names.append(name)
        size, sha256, sha3 = _digest(payload / name)
        _require((size, sha256, sha3) == (entry["size"], entry["sha256"], entry["sha3_256"]),
                 f"payload digest mismatch: {name}")
    _require(names == sorted(set(names)), "payload names not unique and sorted")
    _require(len({entry["object_path"] for entry in entries}) == len(entries),
             "duplicate public object path")
    _require({p.name for p in payload.iterdir()} == set(names) | {"archive-inventory.json"},
             "unlisted or missing payload file")
    _, index = _read_json(payload / "shards.json")
    _check_identity(index, inventory["tag"])
    expected_roles = {shard["name"]: "canonical_block_shard" for shard in index["shards"]}
    expected_roles.update({
        "shards.json": "canonical_shard_index",
        "source-comparison.json": "source_comparison_report",
        "native-state-comparison.json": "native_state_comparison_report",
        "SNAPSHOT-NOTICE.md": "public_notice",
        "live-anchor-summary.json": "live_anchor_observation",
    })
    if derived_release:
        derived = inventory["derived"]
        _require(isinstance(derived, dict) and set(derived) ==
                 {"schema", "sqlite", "query_packs"}
                 and derived.get("schema") == "qrl.v1.archive.snapshot-derived.v1",
                 "derived inventory descriptor differs")
        sqlite_desc = derived["sqlite"]
        query_desc = derived["query_packs"]
        _require(isinstance(sqlite_desc, dict) and set(sqlite_desc) ==
                 {"whole_file", "part_size", "parts", "certification_report",
                  "balance_label", "snapshot_eligible", "consensus_replayed",
                  "release_ready"}
                 and sqlite_desc["certification_report"] ==
                 "snapshot-sqlite-certification.json"
                 and sqlite_desc["balance_label"] ==
                 "observed-at-cutoff-two-node-agreement"
                 and sqlite_desc["snapshot_eligible"] is True
                 and sqlite_desc["consensus_replayed"] is False
                 and sqlite_desc["release_ready"] is False
                 and sqlite_desc["part_size"] == SQLITE_PART_BYTES,
                 "SQLite parts descriptor differs")
        _require(isinstance(query_desc, dict) and set(query_desc) ==
                 {"index", "verification_report", "file_count", "total_bytes"}
                 and query_desc["index"] == "query-packs-index.json"
                 and query_desc["verification_report"] ==
                 "query-packs-verification.json",
                 "query pack descriptor differs")
        expected_roles.update({
            "snapshot-sqlite-certification.json": "sqlite_snapshot_certification",
            "query-packs-index.json": "query_pack_index",
            "query-packs-verification.json": "query_pack_verification",
        })
        _, certificate = _read_json(payload / "snapshot-sqlite-certification.json")
        query_index_raw, query_index = _read_json(payload / "query-packs-index.json")
        _, query_report = _read_json(payload / "query-packs-verification.json")
        query_files = _check_query_index(query_index, query_report,
                                         inventory["snapshot"],
                                         sqlite_desc["whole_file"]["sha256"],
                                         certificate["native_account_comparison"]["account_count"],
                                         hashlib.sha256(query_index_raw).hexdigest())
        _require(query_desc["file_count"] == len(query_files)
                 and query_desc["total_bytes"] == sum(f["bytes"] for f in query_files),
                 "query pack descriptor counts differ")
        by_name = {entry["filename"]: entry for entry in entries}
        _require(by_name["query-packs-index.json"]["object_path"] ==
                 "query/query-packs-index.json", "query index public path differs")
        for file in query_files:
            name = Path(file["path"]).name
            expected_roles[name] = "query_pack"
            _require(name in by_name and by_name[name]["object_path"] == f"query/{file['path']}"
                     and (by_name[name]["size"], by_name[name]["sha256"],
                          by_name[name]["sha3_256"]) ==
                     (file["bytes"], file["sha256"], file["sha3_256"]),
                     f"query pack inventory differs from index: {name}")
        parts = sqlite_desc["parts"]
        whole = sqlite_desc["whole_file"]
        _require(isinstance(parts, list) and len(parts) > 0
                 and isinstance(whole, dict)
                 and set(whole) == {"bytes", "sha256", "sha3_256"}
                 and isinstance(whole["bytes"], int) and whole["bytes"] > 0
                 and len(parts) ==
                 (whole["bytes"] + SQLITE_PART_BYTES - 1) // SQLITE_PART_BYTES,
                 "SQLite part count or whole-file descriptor differs")
        for number, part in enumerate(parts):
            name = f"snapshot-sqlite-{number:06d}.part"
            expected_size = min(SQLITE_PART_BYTES,
                                whole["bytes"] - number * SQLITE_PART_BYTES)
            _require(isinstance(part, dict)
                     and set(part) == {"filename", "size", "sha256", "sha3_256"}
                     and part["filename"] == name and part["size"] == expected_size
                     and name in by_name
                     and by_name[name]["object_path"] == f"derived/sqlite/{name}"
                     and all(part[key] == by_name[name][key] for key in
                             ("size", "sha256", "sha3_256")),
                     f"SQLite part descriptor differs: {name}")
            expected_roles[name] = "sqlite_snapshot_part"
    _require({entry["filename"]: entry["role"] for entry in entries} == expected_roles,
             "payload names or roles differ from snapshot format")
    snap = inventory["snapshot"]
    _require(set(snap) == {"network_id", "genesis_hash", "height", "hash", "block_count",
                             "transaction_count", "source_run_ids", "block_stream_sha256",
                             "block_stream_sha3_256"}, "snapshot identity fields differ")
    _require((snap["network_id"], snap["genesis_hash"], snap["height"], snap["hash"],
              snap["block_count"], snap["transaction_count"]) ==
             (index["network_id"], index["genesis_hash"], index["terminal_height"],
              index["terminal_hash"], index["block_count"], index["transaction_count"]),
             "inventory snapshot identity differs from canonical index")
    _require({s["name"] for s in index["shards"]} ==
             {e["filename"] for e in entries if e["role"] == "canonical_block_shard"},
             "inventory shard set differs from canonical index")
    verified = verify_archive(payload, **_anchors(index))
    _require(verified["structural_verified"] is True, "canonical structural verification failed")
    _, report = _read_json(payload / "source-comparison.json")
    result = report.get("result", {})
    _require(report.get("status") == "PASS" and result.get("exact_block_bytes_equal") is True
             and result.get("anchors") == _anchors(index)
             and result.get("a", {}).get("block_stream_sha256") == snap["block_stream_sha256"]
             and result.get("a", {}).get("block_stream_sha3_256") == snap["block_stream_sha3_256"]
             and result.get("b", {}).get("block_stream_sha256") == snap["block_stream_sha256"]
             and result.get("b", {}).get("block_stream_sha3_256") == snap["block_stream_sha3_256"]
             and snap["source_run_ids"] == [result["a"]["run_id"], result["b"]["run_id"]],
             "source comparison evidence differs from inventory")
    _, native_report = _read_json(payload / "native-state-comparison.json")
    native = native_report.get("result", {})
    native_anchors = native.get("anchors", {})
    _require(native_report.get("status") == "PASS"
             and native_report.get("command") == "compare-native-state"
             and native_report.get("exit_code") == 0
             and native.get("exact_native_state_bytes_equal") is True
             and native.get("native_state_agreement_verified") is True
             and all(native_anchors.get(field) == index[field] for field in
                     ("genesis_hash", "fork_height", "fork_hash", "terminal_height", "terminal_hash"))
             and native_anchors.get("network_id") in ("Final Testnet", "testnet"),
             "native comparison evidence is not a pass")
    _require((payload / "SNAPSHOT-NOTICE.md").read_bytes() ==
             _notice(index, inventory["tag"], derived=derived_release),
             "live snapshot notice missing")
    _, live = _read_json(payload / "live-anchor-summary.json")
    _require(live.get("schema") == "qrl.v1.archive.public-live-anchor.v1"
             and live.get("network_id") == "testnet"
             and live.get("snapshot_height") == snap["height"]
             and live.get("snapshot_hash") == snap["hash"]
             and live.get("network_remains_live") is True
             and live.get("point_in_time_only") is True
             and _utc_timestamp(live.get("reported_at_utc"))
             and isinstance(live.get("private_operator_report_sha256"), str)
             and HEX_32.fullmatch(live["private_operator_report_sha256"]) is not None
             and isinstance(live.get("observations"), list)
             and len(live["observations"]) == 2
             and all(isinstance(item, dict) for item in live["observations"])
             and [item.get("source_label") for item in live["observations"]] ==
             ["observer-1", "observer-2"]
             and {item.get("transport") for item in live["observations"]} ==
             {"host_key_verified_ssh_local_grpc", "public_unauthenticated_grpc"}
             and all(item.get("historical_height") == snap["height"]
                     and item.get("historical_block_hash") == snap["hash"]
                     and isinstance(item.get("head_height"), int)
                     and item["head_height"] >= snap["height"] for item in live["observations"]),
             "public live anchor differs from snapshot")
    if derived_release:
        with tempfile.TemporaryDirectory(prefix="qrl-snapshot-sqlite-verify-") as directory:
            reconstructed = Path(directory) / "reassembled.snapshot.sqlite"
            with reconstructed.open("wb") as target:
                for part in sqlite_desc["parts"]:
                    with (payload / part["filename"]).open("rb") as source:
                        shutil.copyfileobj(source, target, length=1024 * 1024)
            _check_snapshot_sqlite(reconstructed, certificate, index,
                                   sqlite_desc["whole_file"])
    result = {"schema": inventory["schema"], "tag": inventory["tag"],
            "height": snap["height"], "hash": snap["hash"],
            "payload_count": len(entries) + 1, "structural_verified": True,
            "derived_verified": derived_release,
            "signed_verified": False}
    if derived_release:
        result["query_logical_comparison_report_checked"] = True
        result["query_logical_comparison_freshly_rerun"] = False
        result["sqlite_reassembled_verified"] = True
        result["snapshot_eligible"] = True
    return result


def _verify_qrlft(qrlft: Path, source: Path, key: Path, context: str,
                  *, signature: str | None = None, sigfile: Path | None = None) -> None:
    option = f"--signature={signature}" if signature is not None else f"--sigfile={sigfile}"
    result = subprocess.run(
        (str(qrlft), "verify", "-a", "mldsa", f"--context={context}", option,
         f"--pkfile={key}", str(source)),
        capture_output=True, text=True, check=False,
    )
    if result.returncode:
        raise PublicationError(f"ML-DSA verification failed: {source.name}")


def verify_signed(release: Path, trusted_key: Path, qrlft: Path) -> dict:
    result = verify_prepared(release)
    if _digest(trusted_key)[1] != KEY_SHA256:
        raise PublicationError("trusted key differs from pinned theQRL/security public key")
    manifest_path = release / "manifest.json"
    sigfile = release / "manifest.json.sig"
    signatures_path = release / "signatures.txt"
    _, manifest = _read_json(manifest_path)
    _require(set(manifest) == {"schema", "product", "tag", "context", "artifacts"},
             "action manifest fields differ")
    _require(manifest["schema"] == "theqrl.release-manifest.v1"
             and manifest["product"] == PRODUCT
             and manifest["tag"] == result["tag"]
             and manifest["context"] == ARTIFACT_CONTEXT,
             "action manifest release identity differs")
    if sigfile.is_symlink() or not sigfile.is_file():
        raise SourceError("manifest signature missing or linked")
    signature = sigfile.read_text(encoding="ascii").strip()
    _require(re.fullmatch(rf"[0-9a-fA-F]{{{SIGNATURE_HEX_LENGTH}}}", signature) is not None,
             "invalid manifest signature encoding")
    _verify_qrlft(qrlft, manifest_path, trusted_key, MANIFEST_CONTEXT, sigfile=sigfile)
    payload = release / "payload"
    expected = []
    for file in payload.iterdir():
        size, sha256, _ = _digest(file)
        expected.append({"filename": file.name, "size": size, "sha256": sha256})
    expected.sort(key=lambda item: item["filename"])
    _require(manifest["artifacts"] == expected, "manifest artifact set or digest differs")
    if signatures_path.is_symlink() or not signatures_path.is_file():
        raise SourceError("signatures file missing or linked")
    signatures = {}
    for line in signatures_path.read_text(encoding="ascii").splitlines():
        signature, separator, path = line.partition(" ")
        _require(bool(separator) and path.startswith("payload/")
                 and path.count("/") == 1, "invalid signature-list path")
        name = path.removeprefix("payload/")
        _require(name not in signatures and re.fullmatch(
            rf"[0-9a-fA-F]{{{SIGNATURE_HEX_LENGTH}}}", signature) is not None,
            "duplicate or malformed artifact signature")
        signatures[name] = signature
    _require(set(signatures) == {item["filename"] for item in expected},
             "artifact signatures do not cover every manifest entry")
    for item in expected:
        _verify_qrlft(qrlft, payload / item["filename"], trusted_key,
                      ARTIFACT_CONTEXT, signature=signatures[item["filename"]])
    result["signed_verified"] = True
    result["trusted_key_sha256"] = KEY_SHA256
    result["security_commit"] = SECURITY_COMMIT
    result["signature_count"] = len(signatures) + 1
    result["manifest_sha256"] = _digest(manifest_path)[1]
    result["manifest_signature_sha256"] = _digest(sigfile)[1]
    result["signatures_sha256"] = _digest(signatures_path)[1]
    result["inventory_sha256"] = _digest(payload / "archive-inventory.json")[1]
    return result


def _build_fixed_qrlft(repo: Path, scratch: Path,
                       commit: str = FIXED_QRLFT_COMMIT) -> Path:
    """Build the reviewed full-file reader from an exact local Git commit."""
    revision = subprocess.run(
        ("git", "cat-file", "-t", commit), cwd=repo,
        capture_output=True, text=True, check=False,
    )
    if revision.returncode or revision.stdout.strip() != "commit":
        raise PublicationError("fixed qrlft commit is absent from the local source checkout")
    archive = subprocess.run(
        ("git", "archive", commit), cwd=repo,
        capture_output=True, check=False,
    )
    if archive.returncode:
        raise PublicationError("could not export pinned qrlft source")
    source = scratch / "qrlft-source"
    source.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive.stdout)) as contents:
        contents.extractall(source, filter="data")
    binary = scratch / "qrlft"
    environment = os.environ.copy()
    environment["GOCACHE"] = str(scratch / "go-cache")
    environment["GOPROXY"] = "off"
    environment["GOSUMDB"] = "off"
    built = subprocess.run(
        ("go", "build", "-trimpath", "-o", str(binary), "."),
        cwd=source, env=environment, capture_output=True, text=True, check=False,
    )
    if built.returncode or not binary.is_file():
        raise PublicationError("could not build pinned full-read qrlft source")
    return binary


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m qrl_archive.snapshot_release")
    commands = parser.add_subparsers(dest="command", required=True)
    prepare_parser = commands.add_parser("prepare")
    prepare_parser.add_argument("--canonical", type=Path, required=True)
    prepare_parser.add_argument("--secondary", type=Path, required=True)
    prepare_parser.add_argument("--comparison-report", type=Path, required=True)
    prepare_parser.add_argument("--native-report", type=Path, required=True)
    prepare_parser.add_argument("--live-anchor-report", type=Path, required=True)
    prepare_parser.add_argument("--snapshot-sqlite", type=Path,
                                help="certified live-snapshot SQLite file")
    prepare_parser.add_argument("--snapshot-sqlite-report", type=Path)
    prepare_parser.add_argument("--query-packs", type=Path,
                                help="completed, independently verified query pack directory")
    prepare_parser.add_argument("--query-verification-report", type=Path)
    prepare_parser.add_argument("--output", type=Path, required=True)
    prepare_parser.add_argument("--tag", required=True)
    check_parser = commands.add_parser("verify-prepared")
    check_parser.add_argument("release", type=Path)
    signed_parser = commands.add_parser("verify-signed")
    signed_parser.add_argument("release", type=Path)
    signed_parser.add_argument("--trusted-key", type=Path, required=True)
    signed_parser.add_argument("--qrlft-repo", type=Path, required=True,
                               help="local qrlft Git checkout containing the pinned full-read commit")
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.command == "prepare":
            inventory = prepare(args.canonical, args.secondary, args.comparison_report,
                                args.native_report, args.live_anchor_report,
                                args.output, args.tag,
                                sqlite_path=args.snapshot_sqlite,
                                sqlite_report_path=args.snapshot_sqlite_report,
                                query_dir=args.query_packs,
                                query_verify_path=args.query_verification_report)
            result = {"status": "PREPARED_UNSIGNED", "tag": inventory["tag"],
                      "height": inventory["snapshot"]["height"],
                      "payload_count": len(inventory["payloads"]) + 1}
        elif args.command == "verify-prepared":
            result = verify_prepared(args.release)
        else:
            with tempfile.TemporaryDirectory(prefix="qrl-snapshot-verifier-") as directory:
                qrlft = _build_fixed_qrlft(args.qrlft_repo, Path(directory))
                result = verify_signed(args.release, args.trusted_key, qrlft)
            result["qrlft_source_commit"] = FIXED_QRLFT_COMMIT
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ArchiveError, OSError, KeyError, TypeError, ValueError) as error:
        print(f"snapshot release: {error}", file=sys.stderr)
        return error.exit_code if isinstance(error, ArchiveError) else 4


if __name__ == "__main__":
    raise SystemExit(main())
