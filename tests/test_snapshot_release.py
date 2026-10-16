"""Local snapshot staging tests. Synthetic blocks have no valid PoW."""

from __future__ import annotations

import json
import hashlib
import shutil
import sqlite3
from pathlib import Path

import pytest

from qrl_archive.comparison import compare_archives
from qrl_archive.errors import IntegrityError, UsageError
from qrl_archive.snapshot_release import _check_object_path, _json_bytes, prepare, verify_prepared
from qrl_archive.snapshot_release import _anchors, _digest
from test_block_stream import _export


def _fixture(tmp_path: Path):
    _, source, hashes, _, _ = _export(tmp_path)
    secondary = tmp_path / "secondary"
    shutil.copytree(source, secondary)
    anchors = {
        "network_id": "testnet",
        "genesis_hash": hashes[0].hex(),
        "fork_height": 1,
        "fork_hash": hashes[1].hex(),
        "terminal_height": 2,
        "terminal_hash": hashes[2].hex(),
    }
    comparison = compare_archives(source, secondary, **anchors)
    compare_path = tmp_path / "comparison.json"
    compare_path.write_bytes(_json_bytes({
        "schema": "qrl.v1.archive.report.v1", "command": "compare",
        "status": "PASS", "exit_code": 0, "result": comparison,
    }))
    native_path = tmp_path / "native.json"
    native_path.write_bytes(_json_bytes({
        "schema": "qrl.v1.archive.report.v1", "command": "compare-native-state",
        "status": "PASS", "exit_code": 0,
        "result": {"schema": "qrl.v1.archive.native-state-compare.v1",
                   "exact_native_state_bytes_equal": True,
                   "native_state_agreement_verified": True,
                   "anchors": {**anchors, "network_id": "Final Testnet"}},
    }))
    live_path = tmp_path / "live.json"
    live_path.write_bytes(_json_bytes({
        "schema": "qrl-v1-live-snapshot-anchor-observation-v1",
        "reported_at_utc": "2026-10-15T21:04:57Z",
        "network_id": "Final Testnet",
        "snapshot_height": 2,
        "snapshot_block_hash": hashes[2].hex(),
        "observations": [
            {"node": "a", "transport": "host-key-verified SSH to local QRL gRPC API",
             "head_height": 5, "historical_height": 2,
             "historical_block_hash": hashes[2].hex(),
             "ssh_host_key_ed25519_sha256": "private-fixture-fingerprint"},
            {"node": "b", "transport": "public unauthenticated gRPC API",
             "head_height": 6, "historical_height": 2,
             "historical_block_hash": hashes[2].hex()},
        ],
    }))
    tag = f"testnet-snapshot-h2-{hashes[2].hex()[:8]}-r1"
    release = tmp_path / "release"
    return source, secondary, compare_path, native_path, live_path, tag, release


def test_prepare_and_verify_live_snapshot(tmp_path):
    source, secondary, compare_path, native_path, live_path, tag, release = _fixture(tmp_path)
    inventory = prepare(source, secondary, compare_path, native_path, live_path, release, tag)
    assert inventory["release_class"] == "LIVE_TESTNET_SNAPSHOT"
    assert inventory["object_prefix"] == f"testnet/snapshots/{tag}"
    assert inventory["verification_scope"]["network_stopped"] is False
    assert inventory["verification_scope"]["historical_consensus_replayed"] is False
    assert verify_prepared(release)["structural_verified"] is True
    assert verify_prepared(release)["signed_verified"] is False
    assert b"The public testnet continues" in (release / "payload" / "SNAPSHOT-NOTICE.md").read_bytes()
    public_live = (release / "payload" / "live-anchor-summary.json").read_bytes()
    assert b"private-fixture-fingerprint" not in public_live
    assert b"public_unauthenticated_grpc" in public_live
    with pytest.raises(UsageError, match="fresh path"):
        prepare(source, secondary, compare_path, native_path, live_path, release, tag)


def test_changed_payload_and_unlisted_file_fail(tmp_path):
    source, secondary, compare_path, native_path, live_path, tag, release = _fixture(tmp_path)
    inventory = prepare(source, secondary, compare_path, native_path, live_path, release, tag)
    shard = next(entry["filename"] for entry in inventory["payloads"]
                 if entry["role"] == "canonical_block_shard")
    path = release / "payload" / shard
    original = path.read_bytes()
    path.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
    with pytest.raises(IntegrityError, match="digest mismatch"):
        verify_prepared(release)
    path.write_bytes(original)
    (release / "payload" / "unlisted.txt").write_text("wrong")
    with pytest.raises(IntegrityError, match="unlisted"):
        verify_prepared(release)


def test_false_terminal_claim_and_changed_trust_root_fail(tmp_path):
    source, secondary, compare_path, native_path, live_path, tag, release = _fixture(tmp_path)
    prepare(source, secondary, compare_path, native_path, live_path, release, tag)
    path = release / "payload" / "archive-inventory.json"
    original = path.read_bytes()
    inventory = json.loads(original)
    inventory["verification_scope"]["network_stopped"] = True
    path.write_bytes(_json_bytes(inventory))
    with pytest.raises(IntegrityError, match="scope changed"):
        verify_prepared(release)
    inventory = json.loads(original)
    inventory["trust_root"]["public_key_sha256"] = "0" * 64
    path.write_bytes(_json_bytes(inventory))
    with pytest.raises(IntegrityError, match="trust root differs"):
        verify_prepared(release)


def test_bad_source_comparison_report_refuses_staging(tmp_path):
    source, secondary, compare_path, native_path, live_path, tag, release = _fixture(tmp_path)
    report = json.loads(compare_path.read_text())
    report["result"]["exact_block_bytes_equal"] = False
    compare_path.write_bytes(_json_bytes(report))
    with pytest.raises(IntegrityError, match="source comparison report"):
        prepare(source, secondary, compare_path, native_path, live_path, release, tag)
    assert not release.exists()


def test_live_anchor_mismatch_refuses_staging(tmp_path):
    source, secondary, compare_path, native_path, live_path, tag, release = _fixture(tmp_path)
    report = json.loads(live_path.read_text())
    report["observations"][1]["historical_block_hash"] = "0" * 64
    live_path.write_bytes(_json_bytes(report))
    with pytest.raises(IntegrityError, match="does not retain the cutoff block"):
        prepare(source, secondary, compare_path, native_path, live_path, release, tag)
    assert not release.exists()


@pytest.mark.parametrize("object_path", [
    "../height-000000.json", "query/../height-000000.json",
    "query//height-000000.json", "query/blocks/height/other.json",
    "blocks/height/height-000000.json", "query/manifest.json",
    "/query/blocks/height/height-000000.json",
])
def test_public_object_path_rejects_traversal_and_aliases(object_path):
    with pytest.raises(IntegrityError, match="unsafe public object path"):
        _check_object_path("height-000000.json", object_path)


def test_public_query_object_path_accepts_indexed_layout():
    _check_object_path("height-000000.json", "query/blocks/height/height-000000.json")
    _check_object_path("address-events-00.bin", "query/addresses/address-events-00.bin")
    _check_object_path("query-packs-index.json", "query/query-packs-index.json")


def test_derived_snapshot_parts_query_binding_and_tamper(tmp_path):
    source, secondary, compare_path, native_path, live_path, tag, release = _fixture(tmp_path)
    index = json.loads((source / "shards.json").read_text())
    snapshot = {
        "network_id": "testnet", "genesis_hash": index["genesis_hash"],
        "height": index["terminal_height"], "hash": index["terminal_hash"],
        "block_count": index["block_count"],
        "transaction_count": index["transaction_count"],
        "block_stream_sha256": json.loads(compare_path.read_text())["result"]["a"]["block_stream_sha256"],
    }
    db_path = tmp_path / "source.snapshot.sqlite"
    with sqlite3.connect(db_path) as db:
        db.execute("CREATE TABLE archive_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)")
        db.execute("CREATE TABLE blocks(height INTEGER)")
        db.execute("CREATE TABLE transactions(tx_hash BLOB)")
        db.execute("CREATE TABLE final_address_state(address BLOB)")
        db.execute("CREATE TABLE padding(bytes BLOB)")
        db.executemany("INSERT INTO blocks VALUES(?)", [(n,) for n in range(index["block_count"])])
        db.executemany("INSERT INTO transactions VALUES(?)",
                       [(bytes([n % 256]),) for n in range(index["transaction_count"])])
        db.execute("INSERT INTO final_address_state VALUES (X'01')")
        db.execute("INSERT INTO padding VALUES (?)", (b"x" * (17 * 1024 * 1024),))
        meta = {**{key: str(value) for key, value in _anchors(index).items()},
                "snapshot_eligible": "true", "snapshot_kind": "live-chain-point-in-time",
                "snapshot_canonical_verification": "structural-only",
                "snapshot_balance_label": "observed-at-cutoff-two-node-agreement",
                "snapshot_source_independence": "operator-attested",
                "snapshot_account_rows_sha256": "1" * 64,
                "snapshot_account_rows_sha3_256": "2" * 64,
                "release_ready": "false", "consensus_replayed": "false",
                "balance_source": "qrl-state-v3-anchored-not-replayed"}
        db.executemany("INSERT INTO archive_meta VALUES(?,?)", meta.items())
    size, sha256, sha3 = _digest(db_path)
    certificate = {
        "schema": "qrl-v1-sqlite-snapshot-certification-v1",
        "anchors": _anchors(index), "snapshot_eligible": True,
        "snapshot_kind": "live-chain-point-in-time",
        "balances_observed_at_cutoff": True,
        "independent_sources_attested_by_operator": True,
        "chain_derived_tables_equal": True,
        "consensus_replayed": False, "release_ready": False,
        "file": {"bytes": size, "sha256": sha256, "sha3_256": sha3},
        "native_account_comparison": {
            "schema": "qrl-v1-native-balance-check-v1", "anchors": _anchors(index),
            "all_balances_nonces_and_state_pb_equal": True,
            "source_independence_verified": False,
            "consensus_replayed": False, "release_ready": False,
            "account_count": 1, "rows_sha256": "1" * 64,
            "rows_sha3_256": "2" * 64},
        "canonical_structural_check": {
            "structural_verified": True, "consensus_verified": False,
            "block_count": index["block_count"],
            "transaction_count": index["transaction_count"]},
    }
    cert_path = tmp_path / "certificate.json"
    cert_path.write_bytes(_json_bytes(certificate))
    query = tmp_path / "query-finished"
    (query / "addresses").mkdir(parents=True)
    query_file = query / "addresses" / "address-events-00.bin"
    query_file.write_bytes(b"fixture-pack")
    pack_size, pack_sha256, pack_sha3 = _digest(query_file)
    query_index = {
        "schema": "qrl.v1.archive.query-packs.v1", "network": "testnet",
        "genesis_hash": index["genesis_hash"],
        "snapshot_height": index["terminal_height"],
        "snapshot_hash": index["terminal_hash"],
        "snapshot_kind": "live-chain-point-in-time",
        "snapshot_balance_label": "observed-at-cutoff-two-node-agreement",
        "consensus_replayed": False, "source_sqlite_sha256": sha256,
        "canonical_stream_sha256": snapshot["block_stream_sha256"],
        "block_count": index["block_count"],
        "transaction_count": index["transaction_count"],
        "address_count": 1, "event_count": 1,
        "height_pack_size": 1000, "event_record_bytes": 54,
        "files": [{"path": "addresses/address-events-00.bin", "bytes": pack_size,
                   "sha256": pack_sha256, "sha3_256": pack_sha3}],
    }
    (query / "query-packs-index.json").write_bytes(_json_bytes(query_index))
    query_report = {
        "schema": "qrl.v1.archive.query-packs.v1", "status": "PASS",
        "release_ready": False, "network": "testnet",
        "snapshot_height": index["terminal_height"],
        "snapshot_hash": index["terminal_hash"],
        "canonical_stream_sha256": snapshot["block_stream_sha256"],
        "source_sqlite_sha256": sha256,
        "query_index_sha256": hashlib.sha256(
            (query / "query-packs-index.json").read_bytes()).hexdigest(),
        "block_count": index["block_count"],
        "transaction_count": index["transaction_count"],
        "address_count": 1, "event_count": 1,
        "observed_account_state_count": 1,
        "sha256_sha3_checked": True, "sqlite_logical_comparison_passed": True,
        "signed_verified": False, "served_bytes_verified": False,
        "file_count": 1, "total_bytes": pack_size,
        "max_file_bytes": pack_size,
    }
    query_report_path = tmp_path / "query-verify.json"
    query_report_path.write_bytes(_json_bytes(query_report))
    inventory = prepare(source, secondary, compare_path, native_path, live_path,
                        release, tag, sqlite_path=db_path,
                        sqlite_report_path=cert_path, query_dir=query,
                        query_verify_path=query_report_path)
    assert inventory["schema"] == "qrl.v1.archive.snapshot-inventory.v2"
    assert len(inventory["derived"]["sqlite"]["parts"]) == 2
    result = verify_prepared(release)
    assert result["sqlite_reassembled_verified"] is True
    assert result["query_logical_comparison_report_checked"] is True
    assert result["query_logical_comparison_freshly_rerun"] is False
    part = release / "payload" / inventory["derived"]["sqlite"]["parts"][-1]["filename"]
    data = part.read_bytes()
    part.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
    with pytest.raises(IntegrityError, match="digest mismatch"):
        verify_prepared(release)
