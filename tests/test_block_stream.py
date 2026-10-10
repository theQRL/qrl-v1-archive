"""Synthetic structural fixtures. These blocks are deliberately not PoW-valid."""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

import plyvel
import pytest
from google.protobuf.json_format import MessageToJson

from qrl_archive.block_stream_v1 import export_source, verify_archive
from qrl_archive.cli import main
from qrl_archive.errors import IntegrityError, SourceError
from qrl_archive.source import LevelDBSource, _get
from qrl_archive.vendor import qrl_pb2


def _hash(text: str) -> bytes:
    return hashlib.sha256(text.encode()).digest()


def _chain(db_path: Path, *, duplicate_tx: bool = False):
    db = plyvel.DB(str(db_path), create_if_missing=True)
    raws = []
    hashes = [_hash(f"block-{height}") for height in range(3)]
    for height in range(3):
        block = qrl_pb2.Block()
        block.header.hash_header = hashes[height]
        block.header.block_number = height
        block.header.hash_header_prev = hashes[height - 1] if height else bytes(32)
        tx = block.transactions.add()
        tx.transaction_hash = _hash("tx-0" if duplicate_tx else f"tx-{height}")
        tx.coinbase.SetInParent()
        raw = block.SerializeToString() + b"\xf8\x07\x01"  # valid unknown field, retained byte-for-byte
        raws.append(raw)
        db.put(hashes[height], raw)
        mapping = qrl_pb2.BlockNumberMapping(
            headerhash=hashes[height],
            prev_headerhash=hashes[height - 1] if height else bytes(32),
        )
        db.put(str(height).encode(), MessageToJson(mapping, sort_keys=True).encode())
        db.put(b"metadata_" + hashes[height], qrl_pb2.BlockMetaData(cumulative_difficulty=bytes([height + 1])).SerializeToString())
    db.put(b"blockheight", (2).to_bytes(8, "big"))
    db.put(b"state_version", b"3")
    db.close()
    return hashes, raws


def _export(tmp_path: Path, *, duplicate_tx: bool = False):
    db_path = tmp_path / "state"
    hashes, raws = _chain(db_path, duplicate_tx=duplicate_tx)
    output = tmp_path / "archive"
    with LevelDBSource(db_path) as source:
        index = export_source(
            source, output, network_id="testnet", genesis_hash=hashes[0].hex(),
            fork_height=1, fork_hash=hashes[1].hex(),
            terminal_height=2, terminal_hash=hashes[2].hex(),
            run_id="testnet-r1-unit", max_blocks=2, max_bytes=1024,
        )
    return db_path, output, hashes, raws, index


def _verify(output: Path, hashes: list[bytes]):
    return verify_archive(
        output, network_id="testnet", genesis_hash=hashes[0].hex(),
        fork_height=1, fork_hash=hashes[1].hex(),
        terminal_height=2, terminal_hash=hashes[2].hex(),
    )


def _replace_and_rehash(output: Path, index: dict, shard_number: int, data: bytes):
    shard = index["shards"][shard_number]
    (output / shard["name"]).write_bytes(data)
    shard["bytes"] = len(data)
    shard["sha256"] = hashlib.sha256(data).hexdigest()
    shard["sha3_256"] = hashlib.sha3_256(data).hexdigest()
    (output / "shards.json").write_text(json.dumps(index, sort_keys=True, separators=(",", ":")) + "\n")


def test_exact_stored_bytes_and_structural_report(tmp_path):
    db_path, output, hashes, raws, index = _export(tmp_path)
    assert [entry["record_count"] for entry in index["shards"]] == [2, 1]
    assert index["block_count"] == 3
    assert _verify(output, hashes)["structural_verified"] is True
    assert _verify(output, hashes)["consensus_verified"] is False
    first_shard = (output / index["shards"][0]["name"]).read_bytes()
    assert struct.pack("<Q", len(raws[0])) + raws[0] in first_shard
    with LevelDBSource(db_path) as source:
        assert source.inspect()["cumulative_difficulty"] == "3"
        assert source.get_block(0)[0] == raws[0]


def test_wrong_expected_identity_fails(tmp_path):
    _, output, hashes, _, _ = _export(tmp_path)
    with pytest.raises(IntegrityError, match="network_id"):
        verify_archive(output, network_id="mainnet", genesis_hash=hashes[0].hex(),
                       fork_height=1, fork_hash=hashes[1].hex(),
                       terminal_height=2, terminal_hash=hashes[2].hex())


def test_tampered_shard_digest_fails(tmp_path):
    _, output, hashes, _, index = _export(tmp_path)
    path = output / index["shards"][0]["name"]
    data = bytearray(path.read_bytes())
    data[-1] ^= 1
    path.write_bytes(data)
    with pytest.raises(IntegrityError, match="digest"):
        _verify(output, hashes)


def test_truncation_fails_even_if_index_rehashed(tmp_path):
    _, output, hashes, _, index = _export(tmp_path)
    path = output / index["shards"][0]["name"]
    _replace_and_rehash(output, index, 0, path.read_bytes()[:-1])
    with pytest.raises(IntegrityError, match="framing|truncated"):
        _verify(output, hashes)


def test_wrong_shard_height_fails_even_if_index_rehashed(tmp_path):
    _, output, hashes, _, index = _export(tmp_path)
    path = output / index["shards"][1]["name"]
    data = bytearray(path.read_bytes())
    offset = 8 + 4 + 4 + len("testnet") + 4 + 32
    data[offset : offset + 8] = (99).to_bytes(8, "little")
    _replace_and_rehash(output, index, 1, bytes(data))
    with pytest.raises(IntegrityError, match="contiguous"):
        _verify(output, hashes)


def test_duplicate_json_key_in_index_fails(tmp_path):
    _, output, hashes, _, _ = _export(tmp_path)
    path = output / "shards.json"
    path.write_text(path.read_text().replace('{"block_count":', '{"schema":"other","block_count":', 1))
    with pytest.raises(IntegrityError, match="duplicate JSON key"):
        _verify(output, hashes)


def test_unlisted_shard_fails(tmp_path):
    _, output, hashes, _, _ = _export(tmp_path)
    (output / "unlisted.qrlblk").write_bytes(b"extra")
    with pytest.raises(IntegrityError, match="unlisted shard"):
        _verify(output, hashes)


def test_duplicate_transaction_hash_fails_closed(tmp_path):
    with pytest.raises(IntegrityError, match="duplicate transaction"):
        _export(tmp_path, duplicate_tx=True)
    assert not (tmp_path / "archive").exists()


def test_source_tip_must_match_terminal(tmp_path):
    db_path = tmp_path / "state"
    hashes, _ = _chain(db_path)
    with LevelDBSource(db_path) as source:
        with pytest.raises(IntegrityError, match="source tip"):
            export_source(source, tmp_path / "archive", network_id="testnet",
                          genesis_hash=hashes[0].hex(), fork_height=1,
                          fork_hash=hashes[1].hex(), terminal_height=1,
                          terminal_hash=hashes[1].hex(), run_id="testnet-r1-unit")


def test_live_leveldb_lock_is_rejected(tmp_path):
    db_path = tmp_path / "state"
    _chain(db_path)
    writer = plyvel.DB(str(db_path), create_if_missing=False)
    try:
        with pytest.raises(SourceError, match="lock"):
            with LevelDBSource(db_path):
                pass
    finally:
        writer.close()


def test_nested_source_entry_fails_closed(tmp_path):
    db_path = tmp_path / "state"
    _chain(db_path)
    (db_path / "nested").mkdir()
    with pytest.raises(SourceError, match="nested or non-regular"):
        with LevelDBSource(db_path):
            pass


def test_leveldb_decode_error_is_a_source_failure():
    class BrokenDB:
        def get(self, key):
            raise plyvel.Error("simulated compressed-block read failure")

    with pytest.raises(SourceError, match="reader compatibility and source integrity"):
        _get(BrokenDB(), b"0", "height mapping 0")


def test_cli_consensus_mode_fails_with_report(tmp_path):
    _, output, hashes, _, _ = _export(tmp_path)
    report = tmp_path / "verify-report.json"
    code = main([
        "verify", "--canonical", str(output), "--expect-network-id", "testnet",
        "--expect-genesis-hash", hashes[0].hex(), "--expect-fork-height", "1",
        "--expect-fork-hash", hashes[1].hex(), "--expect-terminal-height", "2",
        "--expect-terminal-hash", hashes[2].hex(), "--mode", "consensus",
        "--json-report", str(report),
    ])
    assert code == 4
    assert json.loads(report.read_text())["status"] == "FAIL"
    original = report.read_bytes()
    assert main([
        "verify", "--canonical", str(output), "--expect-network-id", "testnet",
        "--expect-genesis-hash", hashes[0].hex(), "--expect-fork-height", "1",
        "--expect-fork-hash", hashes[1].hex(), "--expect-terminal-height", "2",
        "--expect-terminal-hash", hashes[2].hex(), "--mode", "consensus",
        "--json-report", str(report),
    ]) == 3
    assert report.read_bytes() == original
