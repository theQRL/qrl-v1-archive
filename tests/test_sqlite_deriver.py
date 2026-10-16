"""Golden SQLite rows from a small synthetic chain plus one real mainnet token."""

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
from pathlib import Path

import plyvel
import pytest
from google.protobuf.json_format import MessageToJson

from qrl_archive.block_stream_v1 import export_source
from qrl_archive.cli import main
from qrl_archive.errors import DisagreementError, IntegrityError, UsageError
from qrl_archive.native_balance_check import compare_sqlite_native_accounts
from qrl_archive.snapshot_sqlite import certify_snapshot_sqlite
from qrl_archive.source import LevelDBSource
from qrl_archive.sqlite_v1 import _address_from_pk, derive_sqlite
from qrl_archive.vendor import qrl_pb2


def _hash(label: str) -> bytes:
    return hashlib.sha256(label.encode("ascii")).digest()


def _address(public_key: bytes) -> bytes:
    prefix = public_key[:3] + hashlib.sha256(public_key).digest()
    return prefix + hashlib.sha256(prefix).digest()[-4:]


def _wallet_key(label: int) -> bytes:
    return bytes.fromhex("010500") + bytes([label]) * 64


def _fixture(tmp_path: Path, *, bad_parallel_arrays: bool = False, with_state: bool = False):
    keys = [_wallet_key(value) for value in (1, 2, 3)]
    addresses = [_address(key) for key in keys]
    hashes = [_hash(f"sqlite-block-{height}") for height in range(3)]
    source_path = tmp_path / "working-state"
    db = plyvel.DB(str(source_path), create_if_missing=True)
    for height in range(3):
        block = qrl_pb2.Block()
        header = block.header
        header.hash_header = hashes[height]
        header.hash_header_prev = hashes[height - 1] if height else bytes(32)
        header.block_number = height
        header.timestamp_seconds = 1000 + height
        header.reward_block = 2**63 + height
        header.reward_fee = 2**63 + 100 + height
        header.mining_nonce = height
        coinbase = block.transactions.add()
        coinbase.transaction_hash = _hash(f"coinbase-{height}")
        coinbase.master_addr = bytes(32)
        coinbase.coinbase.addr_to = addresses[0]
        coinbase.coinbase.amount = 10 + height
        if height == 0:
            allocation = block.genesis_balance.add()
            allocation.address = bytes(32)
            allocation.balance = 2**63 + 5
        if height == 1:
            transfer = block.transactions.add()
            transfer.transaction_hash = _hash("multi-output-transfer")
            transfer.public_key = keys[0]
            transfer.signature = b"synthetic-signature"
            transfer.fee = 2**63 + 7
            transfer.nonce = 2**63 + 9
            transfer.transfer.addrs_to.extend([addresses[1], addresses[1], addresses[2], addresses[0]])
            transfer.transfer.amounts.extend([1, 2, 3, 4] if not bad_parallel_arrays else [1, 2, 3])
            transfer.transfer.message_data = b"\x00\xff"
            transfer.ParseFromString(transfer.SerializeToString() + b"\xf8\x07\x01")
        if height == 2:
            real_block = qrl_pb2.Block.FromString(
                (Path(__file__).parent / "fixtures" / "mainnet-api" /
                 "4000000-block-from-rpc.pb").read_bytes())
            block.transactions.add().CopyFrom(real_block.transactions[1])
            token_transfer = block.transactions.add()
            token_transfer.transaction_hash = _hash("token-transfer")
            token_transfer.public_key = keys[0]
            token_transfer.transfer_token.token_txhash = bytes(real_block.transactions[1].transaction_hash)
            token_transfer.transfer_token.addrs_to.extend([addresses[1], addresses[2]])
            token_transfer.transfer_token.amounts.extend([4, 5])
            message = block.transactions.add()
            message.transaction_hash = _hash("message")
            message.public_key = keys[0]
            message.message.addr_to = addresses[2]
            message.message.message_hash = b"payload"
            multi_sig = block.transactions.add()
            multi_sig.transaction_hash = _hash("multisig-create")
            multi_sig.public_key = keys[0]
            multi_sig.multi_sig_create.signatories.extend([addresses[0], addresses[1]])
            multi_sig.multi_sig_create.weights.extend([1, 2])
            multi_sig.multi_sig_create.threshold = 2
        raw = block.SerializeToString()
        db.put(hashes[height], raw)
        mapping = qrl_pb2.BlockNumberMapping(
            headerhash=hashes[height],
            prev_headerhash=hashes[height - 1] if height else bytes(32))
        db.put(str(height).encode(), MessageToJson(mapping, sort_keys=True).encode())
    db.put(b"blockheight", (2).to_bytes(8, "big"))
    if with_state:
        db.put(b"state_version", b"3")
        config_key = b"dev_config_" + _hash("config")
        db.put(b"dev_config_current_state_key", config_key)
        db.put(config_key, qrl_pb2.DevConfig().SerializeToString())
        db.put(b"total_coin_supply", (100).to_bytes(8, "big"))
        db.put(bytes(32), qrl_pb2.OptimizedAddressState(address=bytes(32), balance=0).SerializeToString())
        db.put(addresses[0], qrl_pb2.OptimizedAddressState(
            address=addresses[0], balance=2**63 + 21, nonce=2**63 + 11).SerializeToString())
        db.put(addresses[1], qrl_pb2.OptimizedAddressState(
            address=addresses[1], balance=2).SerializeToString())
    db.close()
    canonical = tmp_path / "canonical"
    anchors = dict(network_id="testnet", genesis_hash=hashes[0].hex(),
                   fork_height=1, fork_hash=hashes[1].hex(),
                   terminal_height=2, terminal_hash=hashes[2].hex())
    with LevelDBSource(source_path) as source:
        export_source(source, canonical, run_id="sqlite-fixture", max_blocks=2,
                      max_bytes=1024 * 1024, **anchors)
    return canonical, source_path, anchors, addresses


def test_mainnet_token_owner_validates_v1_public_key_derivation():
    block = qrl_pb2.Block.FromString(
        (Path(__file__).parent / "fixtures" / "mainnet-api" /
         "4000000-block-from-rpc.pb").read_bytes())
    token = block.transactions[1]
    assert token.WhichOneof("transactionType") == "token"
    assert _address_from_pk(bytes(token.public_key)) == bytes(token.token.owner)


def test_derive_golden_multi_output_exact_tx_bytes_and_partial_gate(tmp_path):
    canonical, _, anchors, addresses = _fixture(tmp_path)
    output = tmp_path / "archive.partial.sqlite"
    result = derive_sqlite(canonical, output, **anchors)
    assert result["release_ready"] is False
    assert result["block_count"] == 3
    assert result["transaction_count"] == 8
    assert result["native_account_count"] == 0
    assert result["file"]["bytes"] == output.stat().st_size
    with sqlite3.connect(f"file:{output}?mode=ro", uri=True) as db:
        db.execute("PRAGMA foreign_keys=ON")
        assert db.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert list(db.execute("PRAGMA foreign_key_check")) == []
        assert db.execute("SELECT value FROM archive_meta WHERE key='release_ready'").fetchone() == ("false",)
        assert db.execute("SELECT value FROM archive_meta WHERE key='balance_source'").fetchone() == ("absent",)
        assert db.execute("SELECT COUNT(*) FROM final_address_state").fetchone() == (0,)
        assert db.execute("SELECT balance_shor FROM final_address_state WHERE address=?", (addresses[0],)).fetchone() is None
        assert db.execute("SELECT block_reward_shor,fee_reward_shor FROM blocks WHERE height=1").fetchone() == (
            str(2**63 + 1), str(2**63 + 101))
        assert db.execute("SELECT address,amount_shor FROM genesis_allocations").fetchone() == (
            bytes(32), str(2**63 + 5))
        tx_hash = _hash("multi-output-transfer")
        outputs = list(db.execute("SELECT output_index,to_address,amount_shor,asset_id FROM tx_outputs WHERE tx_hash=? ORDER BY output_index", (tx_hash,)))
        assert outputs == [(0, addresses[1], "1", None), (1, addresses[1], "2", None),
                           (2, addresses[2], "3", None), (3, addresses[0], "4", None)]
        assert list(db.execute("SELECT role,output_index,amount_shor FROM address_events WHERE address=? AND tx_hash=? ORDER BY role,output_index", (addresses[1], tx_hash))) == [
            ("receive", 0, "1"), ("receive", 1, "2")]
        assert list(db.execute("SELECT role FROM address_events WHERE address=? AND tx_hash=? ORDER BY role", (addresses[0], tx_hash))) == [
            ("from",), ("receive",), ("signer",)]
        raw_tx = db.execute("SELECT raw_pb FROM transactions WHERE tx_hash=?", (tx_hash,)).fetchone()[0]
        assert raw_tx.endswith(b"\xf8\x07\x01")
        assert qrl_pb2.Transaction.FromString(raw_tx).transaction_hash == tx_hash
        assert db.execute("SELECT fee_shor,nonce,from_address,signer_address FROM transactions WHERE tx_hash=?", (tx_hash,)).fetchone() == (
            str(2**63 + 7), str(2**63 + 9), addresses[0], addresses[0])
        details = json.loads(db.execute("SELECT decoded_json FROM tx_details WHERE tx_hash=?", (tx_hash,)).fetchone()[0])
        assert details["schema"] == "qrl.v1.tx-details.v1"
        assert details["fields"]["message_data"] == "00ff"
        assert details["fields"]["amounts"] == ["1", "2", "3", "4"]
        assert db.execute("SELECT COUNT(*) FROM tx_outputs WHERE asset_id IS NOT NULL").fetchone() == (3,)
        assert db.execute("SELECT COUNT(*) FROM address_events WHERE role='multisig_created'").fetchone() == (1,)


def test_optional_native_balances_are_anchored_but_not_release_ready(tmp_path):
    canonical, source_path, anchors, addresses = _fixture(tmp_path, with_state=True)
    output = tmp_path / "native-comparison.partial.sqlite"
    result = derive_sqlite(canonical, output, source_db=source_path, **anchors)
    assert result["native_account_count"] == 3
    assert result["balances_imported_from_native_state"] is True
    assert result["release_ready"] is False
    with sqlite3.connect(output) as db:
        assert db.execute("SELECT balance_shor,nonce,source FROM final_address_state WHERE address=?", (addresses[0],)).fetchone() == (
            str(2**63 + 21), str(2**63 + 11), "qrl-state-v3-anchored-not-replayed")
        assert db.execute("SELECT value FROM archive_meta WHERE key='release_ready'").fetchone() == ("false",)
    second_source = tmp_path / "independent-state"
    shutil.copytree(source_path, second_source)
    comparison = compare_sqlite_native_accounts(output, second_source, **anchors)
    assert comparison["account_count"] == 3
    assert comparison["all_balances_nonces_and_state_pb_equal"] is True
    assert comparison["release_ready"] is False
    with plyvel.DB(str(second_source), create_if_missing=False) as db:
        db.put(addresses[1], qrl_pb2.OptimizedAddressState(
            address=addresses[1], balance=3).SerializeToString())
    with pytest.raises(DisagreementError, match="SQLite account differs"):
        compare_sqlite_native_accounts(output, second_source, **anchors)


def test_logical_digests_repeat_for_same_canonical_input(tmp_path):
    canonical, _, anchors, _ = _fixture(tmp_path)
    first = derive_sqlite(canonical, tmp_path / "first.partial.sqlite", **anchors)
    second = derive_sqlite(canonical, tmp_path / "second.partial.sqlite", **anchors)
    assert first["logical_tables"] == second["logical_tables"]
    assert first["file"]["sha256"] == second["file"]["sha256"]


def test_deriver_rejects_invalid_parallel_arrays_without_output(tmp_path):
    canonical, _, anchors, _ = _fixture(tmp_path, bad_parallel_arrays=True)
    output = tmp_path / "should-not-exist.partial.sqlite"
    with pytest.raises(IntegrityError, match="recipient and amount counts differ"):
        derive_sqlite(canonical, output, **anchors)
    assert not output.exists()


def test_cli_reports_incomplete_even_when_sqlite_was_built(tmp_path):
    canonical, _, anchors, _ = _fixture(tmp_path)
    output = tmp_path / "cli.partial.sqlite"
    report = tmp_path / "derive.json"
    argv = ["derive-sqlite", "--canonical", str(canonical),
            "--expect-network-id", anchors["network_id"],
            "--expect-genesis-hash", anchors["genesis_hash"],
            "--expect-fork-height", str(anchors["fork_height"]),
            "--expect-fork-hash", anchors["fork_hash"],
            "--expect-terminal-height", str(anchors["terminal_height"]),
            "--expect-terminal-hash", anchors["terminal_hash"],
            "--output", str(output), "--json-report", str(report)]
    assert main(argv) == 4
    assert output.is_file()
    saved = json.loads(report.read_text())
    assert saved["status"] == "INCOMPLETE"
    assert saved["exit_code"] == 4
    assert saved["result"]["sqlite_integrity_verified"] is True
    assert saved["result"]["release_ready"] is False


def test_snapshot_certification_requires_two_matching_observed_states(tmp_path):
    canonical, source_path, anchors, addresses = _fixture(tmp_path, with_state=True)
    canonical_db = tmp_path / "canonical.partial.sqlite"
    native_db = tmp_path / "native.partial.sqlite"
    canonical_report = tmp_path / "canonical-derive.json"
    native_report = tmp_path / "native-derive.json"
    canonical_report.write_text(json.dumps(derive_sqlite(canonical, canonical_db, **anchors)))
    native_report.write_text(json.dumps(derive_sqlite(canonical, native_db, source_db=source_path, **anchors)))
    independent = tmp_path / "independent-state"
    shutil.copytree(source_path, independent)
    first = tmp_path / "first.snapshot.sqlite"
    args = (canonical, native_db, canonical_db, native_report, canonical_report, independent)
    result = certify_snapshot_sqlite(*args, first, independent_sources_attested=True, **anchors)
    assert result["snapshot_eligible"] is True
    assert result["release_ready"] is False
    assert result["consensus_replayed"] is False
    assert result["native_account_comparison"]["account_count"] == 3
    with sqlite3.connect(f"file:{first}?mode=ro", uri=True) as db:
        meta = dict(db.execute("SELECT key,value FROM archive_meta"))
        assert meta["snapshot_eligible"] == "true"
        assert meta["snapshot_kind"] == "live-chain-point-in-time"
        assert meta["snapshot_balance_label"] == "observed-at-cutoff-two-node-agreement"
        assert meta["snapshot_account_rows_sha256"] == result["native_account_comparison"]["rows_sha256"]
        assert meta["release_ready"] == "false"
        assert meta["consensus_replayed"] == "false"
        assert db.execute("SELECT balance_shor FROM final_address_state WHERE address=?", (addresses[0],)).fetchone() == (str(2**63 + 21),)
    second = tmp_path / "second.snapshot.sqlite"
    repeated = certify_snapshot_sqlite(*args, second, independent_sources_attested=True, **anchors)
    assert repeated["file"] == result["file"]
    unattested = tmp_path / "unattested.snapshot.sqlite"
    with pytest.raises(UsageError, match="independent node provenance"):
        certify_snapshot_sqlite(*args, unattested, independent_sources_attested=False, **anchors)
    assert not unattested.exists()
    with plyvel.DB(str(independent), create_if_missing=False) as db:
        db.put(addresses[1], qrl_pb2.OptimizedAddressState(
            address=addresses[1], balance=3).SerializeToString())
    rejected = tmp_path / "rejected.snapshot.sqlite"
    with pytest.raises(DisagreementError, match="SQLite account differs"):
        certify_snapshot_sqlite(*args, rejected, independent_sources_attested=True, **anchors)
    assert not rejected.exists()
