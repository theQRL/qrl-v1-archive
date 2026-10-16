"""Native state comparison fixtures; synthetic blocks do not prove consensus."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import plyvel
import pytest
from google.protobuf.json_format import MessageToJson

from qrl_archive.cli import main
from qrl_archive.errors import DisagreementError, IntegrityError, UsageError
from qrl_archive.native_state import compare_native_state
from qrl_archive.vendor import qrl_pb2


def _hash(label: str) -> bytes:
    return hashlib.sha256(label.encode()).digest()


def _address(label: str, *, multisig: bool = False) -> bytes:
    descriptor = b"\x11\x00\x00" if multisig else b"\x00\x00\x00"
    payload = descriptor + _hash(label)
    return payload + hashlib.sha256(payload).digest()[-4:]


def _fixture(path: Path, *, reverse_state_writes: bool = False):
    db = plyvel.DB(str(path), create_if_missing=True)
    hashes = [_hash("genesis"), _hash("terminal")]
    for height in range(2):
        block = qrl_pb2.Block()
        block.header.block_number = height
        block.header.hash_header = hashes[height]
        block.header.hash_header_prev = hashes[height - 1] if height else bytes(32)
        db.put(hashes[height], block.SerializeToString())
        mapping = qrl_pb2.BlockNumberMapping(headerhash=hashes[height],
                                               prev_headerhash=hashes[height - 1] if height else bytes(32))
        db.put(str(height).encode(), MessageToJson(mapping, sort_keys=True).encode())
    db.put(b"blockheight", (1).to_bytes(8, "big"))
    db.put(b"state_version", b"3")
    db.put(b"metadata_" + hashes[1], qrl_pb2.BlockMetaData(cumulative_difficulty=b"\x01").SerializeToString())
    db.put(b"last_txn", b"auxiliary one")
    db.put(b"reorg_limit", (0).to_bytes(8, "big"))

    address = _address("wallet")
    multisig = _address("multisig", multisig=True)
    token = _hash("token")
    config_key = b"dev_config_" + hashes[0]
    state_records = [
        (bytes(32), qrl_pb2.OptimizedAddressState(address=bytes(32), balance=10).SerializeToString()),
        (address, qrl_pb2.OptimizedAddressState(address=address, balance=5,
                                                transaction_hash_count=1).SerializeToString()),
        (multisig, qrl_pb2.MultiSigAddressState(address=multisig, balance=2).SerializeToString()),
        (b"bitfield_" + address + b"_" + (1).to_bytes(8, "big"),
         qrl_pb2.DataList(values=[b"\x01"]).SerializeToString()),
        (b"p_tx_hash_" + address + b"_0", qrl_pb2.DataList(values=[_hash("tx")]).SerializeToString()),
        (b"p_tx_hash_" + bytes(32) + b"_0", qrl_pb2.DataList(values=[_hash("coinbase")]).SerializeToString()),
        (b"token_" + token, qrl_pb2.TokenMetadata(token_txhash=token).SerializeToString()),
        (b"token_" + address + b"_" + token, qrl_pb2.TokenBalance(balance=3).SerializeToString()),
        (b"slave_" + address + b"_" + _hash("slave"), qrl_pb2.SlaveMetadata(access_type=1).SerializeToString()),
        (b"lattice_pk_" + address + b"_" + _hash("pk1"), qrl_pb2.LatticePKMetadata(enabled=True).SerializeToString()),
        (b"shared_key_" + _hash("shared"), qrl_pb2.VoteStats(shared_key=_hash("shared")).SerializeToString()),
        (b"proposal_record_block_number_" + (10).to_bytes(8, "big"),
         qrl_pb2.ProposalRecord(number_of_tx_hashes=1).SerializeToString()),
        (b"dev_config_current_state_key", config_key),
        (config_key, qrl_pb2.DevConfig(current_state_key=config_key).SerializeToString()),
        (b"total_coin_supply", (17).to_bytes(8, "big")),
    ]
    for key, value in reversed(state_records) if reverse_state_writes else state_records:
        db.put(key, value)
    db.close()
    return hashes, address


def _compare(a: Path, b: Path, hashes):
    return compare_native_state(
        a, b, network_id="Final Testnet", genesis_hash=hashes[0].hex(),
        fork_height=1, fork_hash=hashes[1].hex(),
        terminal_height=1, terminal_hash=hashes[1].hex(),
    )


def test_exact_native_state_matches_despite_physical_write_order_and_auxiliary_difference(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    hashes, _ = _fixture(a)
    _fixture(b, reverse_state_writes=True)
    db = plyvel.DB(str(b))
    db.put(b"last_txn", b"different local cache")
    db.close()
    result = _compare(a, b, hashes)
    assert result["exact_native_state_bytes_equal"] is True
    assert result["a"]["state_record_count"] == 15
    assert result["a"]["categories"] == result["b"]["categories"]
    assert result["a"]["total_classified_key_count"] == 24
    assert result["consensus_verified"] is False
    assert result["source_independence_verified"] is False


def test_changed_account_value_reports_first_difference_and_dual_hashes(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    hashes, address = _fixture(a)
    _fixture(b)
    db = plyvel.DB(str(b))
    db.put(address, qrl_pb2.OptimizedAddressState(address=address, balance=6).SerializeToString())
    db.close()
    with pytest.raises(DisagreementError) as failure:
        _compare(a, b, hashes)
    result = failure.value.result
    assert result["first_mismatch"]["reason"] == "value differs"
    assert result["first_mismatch"]["a"]["key_hex"] == address.hex()
    assert result["first_mismatch"]["a"]["value_sha256"] != result["first_mismatch"]["b"]["value_sha256"]
    assert result["a"]["categories"]["account"]["sha3_256"] != result["b"]["categories"]["account"]["sha3_256"]
    assert result["consensus_verified"] is False


def test_missing_bitfield_page_reports_key_absent(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    hashes, address = _fixture(a)
    _fixture(b)
    db = plyvel.DB(str(b))
    db.delete(b"bitfield_" + address + b"_" + (1).to_bytes(8, "big"))
    db.close()
    with pytest.raises(DisagreementError) as failure:
        _compare(a, b, hashes)
    assert failure.value.result["first_mismatch"]["reason"] == "key absent from b"


@pytest.mark.parametrize("key, value, error", [
    (b"mystery", b"value", "unclassified native DB key"),
    (b"fork_state", b"incomplete", "unfinished fork_state"),
    (b"state_version", b"2", "only supports state_version 3"),
])
def test_unknown_or_unsupported_native_state_fails_closed(tmp_path, key, value, error):
    a, b = tmp_path / "a", tmp_path / "b"
    hashes, _ = _fixture(a)
    _fixture(b)
    db = plyvel.DB(str(b))
    db.put(key, value)
    db.close()
    with pytest.raises(IntegrityError, match=error):
        _compare(a, b, hashes)


def test_address_key_must_match_embedded_protobuf_address(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    hashes, address = _fixture(a)
    _fixture(b)
    db = plyvel.DB(str(b))
    db.put(address, qrl_pb2.OptimizedAddressState(address=_address("other"), balance=5).SerializeToString())
    db.close()
    with pytest.raises(IntegrityError, match="embedded address"):
        _compare(a, b, hashes)


def test_same_db_cannot_be_compared_to_itself(tmp_path):
    a = tmp_path / "a"
    hashes, _ = _fixture(a)
    with pytest.raises(UsageError, match="distinct working directories"):
        _compare(a, a, hashes)


def test_cli_writes_deterministic_failed_comparison_report(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    hashes, address = _fixture(a)
    _fixture(b)
    db = plyvel.DB(str(b))
    db.put(address, qrl_pb2.OptimizedAddressState(address=address, balance=99).SerializeToString())
    db.close()
    report = tmp_path / "native-compare.json"
    code = main([
        "compare-native-state", "--source-db-a", str(a), "--source-db-b", str(b),
        "--expect-network-id", "Final Testnet", "--expect-genesis-hash", hashes[0].hex(),
        "--expect-fork-height", "1", "--expect-fork-hash", hashes[1].hex(),
        "--expect-terminal-height", "1", "--expect-terminal-hash", hashes[1].hex(),
        "--json-report", str(report),
    ])
    saved = json.loads(report.read_text())
    assert code == 5
    assert saved["result"]["schema"] == "qrl.v1.archive.native-state-compare.v1"
    assert saved["result"]["first_mismatch"]["a"]["key_hex"] == address.hex()
    assert "started_at_utc" not in saved
    assert saved["status"] == "FAIL"
