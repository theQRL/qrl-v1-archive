"""Offline QRL v1 mainnet API schema fixtures from official public nodes.

These RPC responses are not native LevelDB block values.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from qrl_archive.vendor import qrl_pb2


FIXTURES = Path(__file__).parent / "fixtures" / "mainnet-api"
HEIGHTS = (0, 1, 1_000_000, 2_000_000, 3_000_000, 4_000_000, 4_373_500)
SCHEMA_SHA256 = "0d70a3372c4668a1bf4fd42983ae01f2e0fb54b4030b808bbea78e5adadb23f0"
GENESIS_HASH = "2a1c4a9433f1de36f8b99c7c5aceb7bd2eb39e1ead648ea58227d399ad84c724"
BLOCK_4M_HASH = "393553df8c87aec706154532a0cf4f8988881a31219ca9a6ca24394600000000"


def _manifest() -> dict:
    return json.loads((FIXTURES / "manifest.json").read_text())


def _read_varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    for position in range(10):
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << (7 * position)
        if byte < 0x80:
            return value, offset
    raise AssertionError("malformed protobuf varint")


def _embedded_block_wire(response: bytes) -> bytes:
    # GetBlockByNumberResp has one length-delimited Block field, number 1.
    tag, offset = _read_varint(response, 0)
    assert tag == 10
    size, offset = _read_varint(response, offset)
    assert offset + size == len(response)
    return response[offset:]


def test_mainnet_fixture_provenance_and_schema_pin():
    manifest = _manifest()
    assert manifest["format"] == "qrl-v1-mainnet-rpc-protobuf-fixtures-v1"
    assert manifest["source_endpoint"] == "mainnet-1.automated.theqrl.org:19009"
    assert manifest["source_method"] == "qrl.PublicAPI/GetBlockByNumber"
    assert manifest["node_version"] == "4.0.11 python"
    assert manifest["network_id"] == "The sleeper must awaken"
    assert manifest["observed_tip_height"] >= HEIGHTS[-1]
    assert manifest["protobuf_schema_sha256"] == SCHEMA_SHA256
    schema = Path(qrl_pb2.__file__).with_name("qrl.proto")
    assert hashlib.sha256(schema.read_bytes()).hexdigest() == SCHEMA_SHA256
    assert [item["height"] for item in manifest["samples"]] == list(HEIGHTS)


@pytest.mark.parametrize("height", HEIGHTS)
def test_real_mainnet_rpc_block_decodes_with_vendored_schema(height: int):
    entry = next(item for item in _manifest()["samples"] if item["height"] == height)
    assert entry["response_file"] == f"{height}-response.pb"
    assert entry["block_file"] == f"{height}-block-from-rpc.pb"
    response = (FIXTURES / entry["response_file"]).read_bytes()
    block_wire = (FIXTURES / entry["block_file"]).read_bytes()
    assert len(response) == entry["response_bytes"]
    assert hashlib.sha256(response).hexdigest() == entry["response_sha256"]
    assert len(block_wire) == entry["block_bytes"]
    assert hashlib.sha256(block_wire).hexdigest() == entry["block_sha256"]
    assert _embedded_block_wire(response) == block_wire

    block = qrl_pb2.Block.FromString(block_wire)
    assert qrl_pb2.GetBlockByNumberResp.FromString(response).block == block
    assert block.header.block_number == height
    assert block.header.hash_header.hex() == entry["block_hash"]
    assert block.header.hash_header_prev.hex() == entry["previous_hash"]
    assert len(block.transactions) == entry["transaction_count"]
    assert len(block.genesis_balance) == entry["genesis_balance_count"]
    types = [tx.WhichOneof("transactionType") for tx in block.transactions]
    assert all(types), "a transaction kind was not recognized by the vendored schema"
    assert sorted(set(types)) == entry["transaction_types"]


def test_mainnet_genesis_link_and_token_fixture():
    entries = {item["height"]: item for item in _manifest()["samples"]}
    assert entries[0]["block_hash"] == GENESIS_HASH
    assert entries[0]["previous_hash"] == b"The sleeper must awaken".hex()
    assert entries[1]["previous_hash"] == GENESIS_HASH
    assert entries[4_000_000]["block_hash"] == BLOCK_4M_HASH
    assert entries[4_000_000]["transaction_types"] == ["coinbase", "token"]
