"""Compare two structurally verified canonical exports by stored block bytes."""

from __future__ import annotations

import hashlib
import json
from itertools import zip_longest
from pathlib import Path

from .block_stream_v1 import (
    MAX_SHARD_BYTES,
    _read_exact,
    _read_shard_header,
    _read_u64,
    _unique_json_object,
    _u64,
    verify_archive,
)
from .errors import DisagreementError, IntegrityError, SourceError, UsageError


SCHEMA = "qrl.v1.archive.compare.v1"
DIGEST_DOMAIN = b"qrl-v1-canonical-block-bytes-v1\x00"


class _HashingReader:
    def __init__(self, stream):
        self.stream = stream
        self.sha256 = hashlib.sha256()
        self.sha3_256 = hashlib.sha3_256()
        self.size = 0

    def read(self, count: int) -> bytes:
        data = self.stream.read(count)
        self.sha256.update(data)
        self.sha3_256.update(data)
        self.size += len(data)
        return data

    def tell(self) -> int:
        return self.stream.tell()


def _read_index(directory: Path) -> tuple[bytes, dict]:
    try:
        path = directory / "shards.json"
        if path.is_symlink() or not path.is_file():
            raise SourceError("missing or linked shards.json")
        raw = path.read_bytes()
        index = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_json_object)
    except (OSError, UnicodeError, ValueError) as error:
        raise SourceError("could not read a valid shards.json") from error
    if not isinstance(index, dict):
        raise IntegrityError("shards index is not an object")
    return raw, index


def _records(directory: Path, index: dict, *, network_id: str, genesis_hash: str):
    """Read every framed value again after verification and check each shard digest."""
    next_height = 0
    for shard in index["shards"]:
        path = directory / shard["name"]
        if path.is_symlink() or not path.is_file():
            raise SourceError(f"missing shard {shard['name']}")
        try:
            with path.open("rb") as source:
                stream = _HashingReader(source)
                network, genesis, first, last, count = _read_shard_header(stream)
                if (network, genesis.hex(), first, last, count) != (
                    network_id, genesis_hash, shard["first_height"],
                    shard["last_height"], shard["record_count"],
                ):
                    raise IntegrityError(f"shard header changed during comparison: {shard['name']}")
                if first != next_height:
                    raise IntegrityError(f"shard height changed during comparison: {shard['name']}")
                for _ in range(count):
                    height = _read_u64(stream)
                    length = _read_u64(stream)
                    if height != next_height or length < 1 or length > MAX_SHARD_BYTES:
                        raise IntegrityError(f"record framing changed at height {next_height}")
                    raw = _read_exact(stream, length)
                    next_height += 1
                    yield height, raw
                if stream.read(1):
                    raise IntegrityError(f"trailing bytes in shard {shard['name']}")
                if (stream.size, stream.sha256.hexdigest(), stream.sha3_256.hexdigest()) != (
                    shard["bytes"], shard["sha256"], shard["sha3_256"],
                ):
                    raise IntegrityError(f"shard changed during comparison: {shard['name']}")
        except OSError as error:
            raise SourceError(f"could not read shard {shard['name']}") from error
    if next_height != index["block_count"]:
        raise IntegrityError("block count changed during comparison")


def _stream_digest():
    sha256 = hashlib.sha256()
    sha3_256 = hashlib.sha3_256()
    sha256.update(DIGEST_DOMAIN)
    sha3_256.update(DIGEST_DOMAIN)
    return sha256, sha3_256


def compare_archives(a: Path, b: Path, *, network_id: str, genesis_hash: str,
                     fork_height: int, fork_hash: str, terminal_height: int,
                     terminal_hash: str) -> dict:
    """Verify both exports and compare their exact stored protobuf values."""
    if a.resolve() == b.resolve():
        raise UsageError("comparison requires two distinct canonical directories")

    anchor = {
        "network_id": network_id,
        "genesis_hash": genesis_hash,
        "fork_height": fork_height,
        "fork_hash": fork_hash,
        "terminal_height": terminal_height,
        "terminal_hash": terminal_hash,
    }
    original_a, index_a = _read_index(a)
    original_b, index_b = _read_index(b)
    verified_a = verify_archive(a, **anchor)
    verified_b = verify_archive(b, **anchor)
    if _read_index(a)[0] != original_a or _read_index(b)[0] != original_b:
        raise IntegrityError("shards index changed during verification")
    if not isinstance(index_a.get("run_id"), str) or not isinstance(index_b.get("run_id"), str):
        raise IntegrityError("comparison requires run IDs in both shards indexes")

    a_sha256, a_sha3 = _stream_digest()
    b_sha256, b_sha3 = _stream_digest()
    a_bytes = b_bytes = block_count = 0
    first_mismatch = None
    missing = object()
    for record_a, record_b in zip_longest(
        _records(a, index_a, network_id=network_id, genesis_hash=genesis_hash),
        _records(b, index_b, network_id=network_id, genesis_hash=genesis_hash),
        fillvalue=missing,
    ):
        if record_a is missing or record_b is missing:
            raise IntegrityError("block count changed during comparison")
        height_a, raw_a = record_a
        height_b, raw_b = record_b
        if height_a != block_count or height_b != block_count:
            raise IntegrityError("block height changed during comparison")
        for raw, sha256, sha3_256 in ((raw_a, a_sha256, a_sha3), (raw_b, b_sha256, b_sha3)):
            framed = _u64(block_count) + _u64(len(raw))
            sha256.update(framed)
            sha256.update(raw)
            sha3_256.update(framed)
            sha3_256.update(raw)
        a_bytes += len(raw_a)
        b_bytes += len(raw_b)
        if first_mismatch is None and raw_a != raw_b:
            first_mismatch = {
                "height": block_count,
                "a_bytes": len(raw_a),
                "b_bytes": len(raw_b),
                "a_sha256": hashlib.sha256(raw_a).hexdigest(),
                "b_sha256": hashlib.sha256(raw_b).hexdigest(),
                "a_sha3_256": hashlib.sha3_256(raw_a).hexdigest(),
                "b_sha3_256": hashlib.sha3_256(raw_b).hexdigest(),
            }
        block_count += 1

    if _read_index(a)[0] != original_a or _read_index(b)[0] != original_b:
        raise IntegrityError("shards index changed during comparison")
    if block_count != terminal_height + 1:
        raise IntegrityError("block count changed during comparison")

    result = {
        "schema": SCHEMA,
        "anchors": anchor,
        "block_count": block_count,
        "a": {
            "run_id": index_a["run_id"],
            "index_sha256": hashlib.sha256(original_a).hexdigest(),
            "shard_count": verified_a["shard_count"],
            "transaction_count": verified_a["transaction_count"],
            "raw_block_bytes": a_bytes,
            "block_stream_sha256": a_sha256.hexdigest(),
            "block_stream_sha3_256": a_sha3.hexdigest(),
        },
        "b": {
            "run_id": index_b["run_id"],
            "index_sha256": hashlib.sha256(original_b).hexdigest(),
            "shard_count": verified_b["shard_count"],
            "transaction_count": verified_b["transaction_count"],
            "raw_block_bytes": b_bytes,
            "block_stream_sha256": b_sha256.hexdigest(),
            "block_stream_sha3_256": b_sha3.hexdigest(),
        },
        "first_mismatch": first_mismatch,
        "exact_block_bytes_equal": first_mismatch is None,
        "structural_verified_a": True,
        "structural_verified_b": True,
        "consensus_verified": False,
        "source_independence_verified": False,
    }
    if first_mismatch is not None:
        error = DisagreementError(f"canonical block bytes differ at height {first_mismatch['height']}")
        error.result = result
        raise error
    return result
