"""The qrl-v1-block-stream-v1 on-disk format and structural reader."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import struct
import tempfile
from pathlib import Path

from .errors import IntegrityError, SourceError, UsageError
from .protobuf_schema import (
    PROTOBUF_BINDING_SHA256,
    PROTOBUF_DESCRIPTOR_SHA256,
    PROTOBUF_SCHEMA_SHA256,
    assert_pinned_schema,
)
from .source import decode_block


MAGIC = b"QRLV1BLK"
VERSION = 1
MAX_BLOCKS_PER_SHARD = 10_000
MAX_SHARD_BYTES = 64 * 1024 * 1024
SCHEMA = "qrl-v1-block-stream-v1"
INDEX_SCHEMA = "qrl.v1.archive.shards.v1"


def _u32(value: int) -> bytes:
    return struct.pack("<I", value)


def _u64(value: int) -> bytes:
    return struct.pack("<Q", value)


def _read_exact(stream, count: int) -> bytes:
    data = stream.read(count)
    if len(data) != count:
        raise IntegrityError("truncated block-stream shard")
    return data


def _read_u32(stream) -> int:
    return struct.unpack("<I", _read_exact(stream, 4))[0]


def _read_u64(stream) -> int:
    return struct.unpack("<Q", _read_exact(stream, 8))[0]


def _hex32(value: str, label: str) -> bytes:
    try:
        decoded = bytes.fromhex(value)
    except (ValueError, TypeError) as error:
        raise UsageError(f"{label} must be 64 hexadecimal characters") from error
    if len(decoded) != 32 or value != decoded.hex():
        raise UsageError(f"{label} must be 64 lowercase hexadecimal characters")
    return decoded


def _header(network_id: str, genesis_hash: bytes, first: int, last: int, count: int) -> bytes:
    network = network_id.encode("utf-8")
    if not 1 <= len(network) <= 128 or len(genesis_hash) != 32:
        raise UsageError("invalid network ID or genesis hash")
    return (
        MAGIC + _u32(VERSION) + _u32(len(network)) + network
        + _u32(len(genesis_hash)) + genesis_hash
        + _u64(first) + _u64(last) + _u64(count)
    )


def _digest_file(path: Path) -> tuple[int, str, str]:
    sha256 = hashlib.sha256()
    sha3 = hashlib.sha3_256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            sha256.update(chunk)
            sha3.update(chunk)
            size += len(chunk)
    return size, sha256.hexdigest(), sha3.hexdigest()


def _unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise IntegrityError(f"duplicate JSON key in shards index: {key}")
        result[key] = value
    return result


def _sync_dir(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class _ShardWriter:
    def __init__(self, directory: Path, name: str, network_id: str, genesis_hash: bytes,
                 first_height: int, max_bytes: int):
        self.name = name
        self.path = directory / name
        self.stream = self.path.open("w+b")
        self.network_id = network_id
        self.genesis_hash = genesis_hash
        self.first = first_height
        self.last = first_height
        self.count = 0
        self.max_bytes = max_bytes
        self.stream.write(_header(network_id, genesis_hash, first_height, first_height, 0))

    def can_add(self, raw_length: int, max_blocks: int) -> bool:
        return self.count < max_blocks and self.stream.tell() + 16 + raw_length <= self.max_bytes

    def add(self, height: int, raw: bytes) -> None:
        if not self.can_add(len(raw), MAX_BLOCKS_PER_SHARD):
            raise IntegrityError("stored block exceeds shard limit")
        self.stream.write(_u64(height))
        self.stream.write(_u64(len(raw)))
        self.stream.write(raw)
        self.last = height
        self.count += 1

    def finish(self) -> dict:
        if self.count == 0:
            raise IntegrityError("empty shard")
        self.stream.seek(0)
        self.stream.write(_header(self.network_id, self.genesis_hash, self.first, self.last, self.count))
        self.stream.flush()
        os.fsync(self.stream.fileno())
        self.stream.close()
        size, sha256, sha3_256 = _digest_file(self.path)
        return {
            "name": self.name,
            "first_height": self.first,
            "last_height": self.last,
            "record_count": self.count,
            "bytes": size,
            "sha256": sha256,
            "sha3_256": sha3_256,
        }

    def discard(self) -> None:
        if not self.stream.closed:
            self.stream.close()


def export_source(source, output: Path, *, network_id: str, genesis_hash: str,
                  fork_height: int, fork_hash: str, terminal_height: int,
                  terminal_hash: str, run_id: str, max_blocks: int = MAX_BLOCKS_PER_SHARD,
                  max_bytes: int = MAX_SHARD_BYTES) -> dict:
    import re

    assert_pinned_schema()

    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,99}", run_id):
        raise UsageError("run ID must be 1-100 safe ASCII characters")
    if not 1 <= max_blocks <= MAX_BLOCKS_PER_SHARD:
        raise UsageError("max blocks per shard must be between 1 and 10000")
    if not 1024 <= max_bytes <= MAX_SHARD_BYTES:
        raise UsageError("max shard bytes must be between 1024 and 64 MiB")
    if terminal_height != source.tip_height:
        raise IntegrityError("source tip does not equal the declared terminal height")
    if not 0 <= fork_height <= terminal_height:
        raise UsageError("fork height is outside the declared chain")
    genesis_bytes = _hex32(genesis_hash, "genesis hash")
    fork_bytes = _hex32(fork_hash, "fork hash")
    terminal_bytes = _hex32(terminal_hash, "terminal hash")
    if output.exists():
        raise SourceError("output path already exists")
    if not output.parent.is_dir():
        raise SourceError("output parent directory does not exist")

    stage = Path(tempfile.mkdtemp(prefix=".qrl-archive-", dir=output.parent))
    shards: list[dict] = []
    writer = None
    previous_hash = None
    transaction_count = 0
    try:
        for height in range(terminal_height + 1):
            raw, block = source.get_block(height)
            header = block.header
            block_hash = bytes(header.hash_header)
            if height == 0 and block_hash != genesis_bytes:
                raise IntegrityError("source genesis hash differs from expectation")
            if height and bytes(header.hash_header_prev) != previous_hash:
                raise IntegrityError(f"chain link mismatch at height {height}")
            if height == fork_height and block_hash != fork_bytes:
                raise IntegrityError("source fork hash differs from expectation")
            if height == terminal_height and block_hash != terminal_bytes:
                raise IntegrityError("source terminal hash differs from expectation")
            transaction_count += len(block.transactions)
            if writer is None or not writer.can_add(len(raw), max_blocks):
                if writer is not None:
                    shards.append(writer.finish())
                name = f"{run_id}-blocks-{height:010d}.qrlblk"
                writer = _ShardWriter(stage, name, network_id, genesis_bytes, height, max_bytes)
                if not writer.can_add(len(raw), max_blocks):
                    raise IntegrityError(f"stored block at height {height} exceeds shard limit")
            writer.add(height, raw)
            previous_hash = block_hash
        if writer is not None:
            shards.append(writer.finish())
            writer = None

        index = {
            "schema": INDEX_SCHEMA,
            "block_stream_format": SCHEMA,
            "protobuf_schema_sha256": PROTOBUF_SCHEMA_SHA256,
            "protobuf_binding_sha256": PROTOBUF_BINDING_SHA256,
            "protobuf_descriptor_sha256": PROTOBUF_DESCRIPTOR_SHA256,
            "run_id": run_id,
            "network_id": network_id,
            "genesis_hash": genesis_hash,
            "fork_height": fork_height,
            "fork_hash": fork_hash,
            "terminal_height": terminal_height,
            "terminal_hash": terminal_hash,
            "block_count": terminal_height + 1,
            "transaction_count": transaction_count,
            "max_blocks_per_shard": max_blocks,
            "max_shard_bytes": max_bytes,
            "shards": shards,
        }
        with (stage / "shards.json").open("wb") as stream:
            stream.write(json.dumps(index, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        source.assert_stable()
        verify_archive(stage, network_id=network_id, genesis_hash=genesis_hash,
                       fork_height=fork_height, fork_hash=fork_hash,
                       terminal_height=terminal_height, terminal_hash=terminal_hash)
        _sync_dir(stage)
        os.replace(stage, output)
        _sync_dir(output.parent)
        return index
    except Exception:
        if writer is not None:
            writer.discard()
        shutil.rmtree(stage, ignore_errors=True)
        raise


def _read_shard_header(stream) -> tuple[str, bytes, int, int, int]:
    if _read_exact(stream, len(MAGIC)) != MAGIC:
        raise IntegrityError("invalid block-stream magic")
    if _read_u32(stream) != VERSION:
        raise IntegrityError("unsupported block-stream version")
    network_length = _read_u32(stream)
    if not 1 <= network_length <= 128:
        raise IntegrityError("invalid network ID length")
    try:
        network = _read_exact(stream, network_length).decode("utf-8")
    except UnicodeDecodeError as error:
        raise IntegrityError("network ID is not UTF-8") from error
    genesis_length = _read_u32(stream)
    if genesis_length != 32:
        raise IntegrityError("invalid genesis hash length")
    genesis = _read_exact(stream, genesis_length)
    return network, genesis, _read_u64(stream), _read_u64(stream), _read_u64(stream)


def verify_archive(directory: Path, *, network_id: str, genesis_hash: str,
                   fork_height: int, fork_hash: str, terminal_height: int,
                   terminal_hash: str) -> dict:
    assert_pinned_schema()
    genesis_bytes = _hex32(genesis_hash, "genesis hash")
    fork_bytes = _hex32(fork_hash, "fork hash")
    terminal_bytes = _hex32(terminal_hash, "terminal hash")
    try:
        index = json.loads((directory / "shards.json").read_text("utf-8"),
                           object_pairs_hook=_unique_json_object)
    except (OSError, UnicodeError, ValueError) as error:
        raise SourceError("could not read a valid shards.json") from error
    if not isinstance(index, dict) or index.get("schema") != INDEX_SCHEMA or index.get("block_stream_format") != SCHEMA:
        raise IntegrityError("unsupported shards index schema")
    expected = {
        "protobuf_schema_sha256": PROTOBUF_SCHEMA_SHA256,
        "protobuf_binding_sha256": PROTOBUF_BINDING_SHA256,
        "protobuf_descriptor_sha256": PROTOBUF_DESCRIPTOR_SHA256,
        "network_id": network_id,
        "genesis_hash": genesis_hash,
        "fork_height": fork_height,
        "fork_hash": fork_hash,
        "terminal_height": terminal_height,
        "terminal_hash": terminal_hash,
        "block_count": terminal_height + 1,
    }
    for key, value in expected.items():
        if index.get(key) != value:
            raise IntegrityError(f"shards index {key} differs from expectation")
    shards = index.get("shards")
    if not isinstance(shards, list) or not shards:
        raise IntegrityError("shards index has no shards")
    max_bytes = index.get("max_shard_bytes")
    max_blocks = index.get("max_blocks_per_shard")
    if not isinstance(max_bytes, int) or not 1024 <= max_bytes <= MAX_SHARD_BYTES:
        raise IntegrityError("invalid shard byte cap")
    if not isinstance(max_blocks, int) or not 1 <= max_blocks <= MAX_BLOCKS_PER_SHARD:
        raise IntegrityError("invalid shard block cap")

    next_height = 0
    previous_hash = None
    transaction_count = 0
    names = set()
    with tempfile.TemporaryDirectory(prefix="qrl-archive-verify-") as scratch:
        seen = sqlite3.connect(str(Path(scratch) / "seen.sqlite"))
        seen.execute("PRAGMA journal_mode=OFF")
        seen.execute("PRAGMA synchronous=OFF")
        seen.execute("CREATE TABLE blocks (hash BLOB PRIMARY KEY) WITHOUT ROWID")
        seen.execute("CREATE TABLE transactions (hash BLOB PRIMARY KEY) WITHOUT ROWID")
        for shard in shards:
            if not isinstance(shard, dict):
                raise IntegrityError("invalid shard entry")
            name = shard.get("name")
            if not isinstance(name, str) or not name.endswith(".qrlblk") or Path(name).name != name or name in names:
                raise IntegrityError("unsafe or duplicate shard filename")
            names.add(name)
            path = directory / name
            if path.is_symlink() or not path.is_file():
                raise SourceError(f"missing shard {name}")
            size, sha256, sha3_256 = _digest_file(path)
            if size != shard.get("bytes") or size > max_bytes or sha256 != shard.get("sha256") or sha3_256 != shard.get("sha3_256"):
                raise IntegrityError(f"shard digest or size mismatch: {name}")
            with path.open("rb") as stream:
                shard_network, shard_genesis, first, last, count = _read_shard_header(stream)
                if shard_network != network_id or shard_genesis != genesis_bytes:
                    raise IntegrityError(f"shard identity mismatch: {name}")
                if first != next_height or count < 1 or count > max_blocks or last != first + count - 1:
                    raise IntegrityError(f"shard height range is not contiguous: {name}")
                if (first, last, count) != (shard.get("first_height"), shard.get("last_height"), shard.get("record_count")):
                    raise IntegrityError(f"shard header differs from index: {name}")
                for offset in range(count):
                    height = _read_u64(stream)
                    length = _read_u64(stream)
                    if height != next_height or length < 1 or length > max_bytes or stream.tell() + length > size:
                        raise IntegrityError(f"invalid record framing at height {next_height}")
                    raw = _read_exact(stream, length)
                    block = decode_block(raw, height)
                    block_hash = bytes(block.header.hash_header)
                    if height == 0 and block_hash != genesis_bytes:
                        raise IntegrityError("genesis hash mismatch")
                    if height and bytes(block.header.hash_header_prev) != previous_hash:
                        raise IntegrityError(f"chain link mismatch at height {height}")
                    if height == fork_height and block_hash != fork_bytes:
                        raise IntegrityError("fork hash mismatch")
                    if height == terminal_height and block_hash != terminal_bytes:
                        raise IntegrityError("terminal hash mismatch")
                    try:
                        seen.execute("INSERT INTO blocks VALUES (?)", (block_hash,))
                    except sqlite3.IntegrityError as error:
                        raise IntegrityError(f"duplicate block hash at height {height}") from error
                    for tx in block.transactions:
                        tx_hash = bytes(tx.transaction_hash)
                        if len(tx_hash) != 32 or tx.WhichOneof("transactionType") is None:
                            raise IntegrityError(f"invalid transaction header at height {height}")
                        try:
                            seen.execute("INSERT INTO transactions VALUES (?)", (tx_hash,))
                        except sqlite3.IntegrityError as error:
                            raise IntegrityError(f"duplicate transaction hash at height {height}") from error
                        transaction_count += 1
                    previous_hash = block_hash
                    next_height += 1
                if stream.read(1):
                    raise IntegrityError(f"trailing bytes in shard {name}")
        seen.close()
    if next_height != terminal_height + 1 or previous_hash != terminal_bytes:
        raise IntegrityError("archive does not end at declared terminal block")
    if transaction_count != index.get("transaction_count"):
        raise IntegrityError("transaction count differs from index")
    actual_shards = {path.name for path in directory.iterdir() if path.name.endswith(".qrlblk")}
    if actual_shards != names:
        raise IntegrityError("canonical directory contains an unlisted shard")
    return {
        "block_count": next_height,
        "transaction_count": transaction_count,
        "shard_count": len(shards),
        "genesis_hash": genesis_hash,
        "fork_hash": fork_hash,
        "terminal_hash": terminal_hash,
        "structural_verified": True,
        "consensus_verified": False,
        "native_final_state_verified": False,
        "derived_data_verified": False,
    }
