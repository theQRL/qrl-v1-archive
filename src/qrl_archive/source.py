"""Exact stored-byte reader for a stopped QRL v1 LevelDB copy.

The LevelDB library takes an exclusive lock and may compact its own files.
Operators must open a disposable working copy, never a custodial snapshot.
"""

from __future__ import annotations

import stat
from pathlib import Path

import plyvel
from google.protobuf.json_format import Parse

from .errors import IntegrityError, SourceError
from .protobuf_schema import assert_pinned_schema
from .vendor import qrl_pb2


def _file_manifest(db_path: Path) -> tuple[tuple[str, int, int], ...]:
    """Record file churn and reject unsafe entries while the reader is open."""
    result = []
    for item in db_path.iterdir():
        try:
            item_stat = item.lstat()
        except FileNotFoundError:
            # A compacted SST file can vanish between directory enumeration
            # and stat; retain that observation as file churn.
            result.append((item.name, -1, -1))
            continue
        if stat.S_ISLNK(item_stat.st_mode):
            raise SourceError("database contains a symbolic link")
        if not stat.S_ISREG(item_stat.st_mode):
            raise SourceError("database contains a nested or non-regular entry")
        if item.name in {"LOCK", "LOG", "LOG.old"}:
            continue
        result.append((item.name, item_stat.st_size, item_stat.st_mtime_ns))
    return tuple(sorted(result))


def decode_block(raw: bytes, expected_height: int | None = None):
    if not raw:
        raise IntegrityError("empty stored block")
    block = qrl_pb2.Block()
    try:
        block.ParseFromString(raw)
    except Exception as error:
        raise IntegrityError("malformed stored block protobuf") from error
    if not block.HasField("header"):
        raise IntegrityError("block has no header")
    header = block.header
    if expected_height is not None and header.block_number != expected_height:
        raise IntegrityError(f"block number mismatch at height {expected_height}")
    if len(header.hash_header) != 32:
        raise IntegrityError("block header hash must be 32 bytes")
    if expected_height and len(header.hash_header_prev) != 32:
        raise IntegrityError("previous header hash must be 32 bytes")
    return block


def _get(db, key: bytes, label: str) -> bytes | None:
    try:
        return db.get(key)
    except plyvel.Error as error:
        raise SourceError(f"LevelDB could not read {label}; check reader compatibility and source integrity") from error


class LevelDBSource:
    def __init__(self, db_path: Path):
        self.path = db_path
        self.db = None
        self.snapshot = None
        self.before = None
        self.tip_height = None
        self.data_files_changed_during_read = False
        self._finished = False
        self._anchors: dict[bytes, tuple[bytes, str]] = {}

    def __enter__(self):
        assert_pinned_schema()
        if self.path.is_symlink() or not self.path.is_dir():
            raise SourceError("source must be an existing, non-symlink LevelDB directory")
        if not (self.path / "CURRENT").is_file():
            raise SourceError("source has no LevelDB CURRENT file")
        _file_manifest(self.path)  # reject symlinks before LevelDB recovery
        try:
            self.db = plyvel.DB(str(self.path), create_if_missing=False)
        except Exception as error:
            raise SourceError("could not acquire the source LevelDB lock") from error
        try:
            self.snapshot = self.db.snapshot()
            height = _get(self.snapshot, b"blockheight", "blockheight")
            if height is None or len(height) != 8:
                raise IntegrityError("source has no valid blockheight record")
            self.tip_height = int.from_bytes(height, "big")
            self.pin_anchor(0, role="genesis")
            if self.tip_height:
                self.pin_anchor(self.tip_height, role="terminal")
            # Recovery can rewrite files on open; subsequent reads can trigger
            # compaction. The snapshot pins one logical view for every read.
            self.before = _file_manifest(self.path)
            return self
        except Exception:
            if self.snapshot is not None:
                self.snapshot.close()
                self.snapshot = None
            self.db.close()
            self.db = None
            raise

    def __exit__(self, exc_type, exc, traceback):
        if self.db is not None:
            try:
                if exc_type is None and not self._finished:
                    self.finish_read()
            finally:
                try:
                    if self.snapshot is not None:
                        self.snapshot.close()
                        self.snapshot = None
                finally:
                    self.db.close()
                    self.db = None

    def assert_stable(self) -> None:
        if self.db is None:
            raise SourceError("source is closed")
        if _get(self.db, b"blockheight", "blockheight") != self.tip_height.to_bytes(8, "big"):
            raise SourceError("source tip moved while being read")
        for key, (expected, label) in self._anchors.items():
            if _get(self.db, key, label) != expected:
                raise SourceError(f"source {label} changed while being read")
        # The reader itself can compact SST files, so file churn is evidence
        # to report, not proof that an external writer changed the chain.
        self.data_files_changed_during_read |= _file_manifest(self.path) != self.before

    def pin_anchor(self, height: int, *, role: str) -> None:
        """Remember the snapshot's mapping and block bytes for a live recheck."""
        raw, block = self.get_block(height)
        mapping_key = str(height).encode("ascii")
        mapping_raw = _get(self.snapshot, mapping_key, f"{role} mapping")
        self._anchors.setdefault(mapping_key, (mapping_raw, f"{role} mapping"))
        self._anchors.setdefault(bytes(block.header.hash_header), (raw, f"{role} block"))

    def finish_read(self) -> None:
        """Perform the final source check before a staged export is published."""
        if not self._finished:
            self.assert_stable()
            self._finished = True

    def get_block(self, height: int) -> tuple[bytes, qrl_pb2.Block]:
        if self.snapshot is None or self._finished:
            raise SourceError("source is closed")
        if not 0 <= height <= self.tip_height:
            raise SourceError(f"height {height} is outside source chain")
        mapping_raw = _get(self.snapshot, str(height).encode("ascii"), f"height mapping {height}")
        if mapping_raw is None:
            raise IntegrityError(f"missing height mapping at {height}")
        mapping = qrl_pb2.BlockNumberMapping()
        try:
            Parse(mapping_raw.decode("utf-8"), mapping)
        except Exception as error:
            raise IntegrityError(f"malformed height mapping at {height}") from error
        header_hash = bytes(mapping.headerhash)
        if len(header_hash) != 32:
            raise IntegrityError(f"invalid mapped header hash at {height}")
        raw = _get(self.snapshot, header_hash, f"stored block {height}")
        if raw is None:
            raise IntegrityError(f"missing mapped block bytes at {height}")
        block = decode_block(raw, height)
        if bytes(block.header.hash_header) != header_hash:
            raise IntegrityError(f"mapped header hash differs from block at {height}")
        if height and bytes(block.header.hash_header_prev) != bytes(mapping.prev_headerhash):
            raise IntegrityError(f"mapped previous hash differs from block at {height}")
        return bytes(raw), block

    def cumulative_difficulty(self, header_hash: bytes) -> str:
        raw = _get(self.snapshot, b"metadata_" + header_hash, "tip metadata")
        if raw is None:
            raise IntegrityError("tip metadata is missing")
        metadata = qrl_pb2.BlockMetaData()
        try:
            metadata.ParseFromString(raw)
        except Exception as error:
            raise IntegrityError("tip metadata is malformed") from error
        return str(int.from_bytes(metadata.cumulative_difficulty, "big"))

    def inspect(self) -> dict:
        genesis_raw, genesis = self.get_block(0)
        tip_raw, tip = self.get_block(self.tip_height)
        version = _get(self.snapshot, b"state_version", "state version")
        return {
            "tip_height": self.tip_height,
            "tip_hash": tip.header.hash_header.hex(),
            "genesis_hash": genesis.header.hash_header.hex(),
            "cumulative_difficulty": self.cumulative_difficulty(tip.header.hash_header),
            "state_version": version.decode("ascii") if version else None,
            "genesis_stored_bytes": len(genesis_raw),
            "tip_stored_bytes": len(tip_raw),
            "db_data_file_count": len(self.before),
        }
