"""Exact logical-state comparison for two stopped QRL v1 LevelDB working copies.

The classifier is intentionally limited to the observed state-version-3 layout.
It distinguishes application state from hash-addressed blocks, transactions,
height mappings and other chain indexes. Every key must have a known shape.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import plyvel

from .errors import DisagreementError, IntegrityError, SourceError, UsageError
from .source import LevelDBSource, _get
from .vendor import qrl_pb2


SCHEMA = "qrl.v1.archive.native-state-compare.v1"
DOMAIN = b"qrl-v1-native-state-kv-v1\x00"
COINBASE_KEY = bytes(32)

STATE_CATEGORIES = (
    "account", "bitfield", "pagination", "token", "slave", "lattice",
    "vote", "proposal", "config", "supply",
)

PAGINATION_PREFIXES = (
    b"p_tx_hash_", b"p_tokens_", b"p_slaves_", b"p_lattice_pk_",
    b"p_multisig_address_", b"p_multi_sig_spend_", b"p_inbox_message_",
)
PROPOSAL_PAGINATION_PREFIX = b"p_proposal_tx_hash_"
AUXILIARY_FIXED = {b"blockheight", b"state_version", b"reorg_limit", b"last_txn"}


def _u32(number: int) -> bytes:
    return number.to_bytes(4, "big")


def _u64(number: int) -> bytes:
    return number.to_bytes(8, "big")


def _valid_address(key: bytes) -> bool:
    # QRL v1's historical rule accepts descriptor variants that newer qrllib
    # releases rejected. Keep this rule pinned to the archived node source.
    return (len(key) == 39 and key[1] >> 4 == 0
            and hashlib.sha256(key[:35]).digest()[-4:] == key[-4:])


def _canonical_decimal(value: bytes) -> bool:
    return bool(value) and value.isascii() and value.isdigit() and (value == b"0" or value[0] != 48)


def _pagination_key(key: bytes, prefix: bytes) -> bool:
    suffix = key[len(prefix):]
    for address in (suffix[:39], suffix[:32]):
        if (_valid_address(address) or address == COINBASE_KEY) and suffix[len(address):len(address) + 1] == b"_":
            return _canonical_decimal(suffix[len(address) + 1:])
    return False


def _classify(key: bytes, terminal_height: int) -> tuple[str, bool]:
    """Return (category, is_final_state); reject keys outside known layouts."""
    if key == b"fork_state":
        raise IntegrityError("source has an unfinished fork_state record")
    if key in AUXILIARY_FIXED:
        return key.decode("ascii"), False
    if key == b"total_coin_supply":
        return "supply", True
    if key == b"dev_config_current_state_key":
        return "config", True
    if key == COINBASE_KEY or _valid_address(key):
        return "account", True
    if key.startswith(b"bitfield_"):
        suffix = key[len(b"bitfield_"):]
        if (len(suffix) != 48 or not _valid_address(suffix[:39])
                or suffix[39:40] != b"_" or int.from_bytes(suffix[40:], "big") == 0):
            raise IntegrityError("invalid bitfield key shape")
        return "bitfield", True
    for prefix in PAGINATION_PREFIXES:
        if key.startswith(prefix):
            if not _pagination_key(key, prefix):
                raise IntegrityError("invalid pagination key shape")
            return "pagination", True
    if key.startswith(PROPOSAL_PAGINATION_PREFIX):
        # ProposalRecord defines this name, but current v3 code does not
        # instantiate it. Preserve any future value and require a page suffix.
        if not _canonical_decimal(key.rsplit(b"_", 1)[-1]):
            raise IntegrityError("invalid proposal pagination key shape")
        return "pagination", True
    if key.startswith(b"token_"):
        suffix = key[len(b"token_"):]
        if len(suffix) != 32 and not (len(suffix) == 72 and _valid_address(suffix[:39])
                                      and suffix[39:40] == b"_"):
            raise IntegrityError("invalid token key shape")
        return "token", True
    if key.startswith(b"slave_"):
        suffix = key[len(b"slave_"):]
        if len(suffix) < 41 or not _valid_address(suffix[:39]) or suffix[39:40] != b"_":
            raise IntegrityError("invalid slave key shape")
        return "slave", True
    if key.startswith(b"lattice_pk_"):
        suffix = key[len(b"lattice_pk_"):]
        if len(suffix) < 41 or not _valid_address(suffix[:39]) or suffix[39:40] != b"_":
            raise IntegrityError("invalid lattice key shape")
        return "lattice", True
    if key.startswith(b"shared_key_"):
        if len(key) != len(b"shared_key_") + 32:
            raise IntegrityError("invalid shared-key vote key shape")
        return "vote", True
    if key.startswith(b"proposal_record_block_number_"):
        if len(key) != len(b"proposal_record_block_number_") + 8:
            raise IntegrityError("invalid proposal key shape")
        return "proposal", True
    if key.startswith(b"dev_config_"):
        if len(key) != len(b"dev_config_") + 32:
            raise IntegrityError("invalid dev config key shape")
        return "config", True
    if key.startswith(b"metadata_"):
        if len(key) != len(b"metadata_") + 32:
            raise IntegrityError("invalid block metadata key shape")
        return "block_metadata", False
    if len(key) == 32:
        return "hash_addressed_chain_record", False
    if _canonical_decimal(key) and int(key) <= terminal_height:
        return "height_mapping", False
    raise IntegrityError(f"unclassified native DB key {key[:24].hex()}")


def _parse(value: bytes, message_type, label: str):
    message = message_type()
    try:
        message.ParseFromString(value)
    except Exception as error:
        raise IntegrityError(f"malformed {label} protobuf") from error
    return message


def _validate_state_value(category: str, key: bytes, value: bytes) -> None:
    if category == "account":
        kind = qrl_pb2.MultiSigAddressState if key != COINBASE_KEY and key[0] == 0x11 else qrl_pb2.OptimizedAddressState
        account = _parse(value, kind, "address state")
        if bytes(account.address) != key:
            raise IntegrityError("address state key differs from embedded address")
    elif category in {"bitfield", "pagination"}:
        _parse(value, qrl_pb2.DataList, category)
    elif category == "token":
        kind = qrl_pb2.TokenMetadata if len(key) == len(b"token_") + 32 else qrl_pb2.TokenBalance
        _parse(value, kind, "token state")
    elif category == "slave":
        _parse(value, qrl_pb2.SlaveMetadata, "slave state")
    elif category == "lattice":
        _parse(value, qrl_pb2.LatticePKMetadata, "lattice state")
    elif category == "vote":
        _parse(value, qrl_pb2.VoteStats, "vote state")
    elif category == "proposal":
        _parse(value, qrl_pb2.ProposalRecord, "proposal state")
    elif category == "config":
        if key == b"dev_config_current_state_key":
            if len(value) != len(b"dev_config_") + 32 or not value.startswith(b"dev_config_"):
                raise IntegrityError("invalid active dev config pointer")
        else:
            _parse(value, qrl_pb2.DevConfig, "dev config")
    elif category == "supply" and len(value) != 8:
        raise IntegrityError("total_coin_supply is not eight bytes")


def _anchor_bytes(anchor: dict) -> bytes:
    network = anchor["network_id"].encode("utf-8")
    return (DOMAIN + _u32(len(network)) + network
            + bytes.fromhex(anchor["genesis_hash"])
            + _u64(anchor["fork_height"]) + bytes.fromhex(anchor["fork_hash"])
            + _u64(anchor["terminal_height"]) + bytes.fromhex(anchor["terminal_hash"]))


def _validate_anchor(anchor: dict) -> None:
    if not isinstance(anchor["network_id"], str) or not anchor["network_id"]:
        raise UsageError("network ID must be nonempty")
    if not (isinstance(anchor["fork_height"], int) and isinstance(anchor["terminal_height"], int)
            and 0 <= anchor["fork_height"] <= anchor["terminal_height"] < 2**64):
        raise UsageError("invalid fork or terminal height")
    for name in ("genesis_hash", "fork_hash", "terminal_hash"):
        value = anchor[name]
        if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise UsageError(f"{name} must be 64 lowercase hex characters")


def _check_source(source: LevelDBSource, anchor: dict) -> None:
    if source.tip_height != anchor["terminal_height"]:
        raise IntegrityError("source tip height differs from declared terminal height")
    genesis = source.get_block(0)[1].header.hash_header.hex()
    fork = source.get_block(anchor["fork_height"])[1].header.hash_header.hex()
    terminal = source.get_block(source.tip_height)[1].header.hash_header.hex()
    if (genesis, fork, terminal) != (anchor["genesis_hash"], anchor["fork_hash"], anchor["terminal_hash"]):
        raise IntegrityError("source genesis, fork or terminal hash differs from expectation")
    source.pin_anchor(anchor["fork_height"], role="fork")
    if _get(source.snapshot, b"state_version", "state version") != b"3":
        raise IntegrityError("native state comparison only supports state_version 3")
    if _get(source.snapshot, b"fork_state", "fork state") is not None:
        raise IntegrityError("source has an unfinished fork_state record")
    if _get(source.snapshot, COINBASE_KEY, "coinbase state") is None:
        raise IntegrityError("source has no coinbase address state")
    current_config = _get(source.snapshot, b"dev_config_current_state_key", "active config pointer")
    if current_config is None or not current_config.startswith(b"dev_config_") or len(current_config) != 43:
        raise IntegrityError("source has no valid active dev config pointer")
    if _get(source.snapshot, current_config, "active config") is None:
        raise IntegrityError("source has no active dev config")
    if _get(source.snapshot, b"total_coin_supply", "total supply") is None:
        raise IntegrityError("source has no total coin supply")


class _StateScanner:
    def __init__(self, iterator, anchor: dict):
        self.iterator = iterator
        self.height = anchor["terminal_height"]
        seed = _anchor_bytes(anchor)
        self.hashes = {}
        self.counts = {category: 0 for category in STATE_CATEGORIES}
        self.bytes = {category: 0 for category in STATE_CATEGORIES}
        for category in STATE_CATEGORIES:
            prefix = seed + _u32(len(category)) + category.encode("ascii")
            sha256, sha3_256 = hashlib.sha256(), hashlib.sha3_256()
            sha256.update(prefix)
            sha3_256.update(prefix)
            self.hashes[category] = (sha256, sha3_256)
        self.auxiliary_counts = {}
        self.total_keys = 0
        self._last_key = None

    def next_state(self):
        try:
            for key, value in self.iterator:
                if self._last_key is not None and key <= self._last_key:
                    raise IntegrityError("native DB iterator keys are not strictly increasing")
                self._last_key = key
                self.total_keys += 1
                category, is_state = _classify(key, self.height)
                if not is_state:
                    self.auxiliary_counts[category] = self.auxiliary_counts.get(category, 0) + 1
                    continue
                _validate_state_value(category, key, value)
                frame = _u32(len(key)) + key + _u64(len(value)) + value
                for digest in self.hashes[category]:
                    digest.update(frame)
                self.counts[category] += 1
                self.bytes[category] += len(key) + len(value)
                return key, value, category
        except plyvel.Error as error:
            raise SourceError("LevelDB could not iterate native state") from error
        return None

    def result(self) -> dict:
        category_results = {}
        for category in STATE_CATEGORIES:
            sha256, sha3_256 = self.hashes[category]
            category_results[category] = {
                "record_count": self.counts[category],
                "raw_key_value_bytes": self.bytes[category],
                "sha256": sha256.hexdigest(),
                "sha3_256": sha3_256.hexdigest(),
            }
        return {
            "state_record_count": sum(self.counts.values()),
            "total_classified_key_count": self.total_keys,
            "categories": category_results,
            "auxiliary_key_counts": dict(sorted(self.auxiliary_counts.items())),
        }


def _value_summary(record) -> dict | None:
    if record is None:
        return None
    key, value, category = record
    return {
        "key_hex": key.hex(),
        "category": category,
        "value_bytes": len(value),
        "value_sha256": hashlib.sha256(value).hexdigest(),
        "value_sha3_256": hashlib.sha3_256(value).hexdigest(),
    }


def _scan_current(source: LevelDBSource, anchor: dict) -> dict:
    """Recheck live logical state after the pinned comparison snapshot."""
    with source.db.snapshot() as current:
        with current.iterator() as iterator:
            scanner = _StateScanner(iterator, anchor)
            while scanner.next_state() is not None:
                pass
            return scanner.result()


def compare_native_state(a: Path, b: Path, *, network_id: str, genesis_hash: str,
                         fork_height: int, fork_hash: str, terminal_height: int,
                         terminal_hash: str) -> dict:
    """Compare v3 application-state keys as exact stored bytes, without replay."""
    if a.resolve() == b.resolve():
        raise UsageError("native comparison requires two distinct working directories")
    anchor = {
        "network_id": network_id,
        "genesis_hash": genesis_hash,
        "fork_height": fork_height,
        "fork_hash": fork_hash,
        "terminal_height": terminal_height,
        "terminal_hash": terminal_hash,
    }
    _validate_anchor(anchor)
    with LevelDBSource(a) as source_a, LevelDBSource(b) as source_b:
        _check_source(source_a, anchor)
        _check_source(source_b, anchor)
        first_mismatch = None
        with source_a.snapshot.iterator() as iterator_a, source_b.snapshot.iterator() as iterator_b:
            scanner_a = _StateScanner(iterator_a, anchor)
            scanner_b = _StateScanner(iterator_b, anchor)
            record_a = scanner_a.next_state()
            record_b = scanner_b.next_state()
            while record_a is not None or record_b is not None:
                if record_a is not None and record_b is not None and record_a[0] == record_b[0]:
                    if first_mismatch is None and record_a[1] != record_b[1]:
                        first_mismatch = {"reason": "value differs", "a": _value_summary(record_a),
                                          "b": _value_summary(record_b)}
                    record_a = scanner_a.next_state()
                    record_b = scanner_b.next_state()
                elif record_b is None or (record_a is not None and record_a[0] < record_b[0]):
                    if first_mismatch is None:
                        first_mismatch = {"reason": "key absent from b", "a": _value_summary(record_a), "b": None}
                    record_a = scanner_a.next_state()
                else:
                    if first_mismatch is None:
                        first_mismatch = {"reason": "key absent from a", "a": None, "b": _value_summary(record_b)}
                    record_b = scanner_b.next_state()
            result_a = scanner_a.result()
            result_b = scanner_b.result()

        # A writer cannot normally open either LevelDB while these locks are
        # held. Re-scan the current logical state too, so accidental writes by
        # this process cannot turn a stale snapshot into a passing result.
        if _scan_current(source_a, anchor)["categories"] != result_a["categories"]:
            raise SourceError("source a native state changed during comparison")
        if _scan_current(source_b, anchor)["categories"] != result_b["categories"]:
            raise SourceError("source b native state changed during comparison")
        source_a.finish_read()
        source_b.finish_read()

    result = {
        "schema": SCHEMA,
        "anchors": anchor,
        "state_version": 3,
        "a": result_a,
        "b": result_b,
        "first_mismatch": first_mismatch,
        "exact_native_state_bytes_equal": first_mismatch is None,
        "native_state_agreement_verified": first_mismatch is None,
        "consensus_verified": False,
        "replayed_state_verified": False,
        "source_independence_verified": False,
        "source_leveldb_file_churn_observed_a": source_a.data_files_changed_during_read,
        "source_leveldb_file_churn_observed_b": source_b.data_files_changed_during_read,
    }
    if first_mismatch is not None:
        error = DisagreementError("native final-state records differ")
        error.result = result
        raise error
    return result
