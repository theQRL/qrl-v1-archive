"""Build the inspectable SQLite v1 derivative from verified QRL block shards.

This is a structural derivative. Native account balances can be copied from a
stopped, anchored state-v3 working copy, but neither path replays consensus.
The resulting database always records release_ready=false.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
from contextlib import closing
from importlib.resources import files
from pathlib import Path

from google.protobuf.descriptor import FieldDescriptor

from .block_stream_v1 import iter_verified_records
from .errors import IntegrityError, SourceError, UsageError
from .native_state import COINBASE_KEY, _check_source, _classify, _validate_state_value
from .source import LevelDBSource
from .vendor import qrl_pb2


SCHEMA_FILE = files("qrl_archive").joinpath("qrl-v1-sqlite-v1.sql")
DETAILS_SCHEMA = "qrl.v1.tx-details.v1"
ROW_DIGEST_DOMAIN = b"qrl-v1-sqlite-logical-rows-v1\x00"
MAX_SQLITE_INTEGER = (1 << 63) - 1


def _sqlite_integer(value: int, label: str) -> int:
    if not 0 <= value <= MAX_SQLITE_INTEGER:
        raise IntegrityError(f"{label} exceeds SQLite's signed integer range")
    return value


def _decimal(value: int) -> str:
    if not 0 <= value < 1 << 64:
        raise IntegrityError("protobuf unsigned amount is outside uint64 range")
    return str(value)


def _address(raw: bytes, label: str, *, allow_coinbase: bool = False) -> bytes:
    address = bytes(raw)
    if allow_coinbase and address == COINBASE_KEY:
        return address
    if (len(address) != 39 or address[1] >> 4 != 0
            or hashlib.sha256(address[:35]).digest()[-4:] != address[-4:]):
        raise IntegrityError(f"{label} is not a QRL v1 address")
    return address


def _address_from_pk(public_key: bytes) -> bytes:
    # The v1 node calls QRLHelper.getAddress(PK). The 4M mainnet token owner
    # fixture independently checks this descriptor/hash/checksum construction.
    if len(public_key) != 67:
        raise IntegrityError("non-coinbase transaction has no 67-byte public key")
    prefix = public_key[:3] + hashlib.sha256(public_key).digest()
    return _address(prefix + hashlib.sha256(prefix).digest()[-4:], "signer")


def _multisig_address(tx_hash: bytes) -> bytes:
    # Pinned QRL MultiSigAddressState.generate_multi_sig_address.
    prefix = bytes.fromhex("110000") + hashlib.sha256(bytes.fromhex("110000") + tx_hash).digest()
    return _address(prefix + hashlib.sha256(prefix).digest()[-4:], "multisig account")


def _read_varint(data: bytes, offset: int) -> tuple[int, int]:
    number = 0
    for index in range(10):
        if offset >= len(data):
            raise IntegrityError("truncated protobuf varint while locating transactions")
        byte = data[offset]
        offset += 1
        if index == 9 and byte > 1:
            raise IntegrityError("protobuf varint overflow while locating transactions")
        number |= (byte & 0x7f) << (7 * index)
        if byte < 0x80:
            return number, offset
    raise IntegrityError("overlong protobuf varint while locating transactions")


def _exact_transaction_wires(raw_block: bytes) -> list[bytes]:
    """Extract Block.transactions field 2 without reserializing its wire bytes."""
    result = []
    offset = 0
    while offset < len(raw_block):
        tag, offset = _read_varint(raw_block, offset)
        field_number, wire_type = tag >> 3, tag & 7
        if field_number == 0:
            raise IntegrityError("invalid protobuf field number in block")
        if wire_type == 0:
            _, offset = _read_varint(raw_block, offset)
        elif wire_type == 1:
            offset += 8
        elif wire_type == 2:
            length, offset = _read_varint(raw_block, offset)
            end = offset + length
            if end > len(raw_block):
                raise IntegrityError("truncated protobuf field in block")
            if field_number == 2:
                result.append(raw_block[offset:end])
            offset = end
        elif wire_type == 5:
            offset += 4
        else:
            raise IntegrityError("unsupported protobuf wire type in block")
        if offset > len(raw_block):
            raise IntegrityError("truncated protobuf field in block")
    return result


def _json_scalar(field: FieldDescriptor, value):
    if field.type == FieldDescriptor.TYPE_BYTES:
        return bytes(value).hex()
    if field.type == FieldDescriptor.TYPE_MESSAGE:
        return _json_message(value)
    if field.type in (FieldDescriptor.TYPE_INT64, FieldDescriptor.TYPE_UINT64,
                      FieldDescriptor.TYPE_SINT64, FieldDescriptor.TYPE_FIXED64,
                      FieldDescriptor.TYPE_SFIXED64):
        return str(value)
    return value


def _json_message(message) -> dict:
    result = {}
    for field, value in sorted(message.ListFields(), key=lambda item: item[0].number):
        if field.is_repeated:
            if field.message_type is not None and field.message_type.GetOptions().map_entry:
                result[field.name] = {str(key): _json_scalar(field.message_type.fields_by_name["value"], val)
                                      for key, val in sorted(value.items())}
            else:
                result[field.name] = [_json_scalar(field, item) for item in value]
        else:
            result[field.name] = _json_scalar(field, value)
    return result


def _event(db: sqlite3.Connection, address: bytes, height: int, tx_index: int,
           tx_hash: bytes, role: str, output_index: int = -1, amount: str | None = None) -> None:
    db.execute("INSERT INTO address_events VALUES (?,?,?,?,?,?,?)",
               (address, height, tx_index, tx_hash, role, output_index, amount))


def _output(db: sqlite3.Connection, tx_hash: bytes, index: int, to_address: bytes,
            amount: int, asset_id: bytes | None, height: int, tx_index: int, role: str) -> None:
    amount_text = _decimal(amount)
    db.execute("INSERT INTO tx_outputs VALUES (?,?,?,?,?)",
               (tx_hash, index, to_address, amount_text, asset_id))
    _event(db, to_address, height, tx_index, tx_hash, role, index, amount_text)


def _insert_transaction(db: sqlite3.Connection, tx: qrl_pb2.Transaction, raw: bytes,
                        height: int, index: int) -> int:
    if qrl_pb2.Transaction.FromString(raw) != tx:
        raise IntegrityError(f"transaction wire disagrees with decoded block at {height}:{index}")
    kind = tx.WhichOneof("transactionType")
    if kind is None:
        raise IntegrityError(f"transaction type missing at {height}:{index}")
    tx_hash = bytes(tx.transaction_hash)
    if len(tx_hash) != 32:
        raise IntegrityError(f"transaction hash has wrong length at {height}:{index}")
    master = bytes(tx.master_addr) or None
    public_key = bytes(tx.public_key)
    if kind == "coinbase":
        if master not in (None, COINBASE_KEY):
            raise IntegrityError("coinbase master address is not the zero address")
        signer = None
        sender = None
    else:
        signer = _address_from_pk(public_key)
        sender = _address(master, "master address") if master is not None else signer
    db.execute("INSERT INTO transactions VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
               (tx_hash, height, index, kind, sender, signer, master,
                _decimal(tx.fee), _decimal(tx.nonce), public_key or None,
                bytes(tx.signature) or None, raw))
    details = {"schema": DETAILS_SCHEMA, "kind": kind, "fields": _json_message(getattr(tx, kind))}
    db.execute("INSERT INTO tx_details VALUES (?,?,?)",
               (tx_hash, kind, json.dumps(details, sort_keys=True, separators=(",", ":"), ensure_ascii=False)))
    if sender is not None:
        _event(db, sender, height, index, tx_hash, "from")
    if signer is not None:
        _event(db, signer, height, index, tx_hash, "signer")
    if master is not None and kind != "coinbase":
        _event(db, master, height, index, tx_hash, "master")

    body = getattr(tx, kind)
    outputs = 0
    if kind == "coinbase":
        recipient = _address(body.addr_to, "coinbase recipient")
        _output(db, tx_hash, 0, recipient, body.amount, None, height, index, "coinbase_receive")
        outputs = 1
    elif kind in {"transfer", "transfer_token", "multi_sig_spend"}:
        if len(body.addrs_to) != len(body.amounts):
            raise IntegrityError(f"{kind} recipient and amount counts differ at {height}:{index}")
        asset_id = bytes(body.token_txhash) if kind == "transfer_token" else None
        if kind == "transfer_token" and len(asset_id) != 32:
            raise IntegrityError("token transfer has an invalid asset ID")
        if kind == "multi_sig_spend":
            multi_sig = _address(body.multi_sig_address, "multisig spend source")
            _event(db, multi_sig, height, index, tx_hash, "multisig_spend_source")
        role = "token_receive" if kind == "transfer_token" else "receive"
        for output_index, (recipient, amount) in enumerate(zip(body.addrs_to, body.amounts)):
            _output(db, tx_hash, output_index, _address(recipient, kind + " recipient"),
                    amount, asset_id, height, index, role)
            outputs += 1
    elif kind == "token":
        if body.owner:
            _event(db, _address(body.owner, "token owner"), height, index, tx_hash, "token_owner")
        for output_index, allocation in enumerate(body.initial_balances):
            _output(db, tx_hash, output_index,
                    _address(allocation.address, "token initial holder"),
                    allocation.amount, tx_hash, height, index, "token_initial")
            outputs += 1
    elif kind == "message" and body.addr_to:
        _event(db, _address(body.addr_to, "message recipient"), height, index, tx_hash, "message_to")
    elif kind == "slave":
        if len(body.slave_pks) != len(body.access_types):
            raise IntegrityError("slave public key and access type counts differ")
        for slave_index, slave_pk in enumerate(body.slave_pks):
            _event(db, _address_from_pk(bytes(slave_pk)), height, index, tx_hash,
                   "slave_key", slave_index)
    elif kind == "multi_sig_create":
        if len(body.signatories) != len(body.weights):
            raise IntegrityError("multisig signatory and weight counts differ")
        _event(db, _multisig_address(tx_hash), height, index, tx_hash, "multisig_created")
        for signatory_index, signatory in enumerate(body.signatories):
            _event(db, _address(signatory, "multisig signatory"), height, index,
                   tx_hash, "multisig_signatory", signatory_index)
    return outputs


def _insert_accounts(db: sqlite3.Connection, source_db: Path, anchors: dict) -> int:
    count = 0
    with LevelDBSource(source_db) as source:
        _check_source(source, anchors)
        with source.snapshot.iterator() as iterator:
            for key, value in iterator:
                category, is_state = _classify(key, anchors["terminal_height"])
                if not is_state:
                    continue
                _validate_state_value(category, key, value)
                if category != "account":
                    continue
                kind = qrl_pb2.MultiSigAddressState if key != COINBASE_KEY and key[0] == 0x11 else qrl_pb2.OptimizedAddressState
                account = kind.FromString(value)
                db.execute("INSERT INTO final_address_state VALUES (?,?,?,?,?,?)",
                           (key, _decimal(account.balance), _decimal(account.nonce),
                            None, bytes(value), "qrl-state-v3-anchored-not-replayed"))
                count += 1
        source.finish_read()
    return count


def _digest_rows(db: sqlite3.Connection, table: str, order_by: str) -> dict:
    sha256, sha3_256 = hashlib.sha256(), hashlib.sha3_256()
    prefix = ROW_DIGEST_DOMAIN + table.encode("ascii") + b"\x00"
    sha256.update(prefix)
    sha3_256.update(prefix)
    count = 0
    for row in db.execute(f"SELECT * FROM {table} ORDER BY {order_by}"):
        for value in row:
            if value is None:
                frame = b"N"
            else:
                if isinstance(value, bytes):
                    tag, payload = b"B", value
                elif isinstance(value, int):
                    tag, payload = b"I", str(value).encode("ascii")
                elif isinstance(value, str):
                    tag, payload = b"T", value.encode("utf-8")
                else:
                    raise IntegrityError("unexpected SQLite value type in logical digest")
                frame = tag + len(payload).to_bytes(8, "big") + payload
            sha256.update(frame)
            sha3_256.update(frame)
        count += 1
    return {"rows": count, "sha256": sha256.hexdigest(), "sha3_256": sha3_256.hexdigest()}


def _file_digests(path: Path) -> dict:
    sha256, sha3_256 = hashlib.sha256(), hashlib.sha3_256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(chunk)
            sha256.update(chunk)
            sha3_256.update(chunk)
    return {"bytes": size, "sha256": sha256.hexdigest(), "sha3_256": sha3_256.hexdigest()}


def derive_sqlite(canonical: Path, output: Path, *, network_id: str,
                  genesis_hash: str, fork_height: int, fork_hash: str,
                  terminal_height: int, terminal_hash: str,
                  source_db: Path | None = None) -> dict:
    """Build an atomic, read-only SQLite database; never claim release readiness."""
    if not output.name.endswith(".partial.sqlite"):
        raise UsageError("incomplete SQLite output must end in .partial.sqlite")
    if output.exists() or output.is_symlink():
        raise SourceError("derived SQLite output already exists")
    if not output.parent.is_dir():
        raise SourceError("derived SQLite output parent does not exist")
    if not SCHEMA_FILE.is_file():
        raise SourceError("packaged SQLite v1 schema is missing")
    try:
        schema = SCHEMA_FILE.read_text("utf-8")
    except (OSError, UnicodeError) as error:
        raise SourceError("could not read SQLite v1 schema") from error
    anchors = dict(network_id=network_id, genesis_hash=genesis_hash,
                   fork_height=fork_height, fork_hash=fork_hash,
                   terminal_height=terminal_height, terminal_hash=terminal_hash)
    descriptor, temporary = tempfile.mkstemp(prefix=".qrl-archive-sqlite-", suffix=".sqlite",
                                              dir=output.parent)
    os.close(descriptor)
    stage = Path(temporary)
    try:
        with closing(sqlite3.connect(stage)) as db:
            db.executescript(schema)
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN")
            meta = {
                "schema": "qrl-v1-sqlite-v1", "network_id": network_id,
                "genesis_hash": genesis_hash, "fork_height": str(fork_height),
                "fork_hash": fork_hash, "terminal_height": str(terminal_height),
                "terminal_hash": terminal_hash, "release_ready": "false",
                "consensus_replayed": "false",
                "balance_source": "qrl-state-v3-anchored-not-replayed" if source_db else "absent",
            }
            block_count = tx_count = output_count = genesis_count = 0
            for record in iter_verified_records(canonical, **anchors):
                block = record.block
                header = block.header
                db.execute("INSERT INTO blocks VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                           (record.height, bytes(header.hash_header),
                            bytes(header.hash_header_prev) or None,
                            _sqlite_integer(header.timestamp_seconds, "block timestamp"),
                            bytes(header.merkle_root) or None,
                            _decimal(header.mining_nonce), _decimal(header.reward_block),
                            _decimal(header.reward_fee), len(block.transactions),
                            record.shard_name, record.protobuf_offset, record.protobuf_length))
                if block.genesis_balance and record.height != 0:
                    raise IntegrityError("genesis allocation appears after block zero")
                for allocation_index, allocation in enumerate(block.genesis_balance):
                    db.execute("INSERT INTO genesis_allocations VALUES (?,?,?)",
                               (allocation_index, _address(allocation.address, "genesis allocation",
                                                            allow_coinbase=True),
                                _decimal(allocation.balance)))
                    genesis_count += 1
                wires = _exact_transaction_wires(record.raw_block)
                if len(wires) != len(block.transactions):
                    raise IntegrityError(f"transaction wire count differs at height {record.height}")
                for tx_index, (tx, raw_tx) in enumerate(zip(block.transactions, wires)):
                    output_count += _insert_transaction(db, tx, raw_tx, record.height, tx_index)
                    tx_count += 1
                block_count += 1
            if block_count != terminal_height + 1:
                raise IntegrityError("derived block count differs from declared terminal height")
            account_count = _insert_accounts(db, source_db, anchors) if source_db is not None else 0
            meta.update(block_count=str(block_count), transaction_count=str(tx_count),
                        output_count=str(output_count), genesis_allocation_count=str(genesis_count),
                        account_count=str(account_count))
            db.executemany("INSERT INTO archive_meta VALUES (?,?)", sorted(meta.items()))
            db.commit()
            if list(db.execute("PRAGMA foreign_key_check")):
                raise IntegrityError("SQLite foreign key check failed")
            if db.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise IntegrityError("SQLite integrity check failed")
            db.execute("VACUUM")
            if list(db.execute("PRAGMA foreign_key_check")):
                raise IntegrityError("SQLite foreign key check failed after VACUUM")
            if db.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise IntegrityError("SQLite integrity check failed after VACUUM")
            rows = {
                table: _digest_rows(db, table, order)
                for table, order in (
                    ("archive_meta", "key"), ("blocks", "height"),
                    ("transactions", "height,tx_index"),
                    ("tx_outputs", "tx_hash,output_index"),
                    ("address_events", "address,height,tx_index,role,output_index"),
                    ("final_address_state", "address"),
                    ("tx_details", "tx_hash"),
                    ("genesis_allocations", "allocation_index"),
                )
            }
        with closing(sqlite3.connect(f"file:{stage}?mode=ro", uri=True)) as readonly:
            if readonly.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise IntegrityError("read-only SQLite integrity check failed")
            if readonly.execute("PRAGMA application_id").fetchone() != (0x51524C31,):
                raise IntegrityError("SQLite application ID changed")
            if readonly.execute("PRAGMA user_version").fetchone() != (1,):
                raise IntegrityError("SQLite user version changed")
        file_digests = _file_digests(stage)
        descriptor = os.open(stage, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.link(stage, output)
        stage.unlink()
        parent_descriptor = os.open(output.parent, os.O_RDONLY)
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
        return {
            "schema": "qrl-v1-sqlite-v1", "anchors": anchors,
            "file": file_digests, "logical_tables": rows,
            "block_count": block_count, "transaction_count": tx_count,
            "output_count": output_count, "genesis_allocation_count": genesis_count,
            "native_account_count": account_count,
            "structural_verified": True, "sqlite_integrity_verified": True,
            "balances_imported_from_native_state": source_db is not None,
            "consensus_replayed": False, "release_ready": False,
        }
    except sqlite3.Error as error:
        raise IntegrityError("SQLite deriver failed a database invariant") from error
    finally:
        stage.unlink(missing_ok=True)
