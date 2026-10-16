"""Compare imported SQLite account rows with an independent stopped QRL node."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing
from pathlib import Path

from .errors import DisagreementError, IntegrityError, SourceError
from .native_state import COINBASE_KEY, _check_source, _classify, _validate_state_value
from .source import LevelDBSource
from .vendor import qrl_pb2


SCHEMA = "qrl-v1-native-balance-check-v1"


def compare_sqlite_native_accounts(database: Path, source_db: Path, *, network_id: str,
                                   genesis_hash: str, fork_height: int, fork_hash: str,
                                   terminal_height: int, terminal_hash: str) -> dict:
    """Check every imported account row, including exact state protobuf bytes.

    This compares two observations at the same cutoff. It does not replay
    canonical consensus or prove either node's source independence.
    """
    if database.is_symlink() or not database.is_file():
        raise SourceError("SQLite comparison input is missing or linked")
    anchors = dict(network_id=network_id, genesis_hash=genesis_hash,
                   fork_height=fork_height, fork_hash=fork_hash,
                   terminal_height=terminal_height, terminal_hash=terminal_hash)
    try:
        with closing(sqlite3.connect(f"file:{database}?mode=ro", uri=True)) as db:
            if db.execute("PRAGMA application_id").fetchone() != (0x51524C31,) or db.execute("PRAGMA user_version").fetchone() != (1,):
                raise IntegrityError("SQLite v1 identity is invalid")
            meta = dict(db.execute("SELECT key,value FROM archive_meta"))
            for key, value in anchors.items():
                if meta.get(key) != str(value):
                    raise IntegrityError(f"SQLite {key} differs from expected anchor")
            if meta.get("balance_source") != "qrl-state-v3-anchored-not-replayed":
                raise IntegrityError("SQLite has no imported native account state")
            count = 0
            rows = []
            with LevelDBSource(source_db) as source:
                _check_source(source, anchors)
                with source.snapshot.iterator() as iterator:
                    for key, value in iterator:
                        category, _ = _classify(key, terminal_height)
                        if category != "account":
                            continue
                        _validate_state_value(category, key, value)
                        kind = (qrl_pb2.MultiSigAddressState
                                if key != COINBASE_KEY and key[0] == 0x11
                                else qrl_pb2.OptimizedAddressState)
                        account = kind.FromString(value)
                        expected = (str(account.balance), str(account.nonce), bytes(value),
                                    "qrl-state-v3-anchored-not-replayed")
                        row = db.execute("SELECT balance_shor,nonce,state_pb,source FROM final_address_state WHERE address=?", (key,)).fetchone()
                        if row != expected:
                            error = DisagreementError("SQLite account differs from independent native state")
                            error.result = {"first_mismatch_address": key.hex(), "sqlite_row_present": row is not None}
                            raise error
                        rows.append({"address": key.hex(), "balance_shor": expected[0],
                                     "nonce": expected[1],
                                     "state_pb_sha256": hashlib.sha256(value).hexdigest()})
                        count += 1
                source.finish_read()
            if db.execute("SELECT COUNT(*) FROM final_address_state").fetchone()[0] != count:
                raise DisagreementError("SQLite has extra native account rows")
            if meta.get("account_count") != str(count):
                raise IntegrityError("SQLite account_count metadata differs from rows")
    except sqlite3.Error as error:
        raise IntegrityError("could not query SQLite native account rows") from error
    raw = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "schema": SCHEMA, "anchors": anchors,
        "account_count": count,
        "rows_sha256": hashlib.sha256(raw).hexdigest(),
        "rows_sha3_256": hashlib.sha3_256(raw).hexdigest(),
        "all_balances_nonces_and_state_pb_equal": True,
        "consensus_replayed": False,
        "source_independence_verified": False,
        "release_ready": False,
    }
