"""Certify a two-node, point-in-time SQLite snapshot without claiming replay.

This gate is deliberately separate from permanent-retirement readiness. It
checks the canonical structural stream, two independently built derivatives,
and exact account-state agreement with a second stopped node. Consensus replay
and canonical-only balance reconstruction remain unimplemented.
"""

from __future__ import annotations

import json
import os
import shutil
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path

from .block_stream_v1 import verify_archive
from .errors import IntegrityError, SourceError, UsageError
from .native_balance_check import compare_sqlite_native_accounts
from .sqlite_v1 import _file_digests


SCHEMA = "qrl-v1-sqlite-snapshot-certification-v1"
DERIVED_TABLES = (
    "blocks", "transactions", "tx_outputs", "address_events",
    "tx_details", "genesis_allocations",
)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise IntegrityError(f"duplicate JSON key in derivation report: {key}")
        result[key] = value
    return result


def _read_report(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise SourceError("derivation report is missing or linked")
    try:
        result = json.loads(path.read_text("utf-8"), object_pairs_hook=_unique_object)
    except (OSError, UnicodeError, ValueError) as error:
        raise SourceError("could not read a valid derivation report") from error
    # Both a direct library report and the CLI envelope are accepted.
    if isinstance(result, dict) and isinstance(result.get("result"), dict):
        result = result["result"]
    if not isinstance(result, dict) or result.get("schema") != "qrl-v1-sqlite-v1":
        raise IntegrityError("derivation report has the wrong schema")
    return result


def _check_report(report: dict, anchors: dict, file: Path, *, balances: bool) -> None:
    if report.get("anchors") != anchors:
        raise IntegrityError("derivation report anchors differ")
    if (report.get("structural_verified") is not True
            or report.get("sqlite_integrity_verified") is not True
            or report.get("release_ready") is not False
            or report.get("consensus_replayed") is not False
            or report.get("balances_imported_from_native_state") is not balances):
        raise IntegrityError("derivation report has an invalid verification status")
    if balances and (not isinstance(report.get("native_account_count"), int)
                     or report["native_account_count"] < 1):
        raise IntegrityError("native-state derivative has no account rows")
    if not balances and report.get("native_account_count") != 0:
        raise IntegrityError("canonical-only derivative has account rows")
    if _file_digests(file) != report.get("file"):
        raise IntegrityError("SQLite file digest differs from derivation report")


def certify_snapshot_sqlite(
    canonical: Path, native_partial: Path, canonical_partial: Path,
    native_report: Path, canonical_report: Path, independent_state_db: Path,
    output: Path, *, network_id: str, genesis_hash: str, fork_height: int,
    fork_hash: str, terminal_height: int, terminal_hash: str,
    independent_sources_attested: bool,
) -> dict:
    """Create an eligible live snapshot from two checked SQLite derivations.

    ``independent_sources_attested`` is an operator provenance assertion: the
    tool can compare state bytes, but cannot prove how two nodes were synced.
    """
    if independent_sources_attested is not True:
        raise UsageError("independent node provenance must be attested")
    if not output.name.endswith(".snapshot.sqlite"):
        raise UsageError("snapshot SQLite output must end in .snapshot.sqlite")
    if output.exists() or output.is_symlink():
        raise SourceError("snapshot SQLite output already exists")
    if not output.parent.is_dir():
        raise SourceError("snapshot SQLite output parent does not exist")
    for path in (native_partial, canonical_partial):
        if not path.name.endswith(".partial.sqlite") or path.is_symlink() or not path.is_file():
            raise SourceError("input must be an existing, unlinked partial SQLite file")
    if native_partial.resolve() == canonical_partial.resolve():
        raise UsageError("native and canonical-only derivatives must be separate")

    anchors = dict(network_id=network_id, genesis_hash=genesis_hash,
                   fork_height=fork_height, fork_hash=fork_hash,
                   terminal_height=terminal_height, terminal_hash=terminal_hash)
    native_result = _read_report(native_report)
    canonical_result = _read_report(canonical_report)
    _check_report(native_result, anchors, native_partial, balances=True)
    _check_report(canonical_result, anchors, canonical_partial, balances=False)
    for table in DERIVED_TABLES:
        if native_result.get("logical_tables", {}).get(table) != canonical_result.get("logical_tables", {}).get(table):
            raise IntegrityError(f"chain-derived SQLite rows differ: {table}")

    canonical_check = verify_archive(canonical, **anchors)
    if (canonical_check["block_count"] != native_result.get("block_count")
            or canonical_check["transaction_count"] != native_result.get("transaction_count")
            or canonical_check["block_count"] != canonical_result.get("block_count")
            or canonical_check["transaction_count"] != canonical_result.get("transaction_count")):
        raise IntegrityError("canonical record counts differ from SQLite derivation")

    descriptor, temporary = tempfile.mkstemp(prefix=".qrl-archive-snapshot-sqlite-",
                                              suffix=".sqlite", dir=output.parent)
    os.close(descriptor)
    stage = Path(temporary)
    try:
        shutil.copyfile(native_partial, stage)
        # Use the private copy for all later checks and metadata mutation; a
        # changing source cannot be certified between comparison and signing.
        _check_report(native_result, anchors, stage, balances=True)
        native_check = compare_sqlite_native_accounts(stage, independent_state_db, **anchors)
        if native_check["account_count"] != native_result["native_account_count"]:
            raise IntegrityError("independent account count differs from derivation")

        with closing(sqlite3.connect(stage)) as db:
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("PRAGMA synchronous=FULL")
            if db.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise IntegrityError("partial SQLite integrity check failed")
            meta = dict(db.execute("SELECT key,value FROM archive_meta"))
            if (meta.get("release_ready") != "false"
                    or meta.get("consensus_replayed") != "false"
                    or meta.get("balance_source") != "qrl-state-v3-anchored-not-replayed"
                    or meta.get("snapshot_eligible") not in (None, "false")):
                raise IntegrityError("partial SQLite metadata does not permit snapshot certification")
            for key, value in anchors.items():
                if meta.get(key) != str(value):
                    raise IntegrityError(f"partial SQLite {key} differs from expected anchor")
            new_meta = {
                "snapshot_eligible": "true",
                "snapshot_kind": "live-chain-point-in-time",
                "snapshot_canonical_verification": "structural-only",
                "snapshot_balance_label": "observed-at-cutoff-two-node-agreement",
                "snapshot_account_rows_sha256": native_check["rows_sha256"],
                "snapshot_account_rows_sha3_256": native_check["rows_sha3_256"],
                "snapshot_source_independence": "operator-attested",
            }
            db.executemany("INSERT OR REPLACE INTO archive_meta(key,value) VALUES (?,?)",
                           sorted(new_meta.items()))
            db.commit()
            if list(db.execute("PRAGMA foreign_key_check")):
                raise IntegrityError("snapshot SQLite foreign key check failed")
            if db.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise IntegrityError("snapshot SQLite integrity check failed")

        with closing(sqlite3.connect(f"file:{stage}?mode=ro", uri=True)) as readonly:
            meta = dict(readonly.execute("SELECT key,value FROM archive_meta"))
            if (meta.get("snapshot_eligible") != "true"
                    or meta.get("release_ready") != "false"
                    or meta.get("consensus_replayed") != "false"):
                raise IntegrityError("snapshot SQLite readiness flags changed")
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
            "schema": SCHEMA, "anchors": anchors, "file": file_digests,
            "canonical_structural_check": canonical_check,
            "chain_derived_tables_equal": True,
            "native_account_comparison": native_check,
            "native_partial_file": native_result["file"],
            "canonical_partial_file": canonical_result["file"],
            "snapshot_eligible": True, "snapshot_kind": "live-chain-point-in-time",
            "balances_observed_at_cutoff": True,
            "independent_sources_attested_by_operator": True,
            "consensus_replayed": False, "release_ready": False,
        }
    except sqlite3.Error as error:
        raise IntegrityError("snapshot SQLite certification failed a database invariant") from error
    finally:
        stage.unlink(missing_ok=True)
