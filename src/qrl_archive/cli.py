"""CLI for exact-byte export and structural verification of QRL v1 blocks."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .block_stream_v1 import MAX_BLOCKS_PER_SHARD, MAX_SHARD_BYTES, export_source, verify_archive
from .comparison import compare_archives
from .errors import ArchiveError, DisagreementError, IntegrityError, SourceError
from .native_state import compare_native_state
from .protobuf_schema import schema_fingerprints
from .source import LevelDBSource
from .sqlite_v1 import derive_sqlite


def _report_path(value: str) -> Path:
    return Path(value).expanduser()


def _atomic_report(path: Path, report: dict) -> None:
    if not path.parent.is_dir():
        raise SourceError("report parent directory does not exist")
    contents = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"
    descriptor, temporary = tempfile.mkstemp(prefix=".qrl-archive-report-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        # Hard-linking a fully fsynced temporary file creates the final name
        # atomically and refuses to replace an earlier evidence report.
        os.link(temporary, path)
        os.unlink(temporary)
        parent_descriptor = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="qrl-archive", description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    inspect = subparsers.add_parser("inspect", help="inspect a stopped LevelDB working copy")
    inspect.add_argument("--source-db", "--db", type=Path, required=True)
    inspect.add_argument("--network-id", required=True, help="operator-declared network ID; not inferred from DB")
    inspect.add_argument("--expect-genesis-hash", help="known genesis hash, 64 lowercase hex characters")
    inspect.add_argument("--json-report", type=_report_path)

    export = subparsers.add_parser("export", help="export exact stored protobuf bytes")
    export.add_argument("--source-db", "--db", type=Path, required=True)
    export.add_argument("--network-id", required=True)
    export.add_argument("--genesis-hash", required=True)
    export.add_argument("--fork-height", type=int, required=True)
    export.add_argument("--fork-hash", required=True)
    export.add_argument("--terminal-height", type=int, required=True)
    export.add_argument("--terminal-hash", required=True)
    export.add_argument("--run-id", required=True)
    export.add_argument("--output", "--out", type=Path, required=True)
    export.add_argument("--max-blocks-per-shard", type=int, default=MAX_BLOCKS_PER_SHARD)
    export.add_argument("--max-shard-bytes", type=int, default=MAX_SHARD_BYTES)
    export.add_argument("--json-report", type=_report_path)

    verify = subparsers.add_parser("verify", help="verify canonical shard structure and dual digests")
    verify.add_argument("--canonical", type=Path, required=True)
    verify.add_argument("--expect-network-id", required=True)
    verify.add_argument("--expect-genesis-hash", required=True)
    verify.add_argument("--expect-fork-height", type=int, required=True)
    verify.add_argument("--expect-fork-hash", required=True)
    verify.add_argument("--expect-terminal-height", type=int, required=True)
    verify.add_argument("--expect-terminal-hash", required=True)
    verify.add_argument("--mode", choices=("structural", "consensus", "full"), default="structural")
    verify.add_argument("--json-report", type=_report_path)

    compare = subparsers.add_parser("compare", help="verify two exports and compare exact stored block bytes")
    compare.add_argument("--canonical-a", type=Path, required=True)
    compare.add_argument("--canonical-b", type=Path, required=True)
    compare.add_argument("--expect-network-id", required=True)
    compare.add_argument("--expect-genesis-hash", required=True)
    compare.add_argument("--expect-fork-height", type=int, required=True)
    compare.add_argument("--expect-fork-hash", required=True)
    compare.add_argument("--expect-terminal-height", type=int, required=True)
    compare.add_argument("--expect-terminal-hash", required=True)
    compare.add_argument("--json-report", type=_report_path)

    native = subparsers.add_parser("compare-native-state", help="compare exact v3 native state records from two stopped working copies")
    native.add_argument("--source-db-a", type=Path, required=True)
    native.add_argument("--source-db-b", type=Path, required=True)
    native.add_argument("--expect-network-id", required=True)
    native.add_argument("--expect-genesis-hash", required=True)
    native.add_argument("--expect-fork-height", type=int, required=True)
    native.add_argument("--expect-fork-hash", required=True)
    native.add_argument("--expect-terminal-height", type=int, required=True)
    native.add_argument("--expect-terminal-hash", required=True)
    native.add_argument("--json-report", type=_report_path)

    derive = subparsers.add_parser("derive-sqlite", help="build an inspectable, incomplete SQLite v1 derivative")
    derive.add_argument("--canonical", type=Path, required=True)
    derive.add_argument("--expect-network-id", required=True)
    derive.add_argument("--expect-genesis-hash", required=True)
    derive.add_argument("--expect-fork-height", type=int, required=True)
    derive.add_argument("--expect-fork-hash", required=True)
    derive.add_argument("--expect-terminal-height", type=int, required=True)
    derive.add_argument("--expect-terminal-hash", required=True)
    derive.add_argument("--source-db", type=Path,
                        help="optional stopped state-v3 working copy for comparison balances")
    derive.add_argument("--output", type=Path, required=True)
    derive.add_argument("--json-report", type=_report_path)
    return parser


def _execute(args) -> dict:
    if args.command == "inspect":
        with LevelDBSource(args.source_db) as source:
            result = source.inspect()
            source.finish_read()
        result["source_leveldb_file_churn_observed"] = source.data_files_changed_during_read
        if args.expect_genesis_hash and result["genesis_hash"] != args.expect_genesis_hash:
            raise IntegrityError("source genesis hash differs from expectation")
        result["network_id_claim"] = args.network_id
        result["network_id_proven_by_db"] = False
        return result
    if args.command == "export":
        with LevelDBSource(args.source_db) as source:
            index = export_source(
                source, args.output,
                network_id=args.network_id,
                genesis_hash=args.genesis_hash,
                fork_height=args.fork_height,
                fork_hash=args.fork_hash,
                terminal_height=args.terminal_height,
                terminal_hash=args.terminal_hash,
                run_id=args.run_id,
                max_blocks=args.max_blocks_per_shard,
                max_bytes=args.max_shard_bytes,
            )
        return {
            "block_count": index["block_count"],
            "transaction_count": index["transaction_count"],
            "shard_count": len(index["shards"]),
            "terminal_hash": index["terminal_hash"],
            "structural_verified": True,
            "consensus_verified": False,
            "native_final_state_verified": False,
            "derived_data_verified": False,
            "source_leveldb_file_churn_observed": source.data_files_changed_during_read,
        }
    if args.command == "compare":
        return compare_archives(
            args.canonical_a, args.canonical_b,
            network_id=args.expect_network_id,
            genesis_hash=args.expect_genesis_hash,
            fork_height=args.expect_fork_height,
            fork_hash=args.expect_fork_hash,
            terminal_height=args.expect_terminal_height,
            terminal_hash=args.expect_terminal_hash,
        )
    if args.command == "compare-native-state":
        return compare_native_state(
            args.source_db_a, args.source_db_b,
            network_id=args.expect_network_id,
            genesis_hash=args.expect_genesis_hash,
            fork_height=args.expect_fork_height,
            fork_hash=args.expect_fork_hash,
            terminal_height=args.expect_terminal_height,
            terminal_hash=args.expect_terminal_hash,
        )
    if args.command == "derive-sqlite":
        return derive_sqlite(
            args.canonical, args.output,
            network_id=args.expect_network_id,
            genesis_hash=args.expect_genesis_hash,
            fork_height=args.expect_fork_height,
            fork_hash=args.expect_fork_hash,
            terminal_height=args.expect_terminal_height,
            terminal_hash=args.expect_terminal_hash,
            source_db=args.source_db,
        )
    if args.mode != "structural":
        raise IntegrityError("consensus and full verification are not implemented")
    return verify_archive(
        args.canonical,
        network_id=args.expect_network_id,
        genesis_hash=args.expect_genesis_hash,
        fork_height=args.expect_fork_height,
        fork_hash=args.expect_fork_hash,
        terminal_height=args.expect_terminal_height,
        terminal_hash=args.expect_terminal_hash,
    )


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    report = {
        "schema": "qrl.v1.archive.report.v1",
        "tool": "qrl-archive",
        "tool_version": __version__,
        "command": args.command,
    }
    # Comparison reports are byte-for-byte reproducible for unchanged inputs.
    if args.command not in {"compare", "compare-native-state"}:
        report["started_at_utc"] = datetime.now(timezone.utc).isoformat()
    try:
        report.update(schema_fingerprints())
        result = _execute(args)
        if args.command == "derive-sqlite":
            code = 4
            report.update(status="INCOMPLETE", exit_code=code, result=result,
                          error={"class": "ReleaseReadinessError",
                                 "message": "SQLite was built and checked, but canonical consensus replay and final-state derivation are missing"})
        else:
            report.update(status="PASS", exit_code=0, result=result)
            code = 0
    except DisagreementError as error:
        code = error.exit_code
        report.update(status="FAIL", exit_code=code,
                      error={"class": type(error).__name__, "message": str(error)})
        if hasattr(error, "result"):
            report["result"] = error.result
    except ArchiveError as error:
        code = error.exit_code
        report.update(status="FAIL", exit_code=code,
                      error={"class": type(error).__name__, "message": str(error)})
    except OSError as error:
        code = 3
        report.update(status="FAIL", exit_code=code,
                      error={"class": "SourceError", "message": type(error).__name__})
    except Exception:
        code = 4
        report.update(status="FAIL", exit_code=code,
                      error={"class": "InternalError", "message": "unexpected tool error"})
    if args.command not in {"compare", "compare-native-state"}:
        report["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
    if args.json_report is not None:
        try:
            _atomic_report(args.json_report, report)
        except (OSError, ArchiveError):
            print("FAIL: could not write JSON report", file=sys.stderr)
            return 3
    if code:
        print(f"FAIL ({code}): {report['error']['message']}", file=sys.stderr)
    elif args.command == "compare":
        print("PASS: exact stored block bytes match; both exports passed structural verification")
    elif args.command == "compare-native-state":
        print("PASS: exact native state records match; consensus replay has not been verified")
    else:
        print(f"PASS: {args.command} completed; structural checks only")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
