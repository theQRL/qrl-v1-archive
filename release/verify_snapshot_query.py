#!/usr/bin/env python3
"""Freshly compare packaged query bytes with reconstructed snapshot SQLite.

Use after verify-signed on both the local release and a clean public download.
The explorer repository's independent verifier is supplied explicitly.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from qrl_archive.snapshot_release import (
    DERIVED_INVENTORY_SCHEMA,
    _read_json,
    verify_prepared,
)


def run(release: Path, verifier: Path, report: Path) -> dict:
    if report.exists() or not report.parent.is_dir():
        raise RuntimeError("fresh report path must not exist")
    verified = verify_prepared(release)
    if (verified["schema"] != DERIVED_INVENTORY_SCHEMA
            or verified["derived_verified"] is not True
            or verified["snapshot_eligible"] is not True):
        raise RuntimeError("release is not an eligible derived snapshot")
    if verifier.is_symlink() or not verifier.is_file():
        raise RuntimeError("independent query verifier is missing or linked")
    verifier_hash = hashlib.sha256(verifier.read_bytes()).hexdigest()
    payload = release / "payload"
    _, inventory = _read_json(payload / "archive-inventory.json")
    signed_report_name = inventory["derived"]["query_packs"]["verification_report"]
    _, expected = _read_json(payload / signed_report_name)
    with tempfile.TemporaryDirectory(prefix="qrl-snapshot-query-check-",
                                     dir=release.parent) as temporary:
        work = Path(temporary)
        sqlite = work / "snapshot.sqlite"
        with sqlite.open("wb") as target:
            for item in inventory["derived"]["sqlite"]["parts"]:
                with (payload / item["filename"]).open("rb") as source:
                    shutil.copyfileobj(source, target, length=1024 * 1024)
        query = work / "query"
        query.mkdir()
        for item in inventory["payloads"]:
            if item["role"] not in {"query_pack", "query_pack_index"}:
                continue
            object_path = item["object_path"]
            if not object_path.startswith("query/"):
                raise RuntimeError("query public path differs from inventory layout")
            target = work / object_path
            target.parent.mkdir(parents=True, exist_ok=True)
            os.link(payload / item["filename"], target)
        fresh_report = work / "fresh-query-report.json"
        checked = subprocess.run(
            (sys.executable, str(verifier.resolve()), "--sqlite", str(sqlite),
             "--packs", str(query), "--report", str(fresh_report)),
            cwd=work, capture_output=True, text=True, check=False,
        )
        if checked.returncode:
            raise RuntimeError("fresh packaged-query logical comparison failed")
        _, fresh = _read_json(fresh_report)
        if fresh != expected:
            raise RuntimeError("fresh packaged-query result differs from signed PASS report")
        result = {
            "schema": "qrl.v1.archive.packaged-query-check.v1",
            "status": "PASS", "tag": verified["tag"],
            "height": verified["height"], "hash": verified["hash"],
            "inventory_sha256": hashlib.sha256(
                (payload / "archive-inventory.json").read_bytes()).hexdigest(),
            "explorer_verifier_sha256": verifier_hash,
            "sqlite_reassembled_verified": True,
            "query_logical_comparison_freshly_rerun": True,
            "query_report_sha256": hashlib.sha256(fresh_report.read_bytes()).hexdigest(),
            "file_count": fresh["file_count"],
            "total_bytes": fresh["total_bytes"],
        }
        with report.open("x", encoding="utf-8") as output:
            json.dump(result, output, sort_keys=True, separators=(",", ":"))
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("release", type=Path)
    parser.add_argument("--explorer-verifier", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.release, args.explorer_verifier,
                             args.report), sort_keys=True))
        return 0
    except Exception as error:
        print(f"snapshot query check: {error}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
