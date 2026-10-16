"""Sign a 64 MiB throwaway part with the fixed qrlft reader and v2 format."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import subprocess
import tarfile
import tempfile
from pathlib import Path

import signer_fixture as fixture


PART_BYTES = 64 * 1024 * 1024


def _write_part(path: Path) -> None:
    chunk = b"QRL snapshot full-read fixture.\n".ljust(1024 * 1024, b"x")
    with path.open("wb") as stream:
        for _ in range(64):
            stream.write(chunk)
        stream.seek(PART_BYTES - 4)
        stream.write(b"TAIL")
        stream.flush()
        os.fsync(stream.fileno())
    if path.stat().st_size != PART_BYTES:
        raise RuntimeError("large fixture part has the wrong size")


def exercise(action_repo: Path, qrlft_repo: Path) -> dict:
    checks: dict[str, bool] = {}
    with tempfile.TemporaryDirectory(prefix="qrl-snapshot-large-sign-fixture-") as directory:
        work = Path(directory)
        revision = fixture.run("git", "rev-parse", "v2^{}", cwd=action_repo).stdout.strip()
        if revision != fixture.ACTION_COMMIT:
            raise RuntimeError("local action v2 tag differs from reviewed fixture pin")
        action_source = work / "action-v2-source"
        action_source.mkdir()
        archived = subprocess.run(("git", "archive", fixture.ACTION_COMMIT),
                                  cwd=action_repo, capture_output=True, check=True)
        with tarfile.open(fileobj=io.BytesIO(archived.stdout)) as contents:
            contents.extractall(action_source, filter="data")
        old = fixture.build_qrlft(qrlft_repo, work, fixture.QRLFT_COMMIT, "qrlft-keygen")
        fixed = fixture.build_qrlft(qrlft_repo, work, fixture.FIXED_QRLFT_COMMIT,
                                    "qrlft-full-read")
        seed, key = fixture.temporary_key(old, work, "throwaway-key")
        payload = work / "payload"
        payload.mkdir()
        part = payload / "max-size-test.qrlblk"
        _write_part(part)
        notice = payload / "NOTICE.txt"
        notice.write_text("Synthetic data signed by a disposable key. No release.\n")
        original_sha256 = hashlib.sha256(part.read_bytes()).hexdigest()
        manifest = work / "manifest.json"
        signatures_file = work / "signatures.txt"
        env = os.environ.copy()
        env["QRLFT"] = str(fixed)
        fixture.run(
            str(action_source / "entrypoint.sh"), seed, fixture.ARTIFACT_CONTEXT,
            str(signatures_file), "payload/*", fixture.PRODUCT,
            "fixture-max-part-no-release", str(manifest), fixture.MANIFEST_CONTEXT,
            cwd=work, env=env, secret_args=True,
        )
        seed = ""
        signatures = {}
        for line in signatures_file.read_text().splitlines():
            signature, separator, path = line.partition(" ")
            fixture.require(bool(separator) and path not in signatures,
                            "signature-list framing", checks)
            signatures[path] = signature
        fixture.require(set(signatures) == {"payload/max-size-test.qrlblk", "payload/NOTICE.txt"},
                        "both artifacts signed", checks)
        document = json.loads(manifest.read_text())
        fixture.require(document == {
            "schema": "theqrl.release-manifest.v1",
            "product": fixture.PRODUCT,
            "tag": "fixture-max-part-no-release",
            "context": fixture.ARTIFACT_CONTEXT,
            "artifacts": [
                {"filename": "NOTICE.txt", "size": notice.stat().st_size,
                 "sha256": hashlib.sha256(notice.read_bytes()).hexdigest()},
                {"filename": part.name, "size": PART_BYTES, "sha256": original_sha256},
            ],
        }, "exact v2 manifest and full-part SHA-256", checks)
        fixture.require(fixture.verifies(fixed, manifest, key, fixture.MANIFEST_CONTEXT,
                                         sigfile=Path(str(manifest) + ".sig")),
                        "manifest verifies under separate context", checks)
        signature = signatures["payload/max-size-test.qrlblk"]
        fixture.require(fixture.verifies(fixed, part, key, fixture.ARTIFACT_CONTEXT,
                                         signature=signature),
                        "full part verifies", checks)
        with part.open("r+b") as stream:
            stream.seek(-1, os.SEEK_END)
            last = stream.read(1)
            stream.seek(-1, os.SEEK_END)
            stream.write(bytes([last[0] ^ 1]))
            stream.flush()
            os.fsync(stream.fileno())
        fixture.require(hashlib.sha256(part.read_bytes()).hexdigest() != original_sha256,
                        "final-byte mutation changes full digest", checks)
        fixture.require(not fixture.verifies(fixed, part, key, fixture.ARTIFACT_CONTEXT,
                                             signature=signature),
                        "final-byte mutation rejects artifact signature", checks)
    return {
        "schema": "qrl.v1.archive.large-part-signer-fixture.v1",
        "status": "PASS",
        "part_bytes": PART_BYTES,
        "action_commit": fixture.ACTION_COMMIT,
        "fixed_qrlft_commit": fixture.FIXED_QRLFT_COMMIT,
        "action_image_tested": False,
        "organization_key_used": False,
        "checks": checks,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--action-repo", type=Path,
                        default=Path.home() / "actions-mldsa-sign")
    parser.add_argument("--qrlft-repo", type=Path, default=Path.home() / "qrlft")
    args = parser.parse_args()
    print(json.dumps(exercise(args.action_repo, args.qrlft_repo), sort_keys=True))


if __name__ == "__main__":
    main()
