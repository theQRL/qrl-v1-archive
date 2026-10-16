#!/usr/bin/env python3
"""Sign a reviewed native supplement with the pinned action v3 image.

"""

from __future__ import annotations

import argparse
import json
import os
import re
import resource
import sys
import tempfile
from pathlib import Path

from qrl_archive.snapshot_release import FIXED_QRLFT_COMMIT, KEY_SHA256, _build_fixed_qrlft, _digest
from native_recovery_release import verify_prepared, verify_signed
from sign_snapshot_v3 import (
    ACTION_COMMIT, IMAGE, OUTPUTS, SEED_NAME, SIGNER_QRLFT_COMMIT,
    _run_docker,
)


def sign(release: Path, review_file: Path, raw_byte_audit: Path,
         source_classification: Path, normalization_report: Path,
         restricted_report: Path,
         trusted_key: Path, qrlft_repo: Path,
         seed_name: str = SEED_NAME, docker: str = "docker") -> dict:
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if re.fullmatch(r"[A-Z][A-Z0-9_]*", seed_name) is None:
        raise RuntimeError("seed environment variable name is invalid")
    seed = os.environ.pop(seed_name, "")
    if re.fullmatch(r"(?:0[xX])?[0-9a-fA-F]{64}", seed) is None:
        raise RuntimeError("approved signing seed is absent or malformed")
    if any((release / name).exists() or (release / name).is_symlink() for name in OUTPUTS):
        raise RuntimeError("signing outputs already exist; use a fresh prepared release")
    if _digest(trusted_key)[1] != KEY_SHA256:
        raise RuntimeError("trusted public key differs from pinned theQRL/security key")
    checked = verify_prepared(release, review_path=review_file,
                              raw_audit_path=raw_byte_audit,
                              classification_path=source_classification,
                              normalization_report_path=normalization_report,
                              restricted_path=restricted_report)
    if checked["prepared_verified"] is not True or checked["signed_verified"] is not False:
        raise RuntimeError("native supplement is not an eligible unsigned candidate")
    release = release.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix=".qrl-native-sign-", dir=release.parent) as directory:
        output = Path(directory)
        _run_docker(docker, release, output, checked["tag"], seed, seed_name)
        seed = ""
        if {path.name for path in output.iterdir()} != set(OUTPUTS):
            raise RuntimeError("signer output differs from the pinned v3 contract")
        if any((output / name).is_symlink() or not (output / name).is_file()
               for name in OUTPUTS):
            raise RuntimeError("signer output is missing or linked")
        verification_payload = output / "payload"
        verification_payload.mkdir()
        for path in (release / "payload").iterdir():
            os.link(path, verification_payload / path.name)
        with tempfile.TemporaryDirectory(prefix="qrl-independent-native-verifier-") as scratch:
            qrlft = _build_fixed_qrlft(qrlft_repo, Path(scratch),
                                       commit=FIXED_QRLFT_COMMIT)
            verified = verify_signed(output, trusted_key, qrlft,
                                     review_path=review_file,
                                     raw_audit_path=raw_byte_audit,
                                     classification_path=source_classification,
                                     normalization_report_path=normalization_report)
        if verified["signed_verified"] is not True:
            raise RuntimeError("independent native supplement verification failed")
        signed_hashes = {name: _digest(output / name)[1] for name in OUTPUTS}
        placed: list[str] = []
        try:
            for name in OUTPUTS:
                os.link(output / name, release / name)
                placed.append(name)
            if any(_digest(release / name)[1] != signed_hashes[name] for name in OUTPUTS):
                raise RuntimeError("signed output changed during placement")
        except Exception:
            for name in placed:
                (release / name).unlink(missing_ok=True)
            raise
        verified.update({
            "action_source_commit": ACTION_COMMIT,
            "signer_qrlft_source_commit": SIGNER_QRLFT_COMMIT,
            "independent_verifier_source_commit": FIXED_QRLFT_COMMIT,
            "docker_image_digest": IMAGE.split("@", 1)[1],
            "seed_transport": "stdin_pipe_to_disposable_container",
        })
        return verified


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("release", type=Path)
    parser.add_argument("--review-file", type=Path, required=True)
    parser.add_argument("--raw-byte-audit", type=Path, required=True)
    parser.add_argument("--source-classification", type=Path, required=True)
    parser.add_argument("--normalization-report", type=Path, required=True)
    parser.add_argument("--restricted-report", type=Path, required=True)
    parser.add_argument("--trusted-key", type=Path, required=True)
    parser.add_argument("--qrlft-repo", type=Path, required=True)
    parser.add_argument("--seed-env", default=SEED_NAME)
    parser.add_argument("--docker", default="docker")
    args = parser.parse_args()
    try:
        result = sign(args.release, args.review_file, args.raw_byte_audit,
                      args.source_classification, args.normalization_report,
                      args.restricted_report,
                      args.trusted_key,
                      args.qrlft_repo, args.seed_env, args.docker)
        print(json.dumps(result, sort_keys=True))
        return 0
    except Exception as error:
        print(f"native supplement signing: {error}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
