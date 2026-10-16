"""Exercise the v2 signer contract with a disposable ML-DSA-87 key.

This is a tool fixture, not a QRL release or proof of access to its release key.
It builds the qrlft commit pinned by actions-mldsa-sign v2 and runs that
action's entry point locally. No network or production secret is required.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import subprocess
import tarfile
import tempfile
from pathlib import Path


ACTION_COMMIT = "266287af83f2b1a8ec4c6e13149d0ecf6cd16cc5"
QRLFT_COMMIT = "edc20365292418f65865c831f3d1364e62e34801"
FIXED_QRLFT_COMMIT = "ed1f29f3e4743ba2f1429154ae31549c37e3a357"
PRODUCT = "qrl-v1-testnet-archive"
TAG = "fixture-no-release-v1"
ARTIFACT_CONTEXT = PRODUCT + "-release-signatures"
MANIFEST_CONTEXT = PRODUCT + "-release-manifest"
NOTICE = "REHEARSAL-NOTICE.md"
PART = "synthetic-blocks-0000000000.part"


def run(*args: str, cwd: Path, env: dict[str, str] | None = None,
        secret_args: bool = False) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        args, cwd=cwd, env=env, text=True, capture_output=True, check=False
    )
    if result.returncode:
        # Keep the raw seed and action output out of logs. Other commands may
        # reveal useful build diagnostics without containing a seed argument.
        detail = "" if secret_args else f": {result.stderr.strip() or result.stdout.strip()}"
        raise RuntimeError(f"fixture command failed with exit code {result.returncode}{detail}")
    return result


def git_text(repo: Path, revision_path: str) -> str:
    return run("git", "show", revision_path, cwd=repo).stdout


def check_action_source(action_repo: Path) -> None:
    revision = run("git", "rev-parse", "v2^{}", cwd=action_repo).stdout.strip()
    if revision != ACTION_COMMIT:
        raise RuntimeError("local action v2 tag differs from the reviewed fixture pin")
    dockerfile = git_text(action_repo, f"{ACTION_COMMIT}:Dockerfile")
    if f"ARG QRLFT_COMMIT={QRLFT_COMMIT}" not in dockerfile:
        raise RuntimeError("action v2 pins a different qrlft commit")
    action = git_text(action_repo, f"{ACTION_COMMIT}:action.yml")
    if "image: docker://ghcr.io/theqrl/actions-mldsa-sign:v2.0.0" not in action:
        raise RuntimeError("action v2 image reference changed")


def pinned_reader_issue(qrlft_repo: Path) -> bool:
    """Report the known single-Read bug in the exact bundled qrlft source."""
    files = ("sign/sign.go", "verify/verify.go")
    return any(
        "file.Read(buffer)" in git_text(qrlft_repo, f"{QRLFT_COMMIT}:{name}")
        for name in files
    )


def build_qrlft(qrlft_repo: Path, work: Path, commit: str, name: str) -> Path:
    if run("git", "cat-file", "-t", commit, cwd=qrlft_repo).stdout.strip() != "commit":
        raise RuntimeError("requested qrlft commit is absent from the local repository")
    source = work / f"{name}-source"
    source.mkdir()
    archive = subprocess.run(
        ("git", "archive", commit), cwd=qrlft_repo, capture_output=True, check=True
    ).stdout
    with tarfile.open(fileobj=io.BytesIO(archive)) as contents:
        contents.extractall(source, filter="data")
    binary = work / name
    env = os.environ.copy()
    env["GOCACHE"] = str(work / "go-cache")
    env["GOPROXY"] = "off"
    env["GOSUMDB"] = "off"
    run("go", "build", "-o", str(binary), ".", cwd=source, env=env)
    return binary


def build_pinned_qrlft(qrlft_repo: Path, work: Path) -> Path:
    return build_qrlft(qrlft_repo, work, QRLFT_COMMIT, "qrlft-pinned-v2")


def temporary_key(qrlft: Path, work: Path, name: str) -> tuple[str, Path]:
    prefix = work / name
    run(str(qrlft), "new", "-a", "mldsa", f"--context={ARTIFACT_CONTEXT}", str(prefix), cwd=work)
    seed_file = Path(str(prefix) + ".private.hexseed")
    lines = seed_file.read_text().splitlines()
    if len(lines) != 3 or "PRIVATE HEXSEED" not in lines[0]:
        raise RuntimeError("pinned qrlft emitted an unexpected hexseed file format")
    seed = lines[1].removeprefix("0x")
    if re.fullmatch(r"[0-9a-fA-F]{64}", seed) is None:
        raise RuntimeError("pinned qrlft emitted an invalid raw test seed")
    return seed, Path(str(prefix) + ".pub")


def verifies(qrlft: Path, file: Path, key: Path, context: str, *, signature: str | None = None,
             sigfile: Path | None = None) -> bool:
    option = f"--signature={signature}" if signature is not None else f"--sigfile={sigfile}"
    result = subprocess.run(
        (str(qrlft), "verify", "-a", "mldsa", f"--context={context}", option,
         f"--pkfile={key}", str(file)),
        cwd=file.parent, capture_output=True, text=True, check=False,
    )
    return result.returncode == 0


def require(condition: bool, label: str, checks: dict[str, bool]) -> None:
    checks[label] = condition
    if not condition:
        raise AssertionError(f"signer fixture failed: {label}")


def exercise(action_repo: Path, qrlft_repo: Path) -> dict[str, object]:
    check_action_source(action_repo)
    reader_issue = pinned_reader_issue(qrlft_repo)
    checks: dict[str, bool] = {}
    with tempfile.TemporaryDirectory(prefix="qrl-archive-signer-fixture-") as temp:
        work = Path(temp)
        action_source = work / "action-v2-source"
        action_source.mkdir()
        action_archive = subprocess.run(
            ("git", "archive", ACTION_COMMIT), cwd=action_repo,
            capture_output=True, check=True,
        ).stdout
        with tarfile.open(fileobj=io.BytesIO(action_archive)) as contents:
            contents.extractall(action_source, filter="data")
        qrlft = build_pinned_qrlft(qrlft_repo, work)
        seed, key = temporary_key(qrlft, work, "test-key")
        _, wrong_key = temporary_key(qrlft, work, "wrong-test-key")
        payload = work / "payload"
        payload.mkdir()
        notice = payload / NOTICE
        notice.write_text(
            "TEST-ONLY signing fixture. No chain data or QRL release.\n",
            encoding="utf-8",
        )
        part = payload / PART
        part.write_bytes(b"QRL signing fixture, synthetic data only.\n" + b"a" * 65536 + b"TAIL\n")
        signatures_file = work / "fixture-signatures.txt"
        manifest = work / "fixture-manifest.json"
        env = os.environ.copy()
        env["QRLFT"] = str(qrlft)
        # action v2 accepts eight ordered inputs. The raw seed is disposable;
        # neither the command nor its output is printed or saved.
        run(
            str(action_source / "entrypoint.sh"), seed, ARTIFACT_CONTEXT,
            str(signatures_file), "payload/*", PRODUCT, TAG, str(manifest),
            MANIFEST_CONTEXT, cwd=work, env=env, secret_args=True,
        )
        seed = ""  # Drop the Python reference as soon as signing finishes.

        expected_paths = {f"payload/{NOTICE}": notice, f"payload/{PART}": part}
        signatures: dict[str, str] = {}
        for line in signatures_file.read_text().splitlines():
            signature, separator, path = line.partition(" ")
            require(bool(separator) and path not in signatures and path in expected_paths,
                    "signature list paths", checks)
            require(re.fullmatch(r"[0-9a-fA-F]{9254}", signature) is not None,
                    "ML-DSA-87 signature length", checks)
            signatures[path] = signature
        require(set(signatures) == set(expected_paths), "all artifact signatures present", checks)

        document = json.loads(manifest.read_text())
        require(set(document) == {"schema", "product", "tag", "context", "artifacts"},
                "exact action manifest fields", checks)
        require((document["schema"], document["product"], document["tag"], document["context"])
                == ("theqrl.release-manifest.v1", PRODUCT, TAG, ARTIFACT_CONTEXT),
                "manifest release identity", checks)
        expected_entries = [
            {"filename": file.name, "size": file.stat().st_size,
             "sha256": hashlib.sha256(file.read_bytes()).hexdigest()}
            for file in expected_paths.values()
        ]
        expected_entries.sort(key=lambda entry: entry["filename"])
        require(document["artifacts"] == expected_entries,
                "manifest binds full artifact bytes and sorted basenames", checks)

        manifest_signature = Path(str(manifest) + ".sig")
        require(verifies(qrlft, manifest, key, MANIFEST_CONTEXT,
                         sigfile=manifest_signature), "manifest signature", checks)
        for path, file in expected_paths.items():
            require(verifies(qrlft, file, key, ARTIFACT_CONTEXT,
                             signature=signatures[path]), f"artifact signature {file.name}", checks)

        tampered_part = work / "tampered.part"
        changed = bytearray(part.read_bytes())
        changed[-1] ^= 1
        tampered_part.write_bytes(changed)
        require(not verifies(qrlft, tampered_part, key, ARTIFACT_CONTEXT,
                             signature=signatures[f"payload/{PART}"]),
                "artifact tail mutation rejected", checks)

        altered_manifest = work / "altered-manifest.json"
        altered = manifest.read_bytes()
        altered_manifest.write_bytes(altered[:-2] + bytes((altered[-2] ^ 1,)) + altered[-1:])
        require(not verifies(qrlft, altered_manifest, key, MANIFEST_CONTEXT,
                             sigfile=manifest_signature), "manifest mutation rejected", checks)
        wrong_tag_manifest = work / "wrong-tag-manifest.json"
        wrong_tag_manifest.write_bytes(manifest.read_bytes().replace(
            TAG.encode(), b"fixture-no-release-v2"
        ))
        require(not verifies(qrlft, wrong_tag_manifest, key, MANIFEST_CONTEXT,
                             sigfile=manifest_signature), "tag mutation rejected", checks)
        require(not verifies(qrlft, manifest, wrong_key, MANIFEST_CONTEXT,
                             sigfile=manifest_signature), "wrong key rejected", checks)
        require(not verifies(qrlft, part, key, MANIFEST_CONTEXT,
                             signature=signatures[f"payload/{PART}"]),
                "wrong artifact context rejected", checks)
        require(not verifies(qrlft, manifest, key, ARTIFACT_CONTEXT,
                             sigfile=manifest_signature),
                "wrong manifest context rejected", checks)

    return {
        "schema": "qrl.v1.archive.signer-fixture.v1",
        "tool_fixture": "PASS",
        "release_readiness": "FAIL" if reader_issue else "UNASSESSED",
        "release_readiness_reason": (
            "actions-mldsa-sign v2.0.0 pins qrlft v4.0.0, whose sign and verify "
            "readFile functions each make one Read call; a short read can omit an "
            "artifact tail. This small-file fixture does not certify archive-sized parts."
            if reader_issue else "This fixture does not certify deployment or key custody."
        ),
        "action_commit": ACTION_COMMIT,
        "qrlft_commit": QRLFT_COMMIT,
        "action_image_tested": False,
        "org_key_used": False,
        "checks": checks,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--action-repo", type=Path, default=Path.home() / "actions-mldsa-sign")
    parser.add_argument("--qrlft-repo", type=Path, default=Path.home() / "qrlft")
    parser.add_argument("--smoke-only", action="store_true",
                        help="exit zero when the throwaway-key checks pass, despite the release blocker")
    args = parser.parse_args()
    report = exercise(args.action_repo, args.qrlft_repo)
    print(json.dumps(report, sort_keys=True))
    return 0 if args.smoke_only else 2 if report["release_readiness"] == "FAIL" else 0


if __name__ == "__main__":
    raise SystemExit(main())
