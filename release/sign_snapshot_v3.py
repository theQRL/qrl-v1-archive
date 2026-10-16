#!/usr/bin/env python3
"""Sign a prepared snapshot using an immutable v3 image and stdin-only ingress.

The caller supplies a 1Password secret reference to ``op run``. This process
removes the resolved seed from its environment before it starts Docker. Docker
receives the seed only over stdin, never in its command or container config.
The v3 action still passes the seed in argv *inside* the container. Run only
on an approved isolated host. This file never retrieves the organization key.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import resource
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

from qrl_archive.snapshot_release import (
    ARTIFACT_CONTEXT,
    DERIVED_INVENTORY_SCHEMA,
    FIXED_QRLFT_COMMIT,
    KEY_SHA256,
    MANIFEST_CONTEXT,
    PRODUCT,
    _build_fixed_qrlft,
    _digest,
    verify_prepared,
    verify_signed,
)


IMAGE = ("ghcr.io/theqrl/actions-mldsa-sign@sha256:"
         "65a6059d2b9c3a706b8560162ccf2d07ca39e1fb5074ff3bdfe9291889ee1afd")
ACTION_COMMIT = "4d9a45b39b989ea244c88fc217fcda794ae94026"
SIGNER_QRLFT_COMMIT = "9cf05342e9aeb175fb336a6985da579302b1ca36"
OUTPUTS = ("signatures.txt", "manifest.json", "manifest.json.sig")
SEED_NAME = "QRL_RELEASE_MLDSA_SEED"
CONTAINER_SCRIPT = r"""
set +x
set -euo pipefail
umask 077
IFS= read -r hexseed
[[ "$hexseed" =~ ^(0[xX])?[[:xdigit:]]{64}$ ]] || exit 72
exec /qrlft/entrypoint.sh "$hexseed" "$@"
"""


def _docker_environment(seed_name: str) -> dict[str, str]:
    allowed = ("PATH", "HOME", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG",
               "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY", "XDG_RUNTIME_DIR",
               "TMPDIR", "LANG", "LC_ALL")
    return {name: os.environ[name] for name in allowed
            if name != seed_name and name in os.environ}


def _inspect_image(docker: str, environment: dict[str, str]) -> None:
    result = subprocess.run((docker, "image", "inspect", IMAGE), env=environment,
                            capture_output=True, text=True, check=False)
    if result.returncode:
        raise RuntimeError("pinned signer image is not available locally")
    try:
        objects = json.loads(result.stdout)
        image = objects[0]
        revision = image["Config"]["Labels"]["org.opencontainers.image.revision"]
        digests = image["RepoDigests"]
        entrypoint = image["Config"]["Entrypoint"]
        platform = (image["Os"], image["Architecture"])
    except (KeyError, IndexError, TypeError, ValueError) as error:
        raise RuntimeError("pinned signer image metadata is incomplete") from error
    if (IMAGE not in digests or revision != ACTION_COMMIT
            or entrypoint != ["/qrlft/entrypoint.sh"]
            or platform != ("linux", "amd64")):
        raise RuntimeError("local signer image differs from reviewed digest and source")


def _docker_command(docker: str, release: Path, output: Path,
                    tag: str, container_name: str) -> list[str]:
    """Build the Docker invocation without accepting or embedding a seed."""
    return [
        docker, "run", "--rm", "-i", "--pull=never", "--platform=linux/amd64",
        "--name", container_name,
        "--network=none", "--read-only", "--cap-drop=ALL",
        "--security-opt=no-new-privileges", "--pids-limit=64",
        "--memory=2g", "--memory-swap=2g", "--cpus=2",
        "--ulimit=core=0:0", "--log-driver=none",
        "--user", f"{os.getuid()}:{os.getgid()}",
        "--mount", f"type=bind,source={release},target=/work,readonly",
        "--mount", f"type=bind,source={output},target=/out",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",
        "--workdir", "/work", "--entrypoint", "/bin/bash",
        IMAGE, "-c", CONTAINER_SCRIPT, "--",
        ARTIFACT_CONTEXT, "/out/signatures.txt", "payload/*", PRODUCT,
        tag, "/out/manifest.json", MANIFEST_CONTEXT,
    ]


def _stop_container(docker: str, name: str, environment: dict[str, str]) -> None:
    # Docker --rm normally handles cleanup. This catches interruption while
    # the client is still attached; the command and environment contain no seed.
    subprocess.run((docker, "rm", "-f", name), env=environment,
                   capture_output=True, check=False)


def _run_docker(docker: str, release: Path, output: Path, tag: str,
                seed: str, seed_name: str) -> None:
    environment = _docker_environment(seed_name)
    _inspect_image(docker, environment)
    name = f"qrl-snapshot-sign-{uuid.uuid4().hex}"
    command = _docker_command(docker, release, output, tag, name)
    try:
        process = subprocess.Popen(command, cwd=release, env=environment,
                                   stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
        # A failing signer may include sensitive material in diagnostics.
        # Discard both streams rather than retaining them in this process.
        process.communicate((seed + "\n").encode("ascii"))
        if process.returncode:
            raise RuntimeError("isolated v3 signing container failed")
    finally:
        _stop_container(docker, name, environment)


def sign(release: Path, trusted_key: Path, qrlft_repo: Path,
         seed_name: str = SEED_NAME, docker: str = "docker") -> dict:
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if not re.fullmatch(r"[A-Z][A-Z0-9_]*", seed_name):
        raise RuntimeError("seed environment variable name is invalid")
    # Pop before any helper process starts. The seed remains in this Python
    # process memory until container stdin transfer finishes.
    seed = os.environ.pop(seed_name, "")
    if re.fullmatch(r"(?:0[xX])?[0-9a-fA-F]{64}", seed) is None:
        raise RuntimeError("approved 64-hex signing seed is absent or malformed")
    if any((release / name).exists() or (release / name).is_symlink()
           for name in OUTPUTS):
        raise RuntimeError("signing outputs already exist; use a fresh prepared release")
    if _digest(trusted_key)[1] != KEY_SHA256:
        raise RuntimeError("trusted public key differs from pinned theQRL/security key")
    checked = verify_prepared(release)
    if (checked["schema"] != DERIVED_INVENTORY_SCHEMA
            or checked.get("derived_verified") is not True
            or checked.get("snapshot_eligible") is not True
            or checked.get("signed_verified") is not False):
        raise RuntimeError("candidate is not an eligible unsigned derived snapshot")
    release = release.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix=".qrl-snapshot-sign-", dir=release.parent) as directory:
        output = Path(directory)
        _run_docker(docker, release, output, checked["tag"], seed, seed_name)
        seed = ""
        if {p.name for p in output.iterdir()} != set(OUTPUTS):
            raise RuntimeError("signer output set differs from expected v3 contract")
        if any((output / name).is_symlink() or not (output / name).is_file()
               for name in OUTPUTS):
            raise RuntimeError("signer output is missing or linked")
        (output / "payload").symlink_to(release / "payload", target_is_directory=True)
        with tempfile.TemporaryDirectory(prefix="qrl-independent-verifier-") as scratch:
            qrlft = _build_fixed_qrlft(qrlft_repo, Path(scratch),
                                       commit=FIXED_QRLFT_COMMIT)
            verified = verify_signed(output, trusted_key, qrlft)
        if verified.get("signed_verified") is not True:
            raise RuntimeError("independent signature verification did not pass")
        signed_digests = {name: _digest(output / name)[1] for name in OUTPUTS}
        placed: list[str] = []
        try:
            for name in OUTPUTS:
                # Exclusive hard links prevent replacing a file that appeared
                # after the initial clean-candidate check.
                os.link(output / name, release / name)
                placed.append(name)
            if any(_digest(release / name)[1] != signed_digests[name] for name in OUTPUTS):
                raise RuntimeError("signed output changed during final placement")
        except Exception:
            for name in placed:
                (release / name).unlink(missing_ok=True)
            raise
        verified["action_source_commit"] = ACTION_COMMIT
        verified["signer_qrlft_source_commit"] = SIGNER_QRLFT_COMMIT
        verified["independent_verifier_source_commit"] = FIXED_QRLFT_COMMIT
        verified["docker_image_digest"] = IMAGE.split("@", 1)[1]
        verified["seed_transport"] = "stdin_pipe_to_disposable_container"
        return verified


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("release", type=Path)
    parser.add_argument("--trusted-key", type=Path, required=True)
    parser.add_argument("--qrlft-repo", type=Path, required=True,
                        help="independent qrlft checkout containing pinned full-read commit")
    parser.add_argument("--seed-env", default=SEED_NAME)
    parser.add_argument("--docker", default="docker")
    args = parser.parse_args()
    try:
        print(json.dumps(sign(args.release, args.trusted_key, args.qrlft_repo,
                              args.seed_env, args.docker), sort_keys=True))
        return 0
    except Exception as error:
        print(f"snapshot signing: {error}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
