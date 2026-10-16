# Live testnet snapshot release

This release is a fixed view of the still-running QRL v1 testnet through block
1,620,000. It is a data and explorer rehearsal. It is not a terminal network
archive, a claim that testnet has stopped, or authority to retire a node. A
later final archive will record the network after its approved stop. Routine
use of the public archive does not require a node. The permanent archive must
also pass a separate [native node recovery](NATIVE-NODE-RECOVERY.md) gate.
This point-in-time release does not contain a native database or bootable
runtime package and cannot satisfy that gate.

## Local release candidate

`python -m qrl_archive.snapshot_release prepare` takes the primary and
independently sourced secondary canonical exports, their exact-byte comparison
report and native state comparison report. It reruns the canonical structural
checks and compares both
stored block streams before it writes a fresh release directory. The output is
`payload/` with 163 bounded `.qrlblk` shards, `shards.json`, two source reports,
`live-anchor-summary.json`, `SNAPSHOT-NOTICE.md`, and `archive-inventory.json`.
For the public explorer candidate it also requires certified snapshot SQLite,
its certification report, and independently checked static query packs. The
SQLite file is split into ordered 16 MiB `.part` objects. The signed inventory
records both digests for each part and for the whole SQLite file. The query
index and every listed pack are signed payloads, bound to the same cutoff and
the exact certified SQLite SHA-256. Their balances are observed at the cutoff
with two-node state agreement; they are not a consensus replay.
The live anchor summary gives the UTC observation and the two transport trust
classes, but omits the private operator report's host-key fingerprint. It says
explicitly that the observation does not guarantee future canonicality. The
release contains no wallet or private key. The inventory lists every other payload's size, SHA-256 and
SHA3-256, plus the network, genesis and snapshot cutoff. Its
`verification_scope` explicitly says historical consensus has not been
replayed and the network is still running. The native state comparison report
is source evidence, not a replacement for the native LevelDB custody copies.

Use an immutable tag such as
`testnet-snapshot-h1620000-8d7d8a30-r1`. The public object prefix is exactly
`testnet/snapshots/<tag>/`. Each local signed payload has a unique basename for
the action v2 manifest. Its signed inventory `object_path` maps it to a public
object under that prefix. Query packs use `query/`, and SQLite parts use
`derived/sqlite/`. `manifest.json`, `manifest.json.sig`, and
`signatures.txt` go to the same prefix after signing. Do not publish the local
directory until those signatures verify independently.

Example from the repository root, with the paths to the preserved capture
filled in by the archive operator:

```sh
PYTHONPATH=src python3 -m qrl_archive.snapshot_release prepare \
  --canonical "$PRIMARY_EXPORT" --secondary "$SECONDARY_EXPORT" \
  --comparison-report "$EXACT_COMPARE_REPORT" \
  --native-report "$NATIVE_COMPARE_REPORT" \
  --live-anchor-report "$LIVE_ANCHOR_REPORT" \
  --snapshot-sqlite "$CERTIFIED_SNAPSHOT_SQLITE" \
  --snapshot-sqlite-report "$SNAPSHOT_CERTIFICATION_REPORT" \
  --query-packs "$VERIFIED_QUERY_PACKS" \
  --query-verification-report "$QUERY_PACK_VERIFICATION_REPORT" \
  --tag testnet-snapshot-h1620000-8d7d8a30-r1 \
  --output "$NEW_RELEASE_DIR"
PYTHONPATH=src python3 -m qrl_archive.snapshot_release verify-prepared "$NEW_RELEASE_DIR"
```

The command refuses an existing output path. The candidate is unsigned even
when `verify-prepared` passes, and `.partial` derived inputs are refused.
First run `qrl-v1-archive-explorer/src/verify-query-packs.py` against the
certified SQLite file and finished packs to produce the `PASS` report. On the
prepared release, run:

```sh
PYTHONPATH=src python3 release/verify_snapshot_query.py "$NEW_RELEASE_DIR" \
  --explorer-verifier "$EXPLORER_REPO/src/verify-query-packs.py" \
  --report "$FRESH_QUERY_CHECK_REPORT"
```

This reconstructs SQLite from its signed parts, maps the signed query files to
their public paths, reruns the explorer verifier, and requires its result to
equal the included independent `PASS` report. Repeat it against the clean
public download before explorer activation. `verify-prepared` itself checks
the signed report and all bytes but does not rerun the logical SQL comparison;
its JSON result says so explicitly.

## Signing handoff

The established [theQRL release public key](https://github.com/theQRL/security/blob/2aef08563f4d177fb2773215a30d86029ed519f7/theqrl-release-key.pub)
is the trust root. Its exact file SHA-256 is
`8cf05c32a7cb69dfe27e5137b27baedf4ab0008a0684f36e59aa2553ff8f0c5f`.
The key custodian must use the existing protected release secret in the
approved signing environment. No wallet seed or release seed belongs in this
repository, a command line transcript, or an archive object.

Use the [actions-mldsa-sign v3 source](https://github.com/theQRL/actions-mldsa-sign/tree/v3.0.0),
which preserves the action v2 manifest and context contract, with these values:

| Input | Value |
| --- | --- |
| `patterns` | `payload/*` from inside the release directory |
| `product` | `qrl-v1-testnet-archive` |
| `tag` | The immutable snapshot tag |
| `context` | `qrl-v1-testnet-archive-release-signatures` |
| `manifest-context` | `qrl-v1-testnet-archive-release-manifest` |
| `output` | `signatures.txt` outside `payload/` |
| `manifest` | `manifest.json` outside `payload/` |

Action v3 produces a `theqrl.release-manifest.v1` document with only `schema`,
`product`, `tag`, `context`, and sorted `artifacts` entries containing
`filename`, `size`, `sha256`. Do not add the snapshot height or SHA3-256 to
that format. The separately signed `archive-inventory.json` carries those
fields. `manifest.json.sig` uses the manifest context; each signature in
`signatures.txt` uses the artifact context.

The old `v2.0.0` image pins a qrlft reader that can stop after one short
`Read`; do not use it on archive parts. The v3.0.0 source commit is
`4d9a45b39b989ea244c88fc217fcda794ae94026`; its Dockerfile pins qrlft
v4.1.1 commit `9cf05342e9aeb175fb336a6985da579302b1ca36`, which contains the
full-file reader fix. The reviewed v3.0.0 image digest is
`sha256:65a6059d2b9c3a706b8560162ccf2d07ca39e1fb5074ff3bdfe9291889ee1afd`.
Its entrypoint and manifest builder are byte-for-byte unchanged from v2. A
disposable 67,108,881-byte artifact passed signature verification and rejected
a changed final byte and wrong context. Record the exact source commit and
image digest used for the approved signing route; never rely on a floating tag.
The reviewed image is `linux/amd64`; on an ARM Mac, Docker runs it under
emulation, so allow ample time for the 2,946-file snapshot signing pass.

For an approved isolated local key runner, `release/sign_snapshot_v3.py`
requires a complete eligible v2 *archive inventory*, checks the pinned
public key, and runs the reviewed v3 image by its immutable digest. The image
must already be present locally; the wrapper refuses to pull it during
signing. It builds a separate independent qrlft verifier from the pinned
full-file reader source. The 1Password field must
contain the release signing seed as exactly 64 hexadecimal characters, with
an optional `0x` prefix. A qrlft v4.1.1 `new` private-key file is PKCS#8 PEM
and cannot be used as the action's `hexseed` input. Use the existing approved
release key record; do not generate or substitute a new key.

The [1Password CLI `op run` command](https://www.1password.dev/cli/reference/commands/run)
resolves an `op://` secret reference into a child process environment. Put only
the reference in the shell, then invoke the local wrapper as follows. Replace
the reference and checkout placeholders in the approved isolated runner:

```sh
export QRL_RELEASE_MLDSA_SEED='op://VAULT/ITEM/FIELD'
PYTHONPATH=src op run -- python3 release/sign_snapshot_v3.py "$NEW_RELEASE_DIR" \
  --qrlft-repo "$INDEPENDENT_QRLFT_SOURCE_CHECKOUT" \
  --trusted-key "$PINNED_PUBLIC_KEY"
```

Do not use `op run --no-masking`, shell tracing, or commands that print the
resolved variable. The wrapper removes the resolved seed from its Python
environment before it starts helper processes. It passes the seed through a
pipe to a disposable container. The Docker command, Docker client environment
and container configuration contain no seed. The container has no network,
a read-only root filesystem and release input, no added capabilities, no
Docker logs, and only a temporary writable output mount. The action entrypoint
still passes the seed as a process argument **inside the container**. The
resolved seed also exists briefly in the wrapper process environment and
memory, and Docker daemon administrators may inspect container processes or
memory. Run only where that access and crash dumps are controlled by the key
custody procedure. Neither `op run` masking nor this wrapper eliminates these
exposures.

The wrapper writes the action's `signatures.txt`, `manifest.json`, and
`manifest.json.sig` in temporary private storage, then verifies every signature
and digest against the pinned public key using an independently built qrlft.
It moves those three files into the candidate only after verification and
removes partial signing outputs on failure. Its JSON result records the two
exact source commits, image digest and signed manifest digests;
it never includes secret material. An independent verifier must still repeat
the check in a separate environment before publication.

## Independent verification and publication

The verifier obtains the pinned public key from the security repository in a
separate checkout. Build the fixed qrlft source independently, then run:

```sh
PYTHONPATH=src python3 -m qrl_archive.snapshot_release verify-signed \
  "$NEW_RELEASE_DIR" --trusted-key "$PINNED_PUBLIC_KEY" \
  --qrlft-repo "$QRLFT_SOURCE_CHECKOUT"
```

`verify-signed` checks the key fingerprint, the action manifest's exact fields,
release identity, every payload basename/size/SHA-256, every SHA3-256 in the
signed inventory, the manifest signature under its own context, every payload
signature under the artifact context, and the canonical stream's structural
identity through the cutoff. For the derived release it reassembles SQLite
parts, verifies whole-file digests, metadata, row counts and integrity, and
checks the query index and its independent logical-comparison report against
every listed object's digests. It fails if an artifact is missing or extra.
The CLI builds qrlft from exact commit
`ed1f29f3e4743ba2f1429154ae31549c37e3a357` in the supplied Git checkout
with network module downloads disabled. Preserve the toolchain and module cache
or vendor its dependencies for clean-room verification. The JSON result includes
SHA-256 of the manifest, manifest signature, signatures list and signed
inventory; a publication receipt can bind its served-byte checks to these.

Only after a separate verifier passes should the storage operator upload all
objects to the immutable prefix. Download every object from the public domain
into a fresh directory and rerun `verify-signed` there. Compare full SHA-256
and SHA3-256, not R2 ETags. Check full GET, Range responses and CORS before
pointing the public explorer at the tag. Keep the notice visible on every
explorer page. A final-network banner, archived-network API response, or
shutdown claim would be false for this snapshot.

The release does not satisfy the two destructive testnet rehearsals. Those
still require a later terminal candidate, full operational signoff, independent
restore, and post-shutdown tests.

The earlier canonical-only candidate remains unsigned. The explorer cannot
go live from it. Build a fresh candidate with all derived inputs, and sign one
v2 inventory only after the independent query verifier and full
`verify-prepared` pass. A browser activation receipt is a later deployment
control: it must cite the exact signed manifest and independent public
served-byte report digests, so it cannot be included in the manifest it
cites. Keep the explorer disabled until that receipt is reviewed and deployed.
