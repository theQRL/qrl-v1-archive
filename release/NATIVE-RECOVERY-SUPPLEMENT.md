# Testnet native recovery supplement

The live testnet snapshot through block 1,620,000 is immutable. The approved
native node backups belong to a separate signed supplement under
`testnet/native-recovery/testnet-snapshot-h1620000-8d7d8a30-native-r1/`.
Never add them to the already signed snapshot prefix. This is a point-in-time
testnet record; the network is still running.

`native_recovery_release.py normalize` accepts the two independently captured
stopped `state/` tar files. It writes new deterministic USTAR files with
zero owner IDs, empty owner names, zero timestamps, fixed safe modes and fixed
member order. It leaves every `state/*` and `state.sha256` byte unchanged,
verifies the embedded SHA-256 manifest and compares every file's SHA-256 and
SHA3-256 with its custody copy. The originals remain untouched. `prepare`
then checks the pinned custody hashes, normalized headers, file equivalence,
review and signed snapshot cutoff before creating distributable parts. It writes a
file-level inventory into the signed public candidate and keeps an identical
private working copy for the signing handoff. Each public object is
at most 64 MiB. The signed `native-recovery-inventory.json` gives their order,
object paths, sizes, SHA-256 and SHA3-256, and original and published
whole-tar digests. The signed `native-normalization-report.json` records the
header policy and file-byte equality. `verify-prepared` streams the ordered
parts as tar files and checks each member, the embedded `state.sha256`, and
the normalized headers against the signed file inventory.

## Publication gate

The review of these two captures is complete. The private content audit has
schema `qrl.v1.archive.native-publication-content-audit.v1`, status `PASS`,
and SHA-256
`1230e65c823c00aed81eaf4838f197b9c4065d64447827c60f2bd8d359436df2`.
It checked source writers, raw tar bytes and decoded physical LevelDB table,
WAL and MANIFEST contents. It found no plausible secret, private path,
infrastructure hostname or IP indicator. Apparent credential and URL matches
were checked against the stored chain records. This is a scoped content
review, not proof that arbitrary binary secrets cannot exist.

The operator approved public plaintext for these exact normalized tar hashes:

| Source | Distributed tar SHA-256 |
| --- | --- |
| S1 | `8574b08ea47b0da3facc6793e829d654eb2c2bce3ecb2bb0a54fb91806eae34b` |
| testnet3 | `4748bee7775e49c8080c787e6375fb7a4211c5cb78713a3d685aea15338c381c` |

The private decision has schema `qrl.v1.archive.native-publication-review.v1`,
decision `APPROVED_PUBLIC_PLAINTEXT`, and SHA-256
`55fdaa21dac65312cc9c961de71d8caad5c50bc5748b8df34ab3af5f018077c8`.
The normalization report's SHA-256 is
`94ebd20bee74535bf48b6c75b5e23a0bba01ac0cbb49c90da455de5745ba0014`.
The source-storage classification has schema
`qrl.v1.archive.native-plaintext-source-classification.v2` and SHA-256
`059b8ab0a70fcc499084b0e3964007f913520596b6b3f49b801ffaae22dcaaa2`.
The signed inventory binds these digests and both original custody tar
hashes. Keep the audit and decision in private operator storage. A new capture
needs a new content review and approval. The required review JSON shape is:

```json
{
  "schema": "qrl.v1.archive.native-publication-review.v1",
  "tag": "testnet-snapshot-h1620000-8d7d8a30-native-r1",
  "mode": "reviewed_plaintext",
  "decision": "APPROVED_PUBLIC_PLAINTEXT",
  "subjects": [
    {"label": "s1", "distributed_sha256": "<normalized S1 tar SHA-256>"},
    {"label": "testnet3", "distributed_sha256": "<normalized testnet3 tar SHA-256>"}
  ],
  "custody_subjects": [
    {"label": "s1", "custody_sha256": "<original S1 tar SHA-256>"},
    {"label": "testnet3", "custody_sha256": "<original testnet3 tar SHA-256>"}
  ],
  "reviewer_role": "<authorized role>",
  "reviewed_at_utc": "<ISO 8601 UTC timestamp>",
  "evidence": {
    "raw_byte_audit_sha256": "<SHA-256 of full raw-byte content audit report>",
    "source_classification_sha256": "<SHA-256 of source-storage classification report>",
    "normalization_report_sha256": "<SHA-256 of deterministic normalization report>"
  }
}
```

The content audit must state `status: "PASS"` and list the normalized tar
`subjects` exactly. The preparer hash-binds the source classification report
and checks normalization against both tar pairs. The approval and evidence
remain private; their digest commitments are signed into the public release.
The parser does not make the operator's publication decision. This approved
supplement uses plaintext; the tool has no encrypted-publication mode.

## Prepare and sign

Use paths outside the repository for custody, reports and the candidate. The
parent manifest must be the already independently verified signed snapshot's
`manifest.json`. The native comparison report must be the passing dual-source
report bound to the same cutoff. First create private normalized tars, then
audit those exact bytes and complete the review. The normalized tar directory
is private review material until publication is approved.

```sh
PYTHONPATH=src python3 release/native_recovery_release.py normalize \
  --tag testnet-snapshot-h1620000-8d7d8a30-native-r1 \
  --s1-tar "$S1_STOPPED_TAR" --testnet3-tar "$TESTNET3_STOPPED_TAR" \
  --output "$NEW_PRIVATE_NORMALIZED_DIR"
```

The following steps require the approved review.

```sh
PYTHONPATH=src python3 release/native_recovery_release.py prepare \
  --tag testnet-snapshot-h1620000-8d7d8a30-native-r1 \
  --mode reviewed_plaintext \
  --s1-tar "$S1_STOPPED_TAR" --testnet3-tar "$TESTNET3_STOPPED_TAR" \
  --s1-normalized-tar "$NEW_PRIVATE_NORMALIZED_DIR/s1-normalized.tar" \
  --testnet3-normalized-tar "$NEW_PRIVATE_NORMALIZED_DIR/testnet3-normalized.tar" \
  --normalization-report "$NEW_PRIVATE_NORMALIZED_DIR/native-normalization-report.json" \
  --parent-manifest "$VERIFIED_PARENT_MANIFEST" \
  --native-report "$PASSING_NATIVE_COMPARISON" \
  --publication-review "$PRIVATE_REVIEW_JSON" \
  --raw-byte-audit "$PRIVATE_RAW_BYTE_AUDIT" \
  --source-classification "$PRIVATE_SOURCE_CLASSIFICATION" \
  --restricted-report "$NEW_PRIVATE_FILE_REPORT" \
  --output "$NEW_NATIVE_RELEASE_DIR"

PYTHONPATH=src python3 release/native_recovery_release.py verify-prepared \
  "$NEW_NATIVE_RELEASE_DIR" --review-file "$PRIVATE_REVIEW_JSON" \
  --raw-byte-audit "$PRIVATE_RAW_BYTE_AUDIT" \
  --source-classification "$PRIVATE_SOURCE_CLASSIFICATION" \
  --normalization-report "$NEW_PRIVATE_NORMALIZED_DIR/native-normalization-report.json" \
  --restricted-report "$NEW_PRIVATE_FILE_REPORT"
```

After `prepare`, the candidate is unsigned. The approved key custodian uses the same
pinned [`actions-mldsa-sign` v3 image and two purpose contexts](LIVE-TESTNET-SNAPSHOT.md)
as the parent release. The `sign_native_recovery_v3.py` wrapper requires the
review again, accepts the seed only through the approved `op run` environment,
and independently verifies all signatures before placing outputs. It writes
the action's exact `theqrl.release-manifest.v1` format: `schema`, `product`,
`tag`, `context`, and sorted `{filename,size,sha256}` artifacts. The signed
native inventory carries the additional SHA3-256 and recovery data.

```sh
PYTHONPATH=src op run -- python3 release/sign_native_recovery_v3.py \
  "$NEW_NATIVE_RELEASE_DIR" --review-file "$PRIVATE_REVIEW_JSON" \
  --raw-byte-audit "$PRIVATE_RAW_BYTE_AUDIT" \
  --source-classification "$PRIVATE_SOURCE_CLASSIFICATION" \
  --normalization-report "$NEW_PRIVATE_NORMALIZED_DIR/native-normalization-report.json" \
  --restricted-report "$NEW_PRIVATE_FILE_REPORT" \
  --trusted-key "$PINNED_QRL_RELEASE_PUBLIC_KEY" \
  --qrlft-repo "$PINNED_QRLFT_CHECKOUT"

PYTHONPATH=src python3 release/native_recovery_release.py verify-signed \
  "$NEW_NATIVE_RELEASE_DIR" --review-file "$PRIVATE_REVIEW_JSON" \
  --raw-byte-audit "$PRIVATE_RAW_BYTE_AUDIT" \
  --source-classification "$PRIVATE_SOURCE_CLASSIFICATION" \
  --normalization-report "$NEW_PRIVATE_NORMALIZED_DIR/native-normalization-report.json" \
  --trusted-key "$PINNED_QRL_RELEASE_PUBLIC_KEY" \
  --qrlft-repo "$INDEPENDENT_QRLFT_CHECKOUT"
```

An independent verifier must repeat that check outside the signing
environment. Upload only through a transfer procedure that requires the
matching private review and signed verification result. Serve all parts,
inventory, notice, action manifest, manifest signature and artifact signatures
under the immutable prefix. Download every object from `data.v1.theqrl.org`
into a fresh directory and repeat `verify-signed` plus a full GET and byte
check. Preserve a second independently administered copy.

The approved candidate was signed locally and passed `verify-signed` with the
pinned `theQRL/security` public key and independent `qrlft` source. Its action
manifest SHA-256 is
`cb77b5ccbc4eb7f6fe150770aae2f6e08459aeebc8dc017ae694cc3e10b74108`.
The [public supplement](https://data.v1.theqrl.org/testnet/native-recovery/testnet-snapshot-h1620000-8d7d8a30-native-r1/manifest.json)
now serves 85 objects. A fresh download through `data.v1.theqrl.org` passed
full-object SHA-256 and SHA3-256 comparison and independent ML-DSA verification
on 16 October 2026 at 11:12 UTC. The served-byte receipt records 5,176,522,015
bytes and binds the manifest and signed inventory digests. Preserve the
download and verification evidence with the signed local package.

The matching QRL v1 runtime, configuration, genesis data and a clean-host
offline cold-restore report remain separate required artefacts. Publishing
signed database parts does **not** claim that node recovery has passed. The
[native node recovery requirement](NATIVE-NODE-RECOVERY.md) defines that gate.
