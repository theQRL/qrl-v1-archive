# Signed releases

The signed point-in-time testnet snapshot `testnet-snapshot-h1620000-8d7d8a30-r1` records public testnet through block 1,620,000. Its [release page](https://archive.v1.theqrl.org/testnet/release/), [data index](https://data.v1.theqrl.org/index.json) and [signed manifest](https://data.v1.theqrl.org/testnet/snapshots/testnet-snapshot-h1620000-8d7d8a30-r1/manifest.json) identify the published objects. The public testnet and mainnet remain live. This release is neither a terminal rehearsal nor the final archive.

The [native node recovery requirement](NATIVE-NODE-RECOVERY.md) is a separate release gate. This point-in-time release does not include native LevelDB backup files or a bootable node package.

The [native recovery supplement procedure](NATIVE-RECOVERY-SUPPLEMENT.md)
defines a separate plaintext backup release. The two exact normalized tar files
passed the recorded content review and received operator approval. The
[signed supplement manifest](https://data.v1.theqrl.org/testnet/native-recovery/testnet-snapshot-h1620000-8d7d8a30-native-r1/manifest.json)
is public. A fresh download of all 85 served objects passed SHA-256, SHA3-256
and independent ML-DSA verification on 16 October 2026 at 11:12 UTC.
Clean-host node restoration, a signed runtime package and an independent
provider backup remain open gates.

Do not place or upload the unsigned `fixtures/r2-smoke/` objects here. Later terminal rehearsals require distinct immutable `testnet/rehearsal-N/RUN_ID/` paths, signed deterministic manifests, separate signature contexts and independent post-upload verification before publication. Historical consensus replay and the full rehearsals remain pending.

The [local signer fixture](SIGNER-FIXTURE.md) exercises the action format with
temporary test keys and records why the old v2 image cannot sign large archive
parts. The v3 release and approved local signing route are specified in the
[live testnet snapshot procedure](LIVE-TESTNET-SNAPSHOT.md).

The [live testnet snapshot procedure](LIVE-TESTNET-SNAPSHOT.md) describes the
published point-in-time release and its separate immutable prefix. Its notice
distinguishes the snapshot from a terminal rehearsal or final archive.
