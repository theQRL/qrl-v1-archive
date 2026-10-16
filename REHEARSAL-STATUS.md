# TESTNET ARCHIVE REHEARSAL status

Status: **signed point-in-time testnet snapshot published**. Release
`testnet-snapshot-h1620000-8d7d8a30-r1` records public testnet from genesis
through block 1,620,000. See the [archive release page](https://archive.v1.theqrl.org/testnet/release/),
[data index](https://data.v1.theqrl.org/index.json) and [signed manifest](https://data.v1.theqrl.org/testnet/snapshots/testnet-snapshot-h1620000-8d7d8a30-r1/manifest.json).
The public testnet and mainnet remain live. This cutoff is not a terminal block
or an isolated lab-fork release.

Two stopped node copies agreed on exact stored block bytes and classified
native state through the cutoff. The published snapshot includes canonical
shards, a certified SQLite derivative and bounded read-only lookup packs.
The files under `fixtures/r2-smoke/` remain unsigned transport tests, separate
from the signed snapshot.

The two stopped native database captures for this cutoff passed a scoped
content review and were approved for public plaintext as exact normalized tar
hashes. The separate [signed native supplement](https://data.v1.theqrl.org/testnet/native-recovery/testnet-snapshot-h1620000-8d7d8a30-native-r1/manifest.json)
now serves 85 objects from the public data domain. A fresh public download
verified every object with SHA-256 and SHA3-256 and passed independent ML-DSA
signature verification on 16 October 2026 at 11:12 UTC. The
[release procedure](release/NATIVE-RECOVERY-SUPPLEMENT.md) records the audit
and approval digests. A clean-host restore from these public bytes, the
matching runtime package and an independent provider backup remain pending.
The original signed snapshot is unchanged.

The local tool can inspect a stopped LevelDB working copy, export exact stored
block protobuf bytes, structurally verify SHA-256/SHA3-256 shard digests,
compare two canonical exports byte for byte, and compare the observed testnet
state-version-3 native state. Historical consensus replay and final-retirement
verification still fail closed. The full isolated rehearsals, terminal capture,
clean-room recovery and final archive remain pending.
