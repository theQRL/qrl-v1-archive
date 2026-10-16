# TESTNET ARCHIVE REHEARSAL — QRL v1 archive

> **This is a test of the archival process, not the QRL v1 mainnet archive.** The published snapshot records public testnet through block 1,620,000. The public testnet and mainnet remain live. Later blocks and current balances are outside this snapshot.

This repository holds the first tools and formats needed to preserve and verify QRL v1 chain history. Work is at the implementation and testnet rehearsal stage. A passing rehearsal does not authorise mainnet retirement.

## Published testnet snapshot

The signed point-in-time snapshot, `testnet-snapshot-h1620000-8d7d8a30-r1`, is available through the [archive release page](https://archive.v1.theqrl.org/testnet/release/) and [data index](https://data.v1.theqrl.org/index.json). Its [signed manifest](https://data.v1.theqrl.org/testnet/snapshots/testnet-snapshot-h1620000-8d7d8a30-r1/manifest.json) identifies the immutable release objects. This is a snapshot of a continuing network, not a terminal rehearsal or final archive. Historical consensus replay and the full isolated rehearsals remain pending.

## Current implementation

The local `qrl-archive` CLI inspects a stopped LevelDB working copy, exports exact stored block protobuf bytes into bounded version 1 shards, checks shard structure and digests, and compares two exports byte by byte. Its [scope and commands](src/README.md) are documented with the [block-stream format](schemas/qrl-v1-block-stream-v1.md) and [comparison report](schemas/qrl-v1-comparison-report-v1.md). The published testnet snapshot includes a certified SQLite derivative and bounded static query packs for a read-only explorer; the [snapshot release procedure](release/LIVE-TESTNET-SNAPSHOT.md) packages these with the canonical shards. Consensus replay and final-retirement verification are not implemented.

## Still needed

- Historical consensus replay and final-retirement readiness checks.
- Parquet schema and derivation for the permanent archive, if benchmarked as useful.
- Golden fixtures, including deliberate testnet transactions and transfers with multiple recipients.
- A proven final-network derivation of all required account state solely from canonical records.

The permanent release will preserve native LevelDB custody copies and canonical chain data. Public users need the signed records and read-only explorer; routine use does not require a running node. A separately tested [native node recovery package](release/NATIVE-NODE-RECOVERY.md) must also let an independent operator start a QRL v1 node at the archived height and state. Derived chain indexes must be rebuildable from canonical shards; final account state currently depends on the independently checked native captures. Releases must be checked against independent node exports and signed using QRL's existing release key.

## Current files

`fixtures/r2-smoke/` contains unsigned warning and transport-test objects. [Placeholder asset status](docs/pages-r2-placeholder.md) explains their role. They are separate from the signed snapshot and are not chain data. `REHEARSAL-STATUS.md` records what remains unbuilt.

## Siblings

The read-only website lives in `theQRL/qrl-v1-archive-explorer`.
