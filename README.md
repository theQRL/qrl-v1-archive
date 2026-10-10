# TESTNET ARCHIVE REHEARSAL — QRL v1 archive

> **This is a test of the archival process, not the QRL v1 mainnet archive.** During these rehearsals, the public testnet and mainnet remain live. Blocks produced after the lab fork point belong to an isolated, disposable testnet branch. Do not use rehearsal data as evidence of mainnet balances or finality.

This repository holds the first tools and formats needed to preserve and verify QRL v1 chain history. Work is at the implementation and testnet rehearsal stage. A passing rehearsal does not authorise mainnet retirement.

## Current implementation

The local `qrl-archive` CLI inspects a stopped LevelDB working copy, exports exact stored block protobuf bytes into bounded version 1 shards, and checks shard structure, chain links, identity and SHA-256/SHA3-256 digests. Its [scope and commands](src/README.md) are documented with the [block-stream format](schemas/qrl-v1-block-stream-v1.md). Consensus and full verification requests fail because those modes are not implemented.

## Still needed

- Independent consensus, signature and release verification tools.
- SQLite and Parquet schemas and derivation.
- Golden fixtures, including deliberate testnet transactions and transfers with multiple recipients.
- Tools to rebuild derived data from the canonical archive.

Archive releases will preserve stopped native node data and canonical chain data. Derived databases and indexes must be rebuildable. Releases must be checked against independent node exports and signed using QRL's existing release key.

## Current files

`fixtures/r2-smoke/` contains unsigned warning and transport-test objects. [Placeholder asset status](docs/pages-r2-placeholder.md) explains their role. They are not chain data or an archive release. `REHEARSAL-STATUS.md` records what remains unbuilt.

## Siblings

The read-only website lives in `theQRL/qrl-v1-archive-explorer`. Deployment plans and operational records live in the **private** `theQRL/qrl-v1-archive-ops` repository.
