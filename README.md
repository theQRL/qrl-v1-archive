# qrl-v1-archive

# TESTNET ARCHIVE REHEARSAL — QRL v1 archive

> **This is a test of the archival process, not the QRL v1 mainnet archive.** During these rehearsals, the public testnet and mainnet remain live. Blocks produced after the lab fork point belong to an isolated, disposable testnet branch. Do not use rehearsal data as evidence of mainnet balances or finality.

This repository will hold the tools and formats needed to preserve and verify QRL v1 chain history. Work is at the implementation and testnet rehearsal stage. A passing rehearsal does not authorise mainnet retirement.

## Planned contents

- An exporter for exact block protobuf bytes stored by a pinned QRL v1 node.
- Independent chain, integrity, signature and release verification tools.
- Versioned canonical, SQLite and Parquet schemas.
- Golden fixtures, including deliberate testnet transactions and transfers with multiple recipients.
- Tools to rebuild derived data from the canonical archive.

Archive releases will preserve stopped native node data and canonical chain data. Derived databases and indexes must be rebuildable. Releases must be checked against independent node exports and signed using QRL's existing release key.

## Siblings

The read-only website lives in `theQRL/qrl-v1-archive-explorer`. Deployment plans and operational records live in the **private** `theQRL/qrl-v1-archive-ops` repository.
