# TESTNET ARCHIVE REHEARSAL status

Status: **preparation only**. The first `qrl-archive` slice can inspect a stopped QRL v1 LevelDB working copy, export exact stored block protobuf bytes, and verify the version 1 shard structure and SHA-256/SHA3-256 digests. It has passed synthetic corruption tests and a private, disposable 21-block real-data preflight. That preflight is not a rehearsal release. The files under `fixtures/r2-smoke/` remain unsigned transport tests and a public warning.

The public QRL testnet and mainnet remain live. No lab fork height, terminal block or run ID has been established. Never publish these placeholder objects under `mainnet/` or an immutable `testnet/rehearsal-N/RUN_ID/` release path.

The full consensus verifier, independent A/B comparator, final-state checks, SQLite/Parquet derivation, deliberate transaction fixture runner, signing, backup, post-upload checks and clean-room recovery are not implemented. An R1/R2 release still requires all of them. `consensus` and `full` verification requests currently fail.
