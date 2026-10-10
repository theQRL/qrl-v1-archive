# Archive tools

`qrl-archive` currently implements `inspect`, exact stored-byte `export` and `verify --mode structural`. It reads the pinned QRL v1 LevelDB height mapping, copies each stored protobuf value without serializing it again, and writes the [version 1 block stream](../schemas/qrl-v1-block-stream-v1.md). Export verifies its staged output before making the output directory visible. The report marks consensus, native final-state and derived-data verification as false.

Open a **disposable, stopped LevelDB working copy**. LevelDB takes an exclusive lock and can rewrite its log or manifest during recovery on open. Never point the tool at a live node or a custodial snapshot. It refuses an occupied LevelDB lock, a changing source tip or data files, and a source tip different from the declared terminal height.

The LevelDB library must decode Snappy-compressed historical `.ldb` files. A Python `plyvel` import or version check alone does not establish that its linked LevelDB library has Snappy support. Check the linked library and perform a real block-read preflight on a disposable copy. A build without Snappy fails with a source-read error; do not classify that alone as source corruption. Preserve the exact runtime and linked library in the rehearsal release.

Each `--json-report` path is append-only: the command refuses to replace an existing report. Use a fresh path for each attempt and keep failed reports with the run evidence.

Example interface, with values supplied from an independently reviewed source report:

```text
qrl-archive inspect --source-db STOPPED_WORKING_COPY/state --network-id testnet --expect-genesis-hash G --json-report inspect.json
qrl-archive export --source-db STOPPED_WORKING_COPY/state --network-id testnet --genesis-hash G --fork-height F --fork-hash FORK_HASH --terminal-height H --terminal-hash T --run-id RUN_ID --output canonical --json-report export.json
qrl-archive verify --canonical canonical --expect-network-id testnet --expect-genesis-hash G --expect-fork-height F --expect-fork-hash FORK_HASH --expect-terminal-height H --expect-terminal-hash T --mode structural --json-report verify.json
```

The LevelDB does not store a trusted network name. `--network-id` is an operator claim tied to the independently checked genesis hash. `consensus` and `full` modes fail closed. The independent comparator, SQLite/Parquet builder, release packager, signature verifier and fixture runner remain to be built. The unsigned R2 smoke objects in `fixtures/` do not pass any archive gate.
