# SQLite v1 derivative

The SQL definition is [qrl-v1-sqlite-v1.sql](qrl-v1-sqlite-v1.sql). The builder uses an identical copy packaged with `qrl_archive`; a test fails if the copies diverge. `PRAGMA application_id` is `0x51524c31` (`QRL1`) and `user_version` is `1`. All tables are `STRICT`.

`derive-sqlite` accepts a structurally verified canonical shard directory plus explicit network, genesis, fork and cutoff height/hash. Here `terminal_height` and `terminal_hash` in the current CLI and shard index mean the *last included block in this snapshot*. They do not assert that the live testnet stopped. The source block bytes remain authoritative. The SQLite file is a derived query aid.

The builder runs canonical structural verification before yielding any record and checks each shard's SHA-256 and SHA3-256 again before deriving rows. `blocks.canonical_offset` is the first protobuf byte after the height and length fields in the named `.qrlblk` shard. `transactions.raw_pb` is the exact nested transaction wire value extracted from the stored block, including unknown protobuf fields. It is not reconstructed with `SerializeToString()`.

Block height, transaction index, timestamp, shard offset and length use SQLite `INTEGER` after a signed 64-bit range check. Protobuf `uint64` values, including rewards, amounts, fees, balances and nonces, use canonical unsigned decimal `TEXT`. Binary hashes and addresses use `BLOB`. `tx_details.decoded_json` has schema `qrl.v1.tx-details.v1`; known bytes are lowercase hex and 64-bit integers are decimal strings. The transaction wire value is available in `raw_pb` for fields unknown to the pinned decoder.

`tx_outputs` has one row per payment leg. It includes coinbase QRL reward, normal QRL transfer, multisig spend, token initial allocation and token transfer. `asset_id` is null for QRL and is the 32-byte token creation hash for token amounts. When `asset_id` is present, the schema's `amount_shor` field contains token base units, not QRL shor; consumers must use `asset_id` when labelling amounts. Parallel recipient and amount arrays must have equal lengths. Repeated recipients keep separate output indices. `genesis_allocations` stores `Block.genesis_balance` separately; the genesis allocation is not attributed to a transaction. Some historical genesis records use the 32-byte zero coinbase address.

`address_events` records observed roles, not accounting deltas. A transaction may have separate `from`, `signer` and `master` rows for the same address. Output rows use `receive`, `coinbase_receive`, `token_receive` or `token_initial`, with their output index and amount. Other roles include `message_to`, `token_owner`, `slave_key`, `multisig_created`, `multisig_signatory` and `multisig_spend_source`. The browser can collapse roles for a compact transaction list, but must retain per-leg detail. Signer addresses use the pinned v1 descriptor plus SHA-256 public-key derivation; the real mainnet 4,000,000 token fixture tests the result against its on-chain owner.

Balances cannot safely be calculated by summing these rows. The QRL node applies genesis, multisig and other protocol effects. Without `--source-db`, `final_address_state` stays empty and `archive_meta.balance_source=absent`. The optional `--source-db` must be a separate stopped, disposable state-version-3 LevelDB working copy anchored to the same genesis, fork and cutoff. It fills final address balances and nonce from native account protobuf records; `state_pb` retains those exact bytes. `ots_state` stays null because the optimized account record does not contain the separate bitfield pages. This import is a comparison aid, not an independently replayed final state.

An operator can compare an SQLite file populated from one stopped node with a second stopped node using `qrl_archive.native_balance_check.compare_sqlite_native_accounts`. Supply the same six anchors and a state-version-3 working copy from the independent node. The check requires every account address, balance, nonce and native protobuf byte string to match, and rejects missing or extra rows. Its result includes deterministic logical SHA-256 and SHA3-256 digests. It compares two observed states at the cutoff; even agreement does not establish that canonical bytes alone can reconstruct account balances. The comparison therefore reports `release_ready=false` and `consensus_replayed=false`.

Every output filename must end in `.partial.sqlite`. The database records `archive_meta.release_ready=false` and `archive_meta.consensus_replayed=false`. The CLI writes the checked file and a report with per-table logical SHA-256/SHA3-256 row digests, but exits `4` with status `INCOMPLETE`. A release gate must reject that result until canonical consensus replay, deterministic final-state reconstruction and independent fixture comparisons are implemented. File bytes may vary across SQLite versions; compare logical row digests and query results instead.

For a **signed live-chain point-in-time snapshot**, `qrl_archive.snapshot_sqlite.certify_snapshot_sqlite` provides a narrower gate. It requires the verified canonical shard stream, a canonical-only and a native-account SQLite build with matching chain-derived logical row digests, both derivation reports and whole-file digests, an independent stopped state-v3 node at the same cutoff, and an explicit operator attestation that the two source nodes were independently synced. It then compares every imported account's address, balance, nonce and exact state protobuf bytes against the independent node. On success it writes a separate `.snapshot.sqlite` and a report with `snapshot_eligible=true`, `snapshot_kind=live-chain-point-in-time` and the account comparison digests. The database still records `release_ready=false` and `consensus_replayed=false`; balances must be displayed as **observed at the snapshot cutoff from two agreeing nodes**, not as reconstructed solely from canonical blocks. This snapshot gate does not authorize permanent retirement of source infrastructure.

Run from the source checkout with the six verified anchor values from `shards.json`:

```text
qrl-archive derive-sqlite --canonical CANONICAL_DIR \
  --expect-network-id NETWORK --expect-genesis-hash G \
  --expect-fork-height F --expect-fork-hash FH \
  --expect-terminal-height H --expect-terminal-hash T \
  --output snapshot.partial.sqlite --json-report derive.json
```

The `INCOMPLETE` exit is expected for this milestone. It must not be changed to a pass because the file opens successfully.
