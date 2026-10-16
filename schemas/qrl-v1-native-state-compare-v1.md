# Native state comparison report v1

`qrl-archive compare-native-state` reads two stopped QRL v1 LevelDB **working copies** and writes a deterministic `qrl.v1.archive.native-state-compare.v1` result. It supports only `state_version` 3 and the pinned protobuf binding. LevelDB can recover or compact files while reading, so a custodial copy must never be passed to this command.

Both inputs must have the operator-declared terminal height, genesis hash, fork hash and terminal hash. The command pins a logical LevelDB snapshot for each input, holds both database locks, and checks the live anchors and state again before returning. `network_id` is an operator claim tied to the genesis hash; a LevelDB state has no trusted network-name field. Distinct paths do not prove the sources were independent.

## Included records

The comparison includes the exact stored key and value bytes for:

| Category | QRL v3 LevelDB keys |
| --- | --- |
| `account` | Valid 39-byte binary QRL addresses and the 32-zero-byte coinbase address |
| `bitfield` | `bitfield_` + binary address + `_` + eight-byte big-endian page number |
| `pagination` | `p_tx_hash_`, `p_tokens_`, `p_slaves_`, `p_lattice_pk_`, `p_multisig_address_`, `p_multi_sig_spend_`, `p_inbox_message_`, and `p_proposal_tx_hash_` pages |
| `token` | `token_` token metadata and per-address token balances |
| `slave` | `slave_` per-address public-key permissions |
| `lattice` | `lattice_pk_` per-address lattice-key metadata |
| `vote` | `shared_key_` multisignature vote state |
| `proposal` | `proposal_record_block_number_` records |
| `config` | `dev_config_current_state_key` and `dev_config_` records |
| `supply` | `total_coin_supply` |

The address rule is the historical QRL v1 rule: 39 bytes, address-format high nibble zero, and the final four bytes equal to the last four bytes of SHA-256 of the first 35 bytes. The 32-zero-byte coinbase key is an explicit exception. Address protobufs must contain the same address as the key. The active dev-config pointer and target, coinbase state, and total supply must exist. A `fork_state` record indicates incomplete fork recovery and fails the comparison.

The tool also classifies, counts, and omits from the state digest the known auxiliary keys: decimal block-height mappings, 32-byte hash-addressed block or transaction records, `metadata_` block metadata, `blockheight`, `state_version`, `reorg_limit`, and `last_txn`. Independent nodes can retain different side-fork records, so auxiliary bytes are not an A/B acceptance condition. A key that fits none of the known shapes fails the command. The hash-addressed category is identified by its key length; the tool does not distinguish block bytes from transaction metadata within that category.

## Digest framing and result

Each state category has a fresh SHA-256 and SHA3-256 digest. Both start with these bytes:

```text
ASCII "qrl-v1-native-state-kv-v1" || 0x00
u32be(network_id UTF-8 byte length) || network_id UTF-8 bytes
genesis_hash[32] || u64be(fork_height) || fork_hash[32]
u64be(terminal_height) || terminal_hash[32]
u32be(category ASCII byte length) || category ASCII bytes
```

For each record in LevelDB unsigned-byte key order, both digests receive `u32be(key length) || exact key || u64be(value length) || exact stored value`. The tool never reserializes a protobuf or converts binary values through JSON. The report lists record count, sum of raw key and value lengths, and both digests for every category. It also lists all classified auxiliary-key counts and the total key count. Its first mismatch gives the key, category, value length and both value hashes for each present side, without copying raw values into the report.

Exit 0 means every included key and exact value matched and both sources remained stable under the checks above. Exit 5 means an included key or value differed; the failure report retains both category digests and the first mismatch. Malformed, unknown or unsupported source data fails without an equality claim. The report fields `consensus_verified`, `replayed_state_verified` and `source_independence_verified` remain false. This comparison does not replay blocks, prove PoW or transaction validity, or establish independent node provenance. Preserve custody records and the separate canonical-block comparison with it.
