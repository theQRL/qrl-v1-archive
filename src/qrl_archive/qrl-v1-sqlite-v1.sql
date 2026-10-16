-- QRL v1 derived SQLite schema, version 1.
-- application_id 0x51524c31 is ASCII "QRL1". It identifies this database,
-- while user_version tracks the logical schema version.
-- A builder must enable foreign keys, validate decimal text before insert,
-- run foreign_key_check and integrity_check, VACUUM, then reopen read-only.
PRAGMA application_id = 0x51524c31;
PRAGMA user_version = 1;
PRAGMA foreign_keys = ON;

CREATE TABLE archive_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
CREATE TABLE blocks(
  height INTEGER PRIMARY KEY, hash BLOB NOT NULL UNIQUE,
  previous_hash BLOB, timestamp INTEGER NOT NULL,
  merkle_root BLOB, mining_nonce TEXT, block_reward_shor TEXT,
  fee_reward_shor TEXT, tx_count INTEGER NOT NULL,
  canonical_shard TEXT NOT NULL, canonical_offset INTEGER NOT NULL,
  canonical_length INTEGER NOT NULL
) STRICT;
CREATE TABLE transactions(
  tx_hash BLOB PRIMARY KEY, height INTEGER NOT NULL REFERENCES blocks(height),
  tx_index INTEGER NOT NULL, kind TEXT NOT NULL,
  from_address BLOB, signer_address BLOB, master_address BLOB,
  fee_shor TEXT, nonce TEXT, public_key BLOB, signature BLOB,
  raw_pb BLOB NOT NULL, UNIQUE(height, tx_index)
) STRICT;
CREATE TABLE tx_outputs(
  tx_hash BLOB NOT NULL REFERENCES transactions(tx_hash),
  output_index INTEGER NOT NULL, to_address BLOB NOT NULL,
  amount_shor TEXT NOT NULL, asset_id BLOB,
  PRIMARY KEY(tx_hash, output_index)
) STRICT;
CREATE TABLE address_events(
  address BLOB NOT NULL, height INTEGER NOT NULL,
  tx_index INTEGER NOT NULL, tx_hash BLOB NOT NULL,
  role TEXT NOT NULL, output_index INTEGER NOT NULL DEFAULT -1,
  amount_shor TEXT,
  PRIMARY KEY(address, height, tx_index, role, output_index)
) STRICT;
CREATE TABLE final_address_state(
  address BLOB PRIMARY KEY, balance_shor TEXT NOT NULL,
  nonce TEXT, ots_state BLOB, state_pb BLOB, source TEXT NOT NULL
) STRICT;
CREATE TABLE tx_details(
  tx_hash BLOB PRIMARY KEY REFERENCES transactions(tx_hash),
  kind TEXT NOT NULL, decoded_json TEXT NOT NULL
) STRICT;
-- GenesisBalance is a block field, not a transaction output. Keep it separate
-- rather than attributing it to the genesis coinbase transaction.
CREATE TABLE genesis_allocations(
  allocation_index INTEGER PRIMARY KEY, address BLOB NOT NULL,
  amount_shor TEXT NOT NULL
) STRICT;
CREATE INDEX transactions_height ON transactions(height, tx_index);
CREATE INDEX transactions_from ON transactions(from_address, height DESC);
CREATE INDEX transactions_signer ON transactions(signer_address, height DESC);
CREATE INDEX outputs_to ON tx_outputs(to_address, tx_hash);
CREATE INDEX address_events_page ON address_events(address, height DESC, tx_index DESC, role, output_index);
