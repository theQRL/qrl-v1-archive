# QRL v1 canonical block stream, version 1

This format carries the exact protobuf value stored by a pinned QRL v1 node for each main-chain block. It does not carry RPC-reserialized blocks. An archive release also needs native node preservation, independent export, consensus verification, derived data, signatures and recovery evidence. This format alone proves none of those.

Each `.qrlblk` shard starts with the following fields in this order:

| Field | Encoding |
| --- | --- |
| Magic | Eight ASCII bytes `QRLV1BLK` |
| Version | Unsigned 32-bit little-endian integer `1` |
| Network ID | Unsigned 32-bit little-endian byte length, then UTF-8 bytes |
| Genesis hash | Unsigned 32-bit little-endian byte length `32`, then 32 raw bytes |
| First height | Unsigned 64-bit little-endian integer |
| Last height | Unsigned 64-bit little-endian integer |
| Record count | Unsigned 64-bit little-endian integer |

Each record is an unsigned 64-bit little-endian height, an unsigned 64-bit little-endian byte length, then precisely that many stored protobuf bytes. There is no padding or trailer. Heights are contiguous from zero through the declared terminal height across all ordered shards. A shard contains one to 10,000 whole blocks and cannot exceed 64 MiB. Exporters can choose a lower measured byte cap. They never split one block across shards.

`shards.json` has schema `qrl.v1.archive.shards.v1`, format name `qrl-v1-block-stream-v1`, required `protobuf_schema_sha256`, `protobuf_binding_sha256` and `protobuf_descriptor_sha256` fields, run and chain identity, fork and terminal height/hash, block and transaction counts, configured shard caps, and an ordered `shards` array. These are SHA-256 of the exact included `qrl.proto` bytes, the exact included generated `qrl_pb2.py` bytes, and `qrl_pb2.DESCRIPTOR.serialized_pb`, respectively. Export and verification fail if a shipped component differs from its pinned digest, or if an index pin is missing or wrong. Each shard entry has a unique basename, first and last height, record count, byte count, SHA-256 and SHA3-256 of the whole shard. Writers serialize the index as UTF-8 JSON with sorted keys, compact separators and one trailing newline. Hash strings are lowercase hexadecimal. The index needs its own release signature through the later signed inventory and action manifest; hashes inside an unsigned index are only error detection.

The structural verifier checks framing, file sizes and both hashes, contiguous heights, protobuf parsing, header numbers and stored hashes, previous-hash links, genesis/fork/terminal identity, transaction oneof presence, and global duplicate block/transaction hashes. It does **not** recompute QRL header hashes, prove difficulty or PoW, validate transaction signatures or historical consensus exceptions, compare final address state, verify a second source, or verify release signatures. `consensus` and `full` modes fail until those checks are implemented.

The included protobuf is from QRL v4.0.1 commit `759c9bbb8351a4fa6a20081085e5d3b10d1bc854`; `qrl.proto` SHA-256 is `0d70a3372c4668a1bf4fd42983ae01f2e0fb54b4030b808bbea78e5adadb23f0`. The generated Python binding has file SHA-256 `a6d9fdd3d3490ae04171c4a6fd777bfc42ca2f38f73788893069cc366f7cd4d3` and descriptor SHA-256 `9e65bd19e719a916f46ff2f3b9e5696996c2ae0203d0f9068e707395baf357f0`; it is licensed under the included QRL MIT license. The source `qrl.proto` is byte-identical in the QRL v4.0.1 through v4.0.11 tags. This source comparison, or a mainnet API response decoded with the same protobuf, does not establish which build is running on mainnet or prove that the reader handles native mainnet LevelDB state. Before mainnet use, pin the live node build and database state version, compare its protobuf, and test real mainnet genesis, historical transaction types and a recent tip on a disposable stopped database copy. Preserve exact-byte golden fixtures and independent expected hashes; do not silently replace this binding if a future schema differs.
