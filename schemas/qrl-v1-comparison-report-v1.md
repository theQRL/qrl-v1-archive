# Canonical export comparison report, version 1

`qrl-archive compare` takes two distinct canonical export directories and one set of expected network, genesis, fork and terminal anchors. It runs the structural verifier on each export before comparing their exact stored protobuf values in height order. It compares bytes directly, so a protobuf value with different unknown fields counts as a difference even if both values decode to the same known fields. Different shard boundaries and run IDs do not affect the byte comparison.

The JSON report uses the existing `qrl.v1.archive.report.v1` envelope and a `qrl.v1.archive.compare.v1` result. The comparison envelope omits wall-clock timestamps so the same inputs and tool version produce identical report bytes. JSON keys are sorted, separators are compact, strings are UTF-8, and the file ends with one newline. The report path is append-only. A fresh path is required for each run.

The result contains the six expected anchors, total block count, one section for each export, the first mismatch or `null`, and booleans for exact-byte equality and verification scope. Each export section contains its run ID, SHA-256 of the exact `shards.json` bytes, shard and transaction counts, total raw block bytes, and SHA-256 and SHA3-256 of the framed block stream. The framed stream digest is calculated over these bytes in this order:

```text
ASCII "qrl-v1-canonical-block-bytes-v1" || 0x00
for each height from 0 through the terminal height:
    uint64_le(height) || uint64_le(raw_protobuf_length) || raw_protobuf_bytes
```

Each hash algorithm starts with a fresh digest state. These stream digests are independent of shard filenames and boundaries. The first mismatch records its height, byte lengths, SHA-256 and SHA3-256 of each raw protobuf value. The tool reads all blocks to finish both whole-stream digests even after finding a mismatch. It exits 0 only if both archives pass structural verification and all exact bytes match. A byte difference exits 5 with the full result in the failure report. Invalid archives, changed index or shard bytes, or wrong anchors fail before a comparison result is accepted.

`structural_verified_a` and `structural_verified_b` mean the current structural verifier passed. `consensus_verified` and `source_independence_verified` are always false. Operators must keep independent source provenance, native state checks, consensus checks, and signing evidence outside this report.
