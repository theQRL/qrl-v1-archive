# Archive checks

`test_block_stream.py` checks exact stored-byte export, shard boundaries, source locking, declared tip, identities, altered digests, truncation, reordered ranges, duplicate transaction hashes and failure reporting. Its tiny blocks are intentionally synthetic and do not satisfy QRL PoW. Run it with `PYTHONPATH=src python -m pytest -q tests/test_block_stream.py` in an environment with the packages from `pyproject.toml`.

Independent consensus, derived-schema, signature, tamper and clean-room recovery tests remain to be implemented. The placeholder assets are transport fixtures only.
