# Local signer fixture

`signer_fixture.py` runs the `actions-mldsa-sign@v2` entry point and manifest
builder with the qrlft commit pinned by its v2.0.0 Dockerfile. It creates two
temporary ML-DSA-87 keys, signs a small test notice and a synthetic part, checks
the manifest and both artifact signatures, then checks that altered artifact
tail bytes, manifest bytes, tag, public key and both purpose contexts fail.
Nothing in this fixture is QRL chain data or a release. The keys and outputs
exist only in a temporary directory. It never reads the organization key.

Run from a host with local `theQRL/actions-mldsa-sign` and `theQRL/qrlft`
checkouts at `~/actions-mldsa-sign` and `~/qrlft`, plus Go, Python 3.12 or
later, Bash and `jq`:

```sh
python3 -m unittest discover -s release -p test_signer_fixture.py
python3 release/signer_fixture.py --smoke-only
python3 release/signer_fixture.py
```

The first two commands should pass. The last returns exit code 2 and reports
`release_readiness=FAIL`. That is deliberate. Action v2.0.0 pins qrlft
`edc20365292418f65865c831f3d1364e62e34801`; its signing and verification
readers call `Read` once and can omit the end of a file on a short read. The
current small-file fixture proves the action format and rejection checks, not
that large archive parts are safe. The action Docker image itself is not run by
this fixture. The [live snapshot signing procedure](LIVE-TESTNET-SNAPSHOT.md)
records the independently tested v3 image with the full-file reader, its
immutable digest and a measured 67,108,881-byte test.

The separate G0 key-custody check must use the authorized existing QRL release
seed inside its approved isolated local 1Password signing route, then
independently verify its signed fixture against the public key pinned from
`theQRL/security`. This disposable
test does not satisfy that gate.

Run `python3 release/large_part_fixture.py` for a second test at the canonical
64 MiB shard cap. It archives the exact v2 action scripts from the pinned Git
commit, builds both the v2-pinned qrlft for a disposable key and the reviewed
full-read qrlft commit for signing, then checks the deterministic manifest and
separate signature contexts. It flips the final byte of the part and requires
signature verification to fail. The test neither runs the published v2 Docker
image nor uses the organization key; those release gates remain separate.
