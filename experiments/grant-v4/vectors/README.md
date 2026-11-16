# Grant v4 primitive vectors

**no valid swarma-grant/4 vectors until B0**

See [VECTORS.md](VECTORS.md) for the format, exact source citations, per-vector
purpose/coverage, independent re-derivation and outstanding B0 decisions.

## Tools

Go 1.26.10 generates and drift-checks the fixtures against the sibling wire lab.
Python 3 uses only its standard library for an independent derivation. In an
isolated checkout with task-owned absolute HOME, config, caches and TMPDIR:

```sh
go -C experiments/grant-v4/vectors run ./cmd/generate > .temp/vectors-regenerated.json
go -C experiments/grant-v4/vectors test -count=1 ./...
go -C experiments/grant-v4/vectors vet ./...
python3 -I experiments/grant-v4/vectors/scripts/check-vectors.py
```

The generator writes stdout; tests compare with `vectors.json`. Put diagnostic
outputs in `.temp/`. Full wire/test/build/hygiene and one-byte control commands
are documented in VECTORS.md. No grant schema, real key, node or issuer is used.
