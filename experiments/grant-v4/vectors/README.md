# Grant v4 primitive vectors

No valid swarma-grant/4 vectors until LIP-0020 defines its members.

See [VECTORS.md](VECTORS.md) for the format, exact pins, per-vector inventory,
independent derivation, lab-choice verdicts and specification requirements.

## Tools

Go 1.26.10 generates fixtures and checks drift against the sibling wire lab.
Python 3 independently derives specified results using only its standard library.
The CI entrypoint creates isolated sibling-module copies and short absolute
HOME/config/cache/temp paths, and removes its caches on exit:

```sh
python3 -I experiments/grant-v4/vectors/scripts/check-ci.py --scratch .temp/vector-checks
```

Logs and command exit codes go in the supplied evidence directory. The entrypoint
runs module download/verify, formatting, vet, tests, build, Python derivation,
checker regressions and paired Go/Python one-byte drift controls. The generator
entrypoint is `go run ./cmd/generate` within this module and writes only stdout.
Full commands and the deliberately failing `--plant-drift` control are in
[VECTORS.md](VECTORS.md#tools-and-commands). No real key, grant or node is used.
