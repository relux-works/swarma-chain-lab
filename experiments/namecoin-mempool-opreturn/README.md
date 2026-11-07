The [source and experiment plan](SOURCE_PLAN.md) specifies the measured and
unmeasured boundaries, exact inherited pins, observable timings, adversarial
cases, later read-only survey, and resource/cleanup contract.

`design.json` is the finite machine-readable schedule. `design.py` generates
27 deterministic public OP_RETURN script cases and exports that schedule. It
does not execute the runtime steps, create keys, sign, mine, or contact nodes.
The later driver and its independent signature verifier still require review.

To generate the fixtures, supply an empty absolute directory owned by the
current user, mode 0700, then run the launcher under aggregate resource limits:

```sh
systemd-run --user --wait --pipe --collect \
  -p MemoryMax=3G -p MemorySwapMax=0 -p CPUQuota=200% -p TasksMax=64 \
  -p RuntimeMaxSec=140 \
  bash experiments/namecoin-mempool-opreturn/offline.sh /absolute/private/output
```

The launcher uses a fresh network namespace, empty environment, read-only
source/tools, private tmpfs and absolute private HOME/TMP/cache. It requires
bwrap and the standard host systemd tools. Keep the generated `.bin` files and
`cases.json` together; hashes bind exact script bytes. Predicate fields in the
JSON are source expectations only. All relay/mining observations remain NOT_RUN.
