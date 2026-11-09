# Local composition rehearsal

This opt-in Go harness extends the earlier IT1 composition survey with the actual
RL1 relay, tagged Darwin manager, BG1 V2 producer and the PL1 scripted payload
build. A passing diagnostic run means its recorded boundary was reproduced; it
does **not** mean the complete M5 rental lifecycle passed.

The target is the first unresolved seam, G6. Gateway exchange uses v1 booking
requests. Legacy v1 can complete terms/consent/payment but intentionally produces
no SG1 V2 index. Selecting the actual V2 CLI retains the catalogue shape, then
the gateway's v1 Book request omits the payment coin: HTTP refuses with
`COIN_PROFILE` and the exchange reports `BookPending`. The harness checks
that no slot/hold was silently created, and uses a separate direct HTTP V2
book/consent/payment as the positive control: its original exported Item is read
by the actual signer FileSource. It does not convert the v1 contract, synthesize
an intake Item, issue a substitute grant or bridge around the gateway failure.

The node is genuine isolated Namecoin Core regtest with network discovery and
network activity disabled. CLI and daemon hashes are pinned in the harness.
Only fresh fixture wallets and keys are used. Actual booking, store, signer,
gateway, relay, manager and payload binaries are built from the requested exact
signed head; every exercised source path must match it and have no untracked
files. Manager alone uses `-tags slotdfake`, including its explicit fixture clock.
Other binaries use ordinary builds. The manager startup probe does not imply a
helper or payload was started when issuance is blocked.

The scripted payload's separate tests exercise real proxy accounting against a
fake HTTPS upstream, TLS/HMAC, v1/v2 and refusal controls. If full composition
eventually reaches registration on macOS, the approved substitution is narrowly
an in-process registrar into the real MP1 Service, replacing Linux peer-credential
admin transport in harness code only. The current G6 diagnostic does not reach
or exercise that substitution. Production keeps the Linux-only admin rule.

Issued/ready, live slot delivery, expiry cleanup and early revoke remain NOT RUN
when the first break is G6. Assertions are intentionally specific so a future
G6 fix requires extending the harness instead of silently calling a stale
diagnostic proof a full success.

## Tools and artifacts

Go1.26.8, Darwin, landed BG1/RL1 dependencies and installed pinned modules are
required. Choose a new absolute root for every run; never reset a prior fixture.

```sh
export GOTOOLCHAIN=local GOWORK=off GOPROXY=off GOSUMDB=off GOFLAGS=-mod=readonly
go mod verify
go vet ./...
go test -race -count=1 ./...  # scanner control only; Core explicitly skipped
IT1_REGTEST=1 IT1_PRODUCT_HEAD=<exact-signed-task-head> \
 IT1_RUN_ROOT=/absolute/new-private-run \
 IT1_CORE_DAEMON=/absolute/pinned/namecoind \
 IT1_CORE_CLI=/absolute/pinned/namecoin-cli \
 go test -race -count=1 -timeout 8m -v ./...
```

`<run>/public/result.json` records stages, binary pins, first break, known-secret
scan and direct-PID absence. `<run>/private` contains fixtures, wallets, keys,
configs, native binaries and process logs; never export that directory. A known
canary tests scanner detection beside a public neighbor. That scanner does not
prove absence of unknown secrets, and direct-PID receipts do not inventory every
compiler/runtime descendant. Ordinary command logs belong under `.temp/`.
