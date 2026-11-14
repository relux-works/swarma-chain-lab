# Regtest envelope grant-admission bench

This laboratory verifies BIP-340 envelope-shaped fixtures before checking real
v3 standing grants through `grantcheck`. It returns routing observations and
has no effect callback. Text is integrity-bound, never effect authority.

The existing `agent-wallet` module is the narrowest home: `TestG1BenchCore`
reuses `newPX1Core`, pinned binaries, RPC routes and issuance helpers. It invokes
`rental/cmd/rt-grant-fixture`, without copying provisioning code. That fixture
requires fresh fixed names, so two isolated regtest chains carry issuer-side
and counterpart identities, each with generated issuer/agent keys, registered
names and a live grant. The real terms-v2 issuer cross-binds their executor keys.

## Envelope profile and integration limit

The carriage key and unpadded base64url encoding follow the Matrix adapter at
`a2a-swarm` revision `86c2c308`, `internal/matrix/envelope.go`. The four-member
container and protected `{body,key,role,version}` record follow the
[envelope specification](https://github.com/relux-works/swarma-envelope/blob/e38510c503d266d36a275a5976f933e10fae4060/spec/swarm-envelope-2.md)
sections 2.1–2.4.

**The native specification has no BIP-340 message profile.** It permits Ed25519
authors and P-256 approvers, with attestation verification. This bench therefore
uses an explicitly separate fixture profile: `bip340:<lowercase x-only hex>`
keys, SHA-256 of `g1bench-message/1\n` plus the protected canonical record,
and a synthetic zero attestation reference. It is envelope-shaped, not native
`swarm-envelope/2` conformance or attestation evidence. Native deployment needs
a separately reviewed algorithm/profile or key-binding decision; see
[UNRESOLVED_QUESTIONS.md](UNRESOLVED_QUESTIONS.md).

The codec accepts only canonical JSON from its closed, all-string message
schema. It rejects duplicate/aliased/unknown members, altered delivered text,
room or recipient, bad signatures and invalid message lifetime/nonce. It bounds
carriage to 60 KiB, envelopes to 64 KiB and proof/terms individually to 16384
bytes. It uses a random 16-byte nonce. The signing helper is laboratory tooling.

`Gate.Admit` takes protected carrier routing separately from message content.
Only the verified BIP-340 key reaches the small `inbound` compatibility adapter,
which currently calls `Checker.Inbound(ctx, key, presentation)` from main. That
single function is the switch point for a later transport-neutral checker API.
Neither a Matrix id nor a claimed message sender supplies authority. Every live
result requires a new node/checker observation; no live verdict is cached.
Canonical terms must hash to the signed grant's contract and name the locally
pinned executor. Trusted owner-DM routing returns `outside_admission` before any
checker, node or replay-cache call; this is not an admission bypass returning live.

## Run and artifacts

Use Go 1.26 with `GOTOOLCHAIN=local`. Set `W1_CORE_DAEMON` and `W1_CORE_CLI` to
the existing harness's pinned Core 28.0 binary pair. Set `BENCH_WORK` to a fresh,
private, short directory under your workbench scratch root. From the repository
root:

```sh
mkdir -m 700 "$BENCH_WORK/t" "$BENCH_WORK/cache" "$BENCH_WORK/mod"
export TMPDIR="$BENCH_WORK/t" GOCACHE="$BENCH_WORK/cache" GOMODCACHE="$BENCH_WORK/mod"
export GOTOOLCHAIN=local GOWORK=off
mkdir -p .temp/g1bench
(cd experiments/agent-wallet && go mod download && go mod verify)
(cd experiments/agent-wallet && go vet ./... && go test -race ./g1bench)
(cd experiments/agent-wallet && W1_REGTEST=1 W1_RUN_ROOT="$BENCH_WORK/core" \
  go test -race -count=1 -timeout 20m -json -run '^TestG1BenchCore$' .) \
  > .temp/g1bench/core.json
python3 -B .scripts/check-px1-core-gate.py check \
  --manifest .scripts/g1-bench-core-gate.json .temp/g1bench/core.json
python3 -B .scripts/g1-bench-guards.py \
  --out "$PWD/.temp/g1bench/guards" --private-root "$BENCH_WORK/guards"
python3 -B .scripts/check-module-graph.py
python3 -B .github/scripts/check-public-hygiene.py
```

The Core harness stops only the node PIDs it starts. Private roots contain
throwaway keys, cookies, wallets and datadirs: never publish or upload them.
After all processes exit, make only your scratch tree owner-writable before
removing it. JSON test streams and overlay `results.json` belong in `.temp/`.
`gofmt -l experiments/agent-wallet/g1bench/*.go
experiments/agent-wallet/g1_bench_core_test.go` checks formatting.

The `Agent wallet checks` workflow runs this Core matrix with `-race`, all named
cases required by the manifest, and a real skipped-test control. The skip
control's `go test` must exit 0 and the gate must exit 1. The real run and gate
must both exit 0. A successful top-level run emits `G1_BENCH RAN_AND_PASSED`;
the JSON gate remains authoritative. The same job runs the overlay controls,
existing regtest fixture gate and `TestPX1T18CoreNodePolicy` gate.

## Case-to-test map

All rows below are subtests of `TestG1BenchCore`. Every refusal has a genuine
live neighbour; precondition/route checks additionally assert no checker reads
where applicable. Every test has an adjacent one-line claim in source.

| Case | Test | What it proves |
| --- | --- | --- |
| Two fixture identities | `TwoIdentities` | Both genuine grants live; cross-bound executor keys |
| No envelope | `NoEnvelope` | A cached grant cannot rescue absent carriage |
| Bad envelope signature | `BadSignature` | Correct body/id cannot rescue corrupted BIP-340 signature |
| Wrong envelope key | `WrongKey` | Verified signer must equal the grantee |
| Wrong executor | `WrongExecutor` | Hash-bound terms must name the protected executor |
| Unknown issuer | `UnknownIssuer` | CG1 pin refuses before reads or result metadata |
| Before grant window | `BeforeWindow` | Re-signed, Core-anchored grant live at start, exchange before start |
| After grant window | `AfterWindow` | Inside-window control; exclusive end refuses before chain work |
| Unsynced node | `StaleNode-ibd` | IBD RPC semantics refuse at the bench boundary |
| Old node height | `StaleNode-height` | Actual older RPC snapshot below protected floor refuses |
| Header catch-up | `StaleNode-headers` | Headers ahead of blocks conservatively refuse |
| Envelope/nonce replay | `Replay` | Repeated envelope refuses; fresh nonce still passes |
| Matrix id as sender | `MatrixSender` | Direct CG1 call refuses a carrier id as a key |
| Owner DM | `OwnerDM` | Outside admission, no checker reads or nonce consumption |
| Text claiming authority | `TextAuthority` | Same text cannot rescue wrong key; no chain effect even when live |
| Delivery binding | `DeliveryBinding` | Carrier cannot substitute text, room or recipient |
| Mempool seal spend | `SealMempool` | Real unconfirmed spend closes grant; other identity remains live |
| Confirmed seal spend | `SealConfirmed` | Same real spend confirmed; fresh checker still refuses |

`TestEnvelopeFixtureProfile` adds offline codec negatives with a real signing
positive control. The sync seam always calls the real read-only RPC observer.
It changes only `initialblockdownload`, or `headers=blocks+1`, or returns an
actual earlier `getblockchaininfo` response captured before fixture issuance.
All other RPCs remain real. The protected height floor is captured independently
after issuance, never supplied by the message. These are controlled RPC faults,
not a second live replica or a full network synchronization experiment.

The before-window grant is an explicit boundary fixture: its original valid
consent is retained, `not_before` moves later, the fixture issuer re-signs it,
and the existing Core helper broadcasts/confirms the new issuance commitment.
This isolates the time guard from the pay-grant helper's earlier-consent rule.

Overlay control commands, exact named tests and the limits of each kill are
listed in [CONTROLS.md](CONTROLS.md). The script records source/mutant hashes,
process exits and intended assertion witnesses; unrelated failures are invalid.

## Limits

Regtest only. Fixture keys only. No mainnet contact or broadcast, no real issuer
key, no installed consumers, transport registration, native envelope trust or
cross-user custody qualification. The two identities use separate chains because
the existing fixture has fixed names. The gate's replay set lasts one instance,
is bounded to 4096 accepted key/nonce pairs, and fails closed at capacity; it
provides no replay continuity across restart. The height floor and explicit sync
flags do not prove wall-clock freshness of a connected node. A live verdict is a
bounded observation, never a permission to execute text or a token for later use.
