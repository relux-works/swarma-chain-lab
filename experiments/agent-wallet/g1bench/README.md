# Regtest envelope grant-admission bench

This laboratory verifies native-shaped Ed25519 `swarm-envelope/2` fixtures, then
Track A BIP-340 co-signatures, before checking real v3 standing grants through
the transport-neutral `grantcheck` API. It returns routing observations and
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

The Ed25519 envelope is unchanged by Track A: `ed25519:` plus canonical
unpadded base64url public bytes, the `swarma-msg/2` domain plus LF and the
canonical protected record, signed directly with ordinary Ed25519. The content
id hashes that domain plus LF and canonical body. The target is a station
object. The closed `observe` handler and proof/terms arguments are bench policy.
Keys are generated fixtures and `author_attestation` is a synthetic zero
reference, without root, generation or revocation attestation verification.
This establishes native-shaped envelope mechanics, not native trust conformance.
The BIP-340 author profile (Track B) is a separate future change; it is not
needed for Track A. See [UNRESOLVED_QUESTIONS.md](UNRESOLVED_QUESTIONS.md).

Track A uses the following exact co-signature construction.
The separate content key `works.relux.cg1.cosignature` holds exactly
`{version:"a2a-link-cg1-cosignature/1",key:"bip340:<lowercase x-only hex>",sig:"<128 lowercase hex>"}`.
Let `tag = SHA256("a2a-link cg1 cosignature/1")`; the signed digest is
`SHA256(tag || tag || uint64_be(len(envelope)) || exact_envelope_bytes)`.
It neither reserializes nor changes the Ed25519 envelope. Parsing requires
exactly 64 signature bytes, `r < p` and `s < n` before the library parser;
canonical high-s BIP-340 signatures are accepted. The strict helper is local
with a TODO to reuse the shared helper after it lands on main.

Each message signs exactly one `to`: the exact recipient carrier id, never a
key or an addressee list. `Gate.Outbound` resolves that signed id through a
per-identity protected binding copied at construction to exactly one BIP-340
key, then calls `OutboundFrom` with one `RecipientProof` key. Missing bindings
refuse `recipient_unresolved`; a wrong binding without live proof refuses
`no_grant`. Forwarding with a mismatched protected recipient refuses
`envelope_invalid`. A multi-recipient delivery requires separately signed
envelopes. No key comes from text, room membership or a message claim. This
bench supplies bindings from protected harness configuration, not a production
attestation registry or installed per-identity config.

The codec accepts only canonical JSON from its closed, all-string message
schema. It rejects duplicate/aliased/unknown members, altered delivered text,
room or recipient, bad signatures and invalid message lifetime/nonce. It bounds
carriage to 60 KiB, envelopes to 64 KiB and proof/terms individually to 16384
bytes. It uses a random 16-byte nonce. The signing helper is laboratory tooling.

`Gate.Admit` takes protected carrier routing separately from message content.
Envelope verification precedes the independent co-signature check. Only the
verified BIP-340 co-signer reaches
`InboundFrom(ctx, SenderProof{SwarmEnvelopeV2, key}, presentation)` on a checker
constructed with `NewForTransport(cfg, SwarmEnvelopeV2)`. The legacy compatibility
function is removed. Admission routes use `Verdict.A2ADecision()`; exact original
checker codes remain separately observable in results and assertions.
Neither a Matrix id nor a claimed message sender supplies authority. Every live
result requires a new node/checker observation; no live verdict is cached.
Canonical terms must hash to the signed grant's contract and name the locally
pinned executor. Trusted owner-DM routing returns `outside_admission` before any
checker, node or replay-cache call; this is not an admission bypass returning live.

The wallet module's declared rental and grantcheck versions include the
terms-v2 and transport APIs used here. The published-consumer graph gate also
compiles this package without local replacements, beside a known stale-version
negative control. Local replace directives remain development conveniences.

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
| Bad envelope signature | `BadSignature` | Correct body/id and valid co-signature cannot rescue corrupted Ed25519 signature |
| Wrong co-signer key | `WrongKey` | Verified co-signer must equal the grant-named key |
| Wrong executor | `WrongExecutor` | Hash-bound terms must name the protected executor |
| Unknown issuer | `UnknownIssuer` | Direct CG1 early pin and full Gate refusal propagation; known issuer passes |
| Before grant window | `BeforeWindow` | Re-signed, Core-anchored grant live at start, refuses `not_yet` before start |
| After grant window | `AfterWindow` | Inside-window control; exclusive end refuses before chain work |
| Unsynced node | `StaleNode-ibd` | IBD RPC semantics refuse at the bench boundary |
| Old node height | `StaleNode-height` | Actual older RPC snapshot below protected floor refuses |
| Header catch-up | `StaleNode-headers` | Headers ahead of blocks conservatively refuse |
| Envelope/nonce replay | `Replay` | Repeated envelope refuses; fresh nonce still passes |
| Matrix id as sender | `MatrixSender` | Direct CG1 call refuses a carrier id as a key |
| Owner DM | `OwnerDM` | Outside admission, no checker reads or nonce consumption |
| Text claiming authority | `TextAuthority` | Same text cannot rescue wrong key; no chain effect even when live |
| Delivery binding | `DeliveryBinding/{text,room,to}` | Exactly `refused/envelope_invalid`, no checker reads; text keeps outer carriage equal; unchanged envelope passes |
| Mempool seal spend | `SealMempool` | Same warm Gate/checker/state and cold neighbour refuse with `seal_spent`/Closed; counterpart stays live |
| Confirmed seal spend | `SealConfirmed` | Retained warm Gate and fresh checker refuse after confirmation; independent selection warms before spending |
| Missing co-signature | `CosignatureMissing` | Valid Ed25519 envelope alone refuses `cosignature_missing`; unchanged valid pair passes |
| Other signed bytes | `CosignatureDifferentBytes` | Even a whitespace change to co-signed bytes refuses `cosignature_invalid` |
| Valid envelope, invalid co-signature | `Ed25519ValidCosignatureInvalid` | Envelope verification cannot rescue invalid co-signature math |
| Malformed co-signature lengths | `CosignatureLength63`, `CosignatureLength65` | Non-64-byte encodings refuse beside valid pair |
| Scalar at group order | `CosignatureSAtOrder` | `s = n` refuses beside valid pair |
| Coordinate at field prime | `CosignatureRAtPrime` | `r = p` refuses beside valid pair |
| Valid high-s | `CosignatureHighS` | Real verifying `n/2 < s < n` co-signature passes |
| Co-signature-independent replay | `CosignatureIndependentReplay` | Two valid co-signatures on identical envelope bytes still admit only once, without new chain reads |
| Protected outbound binding | `OutboundRecipientBinding` | One signed recipient per envelope; missing/wrong pins and forwarding refuse, pinned sends pass and bindings are copied |


`TestEnvelopeFixtureProfile` adds offline codec negatives with a real signing
positive control. Every codec negative requires the exact `errEnvelope` sentinel.
`TestCoSignatureStrictBounds` checks pre-parser len/r/s bounds beside a fully
verifying high-s control. `TestCoSignatureMalleatedScalar` shows that the pinned
library normalizes a synthetic `s=1`/`s+n` pair, while the strict wrapper rejects
the alias. That pair proves encoding behavior, not valid signature math; the
adjacent high-s control verifies fully. `TestCoSignatureDigestVector` binds the
exact framing to an independently computed SHA-256 vector.
Expiry uses an unchanged valid lifetime observed at its exclusive end, so the
window-order predicate remains valid. All Core negatives assert exact route/code
pairs; height faults also prove no other sync predicate fails. The warm revocation
cases explicitly check the same checker's cached proof is live before spending,
then send a fresh nonce through the retained Gate after the real spend. No live
verdict is accepted in place of the new check.

The sync seam always calls the real read-only RPC observer.
It changes only `initialblockdownload`, or `headers=blocks+1`, or returns an
actual earlier `getblockchaininfo` response captured before fixture issuance.
All other RPCs remain real. The protected height floor is captured independently
after issuance, never supplied by the message. These are controlled RPC faults,
not a second live replica or a full network synchronization experiment.

The before-window grant is an explicit boundary fixture: its original valid
consent is retained, `not_before` moves later, the fixture issuer re-signs it,
and the existing Core helper broadcasts/confirms the new issuance commitment.
This isolates the time guard from the pay-grant helper's earlier-consent rule.

All 19 original overlays remain, with three added Track A overlays.
Overlay control commands, exact named tests and the limits of each kill are
listed in [CONTROLS.md](CONTROLS.md). The script records source/mutant hashes,
process exits and intended assertion witnesses; unrelated failures are invalid.

## Limits

Regtest only. Fixture keys only. No mainnet contact or broadcast, no real issuer
key, no installed consumers, transport registration, native envelope trust or
cross-user custody qualification. The two identities use separate chains because
the existing fixture has fixed names. The gate's replay set lasts one instance,
is bounded to 4096 accepted directional envelope ids, and fails closed at capacity; it
provides no replay continuity across restart. The height floor and explicit sync
flags do not prove wall-clock freshness of a connected node. A live verdict is a
bounded observation, never a permission to execute text or a token for later use.
