# Draft session lifecycle laboratory

This package computes the life of a session from stated, already verified facts.
It implements **only row 1** of “What can be built from this LIP” in
[LIP-0028 at v0.1.49](https://github.com/relux-works/swarma-link-spec/blob/v0.1.49/lips/LIP-0028-sessions.md),
commit `1c3bcafc8bfc1450c3c0cefb69a122f6a97a448e`.
The annotated tag was signature-verified before implementation.

LIP-0028 is **Draft**. J13 has one owner's decision and awaits the co-author;
the draft's additions await acceptance. A v4 service still admits signed
invocations alone. `session.Draft` explicitly selects this laboratory profile;
the zero value and every other profile refuse. Nothing here enables sessions in
the running proxy. All pre-existing proxy source, configuration, dependencies
and CI definitions remain unchanged. The root credential guard inventory also
audits this package’s three ephemeral carriers.

## Boundary and use

`Apply(profile, state, facts)` returns a new abstract state and a verdict. It
never changes its input. The facts state the independently pinned executor,
ordered proof path, authenticated recipient key, observation/admission verdicts,
connection-derived peer, service clock and completed journal write. Successful
prerequisite checks must be explicit. Missing facts refuse. Model labels such as
`NAME_FACTS`, `KEY_FACTS` and `JOURNAL_WRITE` describe missing prerequisites;
a supplied upstream refusal is preserved. They do not extend LIP-0028 §8.

`DrawToken` uses `crypto/rand` to produce 32 octets. The pure reducer consumes a
successful draw as a fact. The resulting state holds only SHA-256, and the open
result carries the token once. `Facts.Random` holds that exact token value,
not a seed; `Facts.Token`, `Facts.Random` and `Result.Token` are audited carriers.
`Token` redacts fmt verbs (including numeric/hex), JSON and text marshaling.
`RevealForOpen` is the sole explicit raw output accessor, for delivery of the
successful opening reply. The reducer reads raw bytes internally only to draw
entropy and compute SHA-256. No caller should cast/index/slice the array for
output; this value model does not prevent deliberate casts or erase copies.
The one-time guarantee is issuance by `Apply`, not consuming/zeroing the caller’s
value, and there is no token wire encoder in this laboratory. Neither replay,
extension, close nor restart returns a token. A lost opening reply leaves its
session standing; a fresh signed close and a new open are the recovery path.
Synthetic entropy in the fixtures is public test data, never a usable credential.

`CheckUse` and `Reserve` expose the interleaving at the atomic write boundary.
A prepared request holds no token and reserves nothing. `Reserve` uses the
current state's final end and closure records, the final observation/clock
facts, and the checked last signed key. It checks own, optional row, then session
accounts for each consumption key, publishing all debits together. A prepared
request reserves at most once; another unsigned token request gets a distinct
service identity and is charged again. Callers must serialize transitions
against one authoritative current state. Independent forks do not constitute a
shared ledger. The race tests verify pure concurrent forks, not journal locking.

The window is exclusive at its end. Open and extension require
`0 < end - now <= 3600`, with subtraction after the ordering check to avoid
unsigned wraparound. Extension keeps the later end and updates only the last
signed key. Expiry, close and a recorded closure of **any** grant on the proof
path are final. An unvalidated spend, failed observation or unreadable name
refuses without ending. The request that discovers a validated closure returns
the upstream closure refusal; subsequent token requests return `SESSION_ENDED`.

Session ceilings reserve none of the grant. Missing session or grant limit
keys mean zero. Only cumulative account limits are represented. Operator caps
apply where explicitly present, including an explicit zero. Parent own and
parent row accounts are separate; children debit their own and their row.
Counters never decrease. `StartAnew` discards sessions and signed request
identities, fences `iat <= fenced_at`, and retains the **stated** grant exposure,
closures and monotonic clock. It does not reconstruct a lost grant ledger.

## Exclusions and limits

Out of scope: request octets, invocation members or assigned wire commands;
the journal entry form, durable I/O, continuity proofs and recovery procedure;
a real LIP-0022 observation or LIP-0021 name reads; sockets and peer credential
collection; wiring into the running proxy or its HTTP surface; harness and
key-holder implementation; deployment, paid requests and node calls.

The prerequisite facts stand for LIP-0008 §§2, 4, 5, 5.1 and 12;
LIP-0013 §3.6; LIP-0006 §§1 and 4; LIP-0007 §1; LIP-0020;
LIP-0022 §§1–3; LIP-0025 §§3–5; and LIP-0026 §5. This package
verifies none of their signatures, transactions, names or observations.
`WriteOK` states that the abstract transition can commit before any success
reply. It is not a substitute for the store/advance order of LIP-0025.

A uid or address is a **connection fact**, not a caller assertion. The model
accepts canonical bare IP addresses; actual relay/address semantics remain
open. Same-uid token copies work. Same-address copies work, including peers
behind shared address translation. The service cannot observe the origin of a
run or enforce T7.1–T7.7. In particular, two origins sharing a uid defeat the
key-holder origin gate; the known-limit vectors explicitly admit that copy.
No local-socket harness integration or workload attestation is claimed.

[The rule map](RULE-MAP.md) distinguishes decision parts, proposals and external
obligations, and maps every §9 case. [Open questions](UNRESOLVED_QUESTIONS.md)
record the stricter interpretations used here.

## Refusal order

The eleven codes in §8's printed order are:

1. `SESSION_CHANNEL`
2. `SESSION_REPLAY`
3. `SESSION_BINDING`
4. `SESSION_WINDOW`
5. `SESSION_LIMITS`
6. `SESSION_UNKNOWN`
7. `SESSION_TOKEN`
8. `SESSION_PEER`
9. `SESSION_ENDED`
10. `SESSION_COMMAND`
11. `SESSION_LIMIT_OVER`

This list is not a global pipeline. Open checks channel, upstream admission,
replay, binding, window and limits. Extend checks upstream admission, replay,
unknown, ended and window. Close omits ended and window. Token use checks channel,
token, peer, ended, command, proof recheck and accounts. At the atomic reservation,
the current session end precedes the grant closure read. None of these eleven
codes establishes a grant closure.

## Tools and verification

Use Go 1.26.10 with `GOTOOLCHAIN=local` and `GOWORK=off`. From the parent
`model-proxy` module, with task-owned temporary/cache directories configured:

```sh
gofmt -l session/*.go
go vet ./...
go test -race -count=1 ./...
go build ./...
python3 -I session/tools/second_reader.py
python3 -I session/tools/mutants.py .temp/session-mutants
```

`testdata/lifecycle.json` is a **logical test fixture**, not a protocol schema.
Each scenario has a claim, T-rule references and expected verdict/state assertions.
The explicit `base_facts` are overlaid by each step's complete changed fields;
missing prerequisite checks can be tested with an empty `Checks` object.
Go's `TestVectors` and the independent Python reader both compare against these
requirement-derived expectations. Agreement alone is not the oracle. Both check
that a refusal makes no partial debit or session/request-identity allocation.
The Go tests also check input immutability and token custody.

Python uses the standard library, requires isolated mode (`-I`), imports no
implementation code and invokes no Go code. Its arithmetic uses arbitrary
precision, independently of the Go unsigned bounds. It prints a compact JSON
verdict histogram. Mutation controls use Go compiler overlays against only this
package, preserving the candidate source. They cover all eleven refusal codes,
window arithmetic, expiry, extension, token storage/replay, the profile gate,
closure validation/races, atomicity, recovery fencing and fmt/JSON/text custody
(including removal of each redaction method and a corrupted explicit return). Each killed control
requires a named failing test and assertion; a build failure, panic, timeout or
survivor is not a detection. Logs, PIDs, hashes, commands, exits and witnesses
are written only to the supplied `.temp/` output directory.

The unchanged module checks remain `go mod download`, `go mod verify`, the
published-sibling CLI build, root credential-output guard, sibling gatewaybind
vet/race/build, proxy guard tools and daily parallel-reservation stress. The
repository `.scripts/check-module-graph.py` and
`.scripts/check-strict-module-snapshots.py` check dependency/snapshot policy.
This package imports only Go's standard library and adds no require edge.
Local verification does not claim a hosted CI result or production qualification.
