# CG1: grant verification boundary for a2a daemon (a2ad)

Status: implementation baseline with integration-owner corrections. This note
defines the Go library contract for the a2a maintainers; it does not claim a2a daemon
hooks are already installed. Base: chain-lab `c7dd20fa33c0d8827c73c4c847e3d60cbeb1e4c6`.
The module is `experiments/grantcheck`: a verifier and routing decision, with no
mailbox, transport send, messaging key, booking, exchange text or model capability.

## 1. Ownership and integration boundary

a2a daemon authenticates the station and resolves its identity, configured connection
and store before invoking this library. The checker belongs to that resolved
per-identity engine. A request's `--as`, profile or connection fingerprint may be
assertions checked by a2a daemon, never selectors supplied to the checker. No global
"current identity", fallback engine, cross-station cache, or request-controlled
node route/state directory is permitted.

The trusted engine constructor pins the a2a daemon identity, rented agent Namecoin
name, landlord Namecoin name, issuer grant key, sender provenance, canonical private state directory,
verifier clock and read-only node. The library copies that configuration, builds
the landed `kernelbind.Adapter`, and does not expose mutable policy. Identity and
policy binding are persisted separately from K1's own records. Opening the same
state root with a different identity or pins fails; it never relabels a cache.
The transport provenance is included in the binding hash. A pre-provenance state
hash is deliberately incompatible, even for Nostr: guessing or adopting a
previous cache would hide its missing provenance. Refusal leaves state unchanged;
this change supplies no migration and does not authorize discarding closure history.
Separate engine identities require separate private state roots. Binding these
roots to the authenticated station is a2a daemon's responsibility, tested at its
integration boundary; a string passed by an untrusted station is not proof.

The a2a maintainers own insertion of the following calls once a2a daemon's
per-identity engine boundary settles. CG1 changes no a2a-swarm source:

| Direction | Call point | Only a live verdict permits |
| --- | --- | --- |
| Inbound | After transport authentication and strict presentation extraction, before mailbox persistence/wake/model dispatch | Write the authenticated message to that identity's agent inbox |
| Outbound | After resolving the station's requested recipient in the same identity, immediately before agent-key signing/publication | Sign/send that reply to that exact grantee |

An inbound `exchange` result goes to a bounded per-identity spool defined by
a2a, feeding the separate deterministic exchange. It never permits inbox
writes, waking the model, signing arbitrary replies or creating an instance.
A `refused` result performs neither privileged action nor automatic exchange
fallback. No outbound result is `exchange`.

a2a daemon parks `Retryable` refusals in a bounded held queue and checks them again;
advancing the transport cursor must not silently discard these renter messages.
Queue capacity, persistence, expiry and overflow are a2a daemon's contract. CG1
does not own a queue or turn a retryable refusal into admission.

Upstream a2a defines an `admission` interface with no policy by default. The
a2a-link fork registers CG1 at build time; upstream never imports chain-lab.
The owner's decision T23 of 2026-11-14 states that transports only carry and
authority always comes from a signed envelope inside the message, on every
transport. Matrix grant policy is allowed for the v3 test bench only when the
sender key satisfies the contract below. The grant ID and canonical v3 proof of
at most 16384 bytes must be in the envelope or already cached. Owner DM stays
outside admission. Nostr remains the target transport; this does not replace
it, and v1 has no owner bypass on Nostr. A caller-selected provenance cannot
override the immutable constructor pin.

The `SwarmEnvelopeV2` sender is the grant-named BIP-340 key, verified by the caller
from a per-message BIP-340 co-signature over the exact swarm-envelope/2 bytes
(slice 1), or from a BIP-340 author profile of swarm-envelope/2 once one exists
(target); never the envelope's Ed25519 author key, a carrier id, a display name
or a message field. grantcheck does not verify the envelope or the co-signature
itself; it trusts the caller's verified key and checks the grant.

Track A (slice 1) changes only the downstream fork: it keeps the unchanged
Ed25519 `swarm-envelope/2` and carries a domain-separated, per-message BIP-340
co-signature by the grant-named key beside the envelope in the same message,
under its own content key. The adapter verifies the envelope first, then the
co-signature over those exact envelope bytes, and passes that BIP-340 key as
`SenderProof{Transport: SwarmEnvelopeV2, Key: verifiedCosignerKey}`. A missing,
invalid or mismatched co-signature is denied, not retryable, by the adapter
before calling grantcheck. The downstream adapter defines the byte construction
of the co-signature; this library does not.

Track B (target) proposes a proper BIP-340 author profile inside
`swarm-envelope/2` to its owner. If agreed, the co-signature can fold into that
profile later; slice 1 does not change the envelope format owned elsewhere.
`SwarmEnvelopeV2` names the carriage, not the signature scheme.

Outbound means agent-originated replies, not the exchange's fixed protocol
responses. The exchange is separately trusted and rate-limited; routing a normal
agent reply through it to bypass Outbound is forbidden. Scope returned by a live
verdict is authenticated metadata, not authority to execute effects: executors
still check action-specific grants independently.

## 2. Proposed narrow API

```go
type Presentation struct {
    GrantID string // exact lowercase SHA-256 of canonical signed_grant bytes
    Bytes   []byte // full canonical v3 {signed_grant,issuance:{txid}}
}

type Verdict struct {
    Decision  Decision // live | refused | exchange; closed enum
    Code      Code     // closed fixed code; no received error text
    GrantID   string
    Scope     []string
    NotBefore int64
    NotAfter  int64
    CheckedAt int64
    Closed    bool
    Retryable bool // fixed closed classification, never received/backend text
}

type Transport uint8 // closed: NostrNIP17Seal = 1, SwarmEnvelopeV2 = 2
type SenderProof struct { Transport Transport; Key string }
type RecipientProof struct { Transport Transport; Keys []string }

func New(Config) (*Checker, error) // fixed Nostr pin, existing API unchanged
func NewForTransport(Config, Transport) (*Checker, error) // required explicit pin
func (*Checker) Inbound(context.Context, string, *Presentation) Verdict // Nostr only
func (*Checker) InboundFrom(context.Context, SenderProof, *Presentation) Verdict
func (*Checker) Outbound(context.Context, string) Verdict // Nostr only
func (*Checker) OutboundFrom(context.Context, RecipientProof) Verdict
func (Verdict) A2ADecision() (verdict string, reason string, retryable bool)
```

The string parameter is a verified sender key inbound, an exact recipient key
outbound. Require precisely 64 lowercase hex characters representing a valid
BIP-340 key. In NIP-17 it is the verified inner seal signer, with the rumor key
required to agree; it is never the gift-wrap's ephemeral signer, a body field,
claimed display name, `p` tag sender, transport IP or supplied signature string.
The library cannot authenticate a transport by inspecting this string; the
transport adapter must establish that fact before calling it. `InboundFrom`
asserts either NIP-17 inner-seal verification with its verified signer key, or
the caller-verified BIP-340 sender key under Track A/B above. Envelope verification
alone does not establish the grant-named BIP-340 key in slice 1. Zero/unknown
provenance and pin mismatches refuse with `binding_mismatch`; invalid keys use
`invalid_peer`. `NewForTransport` refuses unsupported pins with `ErrConfig`.
The separate constructor is the required explicit pin for new integrations;
`New` is the fixed Nostr constructor so existing Nostr call sites and tests need
no edits. Legacy `Inbound` and `Outbound` refuse on envelope-pinned checkers.

Inbound `nil` means no presentation was supplied: consult only this identity's
cached proof for this sender. With no cached proof, envelope provenance returns
`refused/no_grant`; legacy Nostr keeps `exchange/no_grant`. A non-nil malformed/empty presentation is refused,
never converted to absence and never replaced by a cached valid grant. Outbound
has no presentation parameter: the agent cannot plant authority by attaching a
new proof to its reply. It uses proof admitted by prior live inbound presentation.

Config contains operator-owned identity/name/key pins, StateDir, read-only Node,
and Now (default time.Now), not receive-time fields or messaging credentials.
Each operation reads verifier time itself. A private persisted clock high-water
rejects backward time across calls/restarts rather than reviving an expired grant.
A deadline bounds checks (default/max 5s); cancellation and contention return fixed
refusals. One admitted operation per checker/state root prevents unbounded internal
queues or goroutine creation. Callers may shed/retry busy work; no cached live
fallback is allowed. The node implementation must honor context cancellation.

The adapter exposes no raw kernel errors or RPC bodies. New returns a fixed
configuration/state error class rather than embedding paths, input bytes, keys or
credentials. Verdict fields are bounded public metadata. Scope is returned only
for live decisions and copied before return. Grant ID/window are reported only
from successfully parsed, policy/sender-bound proof; they never confer authority
on an exchange/refused result. Closed means K1 established durable closure, not
"this call failed".

Envelope `OutboundFrom` takes the key resolved by the adapter from the one signed
`to` carrier id per message through a pinned binding, with no room or membership
fallback. This settles the addressee contract; grantcheck defines no wire field.
Missing addressees refuse with `invalid_peer`; more than `MaxRecipients` (64) refuse with `oversize`. Invalid
keys refuse before backend access. Every recipient needs a previously admitted
proof and a fresh live K1 verdict on every send or retry; one failing recipient
denies the whole send. The aggregate success carries no per-grant scope or ID.
After the final recipient check, the earliest grant end and latest checked time
are compared with verifier time to reject expiry or rollback during the batch.
This remains a sequence of bounded observations, not an atomic chain/send step.
A signed-envelope addressee extraction contract belongs to the downstream adapter;
this library neither invents a wire field nor infers keys from room membership.

## 3. Proof acquisition and validation

a2a daemon's transport boundary extracts at most one exact `grant-cert` rumor tag:
`["grant-cert", grant_id, base64_presentation]`. Match M2-05's strict spelling,
arity, lowercase 64-hex ID and base64 length bound before decoding. Reject duplicate
tags and oversized encoded input before allocation. Decoded proof must be 1..16384
bytes inclusive; 16385 is rejected before parsing or kernel/node/state work.

The library repeats the decoded byte and key/ID bounds, uses the landed gateway
`kernel.PresentationID` for strict v3 framing/ID, and uses the existing rental
parser for signed metadata; it does not reimplement cryptography or signed wire.
No v1/v2 fallback exists. Malformed, bad-ID or foreign-sender proof cannot fall
back to an old cache entry. No message text is accepted by the library API.

In v1 a2a daemon accepts only a full grant-cert presentation and does not use S1.
For future resolver integration, S1 is not a presentation oracle:
`grant-store.Client.GetGrant` returns canonical
**signed grant** bytes keyed by grant ID; it does not return the issuance locator.
An operator-configured resolver must obtain the separate issuance txid and build
the full presentation using the landed `rental.PresentIssuedGrant`. The locator is
still untrusted and checked against the verifier's own chain by K1. Failure to
resolve an explicitly requested object/locator is a refusal, not "no grant" or a
reason to retry a different cached proof. Neither a store hit nor an issuer receipt
is live authority. Never follow a received arbitrary URL, accept a mismatched S1
hash, or use store access credentials from the rented agent. CG1 takes completed
bounded bytes and performs no S1/network fetch itself.

Explicit inbound presentation calls `kernelbind.Adapter.Present`, which runs
K1 Check fresh and only then inserts/replaces the per-sender cache. Inbound cache
hits and all outbound calls use `CachedGrant` followed by normal `Check` at current
time. Metadata's grant ID must agree with the receipt and expected presentation
ID. The wrapper adds no independent chain or revocation judgment.

## 4. Closed routing and refusal codes

`A2ADecision` maps public verdicts to the a2a admission seam's closed vocabulary,
without depending on its internal package. The adapter enforces inbound-only
exchange and converts these strings to the seam's named types. The keeper's
2026-11-14 11:39:01Z decision resolves the envelope lifecycle mapping. Inbound
results privately retain the validated checker pin; this is local provenance,
not a wire field. Map the fresh in-memory verdict; serialization omits provenance
and serialized observations must never be reused for admission.

| Grantcheck code / decision | Seam verdict / reason | Retryable |
| --- | --- | --- |
| `live` / live | live / allowed | false |
| `not_yet`, `expired`, `seal_spent`, `landlord_rotated`, `landlord_changed` / exchange, SwarmEnvelopeV2 provenance | refused / denied | false |
| The same five lifecycle codes / exchange, NostrNIP17Seal (including legacy) provenance | exchange / exchange (inbound only) | false |
| `no_grant` / exchange | exchange / exchange (inbound Nostr; envelope absence already returns refused) | false |
| The same lifecycle codes / refused | refused / denied | false |
| `binding_mismatch`, `invalid_presentation`, `oversize`, `invalid_peer` / refused | refused / denied | false |
| `verifier_unavailable`, `busy`, `cancelled`, `clock_invalid`, `grant_pending`, `identity_pending` / refused | refused / dependency_unavailable | true |
| `state_unavailable` / refused | refused / storage_error | true |
| `check_failed` / refused | refused / policy_error | false |
| Unknown code, decision, or contradictory decision/closure | refused / policy_invalid | false |

Retryability is recomputed from this table, never taken from a mutable verdict's
`Retryable` field. Bad signatures and malformed proof use `invalid_presentation`;
wrong sender/issuer pins use `binding_mismatch`. Stale/unavailable node observations
use `verifier_unavailable`. Envelope replay checks remain the adapter's duty.
No grantcheck code is passed through as a seam reason.

The following is the accepted grantcheck observation table, before
`A2ADecision`: its five lifecycle exchange observations map to refused/denied/false
for envelope inbound and exchange/exchange/false for Nostr inbound, as above.
All other rows remain unchanged. The addressee contract is settled as one signed
`to` carrier id per message, resolved by the adapter through a pinned binding;
no addressee wire field is defined here.
All non-live rows deny
inbox/sign/send. Unknown future K1 reasons map to
`check_failed` (refused), never to live or an inferred absence of a grant.

| Condition | Inbound decision/code | Outbound decision/code | Durable closed |
| --- | --- | --- | --- |
| Fresh K1 live, correct bindings and current window | live / live | live / live | false |
| No supplied proof and cache genuinely absent | Nostr exchange / no_grant; envelope refused / no_grant | refused / no_grant | false |
| Well-formed owned grant before start | exchange / not_yet | refused / not_yet | false |
| Owned grant at/after end | exchange / expired | refused / expired | false |
| Proven seal spend (including mempool) | exchange / seal_spent | refused / seal_spent | true |
| Confirmed forward landlord-key rotation | exchange / landlord_rotated | refused / landlord_rotated | true |
| Confirmed forward agent-landlord pointer change | exchange / landlord_changed | refused / landlord_changed | true |
| Pending landlord rotation/pointer change | refused / identity_pending | refused / identity_pending | false |
| Unconfirmed issuance or seal | refused / grant_pending | refused / grant_pending | false |
| Other grantee / wrong agent or landlord pin | refused / binding_mismatch | refused / binding_mismatch | false |
| Malformed/legacy/bad signature/hash or missing locator | refused / invalid_presentation | refused / invalid_presentation | false |
| Oversized decoded presentation | refused / oversize | refused / oversize | false |
| Invalid peer key or missing outbound addressees | refused / invalid_peer | refused / invalid_peer | false |
| Unknown/zero provenance or different constructor pin | refused / binding_mismatch | refused / binding_mismatch | false |
| Node read/observation unavailable or unstable | refused / verifier_unavailable | refused / verifier_unavailable | false |
| Corrupt/private-state/lock/cache-full failure | refused / state_unavailable | refused / state_unavailable | false |
| Clock invalid/backwards or expires during wrapper work | refused / clock_invalid or expired | refused / clock_invalid or expired | false |
| Context cancelled/deadline or checker busy | refused / cancelled or busy | refused / cancelled or busy | false |
| Any unclassified receipt/error/inconsistent live metadata | refused / check_failed | refused / check_failed | false |

`Retryable` is true exactly for `verifier_unavailable`, `state_unavailable`,
`busy`, `cancelled`, `clock_invalid`, `grant_pending` and `identity_pending`.
It is false for every live/exchange result and every other refusal. This fixed
classification lets a2a daemon retain transiently blocked work without guessing
from error text. A closed-and-live or otherwise inconsistent receipt maps to
non-retryable `check_failed` with no scope.

These are fixed codes selected through exact allowlisted K1 reason mappings;
no substring inference or passthrough of received error messages. For example,
`PENDING_LANDLORD_ROTATION` is not `LANDLORD_KEY_ROTATED`. Without the prior observed
name generation K1 may report a mismatch/unobserved transition instead of closure;
CG1 must preserve refusal without inventing Closed. A backend error accompanying
any apparent live receipt refuses. A closed receipt never admits, even if malformed
adapter data also labels it live.

Exchange routing is restricted to proof absence or specifically established
non-live lifecycle states. Malicious presentation, an unavailable verifier or an
unresolved identity transition must not be mistaken for proven no-grant status.
The separate exchange may independently offer rentals through its own authenticated
entry point; this library contains no exchange reply policy.

## 5. Caching, time and observation limits

K1's live-admitted cache contains public proof bytes only (64 senders, aggregate
60000 bytes in the landed profile). It never stores an authorization result for reuse.
A denied new presentation does not overwrite a prior valid proof. Expired/closed
bytes may remain for evidence/repeated checks; "cache never serves a closed grant"
means no cached proof can produce permission without a fresh successful check.
Do not delete K1 closure/seal-index history to recover capacity or revive service.
These lifetime safety journals are distinct from the bounded presentation cache;
CG1 makes no claim that retained historical records have a fixed total size.

Each result is scoped to the exact operation, peer and resolved identity. After
parsing/check/cache persistence, reread verifier time and refuse if the window
ended or the clock moved backward before returning. a2a daemon must not queue a live
receipt for later signing, reuse it for a different recipient, or use it after an
await/delay without another check. At window end there is no permission to receive
or send and no expiry transaction is needed. Local closed state survives restart.

A successful check is a bounded observation, not an atomic transaction with future
chain state, mailbox commit or external relay publication. a2a daemon keeps the
check adjacent to the effect and repeats it after retries/reconnects or delayed
work. CG1 cannot guarantee that a new revocation will not appear after return.
No new signed token or synthetic future-time verdict is introduced to hide that
race. Existing replay/idempotency policy remains a2a daemon's responsibility.

## 6. Verifier-owned node and custody

Use the verifier's own pinned Namecoin Core regtest node, not an agent-provided
endpoint or remote indexer verdict. Reuse `single-use.NewRPC` and the K1 observer:
loopback literal IP, no redirects/proxy, bounded responses, explicit read-method
allowlist (`getblockchaininfo`, `getblockhash`, `getblockheader`,
`getrawtransaction`, `gettxout`, `name_show`, `getrawmempool`, `getblock`). The
landed constructor currently requires the `w3-observer` username; no new route or
username fallback is proposed here. Infra provisions that observer with read-only
rpcauth/rpcwhitelist on the verifier host. Auth material stays in the a2a daemon-owned
private deployment configuration, outside this library's outputs and fixtures.

No wallet RPC, private grant key, grant signing, seal-pool maintenance, transaction
broadcast or funds leave their existing custody. The harness may use only its
explicitly isolated regtest issuer/wallet to create evidence. No mainnet route or
transaction is introduced. Deployment topology and provisioning are not CG1 code.

## 7. Fixtures and executable controls

The no-node package will contain versioned recorded **decision vectors**, not
proofs of current chain liveness. Each vector records the trusted policy/time,
direction, bounded presentation identity, expected decision/code/Closed/metadata,
and genuine-Core producer provenance. Offline consumers can exercise their routing
contract against deterministic fixtures. A live row never bypasses production New
or returns authority without a node. Keep replay/fake-checker tooling test-only.

The opt-in genuine-Core suite creates its own names, payments, authenticated
booking package, K1 issuer-produced v3 grants and framed on-chain commitments.
It records live, foreign grantee, expiry, not-yet, mempool seal spend, confirmed
and pending landlord rotation, malformed, legacy and oversize results. It uses
the real public CG1 API, including outbound and restart after closure. Reuse the
landed issuer/kernel; do not hand-sign synthetic grants to stand in for issuance.
Publish only public proof/receipt fixtures and exact node binary pins; exclude
wallets, RPC secrets, private issuer keys and state containing transport secrets.

Required controls, each with valid neighbours:

- Correct identity/sender in and out; absent outbound recipient refused; one
  identity's presentation/cache/state must not authorize another identity.
- Another grantee's proof, malformed/v2/bad-ID/oversize rejected before kernel;
  exactly 16384 accepted at the size gate while 16385 fails before I/O.
- Start/end boundaries; clock rollback and expiry during check; no future clock
  from transport or caller request.
- Mempool seal spend and confirmed landlord rotation close durably; pending
  rotation and read failures refuse without false closure; no cached live fallback.
- Bad/new proof does not replace cache; live replacement works; restart retains
  closure; state binding/private-directory failures refuse without partial writes.
- Unknown/error-bearing/closed-live receipt cannot admit; errors containing a
  planted sensitive marker never leak to verdict/error/log output.
- Cancellation, bounded contention, no background goroutine/queue growth; no
  inbox/sign/send/model side effect in the library.
- Guard-removal plants must hit named assertions. Build failures, skips, unrelated
  errors and crashes are not detection evidence. Offline fixture tests prove
  adapter/routing behavior; genuine-Core production of the vectors proves their
  provenance at that observed chain state, not perpetual liveness.

## 8. Integration decisions and packaging

1. Accepted decision table: only absent/not-yet/expired/closed lifecycle states
   route inbound to the separate exchange; malformed/foreign/read failures and
   pending identity transitions refuse. Outbound never routes to exchange.
2. Accepted per-identity constructor + no identity selector on calls fits the
   evolving a2a daemon engine seam. The a2a maintainers own exact a2a method/type names.
3. In v1 a2a daemon does not use S1 at all; it accepts only a full grant-cert.
   Any future resolver remains outside CG1. Failed explicit lookup must not
   be passed as nil/absence.

The integration owner requires a separately tagged module. The initial Go 1.25
constraint was corrected after verifying that the landed K1/kernelbind graph
requires Go 1.26: CG1 and the a2a-link fork use Go 1.26; upstream remains on
Go 1.25.x and never imports chain-lab. Existing dependency directives remain
unchanged. The fork's CI must run upstream's complete suite and transport
conformance on Go 1.26; that integration work belongs to the a2a maintainers.
Module publication prerequisites are recorded in UNRESOLVED_QUESTIONS.md.
E1 is not a dependency.

## Source anchors

- Landed authority: `../rental/grant_kernel.go`, `grant_presentation.go`,
  `grant.go`, `grant_names.go`; framed commitment verification in `oplocator/`.
- Existing binding: `../rental-gateway/kernelbind/kernelbind.go`; transport
  framing: `../rental-gateway/kernel/presentation.go` and `gateway/presentation.go`.
- Storage boundary: `../grant-store/grant.go` and its README (signed grant only).
- Read-only node: `../single-use/node.go`; private storage: `single-use/durable`.
- a2a daemon constructor/isolation and inbound/outbound insertion points are the
  integration requirements in the CG1 request, not claims about unlanded internals.
