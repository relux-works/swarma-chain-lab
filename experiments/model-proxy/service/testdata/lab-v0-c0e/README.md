# Lab contract C0 with C0b/C0c/C0d/C0e addenda, revision 10

Status: CONTRACT CANDIDATE FOR REVIEW. Inert construction only, not production
acceptance, a release, owner consent or permission to capture/use a key.
This is the closed byte inventory of [lab profile §5.2](../../docs/lab-profile-v0.md#52-c0s-closed-byte-inventory-and-consumer-joins).
The 30 entries in `surfaces.json` (24 base, C0b, two C0c frames and three C0e records) are authoritative together with this document;
`fixtures.json` pairs every own-format valid record with an unknown-field
negative. Nested negatives carry a complete mutated record, path (array indices
are integers), structure, field and mutation; each is paired with that surface's
valid record. Closure mutations outside an excluded seal member are re-sealed,
so every exported closure negative passes its independent seal-only control.
The composed reader must refuse specifically at field_set before seals.
The acceptance allocations are construction obligations, not claims
that these fixtures implement A01–A12. B1–B5/G1/M1 must exercise their actual
readers and effects against these bytes. No runtime code or constructors ship here.

## Encoding and field grammar

Every record is CCJ-1, exactly as `internal/wire/canonical.go:17`: UTF-8, sorted
object keys, minimal escaping, integers only in the signed safe-integer range,
no duplicate members, null, missing or extra fields, no trailing newline. All
listed fields are required recursively. Arrays preserve order and have at most
256 members; identifiers use ASCII 0x21..0x7e, 1..128 bytes. No unlisted extension
member or alternate format spelling exists. Nested structures are closed too.
The `format` member is the domain/version discriminator; a record digest is
`sha256:` followed by lowercase hex of **complete canonical bytes**, not a secret
fingerprint and not a hash with an added domain prefix. Do not hash material or
an enrollment input into a public operation input pin. For an embedded Approval's `approved_sha256`, the complete canonical target
image is `{"domain":"swarma-broker-lab-approval-target/1","record":R}`,
where R is the enclosing record with its single `approval` or `owner_approval`
member omitted. This image is a hash preimage only, never an acceptable record
or an authority source. The owner also approves the complete external receipt
and its timestamps through the authenticated off-VM channel. This avoids a
self-referential hash while binding every act/input/head field. A lab service
journal's own Head.sha256 similarly hashes the complete canonical image
`{"domain":"swarma-broker-lab-journal-head/1","record":J}` with only its
own top-level head omitted; Head.sequence equals entry count. Entries store a
sequence and previous committed head, never their own next hash. The explicitly
fresh empty journal's image gives its genesis digest. Later commits bind the
whole metadata snapshot and entries, including binding/lease/tombstone state.
Manager prefix heads retain the existing manager-owned hash algorithm rather
than being re-encoded as lab heads. Root/control and lease
frames use a 4-byte unsigned big-endian nonzero payload length then those bytes,
maximum 65536, as `internal/wire/frame.go:14`. Larger Q/release files (maximum
262144) are file records, never oversized socket frames. Activation is 16384 max.

In the machine-readable field grammar: `@Name` references a closed structure,
`[]T` is an array of T, `=text` is a string singleton, and `a|b` is a string enum.
`id` is the identifier above; `digest` is `sha256:` + 64 lowercase hex digits;
`operation` is 32 lowercase hex digits from a fresh 128-bit identifier;
`uuid` is lowercase 8-4-4-4-12 hex; `commit` is 40 lowercase hex. `bool` is a
JSON Boolean; `uint` is 0..9007199254740991; `positive` starts at 1; `time` is
canonical UTC RFC3339Nano after the Unix epoch, with a Z suffix and no redundant fractional zeros
(`time.Parse` followed by `UTC().Format(time.RFC3339Nano)` must reproduce it);
no subsecond precision is discarded from a bound or watermark; `root` is integer 0;
`lifetime` is 1..900; `alignment` is 0..2; `poll` is integer 250;
`capture-timeout` is integer 300; `exit` is 0..255. `material` is a nonempty
ASCII 0x21..0x7e string up to 4096 bytes, carried **only in protected broker custody or the gateway lease
response**, erased from transient holder buffers on terminal paths and never
persisted in a fixture/evidence export with real contents. The published value is a public synthetic marker.
Lease requests use the existing service dialect; this record is its lab material
result, not a new worker route. Custody is the sole protected store object containing material. Account metadata
uses an opaque, never material-derived custody object ID and issued-version IDs;
it contains neither material nor its digest. No second secret store, key hash
or circular custody/account hash join is introduced. The 4096 bound reuses `internal/claude/account_linux.go:94`.

## Required semantic joins (beyond shape)

All consumers compare exact Context, expected heads and digest pins before any
effect, including account, installation, independently approved VM identity,
qualification revision/expiry. A matching local machine ID is insufficient.
A Head is a count plus digest of the exact append-only prefix; count zero has the
approved fresh-install genesis digest, never permission to initialize a missing
store. A nonzero head's digest binds its serialized chain prefix. Stores append
through existing fsync/CAS rules, not a new C0 journal engine. Journal bindings retain current gateway/caller tuples, epochs and revoked
tombstones; lease states retain their binding, issued version, exact deadlines
and issue/renew operation IDs. Entries retain canonical request digests and
results; none of these metadata records contains material. Exact manager
request bytes and returned receipt/request ID/head must agree; never synthesize a
manager receipt. Existing manager records retain their own formats. Principal
facts come from native protected manager evidence and kernel peers, not these
fixture assertions. Authority's gateway is `kind=service`, worker/caller is
`kind=worker`; generations, execution_id values and UIDs are disjoint. Root control
requires kernel UID 0 separately. Lease material goes only to the exact gateway. Every duplicate
configuration lifetime equals activation's one selector; `authorized_until` is
the earliest issue+lifetime/authority/caller/time/qualification deadline. Equality
at a deadline closes use; hold/expiry/revocation invalidates replayed material.

Preparation cannot issue/renew. Enabled activation additionally joins current
preparation, authority, release, fence and all C/protection approvals. Disabled,
absent, stale, malformed, mismatched or expired records never widen authority.
Every manual start consumes a fresh off-home fence joined to off-VM final heads
and clock; later starts require acknowledged orderly-stop heads, not current
observed heads. Persist exact manager-prefix high-water before publication.
Time checkpoints retain watermark, incident and sticky holds across restart;
fresh NTS/settlement is necessary, not sufficient. Restore/clone/regression burns
the installation; no ordinary hold, good report or new revision resets history.
`amendment.txt`, `api-exception.txt` and `joins.txt` bind the exact lab §4.2–4.3
text (LF, quote markers removed for the two blockquotes, final LF retained).
Owners approve **all three file digests** and protected Context. The C1 text uses
retired bounds only as refusal floors, never imported authority or hold release.

`owner-decision` requires exactly repository/time-contract/user-manager roles,
each explicitly accepted; one human may cover roles only with recorded authority
for each. Off-VM authenticated owner approval precedes that exact invocation.
`decisions.json` records only the dated direction/residual act already in §4.1;
**C-OPEN-OWNERS is not recorded**, joins/native qualification and protection
inputs remain pending. Synthetic accepted-role fixtures are not owner decisions.
No production spec, API, consumer or acceptance set is amended by C0.

An access attestation covers all three surfaces: guest/external root/sudo/console/
hypervisor/snapshot access, every owner endpoint/root session through revocation,
and vendor workspace/cap/key administration. All effective privileged controllers
must be human; no agent-held admin key/session through a human principal. Owner
endpoint exclusions are all true; roster/audit coverage is complete/unchanged;
the hard cap and approved workspace/limit match. The owner verifies off-VM
observations and Infra's native complete guest/control-plane roster. Incomplete
visibility is closed. Read back before creation/enrollment, bind, activation,
every Q group, hold-lift and **both** prepare-next transitions; any change closes
admission. Creation occurs only after authenticated no-echo prompt and readback,
inside the window, with no interim holder; agent-exposed material is ineligible
and vendor-revoked. These are native/owner preconditions, not proven by JSON.

## Operation, failure and UNKNOWN contract

Operation envelopes are immutable, produced after predecessor commitment, from
actual current heads and exact nonsecret inputs; owner approval precedes their
own invocation. Enrollment binds preparation, never a public key hash. Same ID
and different content refuse with no effect; same ID and matching content
reconcile read-only, never recapture or silently rerun a root act. Enrollment
marks attempted durably **before** prompting, once per ID, for at most 300 s;
attempted/committed/UNKNOWN/conclusively aborted all spend that prompt ID.
A separate approved operation is required after conclusive recovery.

| State/result | Exit | Authority/effect |
| --- | ---: | --- |
| committed | 0 | Exact recorded act only; replay grants no new effect/material authority. |
| definitive refusal | 1 | None, except an independently admitted narrowing act. |
| not_committed:enrol_no_forward | 1 | Durable zero-forward fence spends the ID; no retry prompt. |
| unknown, attempted, incomplete or not_started | 2 | No success/absence assertion, no widening or re-prompt. |
| syntax | 64 | No request/effect. |
| authorization/closed admission | 69 | No widening/capture. |

Concrete reconciliation is `swarma-credential-broker-lab status --operation-from
FILE`, binding the same `operation_id` in that envelope. Never resubmit blindly.
Root-control `phase=request` carries state=not_started/exit=2 (not a result).
After authenticating both kernel peers and the approved operation, fresh enrol
marks attempted durably and returns one attempted/exit-2 readiness result **on
that same connection only**. It permits the single local prompt, not key use.
The first client receiving that readiness result prompts once, then sends a
4-byte big-endian length (1..4096) followed by exactly those ASCII capture bytes,
with no newline/JSON wrapper and no second frame. The 300-second deadline starts
before readiness; timeout, disconnect, malformed length, extra bytes or capture
abort spends the ID. If zero forwarding is conclusively fenced, record
not_committed:enrol_no_forward; otherwise UNKNOWN. Reconnection or status cannot
produce readiness or another prompt. Key bytes never enter an operation record,
result or log. B3 must prove this two-phase connection lifecycle and zero-forward
abort natively; this transport contract grants no live capture permission.
Result heads are authoritative only at committed; UNKNOWN heads grant nothing.
Hold uses leak_match/account/caller/operation ID, is durable before acknowledgment,
and an unknown result never reopens. Hold-lift binds the exact current hold in a
nonsecret input pin; it cannot revive a removed lease. Finite capacity reserves
narrowing before further widening. Current checks every 250 ms after receipt use a 300 ms RPC
timeout, <50 ms scheduler lateness, independent 750 ms current watchdog and
<=500 ms closure. C0d periodic native singles run 500 ms after receipt with
<250 ms RPC, <50 ms lateness and a separate 1200 ms native-age fence.
Worst case 1200+300+750+500 = 2750 ms is below the new 3000 ms lab closure ceiling;
<1050 ms valid native inter-observation age and <600 ms valid current-success
spacing leave watchdog margin. See lab profile §3.2 and Q4. These timing/effect
obligations belong to M1/B1/G1/B4, not to schema tests. Fence budgets include
scheduling: arm native/current watchdogs at 1150/700 ms with <50 ms dispatch
lateness; do not add jitter after the 1200/750 ms fences.

The root-only matcher accepts a protected collection ID and full issued-version
inventory, **never caller-supplied needle bytes or partial needles**. It emits
only clean/match/incomplete, no offsets/snippets/hashes of material. Nonzero
issued versions and complete encodings are required for clean: raw, JSON,
percent hex variants (one initialized percent row attests both uppercase and
lowercase hex matching, never just one spelling), standard/URL-safe base64 padded/unpadded at all three
alignments (0/1/2). A match durably holds before acknowledgment; an unknown hold
cannot report clean. Partial coverage, malformed inputs and inaccessible surfaces
are incomplete/exit 2. Q evidence includes real case exits, effect/completeness
and encoding bounds, all six Q groups and valid/negative/plant roles; complete
metadata is not a successful native Q. Export omits raw payloads and fingerprints.
Release assets bind signed tags, exact source commits, asset digests/modes and exact regular-file archive member paths/modes/digests
(relative paths, no dot-dot, absolute path, link or special member; these path/type
checks belong to the RB/B5 archive verifier, beyond the Member.path id grammar),
independent second-build equality and the closed contract-index digest. No lab
asset is acceptable to a production release reader.

## Fixture and reproduction boundary

`wire-fixtures.json` has the reconstructed plain API-key Messages body, exact
measured headers, credential-free GET, and adjacent OAuth/credential/beta/body/
path negatives. Request bodies were **not retained**; prompt/metadata strings
here are new public synthetic sentinels. The per-message effort value is also
reconstructed: the original projection retained its field path, not its value. `probe/observed.json` retains only the
original structural observation, without timings or paths. The observed model
is claude-opus-5-5 and max_tokens is 128000; these freeze an **inert observation**,
not a live output/spend approval. A live approved bounded invocation that changes
these bytes/fields requires a reviewed new profile revision and probe, never
silent fixture normalization. G1 forwards admitted body bytes unchanged and all
eleven measured non-OAuth flags; it rejects OAuth, unknown/missing/duplicate/
case-variant flags, duplicate beta fields, TTL 1h, system clear_at or tools outside
this frozen empty-tool invocation. Measured enums/cache values, model, max_tokens
and stream are checked separately from paths; tools must be an empty JSON array.
metadata.user_id and diagnostics.previous_message_id must be strings. Cache
controls are compared as a multiset of the three observed objects, not a
placement claim; swapping their system positions remains admitted. In contrast,
stripping any required field refuses. Per-message effort=medium is a reconstructed fixture constraint, not
an additional measured value. It never strips body fields to fit API-key
mode. Policy GET receives no injected credential and preserves real errors;
fake policy success is a response-side G1/B4 native obligation, not proven by
these request fixtures.

`index.json` seals every contract, probe source and fixture with SHA-256, plus
the complete profile/wire/specification/time-contract/API source bytes; its own
hash is frozen in the test. No PR commit locator is used: unchanged bytes survive
signed rebases. Changing a frozen byte is a contract revision with a new index
and consumer review, not an automatic golden update. Complete production source
pins are intentional tripwires: even an unrelated spec edit requires a scoped
source-diff review, confirmation that the lab amendment/joins are unchanged,
resealing the affected source digest and index/test digest, rerunning both
contract and assembly suites, and consumer review before adoption. The existing production
sealed-index tests and source pins are untouched.

Run `go test -count=1 -v ./internal/labcontractv0 ./internal/assemblyv0` in an
isolated checkout with absolute task-owned HOME/caches/TMPDIR. Outputs go to
owned scratch, not installed broker paths. See [probe reproduction](probe/README.md)
for the exact executable pin, portable harness and bounded synthetic command.

## Source-backed C review

| Decision | Binding evidence / disposition |
| --- | --- |
| Lab conflict remains explicit | `docs/lab-profile-v0.md:5`, `spec/broker.md:880`, `spec/operator-and-activation-v0.md:1137`: manual-root lab only, never production. |
| Residual direction is not C opening | `docs/lab-profile-v0.md:507`, `spec/operator-and-activation-v0.md:1143`: the dated residual act supplies no other owner's consent. |
| Exact amendment/API bytes | `docs/lab-profile-v0.md:531`, `spec/operator-and-activation-v0.md:1285` and `:1349`: extracted text pins above; all three owner roles still required. |
| Every-start and prefix join | `docs/lab-profile-v0.md:593`, `timeconf/consume_linux.go:66`: joined off-VM fence/clock, persisted manager prefix and native NTS witness remain implementation/qualification gates. |
| Existing API-key intake is not assumed | `docs/lab-profile-v0.md:178`, `docs/lab-wire-profile-v0.md:34`, `docs/lab-wire-profile-v0.md:50`: frozen API-key header/body shapes, not the existing OAuth adapter. |

The table cites current file lines; the profile's B/G/M/D aliases resolve at its
immutable source pins. C0 neither edits production specifications nor imports
an accepting consumer. Future consumer implementation must compare this exact
index digest and provide both real lab/production cross-read directions with
own-format valid controls; C0's schema discriminator pairs are not that native
integration proof.

### Error fallback observation (not an admitted profile)

The exact-client HTTP-400 control exits 1 after three local model attempts.
`probe/error-observed.json` (relative to the contract root) retains only projected
headers/shape. The second/third attempts omit thinking-token-count-2026-05-13;
the third exceeds the recorder's reviewed enum projection and therefore has no
complete body shape. The published auditor validates the initial full profile,
fixed auth/path and genuine 400 replies, reports two **unqualified retries**, and
never treats those retries as admitted API-key requests. The corresponding
missing-thinking-beta fixture is a refusal. The lab gateway must reject such
profile drift, not silently broaden the eleven-token/body contract to make an
error fallback succeed. This observation qualifies neither a fallback body nor
vendor retry behavior; live Q1 must tolerate genuine errors under the closed
profile. The successful synthetic control remains exactly GET then POST.

## Refusal coverage and limits

Fixtures are per-surface shape controls, not a mutually joined installation:
heads in different cases are not asserted equal. Principal tuples within each
case are disjoint; service-journal and approval self-target hashes are checked.
Cross-record joins remain native consumer obligations. Tests traverse every
instantiated nested type per surface (including array elements) and every
primitive field, alongside own-format valid controls.

Each max_bytes preflight is tested at its exact limit and one byte over with
the specific size refusal, separately from canonical/shape validity. Compact
fixed-field records cannot reach their large transport ceiling under the frozen
grammar; an at-limit noncanonical payload is therefore only a preflight control,
not a claimed admitted record. Grammar-valid exact-limit records are also
exercised for account/1 (65536 bytes) and release-set/1 (262144 bytes) only.
Arrays admit 256 and refuse 257 members. No payload or array limit is enlarged for a test.

Q-row result/effect semantics, raw-export prohibitions and release/tag/build
semantics remain B4/RB implementation pairs; C0 does not claim those native
behaviors from schema success. The probe trace audit covers traced socket
creation/connect and io_uring only, not sendto or every possible syscall.
Unfinished/resumed lines fail closed and may require a new clean observation.

## Normative negative operator catalogue

Revision 8 retains the following **finite operator catalogue**, not a claim to
exhaust all possible adversaries. `literalMutations`, `separatorMutations`,
`scalarMutations`, `labelCases` and `headerNameCases` in `internal/labcontractv0` implement it.
Traversal applies every applicable operator to every grammar node, enum member,
root/nested member slot, measured body occurrence, body member, envelope/header
literal and beta token/separator. Each generated case runs its unchanged valid
control immediately before its candidate. Applicability and accepted aliases are
part of the catalogue, not exemptions silently selected by the implementation.

| Element | Required operators and controls | Intended gate / test |
| --- | --- | --- |
| Fixed literal or label, including the digest label and JSON names | Whole upper/lower/inverted ASCII case; each letter's case; leading/trailing `x`; paired and single-sided double/single quotes, square/curly/round brackets, space, tab, CRLF, vertical tab and form feed; empty token; each byte deleted or replaced by the near neighbour `x` (`y` for `x`). Labels additionally get fullwidth ASCII and combining-accent forms. | Grammar node in `TestLabGeneratedGrammarPairs`; exact `field_set` in `TestLabGeneratedClosedFieldPairs`; `body_fields` in `TestLabGeneratedWireClosurePairs`; envelope in `TestLabGeneratedWireEnvelopePairs`. |
| Every measured header name | Every label operator, including fullwidth and combining forms; insert every byte 0..255 at every boundary and substitute every byte at every position; replace each applicable `i` by dotted/dotless i, `k` by Kelvin sign, and `s` by long s. Only ASCII case variants of the measured name pass. Separately check all 256 bytes against the complete RFC `tchar` alphabet, with uppercase and empty-token controls, independent of the measured-name allowlist. | `envelope` in `TestLabGeneratedWireEnvelopePairs`; token grammar in `TestLabASCIIHeaderTokenPairs`. |
| Beta byte class and OWS | Insert NUL, CR, LF, all other non-HTAB C0 controls, DEL and each byte 128..255 at **every** byte boundary, including both ends and each side of every comma; all refuse. At each boundary insert SP and HTAB: admitted only outside token interiors. Each group includes admitted SP/HTAB at a token boundary and every negative includes the unchanged request control. Existing token wrappers and separator operators classify CR/LF/CRLF as negatives, never valid OWS. | `beta` in `TestLabGeneratedBetaOWSBytePairs`, `TestLabGeneratedBetaSeparatorPairs` and `TestLabGeneratedWireEnvelopePairs`. |
| Every separator occurrence | Delete, duplicate, replace by **each other** character in `TZ_,.-:/;= ?&()[]{}\"` plus backslash, tab, CR and LF; surround by space, tab or CRLF. Time's `T` and `Z` are separators too. The ten beta commas receive the same operations. | Scalar grammar; `beta` in `TestLabGeneratedBetaSeparatorPairs`. |
| Hex group and length/count/byte bound | Alphabet on both sides (`/`, `0`, `9`, `:`, backtick, `a`, `f`, `g`, `A`); every group's length one below/above; whole-value literal operators, including UUID braces and `urn:uuid:`; min-1/min/min+1/max-1/max/max+1 where representable; arrays 0/1/255/256/257; every frozen payload ceiling at limit and one above. Open ASCII values use both character boundaries and byte lengths, not fixed-literal restrictions. | `TestLabGeneratedGrammarPairs`, `TestLabPayloadLimitPairs`, `TestLabExactLimitRecordPairs`, `TestLabArrayLimitPairs`. |
| USD decimal string | The C0b positive micro-USD bounds and both neighbors; zero/nonzero seeds, integer and six-digit fractional component lengths on both sides, signs, leading/redundant zeros on both sides, fractions/exponents, every literal and decimal-separator operator, null and all wrong JSON kinds. Valid significant fractional zeros and the required fixed six-digit scale remain accepted; no floating-point conversion. | `usd` in `TestLabGeneratedGrammarPairs` and `TestLabBoundedUSDPairs`. |
| Integer spelling and canonical bytes | At both in-range endpoints and zero/nonzero lexical seeds: one/two leading zeros, plus/minus sign, `.0`/`.00`/`.5`, Cartesian `e`/`E` × absent/plus/minus sign × `0`/`00`/`1` exponent, beside canonical integer bytes. Numeric range and wrong-kind refusals are separate from lexical refusals. Out-of-range lexical seeds use the nearest valid bound as their control; singleton endpoints are deliberately exercised twice. | CCJ parser then range in `TestLabGeneratedNumberLexemePairs`; `TestLabGeneratedCanonicalBytePairs` also rejects whitespace and redundant escapes without changing decoded values. |
| Canonical time | Epoch and four-digit-year bounds on both sides; calendar-component bounds; 0/1/8/9/10 fraction digits; all-zero fractions of lengths 1..10; nonzero fractions with/without trailing zero at lengths 1..9; significant leading fractional zeros with/without redundant trailing zeros; signed/leading-zero year, signed/exponent fraction, non-UTC offset; literal and every time-separator operator. Canonical significant leading zeros **remain valid**; `.10Z`, `.120Z`, `.100000000Z` and `.000000010Z` refuse. | Exact time grammar in `TestLabGeneratedGrammarPairs`. |
| Every typed value | Null and each of the other five JSON kinds, excluding only its required kind; fixed Boolean opposite where the measured value is fixed. | Direct grammar node, `TestLabGeneratedWirePairs`, `TestLabGeneratedWireJSONTypePairs`. |
| Every closed object/member | Missing member, extra plain member, rename and extra alias for **every label operator**, duplicate member bytes, wrapper/wrong nesting. Duplicate tests use the test-local raw parser before map projection; they do not prove end-to-end wire-reader duplicate refusal. | `field_set` / `body_fields`, and parser duplicate refusal in `TestLabGeneratedObjectBytePairs`. |
| Paired principal roles and closed owner set | Each principal kind swapped independently and both swapped; each tuple component shared. For **each** owner role: unaccept, remove, duplicate/replace by every other role, add unknown/extra role; independently unaccept residual consent. | `TestLabPrincipalDisjointPairs`, `TestLabGeneratedOwnerSetPairs`. |
| C0d consumption/timing | For each publication role and periodic single, independently remove pair membership/freshness/floor/CAS and native baseline, seen-counter, cooldown, cadence, age, RPC, scheduler and watchdog conditions. Both sides of every bound; stopped/pending/partial answers; singles never advance F, enable publications, postpone use checks or reopen a fence. Distinguish unchanged native sequence/proof from increasing observation counter. | `TestLabObservationConsumptionPairs`, `TestLabObservationPeriodicPairs`, `TestLabObservationTimingBoundaries`, `TestLabObservationBudgetArithmetic`, `TestLabObservationCurrentPairs`, `TestLabObservationNarrowingJoins`; complete wire shape catalogue remains unchanged. |
| C0b/C0c state predicates | Independently negate each conjunct of managed-account currentness; admitted/terminal launch and stop phases, each matching selector independently changed and both changed; absent/partial/full stop sets. Check both sides of each concurrency/hold/cooldown bound, both approval/qualification window endpoints, revocation/current-access and unknown authority before every ordinal AND in flight. Join target, sealed release, sealed A, full plan and launch pins after re-sealing mutated subjects. Sequence and counter generation differ independently and together; sequence reservation must leave every native snapshot member unchanged. Each semantic negative must reach its named gate beside a valid control; re-seal to avoid a stale-digest mask. | `TestLabObservationStopPairs`, `TestLabObservationCurrentnessPairs`, `TestLabObservationLoadPairs`, `TestLabObservationSnapshotSequencePairs`, `TestLabBoundedAuthorityPairs`, `TestLabBoundedReleasePairs`; shape fields still receive EVERY recursive operator above. |

HTTP header names are nonempty ASCII RFC 9110 section 5.6.2 `tchar` tokens,
compared using ASCII-only case folding (section 5.1). Unicode case-mapping aliases
are not header names. Beta order is immaterial; optional whitespace (OWS,
section 5.6.3) is **SP or HTAB only**, around a token, never inside it. Those ASCII
case, order and SP/HTAB variants are **valid controls**, not negatives. CR, LF,
NUL, every other control byte (including DEL), and every non-ASCII byte anywhere
in the beta value refuse at `beta`; no replacement or unfolding is performed. Open text/user-id/diagnostic strings are not fixed literal tokens.
HTTP JSON is not CCJ: this catalogue does not impose CCJ numeric spelling on
forwarded body bytes. The reference wire member reader is recursive and exact;
measured path names are not an ambiguous dotted-set decoder. The cache `scope`
member is optional at measured system-cache positions; the independent multiset
check still requires exactly one global scope across the three caches. Missing
that last global scope refuses at `body_fields` (missing measured path), while
removing it when another remains would violate the multiset at `body_value`.

`TestLabIndependentAdversarialPairs` is a separately enumerated compositional
pass, not generated by the unary catalogue. Its twelve interaction witnesses
must remain refused beside the valid request; additions discovered there require
an explicit catalogue revision, not a silent widening of the checker. All these
are inert reference-reader checks; none qualify a live client or production.


## C0b bounded-invocation addendum

[bounded-invocation.md](bounded-invocation.md) freezes the B5 → M1/B4
`swarma-broker-lab-bounded-invocation/1` file surface, detached approval target,
full-plan/client/wire/launch/executor joins, owner-set values, first-bound stop
and sticky UNKNOWN/debit semantics. It does not approve a live budget or change
`probe/client.json`; new model/output wire bytes still require the reviewed
profile/probe revision described above. `bounded-invocation-fixtures.json`
publishes synthetic admitted and intended-step refused joins. The original 24
surface fixtures and all probe/wire bytes remain unchanged. Native enforcement,
durable reservations, owner provenance and actual executor controls remain M1,
B5 and B4 release/qualification obligations, not C0b implementation evidence.

## C0c manager-owned lab observation

[observation.md](observation.md) defines the tagged M1 → B1 observation
capability, narrow request, complete native join and C0d consumption rules.
Fresh non-reusable pairs are required only for start admission and final
start-affecting commit/debit/stop/invalidation publication. Recurring current/
revocation answers use periodic SINGLE checks plus the independent native-age
fence, never a pair. Native sequence/proof must not move; the distinct durable
observation counter MUST increase on every read. Singles advance only replay
seen S, never publication floor F or a future pair candidate. No reuse,
prevalidation or pipelining across publications. Pair entry first fences use,
shares the single server budget, and has a 1250 ms total budget plus each
original 250 ms RPC deadline. Safety containment does not wait for a pair. `observation-fixtures.json` is inert reference evidence, not a native
receipt or proof of kernel authentication, locking or installed currentness.
`native-executor` is 1..32 ASCII lowercase alphanumeric-first, then lowercase
alphanumeric/hyphen, matching native executor/profile IDs. `native-id` preserves the native manager grammar: ASCII alphanumeric first,
then ASCII alphanumeric, period, underscore or hyphen, 1..64 bytes. Generation
uses the existing 32-lowercase-hex `operation` grammar, not a display name.

Catalogue application: every new label, discriminator, nested field, integer,
array and digest uses the existing complete operator catalogue. The native-id
projection additionally varies all 256 byte values at first/interior/last
positions, both length bounds, fixed separators, Unicode confusables, and all
wrong JSON types. Valid native letters of either ASCII case remain valid.
Paired roles vary client/server individually and together; root is valid as
the manager server, never as a client. Join operators change every native
incarnation field independently; partial, absent, duplicate, stale or reordered
observations fail the intended UNKNOWN gate beside a complete fresh control.
Transport boundary operators vary each size/deadline side, every peer role,
one versus zero/multiple frames, and lock/completeness provenance separately.
Run the existing Go contract/assembly and Python probe commands in the
fixture/reproduction section; C0c
reference checks are test-only, not an observation server or client.

## C0e gateway accounting consumption

[attempt-accounting.md](attempt-accounting.md) refines the C0b executor boundary:
G1b is the only billable-forward gate; M1 checks start admission and serves C0c,
not invocation counts. `model-price.json` pins the published standard/global
price row and model limits as a candidate RG release member, never a budget
approval. The three closed C0e formats and GatewayPrices/GatewayUsage/GatewayAttempt
nested types inherit EVERY applicable operator in the normative catalogue:
member/literal case/insertion/wrapping/deletion/substitution, separator variants,
null/all wrong JSON types, both numeric bounds/canonical zero/sign/fraction/
exponent forms, exact closure/nesting/duplicates and paired-role joins.

New semantic rule operators independently break release/price/model joins, native
start/admission proofs, protected CAS/fsync/head/prefix continuity, ordinal/retry
serialization, price ceilings and all five exact integer rate terms, complete
cache partition/cumulative usage, uncertain full settlement, sticky UNKNOWN and
first-bound count/output/USD/wall stops. Each refusal has an unchanged valid
control. No price source download, fixture or reference transition is native
gateway enforcement or production acceptance. See the coverage map for named
rule witnesses and source-overlay mutations.
