# Read-only chain view contract (CG1, candidate)

CHAINGW-C1 / G1 T4.6. This is a contract-first candidate for acceptance by the
consumer maintainer (Source), not an implemented service or activation approval.
MUST, MUST NOT and SHOULD are normative. Version 1 is frozen only after consumer
acceptance of an exact Git head. Both implementations MUST pin that head and the
same fixtures. The gateway belongs in chain-lab; the live and snapshot adapters
belong in a2a-swarm behind D29's ChainView interface.

## 1. Authority, sources and decision register

The supplied lead ruling authorizes (b), a root helper refreshing a pin at every
block, for OBSERVE ONLY, then (a), a secret-free read-only chain gateway after
contract acceptance. Device-list enforcement MUST use (a). Enforcing over (b)
requires a separate owner decision. No passing fixture enables enforcement.

Pinned spec: [swarma-link-spec v0.1.51, bd3bc80e](https://github.com/relux-works/swarma-link-spec/tree/bd3bc80e5543d8a563343ec05abd1a5f3f67284c).
LIP-0029 remains Draft with co-author agreement pending; released bytes are the
contract input, not evidence that its wider policy is adopted. Book citations
below pin [swarma-docs b57a9be](https://github.com/relux-works/swarma-docs/tree/b57a9be633c245373b448c3786bcbd49d636fe8a).
Every local decision is classified here; **new** entries require the associated
book change before production adoption, **refines** entries require a spec PR.
Those follow-ups are listed in OPEN.md and are not silently declared accepted.

| Decision | Relation | Source and consequence |
| --- | --- | --- |
| Credential outside agent accounts; dedicated service identity | same | Book ch. 11, [“Режим без секретов у агента”, “Кто держит учётные данные”](https://github.com/relux-works/swarma-docs/blob/b57a9be633c245373b448c3786bcbd49d636fe8a/book/ru/11-uchetnye-dannye.md#режим-без-секретов-у-агента); LIP-0029 §1 O1.6. Root compromise remains outside this boundary. |
| Kernel peer identity and a host-selected endpoint | same | Book ch. 5, [“Собеседника устанавливает ядро”](https://github.com/relux-works/swarma-docs/blob/b57a9be633c245373b448c3786bcbd49d636fe8a/book/ru/05-klyuchi.md#собеседника-устанавливает-ядро); model-proxy [“Linux administration and configuration”](../model-proxy/README.md#linux-administration-and-configuration), `peer_linux.go` (`SO_PEERCRED`). This gateway grants public reads to a UID allow-list, not signing authority or generation attestation. |
| New chain-read service class, no forwarding of arbitrary RPC | new | Book ch. 11, “Шлюз учётных данных и адаптеры сервисов” requires separate owner admission and qualification for another service class. The supplied ruling authorizes this contract, not an install. Book PR remains required. |
| Exact name-value bytes, confirmed name operation, 520-byte value | same | [LIP-0010 §§1–2, 8, 11 SH3](https://github.com/relux-works/swarma-link-spec/blob/bd3bc80e5543d8a563343ec05abd1a5f3f67284c/lips/LIP-0010-name-value.md); [LIP-0029 §§3.2–3.3, 11 steps 4–5](https://github.com/relux-works/swarma-link-spec/blob/bd3bc80e5543d8a563343ec05abd1a5f3f67284c/lips/LIP-0029-owner-control.md). Gateway transports octets; consumer interprets the pin and hashes the list. |
| Node network/genesis pinned; no initial block download | same | [protocol/names.md §1.1](https://github.com/relux-works/swarma-link-spec/blob/bd3bc80e5543d8a563343ec05abd1a5f3f67284c/protocol/names.md). This wrapper does not replace consumer name or application verification. |
| Mempool-inclusive seal observation and durable consumer refusal | same | LIP-0029 §8 O8.3–O8.5, O8.9 and §11 step 8. A later unspent answer never clears an existing closure. |
| UTXO absence is not proof of a spending transaction | refines | LIP-0029 §8.3 names `gettxout`; it cannot distinguish spent from never-created. This contract exposes `not_in_utxo_set` and prohibits inventing spend evidence. Consumer mapping needs acceptance and spec clarification. |
| Compare observations at a named chain state | same | Book ch. 26, [“Лёгкое чтение и проверяемый индекс”](https://github.com/relux-works/swarma-docs/blob/b57a9be633c245373b448c3786bcbd49d636fe8a/book/ru/26-cepochka.md#лёгкое-чтение-и-проверяемый-индекс): compare the same height and rules. This trusted full-node projection supplies no light-client proof or consensus qualification. |
| Coherent tip binding, cross-call comparison and bounded retries | refines | LIP-0029 §11 steps 4 and 8; [LIP-0008 §5.1](https://github.com/relux-works/swarma-link-spec/blob/bd3bc80e5543d8a563343ec05abd1a5f3f67284c/lips/LIP-0008-grant-v4.md) distinguishes inconsistent observations from proven closure. CG1 makes the read guarantee explicit. |
| Recursive duplicate, escaped-key and case-alias refusal | same | [STRICT-JSON.md SJ1](../STRICT-JSON.md), including exact typed names. Opaque name-value octets retain their own LIP-0010 parser boundary. |
| Wire ordering, framing, budgets, enums, schema and version | new | Host-local CG1 decisions in §§2–6; no existing book gateway wire is replaced. Consumer acceptance and book PR required. |
| Pin filesystem integrity and 64 KiB read bound | same | [a2a-swarm docs/e2ee.md §3 “Host-written trust artifact”](https://github.com/relux-works/a2a-swarm/blob/479eeddb45a784e52db0e2356871b6494a03e40a/docs/e2ee.md), `internal/e2ee/pin.go` (`ReadHostPin`, `pinStatSafe`), `pin_types.go` (`MaxPin`). Reuse safety rules, not its cross-signing JSON format. |
| Snapshot schema, refresh cadence, stale labels; observe-only | new | Supplied lead ruling and D29 brief r2, ChainView/snapshot scope. Compatibility with the actual D29 pin schema awaits Source; no claim of drop-in compatibility. |

No conflict is resolved locally. The draft policy tension about absent seals and
the unverified D29 file format are explicitly pending in OPEN.md.

## 2. Transport, custody and resource bounds

The sole listener is a Linux AF_UNIX stream socket at an absolute, clean path
selected in root-owned host configuration. No discovery, environment fallback,
TCP listener, HTTP, user-provided URL, node selection or redirects exist.
The server MUST authenticate `SO_PEERCRED` UID against the explicit allow-list
before parsing input or contacting the node. No client-supplied identity counts.
UID 0 is allowed only when explicitly listed for a root helper. Unsupported or
unreadable peer credentials fail closed. Clients MUST validate every socket-path
component, socket type/owner, and connected server UID against host configuration.
A pre-existing socket MUST NOT be unlinked to seize an unknown listener.

Install model (requirements only): binary and configuration root-owned, not
agent-writable; gateway process runs as the dedicated unprivileged `chain-gateway`
user, with no login shell, a private primary service group, and membership
only in the dedicated socket-reader group in addition to that private group.
The root-owned credential file is regular, mode 0640, group readable only
by that exclusive service group; protected root-owned parent directories are
0750. No symlinks, agent ACLs, agent group membership, environment or argv secret
is allowed. Root provisions a cookie or a client username/password for a node
configured with rpcauth; the rpcauth verifier string itself is NOT an RPC client
credential. Cookie rotation reopens and revalidates the same host-configured
file. No credential-management RPC exists.

Only the gateway service reads that file for path (a); neither clients nor
adapters can read it. Logs, errors, metrics, crashes and wire responses MUST NOT
contain its value, encodings, HTTP auth headers, upstream error bodies or dumps.
There is no debug passthrough. Responses are constructed from the closed schema.
An upstream reflection of the credential in a projected string MUST cause
`unavailable`, no data and no reflected diagnostics, before bytes reach clients.
The gateway's egress is restricted to the configured local node. Its upstream
adapter accepts a typed enum only, with fixed read operations; it has no generic
method dispatcher, wallet API, signing/broadcast code, shell or plugin interface.
Ancillary tip reads are internal fixed read operations, never caller-selected.
Read-only capability must be qualified separately from a node credential that
might itself authorize writes.

Socket parent: `chain-gateway`-owned 0750, group the dedicated socket-reader
group; its higher ancestors are protected and root-owned. The daemon creates
the socket as `chain-gateway`, sets its group to socket-reader and mode 0660.
This permits the unprivileged daemon to bind without making the directory
agent-writable. The private credential group MUST be distinct from the reader
group; agents may belong only to the latter. Reader-group membership grants
access to connect only; the UID allow-list still decides. Agent accounts cannot
replace either object. The client pins the connected server UID to the
configured unprivileged service UID, not to a claimed request field.
Root-owned configuration pins network (`main` or `regtest`), node endpoint,
genesis hash, server UID, allowed UIDs, socket path and watched snapshot set.
The backend MUST verify configured network/genesis and refuse initial block
download or a mismatching chain as unavailable before returning observations.
No request changes configuration. All installed-input ancestry excludes symlinks and writable ACLs.

Each connection sends exactly one compact JSON object followed by one LF, then
half-closes its write side. The server waits for EOF; a second frame, trailing
bytes or absent LF is malformed. Response is one compact JSON object plus LF,
then close. EOF without a complete response is transport failure, never success.
No partial response is admissible; clients buffer and validate it entirely.
Limits count JSON payload bytes, excluding the single LF: request 1024,
response 4096. Readers consume at most limit + LF + one overflow byte before
refusal. Framing checks precede JSON/schema checks.

| Bound | Requirement |
| --- | --- |
| Per UID request admission | Token bucket: capacity 16, refill 8 tokens/second by monotonic time, initially full; one token per authenticated connection, including malformed input. No retry refund. |
| Global request admission | Token bucket: capacity 64, refill 32 tokens/second, same accounting. |
| Active reads | At most 2 per UID and 8 globally; no waiting work queue. Excess refuses `rate_limited`. |
| Accepted connections | At most 32, including partial and refusal frames. At capacity, close immediately; clients treat missing response as unavailable. Kernel backlog is not an admitted work queue. |
| Deadlines | Request frame plus EOF: 1 second from accept. Each upstream read attempt: at most 1 second. Entire server request including retries/write: 5 seconds from accept; response write: at most 1 second within that total. Client total deadline: 6 seconds from connect. |
| Retries | At most 3 read attempts total, only for a moved tip; bounded by the same total deadline. No unbounded retries, reconnect loops or cached success fallback. |

Unauthorized connections get `unauthorized` if a complete bounded refusal can
be sent within the deadlines; otherwise close. Framing timeout maps to
`unavailable`; a fully received invalid frame maps to `malformed`. Capacity
closure and broken transports cannot promise a typed wire response.

## 3. Canonical JSON and exact schema

CG1 uses **SJ1 plus the following full-byte canonical profile**, not CCJ-1.
UTF-8 JSON only; one top-level object; depth at most 8 (root object depth 1).
Every key is literal unescaped ASCII and exact lowercase schema spelling.
Recursive duplicate keys, Unicode simple-fold aliases, escaped keys, unknown
fields, missing fields, null, floats, exponent integers, negative numbers,
negative zero, BOM and trailing bytes MUST refuse. No Unicode normalization.
All protocol string values are ASCII. Integers use base-10 minimal spelling and
lie in 0..9007199254740991 unless a narrower bound below applies.

Objects serialize keys in ascending ASCII order, recursively; arrays preserve
their stated order. No insignificant whitespace, including a trailing newline
inside the payload. Strings use literal printable ASCII except `"` and `\`,
which use `\"` and `\\`; control characters are prohibited by field rules.
Escapes for otherwise literal characters, including slash, are noncanonical.
Compare canonical re-encoding with the complete received payload. This profile
applies to the wrapper, never to the decoded name-value bytes. Upstream node
replies MUST pass SJ1 recursive lexical checks and exact selected-field
projection checks before use; unrelated upstream extension fields may be
ignored, never aliases of selected fields (STRICT-JSON.md, sealwatch row).

Types used below:

- `H`: exactly 64 lowercase hex characters; hashes/txids use display byte order,
  never reversed wire order. The schema checks shape, not cryptographic truth.
- `N`: integer in 0..9007199254740991; `O`: integer in 0..4294967295.
- `Name`: 1..255 bytes, matching `[a-z0-9][a-z0-9/._-]*`; no conversion or
  lowercasing. D29 supplies the host-pinned owner's `id/` name. Other name
  encodings are outside v1 and refuse `malformed`.
- `Value`: padded RFC 4648 standard base64, canonical round trip, decoding to
  0..520 exact bytes. It is not base64url. Empty value is `""`. The octets are
  neither parsed nor rewritten by the gateway; even invalid application JSON
  is transported exactly for the consumer to refuse at its own boundary.
- `Tip`: exactly `{"hash":H,"height":N}`.

All object fields below are REQUIRED and CLOSED; no optional extensions.
Examples in fixtures are the exact compact payloads, with no LF in `wire`.

### Requests

Exactly `{"method":M,"params":P,"v":1}`. The method set is CLOSED:

| M | P, exact fields |
| --- | --- |
| `name_show` | `{"name":Name}` |
| `gettxout` | `{"txid":H,"vout":O}` |
| `getblockcount` | `{}` |

There is no generic RPC method, batch, wallet, write, spend, URL, address,
credential, request ID, include-mempool switch or client-selected block selector.
Unknown methods, including valid node RPC names, refuse `malformed`. One request
per connection provides response correlation; clients verify the echoed method
and requested name or outpoint before using the answer.

### Successes

Exactly `{"method":M,"network":Network,"ok":true,"result":R,"tip":Tip,"v":1}`.
Network is `main` or `regtest` and MUST equal protected client configuration.

| M | R, exact fields and semantics |
| --- | --- |
| `name_show` | `{"expired":boolean,"height":N,"name":Name,"name_block_hash":H,"txid":H,"value_b64":Value,"vout":O}`. `height` and `name_block_hash` locate the last confirmed name operation in the active chain, height <= tip height. If height equals tip height, name_block_hash MUST equal tip hash. Value, outpoint and expiry are from that same name state. Expiry is evaluated by the node's consensus rules at Tip, not guessed from a local fixed interval. Expired names can be returned with `expired:true` if the backend can supply their exact record; otherwise `not_found`. They never establish a live pin. An unconfirmed registration is not found; a pending update does not replace the last confirmed value (SH3). |
| `gettxout` | `{"state":"unspent" or "not_in_utxo_set","txid":H,"vout":O}`. Node view MUST include validated mempool effects, fixed true. `unspent` means present and not spent by that mempool at the observation instant; outputs created in the mempool can appear. `not_in_utxo_set` means absent from that view: spent, never created, unknown or unspendable are indistinguishable. It is a successful negative observation, NOT `not_found`, and never proof of a spending transaction. |
| `getblockcount` | `{}`. Tip contains BOTH height and hash; the method's familiar name does not imply a scalar response. |

A consumer MUST refuse admission unless a seal is positively `unspent`; absent
UTXO cannot authorize. Mapping absence to `DEVICE_REVOKED` for that command is
conservative refusal, not a claim that a spend was proved. Whether absence alone
permanently closes a device is OPEN Q2; this contract does not manufacture that
policy. The consumer retains all previously proved/journaled closures across
reorgs, restarts, unavailable reads and later unspent observations. Gateway
errors never themselves create permanent revocation evidence.

### Refusals

Exactly `{"error":{"code":Code},"ok":false,"v":1}`. No `method`, `network`,
`tip`, `result`, echoed input, upstream message, partial value or diagnostics.

| Code (closed enum) | Meaning and consumer action |
| --- | --- |
| `unavailable` | Node, credential, clock needed for deadlines, unsupported backend guarantee, timeout, malformed upstream response, unsafe host inputs or internal failure. Refuse admission; retry later within consumer budget. |
| `not_found` | A well-formed `name_show` has no retrievable confirmed name record. No pin; refuse. MUST NOT be used for UTXO absence. |
| `malformed` | Invalid framing, size, canonical JSON, schema, arguments, version or method. No node call; correct request before retry. |
| `rate_limited` | UID/global token or active-read cap exhausted. No upstream read for this request. Back off at least 1 second; no retry hint field. |
| `unauthorized` | Peer UID not allowed or credentials unsupported. No upstream read; no fallback identity. |
| `tip_moved` | Three attempts discarded because the tip moved, including a same-height hash change. No data survives. Restart the entire logical observation; no closure evidence. |

Refusal precedence: peer authentication; admission caps; frame/deadline;
canonical schema; node read. Once admitted, backend failure is unavailable;
three observed movements yield tip_moved unless a deadline expires first.
Unsupported v values use malformed, not a partially decoded future version.

## 4. Coherent observations and limits

Each success MUST correspond to one coherent read instant with exactly the
returned active-chain Tip. Name height/hash must describe an operation on that
chain. An answer MUST NOT mix name fields from different operations or attach a
new tip to an old value. UTXO/mempool state and its chain Tip must be acquired
coherently. `gettxout` does not return a mempool revision: two answers at an
identical Tip can differ because the mempool changes between reads.

If the active tip moves during acquisition (height OR hash), discard all fields
and restart, up to the limits above; then return tip_moved with no partial data.
A backend MUST establish either an atomic node read snapshot or an equivalent
chain-state lock/change-generation witness that detects every intervening tip
transition. Reading the same tip before and after ordinary RPC calls is
insufficient: an A→B→A transition can hide an inconsistent observation. Without
a proven witness, return unavailable. This is an implementation feasibility gate,
not permission to label an ordinary RPC bracket atomic. No node calls are made
by this unit, so the exact backend capability remains Q3.

The three methods do not provide a multi-request transaction. For a logical D29
check the consumer reads tip, name, all seals, then tip again; ALL successful
answers MUST have identical network, tip height and hash, matching requested
names/outpoints. Any mismatch or refusal discards the entire collected set and
retries the logical check at most twice (3 rounds total), then refuses. That
comparison is necessary but cannot prove mempool immutability or detect a tip
that left and returned between separate connections. It is not an atomic
all-seals snapshot and creates no reusable authorization lease. Source MUST
accept these limits, define freshness at admission, and retain its own closure
journal and continuous seal watcher before enforcement. No polling RPC can
prove a spend which entered and left the mempool entirely between polls.

An answer states a local node observation, not global finality, trusted wall
clock, independent proof of creation, proof of a seal script, spend branch,
wallet authority or proof that the node is on the globally best chain. Wrong
network, stale node, revoked client UID and node trust are host/consumer gates.
A fresh final tip query does not reveal that a node itself is lagging peers.

## 5. Root snapshot file (b): OBSERVE ONLY

A separate absolute clean path is host-configured, without discovery or
fallback into the agent's config/home. Helper runs as root; file and every
protected ancestor are root-owned, directories 0755, regular file exactly 0644,
no agent-writable ACLs, symlink components, special files or hard links
(`nlink` MUST equal 1). Reader is non-root and never creates or repairs the path.
Reuse U2a §3 and `ReadHostPin`: descriptor-relative no-follow traversal from a
trusted root, `fstat` each opened component, bounded read from the same validated
file descriptor. This profile uses protected non-writable ancestry throughout;
it does not adopt U2a's temporary sticky-directory allowance for installation.
The snapshot JSON is a separate format, not U2a's cross-signing pin.

Root helper (b) has its own privileged host chain-read custody during the working
cut; it MUST NOT deliver credentials to the adapter. It does not depend on (a)
existing first. Once (a) is installed, root may be an explicitly allowed gateway
client. Helper authentication configuration is not part of the public snapshot.
Neither helper nor gateway accepts arbitrary RPC from agents.

One complete CG1 canonical object, at most 65536 payload bytes (no LF):

`{"mode":"observe_only","names":[NameRecord...],"network":"main" or "regtest","seals":[SealRecord...],"tip":Tip,"v":1,"written_at":N}`

`NameRecord` is exactly the `name_show` result above. `SealRecord` is exactly the
`gettxout` result above. All records share the SINGLE top-level Tip; name heights
<= tip height. `written_at` is POSIX UTC seconds measured after the complete
coherent collection, before persistence; no time zone strings or nanoseconds.
Names array: 1..16, sorted strictly by name ASCII bytes. Seals: 1..256, sorted
strictly by txid ASCII bytes, then numeric vout. No duplicates or omissions from
the host-configured watch set. The consumer verifies the exact expected watch
set and network against protected configuration; a plausible foreign owner's
snapshot is not acceptable. Value bytes carry the pin; no separately supplied
list hash can override them. Device-list bytes and private keys never enter this
file. Schema validity alone does not prove watch-set completeness.

Helper refreshes on startup, each observed new block OR same-height tip hash
change, and at least every 30 seconds to label write liveness during a long block
interval. It may also refresh on mempool change; no cadence makes it enforceable.
The helper collects a complete set, not a patch, using the per-read
§4 guarantees and requiring one common Tip for every record and both end
checks. It does not claim an atomic multi-record mempool snapshot; observations
can be separated in time even at the same Tip. A failed
read or publication MUST NOT replace the last valid file with partial records,
empty arrays or an invented current timestamp. Unavailable/missing records are
not representable as successful records: keep the previous complete snapshot
and let its age become stale. Missing expected file means unavailable.

Publication: create a fresh same-directory temp file with O_EXCL and no symlink
following, mode 0600; write all bytes and validate; set root ownership and 0644;
fsync file; atomically rename over the configured final file; fsync containing
directory. Sync newly created ancestors before use. Serialize writers; on error
remove only that writer's temp file, retain old published bytes. A crash after
rename before directory fsync may recover either old or new complete snapshot;
publication durability is not claimed until directory sync succeeds.

Adapter labels every accepted snapshot **OBSERVE ONLY** even when fresh:

| Label | Condition (evaluated by consumer, not a field the helper asserts) |
| --- | --- |
| `fresh` | age in 0..60 seconds, independently known live tip exactly equals snapshot Tip, and all configured bindings match |
| `stale` | age >60 seconds, snapshot height behind known live tip, equal height with different hash, or snapshot height ahead of known live tip |
| `unknown` | no independently known live tip or trustworthy clock; tip height alone cannot establish freshness |
| `invalid` | written_at is in the future, schema/filesystem/network/watch-set failure; no usable snapshot |

Label precedence is: invalid schema/bindings; unknown clock; future time invalid;
age stale; unknown live tip; mismatching tip stale; otherwise fresh.

A mempool-only spend can be absent from any snapshot labelled fresh. No label,
short age or atomic replace authorizes enforcement. Freshness of a root file is
not an exemption from the lead's observe-only ruling.

## 6. Versioning, fixture obligations and scope

`v:1` identifies this exact closed schema/profile. Adding fields, methods,
refusal codes, networks or changing canonical bytes requires a new version,
consumer acceptance and new shared vectors. Unknown versions fail closed.
A host config change cannot reinterpret v1; limits may be tightened only if
reported as a distinct deployment profile accepted by both parties.

The gateway-side package contains tests only: `schema_test.go` and
`contract_test.go`. Its executable schema validates wrappers, types, limits,
canonical bytes and fixture relationships. `fixtures/vectors.json` stores exact
payloads as JSON strings so duplicates, whitespace and malformed inputs remain
visible. `wire_b64` carries non-UTF-8 controls. `kind` selects request, response,
`snapshot`, `snapshot_size`, `frame_request` or `frame_response`. Frame-only
vectors test size/LF/EOF
independently of payload schema; they do not claim that arbitrary bounded bytes
are a valid request. Snapshot-size vectors likewise isolate the payload bound
from the full snapshot schema. `fixtures/observations.json` records tip
movement and cross-call correlation scenarios, including A→B→A and same-height reorgs.

The consumer MUST mirror `TestSharedVectors`, `TestObservationVectors`,
`TestSnapshotLabels` and the valid/invalid controls in `TestSchemaControls` in
its own language/decoder, using these same bytes and expected verdicts. Merely
running or copying this Go parser twice is not independent agreement. Source
must bind each fixture to its adapter's real entry point when implementation
exists. The gateway implementer must later bind them to its actual listener and
upstream adapter. Pure schema tests prove neither implementation exists.

Out of scope: gateway/helper code, node/RPC calls, install or root work, credential
provisioning, wallet/write methods, list distribution/cache implementation,
cryptographic device/list/seal validation, durable journal implementation,
continuous watches, historical spend proofs, multi-call atomicity, enforcement
switches and live qualification. See OPEN.md for acceptance and build gates.
