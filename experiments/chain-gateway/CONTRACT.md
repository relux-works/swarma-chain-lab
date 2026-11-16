# Read-only chain view contract (CG1, candidate)

CHAINGW-C1 / G1 T4.6. This is a contract-first candidate for acceptance by the
consumer maintainer (Source), not an implemented service or activation approval.
MUST, MUST NOT and SHOULD are normative. Version 1 is frozen only after consumer
acceptance of an exact Git head. Both implementations MUST pin that head and the
same fixtures. This freezes the interface, not its feasibility: “enforcement-ready”
requires Q3 qualification of coherent `name_show` and negative `gettxout`, plus
Q10's CGW-J1 journal. Until qualified, (a) returns `unavailable` for any read
whose guarantee it cannot establish. The gateway belongs in chain-lab; the live
and snapshot adapters
belong in a2a-swarm behind D29's ChainView interface.

## 1. Authority, sources and decision register

The supplied lead ruling authorizes (b), a root helper refreshing a pin at every
block, for OBSERVE ONLY, then (a), a secret-free read-only chain gateway after
contract acceptance. A gateway-backed reader is a **NON-WITNESS for
mempool-first closures**: it refuses on anything but `unspent` and creates NO
enforcement closure. Device-list enforcement requires BOTH (a) per-command
reads and the separately admitted CGW-J1 watcher journal (§4, Q10 in
[OPEN.md](OPEN.md)); enforcement closures come ONLY from that journal.
Enforcing over (b) requires a separate owner decision. No passing fixture enables
enforcement.

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
| Mempool-inclusive seal observation; non-witness reader | refines | LIP-0029 §8 O8.3–O8.5, O8.9 and §11 step 8; F5's confirmed AND not mempool-spent projection keeps separate transient states (§3). Prior journaled unspent followed by confirmed-set absence yields only an OBSERVE-GRADE closure, never enforcement state. Enforcement closures come only from CGW-J1 (§4, Q10); Q8's spec clarification remains required. |
| Seal script transport, no invented script policy | refines | LIP-0029 §3.1 field 6 binds only the outpoint; §8.3 O8.8 binds fresh-key custody, but its following paragraph explicitly leaves the script open. Return `script_pubkey` bytes; no script validation is claimed for this pinned revision. Q8 must define the expected script or an accepted list-record extension before claiming a script check. |
| UTXO absence is not proof of a spending transaction | refines | LIP-0029 §8.3 names `gettxout`; it cannot distinguish spent from never-created. This contract exposes `not_in_utxo_set` and prohibits inventing spend evidence. Consumer mapping accepted in answers r1 below; policy-owner spec clarification remains Q8. |
| Compare observations at a named chain state | same | Book ch. 26, [“Лёгкое чтение и проверяемый индекс”](https://github.com/relux-works/swarma-docs/blob/b57a9be633c245373b448c3786bcbd49d636fe8a/book/ru/26-cepochka.md#лёгкое-чтение-и-проверяемый-индекс): compare the same height and rules. This trusted full-node projection supplies no light-client proof or consensus qualification. |
| Coherent tip binding, cross-call comparison and bounded retries | refines | LIP-0029 §11 steps 4 and 8; [LIP-0008 §5.1](https://github.com/relux-works/swarma-link-spec/blob/bd3bc80e5543d8a563343ec05abd1a5f3f67284c/lips/LIP-0008-grant-v4.md) distinguishes inconsistent observations from proven closure. CG1 makes the read guarantee explicit. |
| Recursive duplicate, escaped-key and case-alias refusal | same | [STRICT-JSON.md SJ1](../STRICT-JSON.md), including exact typed names. Opaque name-value octets retain their own LIP-0010 parser boundary. |
| Wire ordering, framing, budgets, enums, schema and version | new | Host-local CG1 decisions in §§2–6; no existing book gateway wire is replaced. Consumer acceptance and book PR required. |
| Pin filesystem integrity and 64 KiB read bound | same | [a2a-swarm docs/e2ee.md §3 “Host-written trust artifact”](https://github.com/relux-works/a2a-swarm/blob/479eeddb45a784e52db0e2356871b6494a03e40a/docs/e2ee.md), `internal/e2ee/pin.go` (`ReadHostPin`, `pinStatSafe`), `pin_types.go` (`MaxPin`). Reuse safety rules, not its cross-signing JSON format. |
| Snapshot schema, refresh cadence, stale labels; observe-only | new | Supplied lead ruling and D29 brief r2, ChainView/snapshot scope. Source accepted part (B) as D29's final snapshot format in consumer answers r1; D29 parser adoption still needs its own exact-head evidence. |

Source's consumer answers r1 (2026-11-16, answering head
`3f50b9b257fcc9e337a440146d1330b6f08ef6c7`) accept Q1, Q2, Q4 and Q5
and confirm Q9, with the qualifications below. Part (B) is the accepted final
snapshot format for the helper build; D29's parser must adopt it and report its
own exact head. This delta adds Source's requested tip time before the v1
freeze; Source's delta acceptance and the review of record remain pending.
Q8's policy/spec approval is distinct from consumer acceptance. No install or
enforcement is authorized by these answers. Answer events are recorded in OPEN.md.

## 2. Transport, custody and resource bounds

The sole listener is a Linux AF_UNIX stream socket at an absolute, clean path
selected in root-owned host configuration. No discovery, environment fallback,
TCP listener, HTTP, user-provided URL, node selection or redirects exist.
The server MUST authenticate `SO_PEERCRED` UID against the explicit allow-list
before parsing input or contacting the node. No client-supplied identity counts.
UID 0 is allowed only when explicitly listed for a root helper. Gateway and
clients MUST run in the initial user namespace; `PrivateUsers=` or translated
UIDs are unsupported. Agent allow-lists MUST reject 0, 65534, 65535 and
4294967295; the separately configured root-helper exception is the only use of 0.
The daemon MUST bind/listen itself: inherited listeners and socket activation
are prohibited. `SO_PEERCRED` records connect-time identity, so an authorized
process can delegate a connected fd; this is accepted for public reads only and
must be reassessed for any future non-public method. On restart the service
manager removes only its own stopped service's socket and recreates its private
runtime directory after confirming no live listener; unknown sockets fail
closed. Unsupported or
unreadable peer credentials fail closed. Clients MUST validate every socket-path
component, socket type/owner, and connected server UID against host configuration.
A pre-existing socket MUST NOT be unlinked to seize an unknown listener.

Install model (requirements only): binary and configuration root-owned, not
agent-writable; gateway process runs as the dedicated unprivileged `chain-gateway`
user, with no login shell, a private primary service group, and membership
only in the dedicated socket-reader group in addition to that private group.
Gateway (a) MUST use a dedicated verifier-only rpcauth client user/password,
never a cookie, including on the same host. The root-owned credential file is
regular, mode 0640, group readable only by that exclusive service group;
protected root-owned parent directories are 0750. No symlinks, agent ACLs,
agent group membership, environment or argv secret is allowed. The rpcauth
verifier string is NOT an RPC client credential. Rotation reopens and
revalidates the same protected file; there is no credential-management RPC.
This adopts the G2 node precedent (`deploy/g2_pay.go`, `rpcwhitelist`) and the
owner's verifier-user rule: verifier-only deployments never use a cookie.

Helper (b) normally has its own dedicated rpcauth verifier user, with the same
closed read set. ONLY an explicitly selected same-host Linux root helper may
instead read the node-generated cookie. It opens the live node-owned regular
0600, single-link cookie afresh each run with descriptor-relative no-follow
traversal, pinned node UID, and protected ancestry; no agent, reader group or
gateway gets access. Core owns creation/rotation at restart. No stale root copy,
copying daemon or fallback from a failed verifier credential is implied. If an
installation chooses Infra's copied-cookie option, a separately admitted root
installer must validate that live source, atomically replace a root-owned 0600
copy on every node restart BEFORE enabling the helper, and invalidate the copy
on failure; cookie-generation/copy qualification remains Q7. The cookie can
have broader RPC authority: this exception is install-only, root-helper-only,
not a least-privilege credential and never an option in verifier-only deployments.

Only the gateway service reads (a)'s file; neither clients nor adapters can
read it. The listener AND direct-RPC helper (b) are **Linux-only in v1**.
There is NO platform fallback: absent qualified kernel endpoint-owner proof or
dump/ptrace protection means no credential load, no RPC and no publication.
Both credential holders MUST set `PR_SET_DUMPABLE=0` and `RLIMIT_CORE=0` before
loading credentials; inability to do so fails closed. Logs, errors, metrics,
crashes and wire responses MUST NOT contain credentials, encodings, HTTP auth
headers, upstream error bodies or dumps. There is no debug passthrough.
Reflection checking compares exact bytes of the complete raw client credential
(`user:password` or cookie), its RFC 4648 Basic-auth base64 and complete
`Basic <base64>` header, plus the complete password bytes alone and complete
cookie-secret bytes alone (the bytes after the first colon), against projected
strings and decoded name-value octets, before constructing output. Only entries
for the selected credential mode are loaded. Whole-secret exact equality refuses `unavailable`
with no data/diagnostics. This is whole-value equality, not substring matching;
matching fragments, usernames or short substrings of the password is not the
reflection rule. This bounded check does not claim to
detect arbitrary encodings or fragmented application-level exfiltration.

**Authenticate the upstream before credentials.** Root configuration pins the
local numeric loopback endpoint AND node service UID. The node MUST run under
a dedicated unprivileged account in the initial user AND network namespaces.
Its UID MUST differ from the gateway/server UID, EVERY allow-listed UID
(including an explicit root-helper UID), and every helper, consumer or other
non-node workload UID. The node UID MUST NOT be 0 or a reserved UID. Node RPC
MUST bind AND allow connections on numeric loopback only (IPv4 and IPv6 where
enabled); wildcard, external, translated-namespace and remote RPC are forbidden.
Install/config qualification MUST reject each overlap, shared workload, noninitial
namespace and non-loopback bind/allow, with a distinct-account/loopback positive
control. Kernel UID proof authenticates this exclusive account, not a binary.
On EVERY TCP connection,
before writing any HTTP/request/Authorization byte, gateway and direct-RPC
helper MUST obtain kernel socket ownership and require the listening socket's
owner UID to equal that configured node UID. On Linux use `NETLINK_SOCK_DIAG`,
`SOCK_DIAG_BY_FAMILY` / `inet_diag_req_v2`, and `inet_diag_msg.idiag_uid`
([sock_diag(7)](https://www.man7.org/linux/man-pages/man7/sock_diag.7.html)).
Query the exact endpoint in the same network/initial user namespace and also
verify the server-side connected TCP socket by the reverse connected tuple
(and socket cookie when available). A port-only pre-connect lookup is
insufficient: listener replacement must not authenticate an already connected
impostor. Missing, ambiguous, stale, denied or unsupported kernel evidence,
UID mismatch, mixed-owner reuse-port listeners or namespace mismatch MUST
close without sending a credential and return `unavailable` (helper exits 11,
old file untouched). No DNS, proxy, redirect or remote-node fallback is allowed.
Network/genesis RPC is performed only AFTER this authentication and is not an
authenticator. Pinned-UID ownership is not binary attestation; the node account
and root remain trusted. Q6 qualification pairs the genuine node control with
an impostor UID listener that receives zero Authorization bytes.

The closed upstream read set for BOTH gateway and direct-RPC helper is EXACTLY:

```
getblockchaininfo getblockhash getblockheader name_show gettxout
```

`getblockchaininfo` supplies network/IBD and tip hash/height; `getblockheader`
supplies bound header time; `getblockhash` binds genesis and name-operation
height. `name_show` and the two fixed `gettxout` views supply records. No
`getchaintips`, wallet, write, arbitrary dispatcher, shell or plugin exists.
Each rpcauth user MUST have an explicit node-enforced entry:

```
rpcwhitelist=<verifier-user>:getblockchaininfo,getblockhash,getblockheader,name_show,gettxout
```

Separate verifier users are required for (a) and (b), without unions with
broader whitelist entries. In rpcauth mode, at startup after endpoint
authentication, send the
fixed harmless out-of-set probe `getrpcinfo` and require HTTP 403 with no
projected body; it is a denial probe, never an allowed operation. Otherwise
remain unavailable. Node configuration inspection plus this negative probe
qualifies the complete allow-list; one probe alone does not prove every denial.
The install-only root-cookie exception MUST be explicitly recorded instead of
claiming it passed least-privilege qualification. Any Q3 design needing more
upstream RPCs requires a reviewed contract revision before implementation.

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
genesis hash, node UID, server UID, allowed UIDs, socket path and watched snapshot set.
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
| Per agent UID admission | Capacity 16, refill 8 tokens/second by monotonic time, initially full; one token per accepted connection, before allow-list authorization, including refusals/malformed input. No refund. At most 8 configured agent UIDs. |
| Agent aggregate | Capacity 128, refill 64/second, partitioned into the eight UID buckets; unused shares are not borrowed. One UID cannot consume another's share. |
| Frame-read connections | At most 2 per configured agent UID, separate from active reads; 1-second frame/EOF deadline. Slow frames consume only that UID's reserved slots. |
| Active reads | Start ONLY after complete EOF, canonical schema and authorization; at most 2 per agent UID, 16 agent slots total, reserved per UID. No waiting work queue. Excess refuses `rate_limited`. |
| Unauthorized peers | Charge by kernel peer UID before authorization, capacity 16/refill 8/s; all unlisted peers also share a separate global 16/8 bucket and at most 2 refusal/frame slots. No authorized capacity is consumed. |
| Explicit root-helper reservation | Separate 512-token burst, 128/s refill, 16 frame slots and 16 active slots, unavailable to agents/unlisted root. Never consumes an agent share. Root client paces at or below these bounds. |
| Accepted connections | At most 66: 8 × (2 frame + 2 active), 32 root-helper and 2 unauthorized; unused reserved slots are not borrowed. At capacity close immediately; clients treat no response as unavailable. Kernel backlog is not an admitted queue. |
| Deadlines | Frame plus EOF: 1 second from accept. Each upstream attempt: at most 1 second. Entire server request including retries/write: 5 seconds from accept; write: at most 1 second within that total. Client total: 6 seconds from connect. |
| Gateway read retries | At most 3 backend read attempts per gateway request, only for moved tip, within the same deadline. This is distinct from §5 helper collection retries (which also handle rate limiting). No unbounded loop or cached-success fallback. |

Peer credentials are obtained immediately at accept to select the pre-auth
bucket/compartment; unreadable credentials use the unauthorized compartment.
These partitions bound cross-tenant application-level starvation: another UID
cannot consume a tenant's tokens, frame slots or active slots. They do not
qualify host/kernel scheduling under connection floods; Q6 must test the
configured host's fair progress under bounded competing UID traffic.

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
`name_show` MUST request `allowExpired:true`, `nameEncoding:"hex"` and
`valueEncoding:"hex"`. Decode and verify the exact requested name octets, then
encode the exact decoded value octets as canonical `value_b64`. If the pinned
Core cannot select both encodings per call, its protected node configuration
MUST require hex for both and qualification must verify that response encoding;
no ascii/utf8 fallback or string-to-UTF-8 re-encoding is permitted. Q3 includes
an opaque 00/ff value round trip.

### Bounded upstream profile

Both credential holders use the candidate **Namecoin Core 28.0, JSON-RPC 1.0**
profile below. The exact installed binary/config and these mappings MUST be
qualified in Q3/Q6 before use; these are required outcomes, not a claim that a
live node was tested. A version with different behaviour is unavailable until
a reviewed profile revision, not an error-message heuristic.

Limits cover the entire decoded HTTP entity including ignored extensions,
whitespace and error envelopes. Compression, redirects, batches and chunk/body
fallbacks are forbidden; HTTP chunk framing may be decoded under the same cap.
Do not trust Content-Length: stream through a cap+1 reader, STOP at byte cap+1,
reject overflow before JSON parsing, and close without draining. Apply SJ1
recursively while tokenizing with the method depth cap (objects/arrays, root=1),
before constructing an unbounded tree. Null is allowed only for the specified
RPC envelope/result slots; upstream floats may occur in ignored fields, never
in selected integer fields. No canonical-byte requirement is imposed upstream.

| Method | Entity bytes / container depth | Projection-derived allowance (including bounded envelope/extensions) |
| --- | --- | --- |
| `getblockchaininfo` | 8192 / 4 | chain, IBD, 64-hex best hash and safe height are <256 bytes; 7936 bytes for bounded Core metadata |
| `getblockhash` | 256 / 1 | 64-hex scalar result plus <=190 bytes for envelope/spacing |
| `getblockheader` (verbose=true) | 4096 / 4 | hash, height, time <256 bytes; 3840 bytes for bounded header metadata |
| `name_show` | 4096 / 4 | hex name <=510 and value <=1040 (1550 bytes); 2546 bytes for txid/index/height/expiry, envelope and bounded metadata |
| `gettxout` (each fixed view) | 32768 / 5 | script hex <=20000, bestblock/confirmations <256; 12512 bytes for envelope/script metadata |

These are upstream bounds, not permission to exceed the 4096-byte public
response or 65536-byte snapshot projection limit. Largest projections must
still pass those separate output gates. Additional extensions exceeding a cap
make the backend unavailable; no cap may be silently raised.

Every request has a fixed, nonempty ASCII string id selected by the adapter;
a reply MUST have exactly one matching string id and exactly `result`, `error`,
`id` at its envelope. No JSON-RPC 2.0/version alias or notification is accepted.

| HTTP / JSON-RPC outcome | Mapping |
| --- | --- |
| 200, error=null, correctly typed result and matching id | Selected projection; `gettxout` result=null is the successful absent view |
| 500, result=null, error exactly {code:integer,message:string}, matching id; `name_show` code=-4 | `not_found` ONLY after Q3 qualifies this as no confirmed record with allowExpired=true (including expired-name positive control) |
| Any other RPC error (including -4 on another method), auth 401, whitelist 403, 404, 429, 5xx, or unexpected status | `unavailable`; no upstream body or error text is exposed |
| 200 with non-null error, 500 without the qualified error shape, result AND error non-null, missing slots, id mismatch/type mismatch, malformed SJ1/selected fields, cap/depth overflow | `unavailable`, no partial projection |

The fixed startup denial probe alone expects 403 (§2); 403 is never a normal
read success. Error strings never select a class. Fake-upstream fixtures cover
these boundaries without contacting a node; real-version qualification remains
open.

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
- `Script`: lowercase even-length hex encoding of exact upstream
  `scriptPubKey.hex` octets, 0..10000 bytes; no assembly, address or inferred
  script. The complete response/snapshot byte limit also applies. Oversize
  projections refuse `unavailable` (helper exits 11), never truncate. Snapshot
  count caps are maxima, not a promise that every combination fits 64 KiB;
  installation must qualify the complete configured set within that byte bound.
- `Tip`: exactly `{"hash":H,"height":N,"time":N}`. `time` is that block's
  header timestamp in POSIX UTC seconds, not acquisition time, median time past,
  helper write time or a freshness verdict. All three successful methods bind
  this complete Tip, and the snapshot carries the same type. Refusals carry no
  Tip. Zero and 9007199254740991 are schema boundaries, not claims about a real
  block; invalid/missing times MUST refuse. Hash, height and time MUST describe
  the same block.

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
| `name_show` | `{"expired":boolean,"height":N,"name":Name,"name_block_hash":H,"txid":H,"value_b64":Value,"vout":O}`. `height` and `name_block_hash` locate the last confirmed name operation in the active chain, height <= tip height. If height equals tip height, name_block_hash MUST equal tip hash. Value, outpoint and expiry are from that same name state. Expiry is evaluated by the node's consensus rules at Tip, not guessed from a local fixed interval. Expired names MUST return their exact confirmed record with `expired:true` (`allowExpired:true`); a backend unable to retrieve it returns `unavailable`, never a backend-dependent `not_found`. They never establish a live pin. An unconfirmed registration is not found; a pending update does not replace the last confirmed value (SH3). |
| `gettxout` | For `unspent`, `unconfirmed`, `spend_pending`: exactly `{"confirmations":N,"script_pubkey":Script,"state":State,"txid":H,"vout":O}`. For `not_in_utxo_set`: exactly `{"state":"not_in_utxo_set","txid":H,"vout":O}` (no fabricated confirmation/script). The fixed two-read projection below distinguishes confirmed absence from a pending spend. This is a successful negative observation, NOT `not_found` or proof of a spending transaction. |
| `getblockcount` | `{}`. Tip contains height, hash and block header time; the method's familiar name does not imply a scalar response. |

**Two reads, fixed by v1:** read `gettxout(txid,vout,false)` (confirmed
set, C) AND `gettxout(txid,vout,true)` (mempool-inclusive, M). Both views and the
Tip must satisfy §4's coherent instant guarantee for (a), including mempool
changes across the pair; merely equal bestblock values do not prove it.
For (b), the same two reads use §5's weaker bracketed label semantics.

| C | M | State and returned source |
| --- | --- | --- |
| present, confirmations >=1 | present, same confirmations/script | `unspent`; confirmations/script from that confirmed output |
| absent | present, confirmations =0 | `unconfirmed`; confirmations 0 and script from M |
| present, confirmations >=1 | absent | `spend_pending`; confirmations/script from C; confirmed output is NOT absent |
| absent | absent | `not_in_utxo_set`; absent from the CONFIRMED set and current mempool-inclusive view |

Present answers MUST bind `bestblock` to the complete Tip's hash; confirmations
must be possible at that height (1..height+1 for confirmed states). Conflicting
scripts/counts, C with zero confirmations, or M confirmed when C is absent
are inconsistent and return `unavailable`; no partial record escapes. Vout
above 2147483647 is deterministically `not_in_utxo_set` without an upstream
gettxout call, after qualifying the pinned Core's signed-index range and
obtaining §4's absence witness; a backend without that qualification is
unavailable for the profile, never a different success for the same input.

A gateway-backed reader MUST refuse unless the seal is positively `unspent`:
CONFIRMED (confirmations >=1 at Tip) AND not spent by any mempool transaction.
It is a **NON-WITNESS for mempool-first closures** and MUST create NO enforcement
closure from any of these reads. `unconfirmed` and `spend_pending` both refuse
that command as DEVICE_REVOKED-class, journal NOTHING permanent and NEVER count
as confirmed-set absence. Mempool transactions can be evicted/replaced.

History MUST be keyed by the expected `(network, txid, vout)` from protected
configuration, never by a global seen flag. A wrong network/outpoint, invalid
response or contradictory confirmed view at an already seen Tip is
unavailable-class: refuse the current command, make NO history update or new
closure, and retain existing observe state. Track the confirmed view per Tip
hash (including its height/time): `unspent`/`spend_pending` mean present with
fixed script/confirmations, `unconfirmed`/`not_in_utxo_set` mean absent. A switch
between present and absent, changed confirmed metadata, or the same hash with
different height/time is contradictory. Mempool-only transitions may occur at
one Tip. Confirmed-set changes require a different Tip hash; revisiting a hash
must agree with its remembered confirmed view.

When this reader previously journaled `unspent` for that key and later at a
different Tip sees `not_in_utxo_set`, absent from the CONFIRMED set, it MUST label and journal
an **OBSERVE-GRADE closure** only. The reader validated no spending transaction;
confirmed-set absence can also result from a reorg that removed the funding
transaction. This observe-journal entry MUST NEVER be imported into enforcement
state or used as an enforcement refusal. It remains an observe-grade label
across reorgs, restarts or later states, even if `unspent` is later observed.
Never-seen absence refuses only the command; errors create no closure of either
grade. `unspent` is necessary, not sufficient, for admission: all other consumer
checks and the independent CGW-J1 journal still apply. Enforcement closures come
ONLY from CGW-J1, with validated spender evidence, conflict completeness and one
named tip (§4, Q10 in [OPEN.md](OPEN.md)). Policy-owner spec clarification remains
Q8; the former F5/Q2 permanent-reader-closure wording is superseded.

The consumer checks `script_pubkey` against an expected seal script ONLY when
an accepted spec clause or the verified list record actually defines it. At
pinned LIP-0029 §3.1 field 6 the record defines only txid/vout; §8.3 O8.8 and its
following paragraph leave the script open. Thus this revision transports exact
script bytes but claims NO seal-script validation; Q8 explicitly remains open.
A later defined script binding must cite its clause and gain new shared vectors;
no locally invented script is accepted. Under (b) all states/closures are labels
and observe-journal entries only, never enforcement decisions.

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

Refusal precedence: kernel peer UID and pre-auth budget/frame reservation;
peer authorization; frame/EOF/deadline; canonical schema; active-read reservation;
node authentication/read. No active slot is held while waiting for a frame.
Once admitted, backend failure is unavailable;
three observed movements yield tip_moved unless a deadline expires first.
Unsupported v values use malformed, not a partially decoded future version.
A schema-invalid, noncanonical, truncated or otherwise invalid RESPONSE is
`unavailable` to the consumer; discard the whole collection and journal no
closure. Never salvage a valid-looking subset.

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
by this unit, so the exact backend capability remains Q3. Positive gettxout has
`bestblock`; a null result has no such witness. `name_show` does not supply the
complete bound Tip/name-operation block hash itself. Both negative gettxout and
name_show need a qualified witness beyond ordinary RPC brackets, including the
two-view mempool coherence requirement. Interface freeze is not enforcement
readiness. Confirmed fields at one active tip hash form one confirmed view;
mempool effects remain non-atomic across connections.

The three methods do not provide a multi-request transaction. For a logical D29
check the consumer reads tip, name, the ONE seal of the signing device, then
tip again: four connections per command, all charged to the UID bucket. The
consumer MUST NOT require all device seals per command. V1 permits exactly ONE
name and ONE expected signing-device seal per logical check. Pace the shared
UID at <=8 connections/s, burst <=16 and <=2 active requests, including all
retry rounds; three full rounds consume 12 tokens from an idle bucket. On
rate_limited wait at least one second within the unchanged three-round budget.
A fourth round is forbidden; after three failed rounds refuse without closure.
ALL successful answers
MUST have identical network and complete Tip (hash, height and time), matching requested
names/outpoints. Any mismatch or refusal discards the entire collected set and
retries the logical check at most twice (3 rounds total), then refuses. That
comparison is necessary but cannot prove mempool immutability or detect a tip
that left and returned between separate connections. It is not an atomic
all-seals snapshot and creates no reusable authorization lease. Source MUST
accept these limits, define freshness at admission, and read CGW-J1's independent
closure journal with a qualified continuous seal watcher before enforcement
(Q10 in [OPEN.md](OPEN.md)). No polling RPC can prove a spend which entered and
left the mempool entirely between polls.

An answer states a local node observation, not global finality, trusted wall
clock, independent proof of creation, proof of a seal script, spend branch,
wallet authority or proof that the node is on the globally best chain. Wrong
network, stale node, revoked client UID and node trust are host/consumer gates.
A fresh final tip query alone does not establish the node's global currency.
Source's consumer policy MUST compare trusted check-time with Tip.time against
a host-configured maximum lag, default 7200 seconds. Exceeding that bound means
unavailable-class refusal, never DEVICE_REVOKED; in observe mode it labels the
observation stale. The 7200-second default is consumer policy, not a gateway
rejection threshold, wire limit or claim that block time proves peer agreement.
A lag exactly at the configured bound is permitted by this policy.

### Accepted v1 consumer limits (Q1 and Q9)

The listener and direct-RPC snapshot helper (b) are Linux-only in v1, with NO
fallback when platform proof is absent. A Darwin direct-RPC or listener profile
is NOT admitted; its owner decision and CGW-D1 dependency remain open in OPEN.md.
Multiple clients sharing one UID share the same 8/s bucket; per-client UID
isolation is an S1 follow-up, not a gateway distinction.
An active-chain membership read for the journaled SH5 block is a v2 candidate,
not a fourth method in v1.

SH3 requires the last confirmed name operation; a pending update MUST NOT
change the head. Confirmation depth is tip height minus name height plus one;
Source's v1 minimum is 1, with a larger minimum allowed in host configuration.
The consumer MUST check SH4, SH6 and O3.4–O3.6 on the opaque name-value octets:
exact member spelling, no duplicate or fold alias, owner/network binding and
sequence/hash against the pin. The gateway MUST transport the bytes unchanged.

For SH5 the consumer MUST journal the highest sequence, name-operation txid,
height and block hash, and every refusal. Refusals MUST never be lifted. With
v1's limited reads, a lower sequence at a height above the journaled height
MUST refuse DEVICE_LIST_ROLLBACK. A lower sequence at the same or lower height,
or another block hash at the journaled height, is treated as a reorganisation:
take the confirmed head and retain every journaled refusal. This is an explicit
approximation: v1 cannot establish whether the journaled operation remains in
the active chain, so a deep reorganisation can cause a false refusal until the
owner publishes a higher sequence. The error is in the safe direction. Adapter
docs MUST keep the Draft/co-author status of LIP-0010 §11 and LIP-0029 visible.

### Enforcement precondition (Q10; separate unit)

CGW-J1 is a separately admitted host-owned watcher/journal service next to the
node in chain-lab, plus Source's journal reader. It uses the sealwatch design
(`experiments/sealwatch/README.md`): node-enforced dedicated read credential for
`getblockchaininfo,getblockhash,getrawtransaction,getrawmempool,gettxout,getblock`
to inspect actual spending inputs. These methods belong to CGW-J1, NOT the
v1 gateway credential/interface; v1 gains no fourth method. CGW-J1 needs its own
service-class admission, exact contract, durable-journal and live qualification.
Per-command polling MUST NOT be described as continuous O8.3 observation.
Enforcement closures MUST come ONLY from CGW-J1's watcher journal, never from a
gateway-backed reader, a qualified coherent read alone, or an observe journal.
Before appending an enforcement closure, CGW-J1 MUST validate the spending
transaction bytes against the seal script, establish conflict completeness and
bind that evidence to one named tip. UTXO absence, even at a coherent instant,
is not validated spender evidence. Q10 in [OPEN.md](OPEN.md) tracks this separate
acceptance and qualification gate.
Before enforcement a host-owned watcher, running as a service account rather
than an agent UID, MUST follow blocks and mempool for the watch set and append
those validated closures to a root-owned append-only journal readable but
unwritable by agents, under the snapshot filesystem profile.
The same journal MUST carry SH5's
highest sequence and name-operation txid outside agent write authority. The
consumer MUST refuse if either the journal names the device or live gettxout
is not `unspent`; a missing/unreadable journal MUST refuse. The watcher/journal
writer and consumer reader require a separate accepted unit and qualification.
This contract does not implement them, and enforcement remains off.

## 5. Root snapshot file (b): OBSERVE ONLY

A separate absolute clean path is host-configured, without discovery or
fallback into the agent's config/home. Helper runs as root; file and every
protected ancestor are root-owned, directories have no group/other write bits
(stricter traversal modes such as 0711 are permitted), output parent exactly
0755, regular file exactly 0644,
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

One complete CG1 canonical object, at most 65536 payload bytes. The file is
EXACTLY that payload: no trailing LF. Reader consumes at most 65537 bytes from
the validated descriptor and rejects overflow or a trailing LF:

`{"consistency":"bracketed","mode":"observe_only","names":[NameRecord...],"network":"main" or "regtest","seals":[SealRecord...],"tip":Tip,"v":1,"written_at":N}`

`NameRecord` is exactly the `name_show` result above. `SealRecord` is exactly the
`gettxout` result above. All records share the SINGLE top-level Tip; name heights
<= tip height. `written_at` is POSIX UTC seconds measured after the complete
bracketed collection, before persistence; no time zone strings or nanoseconds.
Names array: 1..16, sorted strictly by name ASCII bytes. Seals: 1..256, sorted
strictly by txid ASCII bytes, then numeric vout. No duplicates or omissions from
the host-configured watch set. The consumer verifies the exact expected watch
set and network against protected configuration; a plausible foreign owner's
snapshot is not acceptable. Value bytes carry the pin; no separately supplied
list hash can override them. Device-list bytes and private keys never enter this
file. Schema validity alone does not prove watch-set completeness. A watched
name with no confirmed record (`not_found`) prevents whole-set publication:
retain the previous file, exit 11, and let it age. Q4 records that the file alone
cannot distinguish a vanished name from helper failure. Watch sets are static
operator configuration: a list update introducing a new seal requires root
reconfiguration; until complete, consumers label the mismatching set invalid.
No inferred/partial watch-set update is allowed.

Helper refreshes on startup, each observed new block OR same-height tip hash
change, and at least every 30 seconds to label write liveness during a long block
interval. It may also refresh on mempool change; no cadence makes it enforceable.
The helper collects a complete set, not a patch. It uses its separate root
bucket and at most 16 concurrent reads when calling (a): 16 names + 256 seals
+ 2 brackets = 274 requests, within its 512-token burst, independent of agents.
Direct-RPC helper uses at most 16 concurrent RPCs and the same fixed read set;
its two-view seal projection is not one RPC. Each invocation has a 20-second
monotonic total collection deadline across all attempts/backoffs and a 1-second
per-RPC deadline; on total timeout exit 11 and retain the file. It never queues
overlapping invocations (flock); the 30-second timer is a target cadence, not a
promise under node failures or repeated movement. Q5 qualifies the maximal
configured set's actual 20-second completion under competing traffic. Both
record-count and serialized-byte bounds must pass before publication. For (b)
only, read the COMPLETE Tip {hash, height, time} BEFORE and AFTER all name and
outpoint reads. Every known middle gateway Tip and upstream `bestblock` MUST
also match the bracket Tip. A different hash/height anywhere discards the whole
attempt as movement, even when the brackets are equal. A single hash with
conflicting height/time is backend inconsistency, NOT movement. Missing witnesses
in ordinary direct-RPC replies do not establish coherence; §5 stays bracketed.
N=3 total collection attempts. Starting an opening bracket consumes an attempt,
even if that read refuses. After an opening refusal do not issue middle or
closing reads; after a closing refusal discard all collected records. Refusals
on either bracket follow the SAME classification as middle-read refusals.
A successful collection requires exactly one correlated reply per configured
name and outpoint: no duplicate, missing or unconfigured reads. Every successful
reply, including each bracket reply, MUST match protected network and its own
request's method and name/outpoint echo BEFORE using any field.

Retry precedence is total: terminal failure (including deadline, wire/schema,
correlation or completeness failure) overrides rate limiting, which overrides
movement, which overrides success. The table below partitions these states;
"only" excludes all higher-precedence evidence. Same-hash header contradictions
are terminal across the ENTIRE invocation, not just within one attempt.
For retry after attempt ordinal 1 or 2, movement-only waits at least 100 or
200 ms respectively; ANY rate limiting waits at least 1000 ms, even when mixed
with movement. The ordinal counts all attempts, not just movement events.
After attempt 3 the exit is decided by attempt 3's row alone: rate-limit evidence
in attempt 3 exits 11, movement-only evidence exits 12. Earlier attempts' classes
affect only the waits. In the exhaustion rows below, M means movement-only and
L means rate-limit evidence with or without movement; all three attempts are
retryable, with no terminal failure or success in the sequence.
These are minima: the root client MUST also pace to its own reservation tokens
and active slots before each read/attempt, within the unchanged total deadline.
It must not induce `rate_limited` by overrunning its own reservation. Q5 must
qualify maximal-set pacing; fixed backoff alone cannot do that.
No record from a discarded attempt survives. The following is the ONE helper
classification table. There is never a partial/best-effort publication or
invented timestamp. Missing expected file means unavailable for observation.

### Helper outcome classification

| Event/stage | Action and final exit | Published path |
| --- | --- | --- |
| Terminal collection evidence: deadline/RPC/backoff timeout, authentication/platform failure, same hash with different height/time, wire/schema/projection failure, missing/duplicate/unconfigured read, wrong network/method/name/outpoint echo, or `unavailable`/`not_found`/`malformed`/`unauthorized` on ANY read; regardless of retryable evidence | Terminal failure, 11; not_found never means seal absence | Previous untouched |
| Attempt 1 or 2, no terminal evidence; `rate_limited` on ANY read, with OR without different-hash Tip/bestblock or `tip_moved` evidence | Discard attempt; wait >=1000 ms before next attempt | Previous untouched |
| Attempt 1 or 2, movement only: different-hash bracket/middle Tip/bestblock or `tip_moved` on ANY read, with NO terminal or rate-limit evidence | Discard attempt; wait >=100/200 ms by inter-attempt ordinal | Previous untouched |
| Retryable exhaustion: M, M, M | Exit 12; preceding minimum waits [100,200] ms | Previous untouched |
| Retryable exhaustion: M, M, L | Exit 11; preceding minimum waits [100,200] ms | Previous untouched |
| Retryable exhaustion: M, L, M | Exit 12; preceding minimum waits [100,1000] ms | Previous untouched |
| Retryable exhaustion: M, L, L | Exit 11; preceding minimum waits [100,1000] ms | Previous untouched |
| Retryable exhaustion: L, M, M | Exit 12; preceding minimum waits [1000,200] ms | Previous untouched |
| Retryable exhaustion: L, M, L | Exit 11; preceding minimum waits [1000,200] ms | Previous untouched |
| Retryable exhaustion: L, L, M | Exit 12; preceding minimum waits [1000,1000] ms | Previous untouched |
| Retryable exhaustion: L, L, L | Exit 11; preceding minimum waits [1000,1000] ms | Previous untouched |
| No terminal, rate-limit or movement evidence: complete equal brackets and all known middle Tips/bestblocks match | Proceed to persistence; if all stages succeed, publish, 0 | New complete durable file on success |
| Before collection: lock contention only | No waiting invocation; benign skip, 14 | Previous untouched |
| Before collection: lock open/validation/acquisition error (not contention), bad config, UID/namespace/bind overlap, unsafe ancestry or installed inputs | Terminal failure, 11 | Previous untouched |
| After successful collection, before rename: serialization or count/65536-byte overflow; recognized-temp inspection/removal, ancestor creation/sync, temp create/write/short-write/validation/ownership/mode/fsync/close, or rename failure | Stop; remove only own validated temp, 11; cleanup failure remains 11 and never broadens deletion scope | Previous untouched |
| AFTER explicit successful rename: directory open/fsync/close failure | Durability unconfirmed, 13; NEVER roll back/unlink final file | New complete file visible; crash recovery may select old or new |

Exit meanings are disjoint: 0 = durable publication; 11 = unsuccessful invocation
with previous bytes untouched (including rate-limit evidence in attempt 3);
12 = exhaustion whose third attempt is movement-only, with previous bytes
untouched; 13 = renamed but directory durability
unconfirmed; 14 = lock-contention skip with no reads or writes. Exit 0 requires
directory durability. Each failed read follows this table, never fabricates
presence or absence. All pre-rename branches leave previous published bytes
untouched. Oracle-domain errors are NOT helper exits and cannot be expected as 11.

`consistency` is REQUIRED with a CLOSED set. V1 writers produce `"bracketed"`
only, and the v1 consumer accepts EXACTLY `"bracketed"`. Any other value,
`"witnessed"` included, is `invalid` until the consumer is updated against a
qualified witness; a helper cannot raise its own claim. `"witnessed"` is named
only as a future value and is INVALID in v1.

A `"bracketed"` snapshot cannot rule out a hidden A→B→A excursion between the
bracket reads. The consumer LABELS only and NEVER refuses on it. A closure
observed through a bracketed snapshot is OBSERVE-GRADE: it labels, goes to an
observe journal, and is NEVER imported into enforcement state. Enforcement
closures come ONLY from the Q10 CGW-J1 watcher journal (§4 and
[OPEN.md](OPEN.md)), with validated spending transaction bytes, conflict
completeness and one named tip. A witnessed read alone creates NO enforcement
closure. §4's coherent-read witness requirement stays IN FULL for gateway (a);
it does not make a gateway-backed reader a mempool-first closure witness.
Ordinary bracketing does not claim coherent per-read chain state or an atomic
multi-record mempool snapshot; observations can differ even at the same Tip.
These requirements are the consumer's acceptance points, backed by the lead in
the HELPER-B r3 amendment.

Publication: create a fresh same-directory temp file named `.snapshot-` plus
24 random lowercase hex characters, with O_EXCL and no symlink following, mode 0600; write all bytes and validate; set root ownership and 0644;
fsync file; atomically rename over the configured final file; fsync containing
directory. Sync newly created ancestors before use. Serialize writers; on a
pre-rename error remove only that writer's validated temp file and retain old
published bytes, using the classification table above. After rename, a directory
failure cannot promise the old path: return 13 without rollback. A crash after
rename before directory fsync may recover either old or new complete snapshot;
publication durability is not claimed until directory sync succeeds. On a later
run, while holding the exclusive writer lock, clean only recognized helper temp
files in that validated directory after no-follow, regular-file, root-owner,
single-link and exact temp-name checks. Never delete unknown files or another
active writer's files; cleanup failure fails publication rather than broadens
cleanup scope.

Adapter labels every accepted snapshot **OBSERVE ONLY** even when fresh:

| Label | Condition (evaluated by consumer, not a field the helper asserts) |
| --- | --- |
| `fresh` | age in 0..60 seconds, consumer's configured tip-lag bound holds, independently known live tip exactly equals snapshot Tip, and all configured bindings match |
| `stale` | age >60 seconds, consumer tip-lag policy exceeded, or complete snapshot Tip differs from independently known live Tip |
| `unknown` | no independently known live tip or trustworthy clock; tip height alone cannot establish freshness |
| `invalid` | written_at is in the future, schema/filesystem/network/watch-set failure; no usable snapshot |

Label precedence is: invalid schema/bindings; unknown clock; future time invalid;
age or consumer tip-lag stale; unknown live tip; mismatching tip stale;
otherwise fresh. Source obtains the independent live Tip through its own
getblockcount over (a) at check-time. On a (b)-only host there is no independent
live source: the label MUST be unknown (or stale by age/consumer lag policy),
never fresh.

A mempool-only spend can be absent from any snapshot labelled fresh. No label,
short age or atomic replace authorizes enforcement. Freshness of a root file is
not an exemption from the lead's observe-only ruling.

## 6. Versioning, fixture obligations and scope

This fix round includes the owner's explicit F5 amendment to the candidate v1
seal projection; earlier-head acceptance does not carry over. Source must accept
this exact amended head. The interface freeze does not depend on waiving Q3.
`v:1` identifies this exact closed schema/profile. Adding fields, methods,
refusal codes, networks or changing canonical bytes requires a new version,
consumer acceptance and new shared vectors. Unknown versions fail closed.
A host config change cannot reinterpret v1; limits may be tightened only if
reported as a distinct deployment profile accepted by both parties. V1's
protected configuration identifier is exactly `profile:"cg1-v1"`; it is not a
new wire field. Any tighter profile needs a new explicit identifier and consumer
acceptance, never an implicit host override.

The contract schema harness consists of: `schema.go` and
`contract_test.go`. Its executable schema validates wrappers, types, limits,
canonical bytes and fixture relationships. `fixtures/vectors.json` stores exact
payloads as JSON strings so duplicates, whitespace and malformed inputs remain
visible. `wire_b64` carries non-UTF-8 controls. `kind` selects request, response,
`snapshot`, `snapshot_size`, `frame_request`, `frame_response`, `lexical`,
`integer_n` or `integer_o`. Lexical vectors isolate recursive parser rules;
integer vectors isolate minimal integer spelling and N/O bounds. Frame-only
vectors test size/LF/EOF
independently of payload schema; they do not claim that arbitrary bounded bytes
are a valid request. Snapshot-size vectors likewise isolate the payload bound
from the full snapshot schema. `fixtures/observations.json` records tip
movement, exact configuration bindings, two-view seal projection and every
seal-state transition (plus unavailable), round budgets and label precedence,
including A→B→A and same-height reorgs. Seal-history decisions explicitly name
`observe_closed`, always leave `enforcement_closed:false`, and separate the
current read's `refuse_command` flag from the observe journal. The explicit
`unavailable` decision flag distinguishes errors/key mismatches/contradictions
from valid non-unspent refusals; such failures cannot update history. A false
refusal flag means only that this read is `unspent`, not that admission is authorized.
Observe-grade closures remain labels and never feed that flag. These are
fixture-oracle labels, not new wire fields. `utxo_views` inputs model selected
upstream fields at an already coherent instant; they do not supply a witness.

New correction scenarios carry claim/control annotations; legacy inputs need not.
All inputs have an exact checked-in
name/kind inventory (`fixtures/inventory.txt`): deletion or renaming fails even
if the remaining scenarios pass. Fixture readers reject trailing data and unknown
or mistyped inner configuration/Tip/history fields. Wire-string collection and
history controls exercise the real canonical response gate before any field is
used; invalid responses refuse unavailable-class with no new closure. Labels
carry explicit `enforceable:false` independent of freshness. Label inputs include
`live_tip_source` (`independent`, `none`, `self`) and `lag_seconds`; a self-derived
Tip is never independent, even when byte-identical.

Snapshot outcome inputs carry protected `config`, per-attempt `requests` and
`replies` (or exact `reply_wires`), plus opening/closing Tips or gateway replies.
An opening refusal consumes one attempt without later reads. Successful
publication requires the complete configured set with one reply per request.
`stage` and `failure` are closed enums; `failure` is timeout, authentication or
platform. Stage fixtures explicitly carry `renamed` and, except early lock/config
failures, successful collection evidence. A directory-stage label alone proves
no rename. Unknown enums, contradictory rename facts, attempts outside 1..3,
retry after a terminal outcome, and premature retry exhaustion are oracle-domain
errors, never exit 11. Expected `wait_ms` records inter-attempt MINIMUM waits;
it is not evidence of elapsed time, token availability or filesystem effects.

The omission aid, adapted from the prior independent review, runs in CI as
`python3 -B omission_analysis_test.py fixtures/vectors.json` from this module;
it exits nonzero for baseline mismatches or unpinned rules. Explicit redundant
guards are reported as single-rule survivors and require named grouped controls,
not misreported as individual kills. Its scope is schema vectors, not runtime
custody/witness qualification; output is retained with validation evidence.

The consumer MUST mirror `TestSharedVectors`, `TestObservationVectors`,
`TestSnapshotLabels` and the valid/invalid controls in `TestSchemaControls` in
its own language/decoder, using these same bytes and expected verdicts. Merely
running or copying this Go parser twice is not independent agreement. Source
must bind each fixture to its adapter's real entry point when implementation
exists. The gateway implementer must later bind them to its actual listener and
upstream adapter. Pure schema tests prove neither implementation exists.

The separate helper implementation uses the accepted §5 amendment; its fake-RPC
evidence does not qualify (a), live nodes or installed custody.

Out of scope for this contract harness: gateway code, live-node calls, install or root work, credential
provisioning, wallet/write methods, list distribution/cache implementation,
cryptographic device/list validation or policy-level seal-script validation,
durable journal implementation,
continuous watches, historical spend proofs, multi-call atomicity, enforcement
switches and live qualification. See OPEN.md for acceptance and build gates.


## Annex: INSTALL PROFILE — Infra proposal, subject to S8 owner GO

This annex records Infra's Q3/Q6/Q7 proposals, not code, installed state,
feasibility evidence or permission to install. S8's owner GO and the lead's
review gate are required. The normative transport/filesystem requirements above
still apply; unresolved proposal conflicts require an S8 decision, not a local
workaround. Infra's reported Core 28.0 host inventory is attributed data only;
no real node was contacted for this contract.

- Dedicated mainnet node adjacent to the gateway: txindex=1, disablewallet,
  listen=0, local-only RPC, network/genesis pinned. Proposed rpcwhitelist:
  name_show, gettxout, getblockcount, getbestblockhash, getblockhash, getchaintips.
  This original proposal is superseded for gateway/helper verifier users by §2's
  EXACT five-method whitelist, adding getblockchaininfo/getblockheader and
  excluding unused getblockcount/getbestblockhash/getchaintips. Q3 must qualify
  the proposed witness without silently broadening that credential.
- Proposed ZMQ sequence stream on a Unix/loopback endpoint witnesses block
  connect/disconnect and sequence gaps. Q3 remains open: qualify real-adapter
  A→B→A and same-height reorg behaviour on regtest with invalidateblock and
  reconsiderblock against the shared observation vectors. No end-tip equality
  or unqualified notification stream substitutes for §4's witness.
- Proposed socket `/run/swarma-chaingw/gateway.sock`: directory
  root:swarma-chain-read 0750, socket 0660. This parent-owner proposal differs
  from §2's daemon-owned bind directory; S8 must resolve socket provisioning
  before install. It does not amend the normative Linux listener profile.
- Proposed snapshot `/var/lib/swarma-chain-snapshot/snapshot.json`:
  root:root 0644, directory 0755, root-owned protected ancestry, no group/world
  write, symlinks, hard links or writable ACLs; same-directory atomic rename.
- Credential stays with the node user. On the same host, Infra proposes a
  root-owned 0640 cookie copy, exclusive group swarma-chaingw. Otherwise a
  per-service RPC user with rpcauth; the verifier itself is not a client secret.
  Owner F1/F2 disposition supersedes gateway cookie access: (a) is verifier-only,
  (b)'s same-host root-cookie exception follows §2 custody/rotation. Verifier-only
  deployments never use a cookie; a host outside §2's Linux-only profile runs
  neither credential holder in v1. Endpoint kernel owner verification precedes
  either admitted mode.
  Exact endpoints, node/service IDs and protected ancestry are install inputs.
- Peer UID allow-list is exactly the designated workload and service-user UIDs from
  S8's accounts list, still to be posted for review; no numeric UIDs are guessed.
  Retirement removes the UID from the allow-list file, restarts and reads back
  the effective list. Reader group access alone never admits a UID.
- Watch names/outpoints come from the owner's pin in operator configuration,
  never from clients. Helper (b) is a root-run oneshot per observed block,
  startup and same-height reorg, with a 30-second heartbeat (blocknotify trigger
  or timer). Proposed lock `/run/swarma-chain-snapshot/helper.lock` uses flock;
  a second writer exits without writing. Read the cookie fresh on every run.
  Publish a whole set with same-directory tmp + fsync + rename + directory fsync.
  When (a) exists, root helper access through an explicitly allow-listed UID is
  accepted by Infra. No systemd unit or installation is supplied here.

## Review-input credit

Fix 1 incorporates the Opus review of record (PR review 5920320803), including
its proposed vectors/observations adapted to Tip.time, bracketed snapshots and
Source's binding F5 decision. Its independent omission-analysis aid is rerun
against this revision; it is separate from the Go harness and runtime
qualification. OPEN.md records the remaining qualification/adoption gates.
