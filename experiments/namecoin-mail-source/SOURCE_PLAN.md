# Source/configuration plan for review

## 1. Scope and acceptance

Closed-world Namecoin regtest only, no real mail, public email gateway, open relay,
mainnet, real economy, or other people's keys. Public networking is restricted to
canonical source acquisition before the offline phase. Runtime access to a public
resolver, public CA fallback, plaintext SMTP delivery and any Internet route are
prohibited. No host packages, service reconfiguration, security changes, capability
changes, or host privileged-port binds. No existing production paths are mounted.

This phase supplies source/configuration candidates, fixtures and prerequisites;
it implements no mail runtime or freshness supervisor. The unavailable external
report section 10 was requested upstream. Its text has not been read and is
not claimed as evidence. Review must reconcile it when supplied, without delaying
independent source pinning. Preserve precedence of the existing chain and ordinary
client work. Registration, mail, migration and negative-control outcomes below are
**planned, not measured**.

## 2. Exact source selection and reproduction

`pins/components.json` gives versions, immutable source identities, licenses,
archive SHA-256 values and verification scope. Namecoin remains 28.0.0, the existing
lab selection. ncdns is the explicit development snapshot recorded in that file,
not its differently shaped v0.3.2 release. Its own checked-in testdata Go module
versions and sums are preserved; only the documented local go-systemd replacement
path is adapted to the same pinned v22.7.0 source. No upstream quick-start command
using `@latest`, `-u`, or tidy is part of this plan.

C prerequisites are Postfix, Unbound, OpenSSL, LMDB and Expat; m4 is a build tool.
Use exact pins, private source/build trees and prefix. ncdns is built with
CGO_ENABLED=0, retaining TLSA support; do not set `no_namecoin_tls`. This avoids
libcap headers and does not grant any capabilities. Postfix uses TLS and LMDB,
without Berkeley DB, NIS, SASL or ICU/EAI; fixture addresses are ASCII. Unbound uses
its built-in event loop, DNSSEC validator and iterator, no Python/dnstap/systemd.
The source checks are not a byte-reproducible binary qualification: distribution
compiler/libc/OpenSSL build identities and binary hashes are recorded separately.
Runtime must stage verified exact inputs offline; missing sources or libraries
are a stop, never a download from inside the lab.

## 3. Authority, network and storage boundaries

`config/authority-matrix.json` specifies documentation-only private-lab addresses.
Use separate user/mount/PID/network namespaces and independently writable volumes
for A, B and Bprime. They each hold only their own disposable provider TLS key,
queue and mailbox. They share no mailbox or queue storage. Bprime receives no B
TLS key, wallet or approval. Each MTA talks only to its protected local resolver
and explicitly allowed fixture MTAs. Distinct point-to-point links/allowlists,
no broadcast trust assumption, no raw-socket authority and no default public route
are required. Network implementation must be reviewed; the matrix is not an
installed firewall.

The controller owns disposable miner and separately scoped Alice/Bob owner
wallets. Mail/DNS cannot reach its RPC, wallet files or control sockets. A separate
wallet-disabled full validator receives regtest blocks over the only allowed
chain link. DNS can call only its `name_show` through a distinct read-only RPC
identity, never the controller cookie. A read-only recorder identity has only the
listed observation methods. Validate the whitelist by positive `name_show` and
negative wallet/mining/name-update requests before sending any mail. A local
authority must provision disposable RPC secrets; all templates are secret-free.
Never export cookies, provider/name-owner private keys, passwords or full env dumps.

ncdns's DNSSEC keys belong to the bridge authority, distinct from all provider and
name-owner keys. Resolvers receive only its public `.bit` anchor; providers cannot
change it. Recorder outputs contain hashes, public fixture transactions, queue IDs,
message IDs and observations, not private keys or unrelated content. Each role has
absolute private HOME/TMP/cache mode 0700. Source/tools are read-only. No host home,
agent sockets, keys, credentials, foreign caches, or production volumes are mounted.

## 4. DNS and mandatory DANE configuration

Start from `config/*.in`; these are reviewed-input templates, not runnable host
configuration. Render per authority, supply disposable runtime-only keys, synthetic
passwd/group files and writable directories, and validate before activation.
`vmailbox` is an exact recipient map: e.g. `bob@bob.bit bob/` on B and independently
on Bprime. The trailing slash selects Maildir, so real message contents can later
be checked in separate mailboxes. No old mailbox is mounted into Bprime.

Use unbracketed ordinary recipient-domain routing, with no relayhost, transport-map
endpoint bypass or fallback relay. Outbound Postfix has `dane-only`, DNSSEC lookup,
DNS-only host lookup, no native fallback or per-site weaker policy.
`tls_required_enable = no` disables the `TLS-Required: no` message-header override:
the pinned Postfix default is yes and can lower `dane-only` to `may` before DANE
initialization. This shared setting applies to A, B and Bprime. Check its effective
rendered value with pinned `postconf`, plus the exact upstream macro/policy-prefix
control in `checks/check_tls_required.py`, without starting a service.
Only a protected local resolver appears in its namespace's resolv.conf. Inbound requires STARTTLS;
relay restrictions allow only local virtual recipients. Fixture submission is via
an authorized labsubmit user in the sender's own MTA namespace, not an open TCP
submission service. Separate provider accounts and recipient maps are still needed
inside a rootless namespace, even when fixture administration owns the image.

Unbound explicitly anchors `.bit`, enables validation, refuses other names, uses
only the ncdns stub, forbids stub fallback and stale serving, and does not configure
`domain-insecure`. Do not infer DNSSEC validity from ncdns's AA bit. Capture signed
MX, A, TLSA and their AD-validated recursive answers, TTLs, anchor fingerprint,
rcode and signature times. A, B and Bprime receive different actual runtime SPKIs;
compute SHA-256 of DER SubjectPublicKeyInfo and base64 it for JSON `[3,1,1,...]`.
A runtime value must replace synthetic fixture association bytes before submission.
The pinned node defines MAX_VALUE_LENGTH=1023 and UI bound 520; this experiment
intentionally enforces the requested stricter <=520 bytes. Check actual serialized
UTF-8 bytes, not JSON character count: each <=520, no imports,
external delegation or wildcard trust. Current parser fixtures are 158/156/158 bytes.

## 5. Freshness gate and cutover window

A source prerequisite remains: a reviewed independent supervisor must compare the
validator's current best block, depth and live `name_show` value/expiry with the
expected experiment epoch and the resolver's actual MX/A/TLSA. It must suppress
DNS/SMTP egress for the affected sender (thereby deferring queued mail) on stale
observations, backend errors, expiry or reorg. It must not let a provider self-attest
freshness. Pin and review that supervisor before runtime; it is not supplied here.

For controlled transition tests: close the affected sender's delivery gate, wait
for the pre-transition SMTP attempt to finish, observe new depth, restart ncdns to
clear its indefinite raw-name cache, flush/restart the protected resolver, and open
only after authenticated current answers match. Disable connection/session reuse;
Postfix's TLS policy cache is already freed per delivery (`smtp_state_free`).
The proposed acceptance bound is 30 s from depth-6 observation to validated new
answers, then 30 s to the first newly submitted message's mailbox delivery. These
are test bounds, not measurements or global finality. Keep the gate closed and
record a failed bound if either is missed. Default RR TTL is 600 s: without this
controlled invalidation and freshness gate, revocation within 30 s is not claimed.

A validly signed stale answer can otherwise still authenticate the old endpoint
and key. DNSSEC by itself cannot satisfy that negative. Outside the declared
post-cutover window, old/new overlap is measured, not silently classified as a
failure or success. An in-flight old accepted message may remain at B; it is never
moved or relabeled as a new-route delivery.

## 6. Registration and bidirectional mailbox baseline

In a new disposable regtest chain, fund only fixture wallets using generated
regtest blocks; no public chain contact. Record chain identity and starting tip.
Alice and Bob each issue `name_new`, wait the source-required commitment maturity
(12 blocks in the pinned consensus), then `name_firstupdate` with
that name's serialized value. Each then issues a separate `name_update`, explicitly
spending its previous name output, even if setting the same initial value.
Record txid, raw public transaction hash, input prevout, name-output index and
owner-wallet role; assert each update's input references that name's previous
output and is signed by its owner. Check both accepted names from the walletless
validator after depth 6. Do not equate broadcast or mempool presence with inclusion.

After authenticated DNS matches the initial fixture/runtime values, send unique
small synthetic messages Alice -> Bob and Bob -> Alice, at most 4 KiB each.
Require sender queue acceptance, TLS authenticated under the intended 3/1/1 TLSA,
receiver final SMTP acceptance and matching Message-ID/body SHA-256 in the correct
recipient Maildir. Queue acceptance alone is not mailbox delivery. Record no real
addresses or mail. Reject relay attempts to an unrelated destination and unknown
local recipients; successful local fixture delivery is their positive control.

## 7. Bob-only route change and timeline

Provision Bprime with its own disposable TLS key, empty queue and mailbox. Bob alone
spends his current `d/bob` output to set `mx2.bob.bit` and its independently computed
TLSA association. Alice's name is unchanged. Bob's email remains `bob@bob.bit`.
Neither B's provider key nor its signature/approval is used. Recorder compares
wallet roles and name prevouts; no promise of mailbox/account portability follows.

Capture RFC3339 UTC plus process monotonic timestamps for: command start/end and
exit; transaction broadcast acknowledgment; first local mempool observation; block
hash/height/first inclusion; each depth observation and depth 6; live validator
name epoch; ncdns restart/answers; resolver cache invalidation and first current
AD-validated answer; gate reopening; first new submission; SMTP handshake/acceptance;
first matching Maildir observation. Record polling interval (proposed 250 ms),
timeout and missing values as null. Local broadcast acknowledgment is not global
propagation time. Use a single recorder clock for intervals; log its clock origin
and uncertainty. Concurrent hosts need measured clock offsets before comparing UTC.

Send fresh messages Alice -> Bob and Bob -> Alice from Bprime and prove delivery
and TLS to the selected endpoints. For a new post-window Alice -> Bob message,
keep old B running with its old key: it must receive zero new SMTP connections or
mail. Also force the old endpoint/key behind the new route as a separate mismatch
probe; require deferred delivery and no post-STARTTLS MAIL/DATA.

## 8. Negative controls, each bracketed by a fresh positive control

Use a new unique message per attempt, preserve queued failures, and change one
condition at a time. For every row, prove delivery on the same route with matching
TLSA immediately before and after recovery. Check actual mailbox non-arrival and
connection/TLS transcript; absence of a log line is insufficient.

| Injected condition | Required observation and positive control |
|---|---|
| Wrong server TLS key; independently, certificate with wrong SPKI trusted by a disposable fixture CA | Deferred, no message data; restore matching key/TLSA and deliver. Trust in that isolated fixture CA must not override 3/1/1; no public CA keys or external issuance are used. |
| Missing, insecure, bogus or wholly unusable TLSA; no STARTTLS | Deferred, no plaintext/PKIX fallback; restore valid signed TLSA and TLS listener and deliver. |
| `TLS-Required: no` on ordinary authorized local submission, with wrong server key; separately, with no STARTTLS | DEFER, no message data and no plaintext/PKIX fallback in either case, on A, B and Bprime. Restore matching key/TLSA and STARTTLS and deliver. Bracket each with no-header positive delivery; separately retain a positive ESMTP REQUIRETLS case on the matching route. These runtime cases are planned, not executed by the source control. |
| Old signed MX/A/TLSA returned after expected cutover epoch | Freshness gate denies sender egress and queue defers; current anchored answer reopens gate and delivers. Also record that DNSSEC alone accepts a valid stale signature. |
| Name expired on actual chain (not only an edited JSON flag) | Validator with allowexpired=0 rejects name, bridge/resolver caches cleared, gate denies delivery; control re-registers legally or uses a separate active name and delivers. Verify actual regtest expiry depth. |
| Resolver down or backend down | Flush all positive caches and restart sender SMTP worker; defer with deadline, no alternate resolver packets; restore fresh DNS and deliver. Separately measure any permitted pre-flush cached success. |
| Old endpoint + old key after declared window | Ordinary new mail goes only to Bprime; forcing B/old key under the new association defers. Matching Bprime route/key delivers. Old accepted queues remain B's. |
| Controlled regtest reorg removes Bob's update | Gate closes on tip change and depth regression; no cached-new-route delivery. Reconcile canonical name, invalidate every layer and deliver to the selected canonical endpoint after its depth requirement is met again. |
| Missing/wrong local anchor, non-bit destination, attempted public resolver | DNS bogus/refused/timeout and deferred mail, zero public egress; restore correct local anchor/bit destination and deliver. |

Pinned RegTestConsensus uses a 30-block name expiry; query actual
height and remaining expires_in first and budget this separately. Do not substitute a fake expired
JSON object for a real chain-expiry control. Reorg commands belong only to this
disposable chain, never an existing node.

## 9. Proof and trust claims actually available

Namecoin Core validates the local regtest chain and name-spend rules; its RPC is a
trusted local state interface. ncdns neither returns nor checks a portable Namecoin
membership/absence proof, state-root proof, freshest-tip proof, global completeness
proof or owner signature on a DNS answer. It translates trusted RPC values.
Its madns dependency optionally signs synthesized DNS answers and denial material
under local KSK/ZSK, an island of trust, not a `.bit` delegation from public DNS.
Unbound verifies that local DNSSEC chain and Postfix trusts its protected AD result.
This proves connection-key agreement with the locally trusted resolver/bridge's
answer under stated freshness assumptions. It does not remove trust in the bridge,
validator, recorder, isolation or chain choice. Regtest has controlled mining, no
public economic security or worldwide finality. A single local recorder does not
prove global dissemination or service availability. This does not qualify SPV,
Electrum, public mail, general account portability, or globally censorship-proof mail.

## 10. Runtime prerequisites, estimates and stop conditions

Before a lab: fresh review binds the exact candidate head/tree, source pins,
parser results, configuration rendering and the IFA discrepancy. Record availability of the requested external report and reconcile it when supplied.
Do not claim it was read while unavailable. Stage exact sources, compiler/runtime libraries,
private UID/GID account map, and a reviewed freshness supervisor/egress policy.
A rootless container runtime must already support subordinate UID/GID mapping for
namespace root, postfix, postdrop and mailbox user. Standard stable Postfix expects
these roles and namespace-local privileged operations. Single-ID bwrap is insufficient
for full MTA service even though it suffices for source checks. If the required
mapping/isolation is unavailable, stop: do not alter host capabilities, security,
packages, services or privileged ports. Port 25/53 are only namespace-local.

Proposed lab budget: 2 vCPU, 3 GiB aggregate RAM, 2 GiB private disk, 90 minutes
wall time for baseline/cutover/short controls, at most 100 synthetic messages,
64 KiB message cap and 1 MiB per mailbox; logs capped at 16 MiB per role. Estimate:
2 regtest nodes ~0.8–1.4 GiB, three minimal MTAs ~0.15–0.3 GiB, bridge/resolvers and
recorder ~0.15–0.35 GiB; allow remaining headroom. These are estimates, not measured
peaks or cgroup enforcement. In regtest expiry is 30 blocks, so pause mining
during mail observations and keep registration/update/depth sequences within that
height budget. Use separate fresh control chains or stopped disposable snapshots
for expiry and reorg cases to avoid unintentionally expiring the baseline names. Three provider authorities may share a machine only
with the stated boundaries. Size expiry/reorg add-ons from actual pinned rules
and stop rather than exceed admitted resources. Capture CPU/RSS/disk high-water
marks and wall/CPU timeouts in the runtime receipt. On stop, terminate only owned
processes, remove disposable secrets/runtime HOME/TMP/cache, retain nonsecret
failure evidence, verify no listeners/child processes or public route escaped,
and export <=24 MiB. A source/build success never authorizes activation or landing.

## 11. Source evidence map

All paths below refer to the exact upstream archive/commit in `pins/components.json`,
not a moving default branch. The packet preserves the referenced source subsets.

| Observation | Source |
|---|---|
| Direct MX, SRV without synthesis, 600-second TTL | ncdns `ncdomain/convert.go`: `appendMXs`, `parseMX`, `parseSRV`, `defaultTTL`; parser fixtures exercise their actual output. |
| Base64 JSON data -> hexadecimal TLSA | ncdns `ncdomain/convert_tls.go`: `parseTLSADANE`. |
| Indefinite raw-name cache | ncdns `backend/backend.go`: `resolveNameCache`, `addNamecoinJSONToCache`, `getNamecoinEntry`; pinned groupcache `lru/lru.go` treats zero MaxEntries as unlimited. |
| No portable chain proof, expiry/height validation in bridge | ncdns `namecoin/namecoin.go`: `NameQuery` returns `nameData.Value`. |
| Local DNSSEC signing, not global chain authentication | ncdns `server/server.go` key setup; madns v2.0.2 `txutil.go`: `signRRs`, `signResponse`; signatures use TTL plus 10 minutes, with inception backdated 10 minutes. |
| IFA-0001 mismatch | `ifa-wg/proposals` pinned `ifa-0001.md`, MX rule at line 455; code emits SRV only. |
| `dane-only` failure behavior | Postfix `src/smtp/smtp_tls_policy.c`: `dane_init`, `dane_incompat`; opportunistic `dane` has a separate downgrade branch. |
| Header override of global TLS policy | Postfix `src/global/mail_params.h`: `DEF_TLSREQUIRED_ENABLE`; `src/cleanup/cleanup_message.c`: header send option; `src/smtp/smtp.h`: `STATE_TLS_NOT_REQUIRED`; `src/smtp/smtp_tls_policy.c`: policy prefix before DANE initialization. Explicitly disable the header override in every mandatory-DANE role. |
| TLS policy cache lifetime | Postfix `src/smtp/smtp_state.c`: `smtp_state_free`, policy cache freed per delivery. |
| Reuse time parameter requires >=1 second | Postfix `src/smtp/smtp_params.c`, `VAR_SMTP_REUSE_TIME` minimum 1; reuse disabled separately by cache configuration. |
| 12-block commitment maturity, 520 UI bound vs 1023 consensus constant | Namecoin `src/names/main.h`. |
| 30-block regtest expiry | Namecoin `src/consensus/params.h`: `RegTestConsensus::NameExpirationDepth`. |
| RPC expiry rejection | Namecoin `src/rpc/names.cpp`: `name_show`, checks `allowExpired`/`-allowexpired` and raises for expired names. |
