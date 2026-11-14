# Signature-bearing identifiers

A BIP-340 signer can use fresh auxiliary randomness to produce different valid
signatures over identical content. Canonical parsing does not make a signature
unique. The identifiers below intentionally include signed bytes; their hashes
must not be described as signature independent. A second signature is not a
forgery, nor the overflowing-s encoding rejected by the strict parser.

The audit covers production SHA-256 calls and hash wrappers across all Go
modules, including hashes of structs, raw JSON, nested signed events, journal
segments, blobs and transaction bytes. Source paths below are relative to
`experiments/` unless explicitly prefixed with `deploy/`.

| Site / signature-bearing hash | Consumers | Independent uniqueness or authority binding | Effect of a second valid signature by the same signer |
| --- | --- | --- | --- |
| `rental/grant.go`: `SignedGrant.ID()` | `grant_kernel.go` per-grant state filenames and seal index; `grant_presentation.go` cache; issuer receipts; downstream grant references | Confirmed issuance commits to the exact signed ID and consent proofs; the durable seal index permits one ID per seal | A different ID fails the original issuance commitment before first admission; after admission it also fails the seal index. It cannot replace the live per-sender cache. |
| `rental/grant.go`: `Grant.SigningHash()` (nested consent signatures), `IssuanceCommitment()` | Issuer signature message and chain issuance output | The signed grant authenticates the exact nested proofs; confirmed issuance binds their exact bytes and grant ID | Re-signing a nested proof changes the grant content and requires a new issuer signature and issuance commitment. It does not reuse the original admission. |
| `rental/kernel.go`, `planner.go`: v1 `Hash(envelope)` / `CertificateSHA256` | Certificate state filename, name value and planned OP_RETURN | Confirmed `rental_certificate_sha256` name value and exact envelope commitment, trusted issuer and seal | Another valid envelope signature gets another hash but fails the original name value/commitment, without a new certificate state record. |
| `rental/detached_kernel.go`, `presentation.go`, `detached_issuer.go`: v2 `Hash(envelope)` | Detached state filename, seal index, per-sender presentation cache and issuer receipt | **No per-certificate chain issuance commitment exists in v2.** The authenticated agent grant key, funded seal and durable first-admitted seal index bind admission | The same observer refuses a second ID as `SEAL_ALREADY_SEEN` and does not cache it or write another detached state record. A fresh observer can accept either signature first. This is a bounded seal-index property, not the v1/v3 commitment guarantee. |
| `rental/grant_issuer.go`, `detached_issuer.go`: request/package/spec hashes, signed-grant ID | Durable issuance request conflict checks and completed-record replay | Booking ID, reserved pool seal and funding inputs identify the operation; exact request/publication bytes are retained | Changed signature-bearing publication/spec bytes conflict with the same booking reservation; a second hash is not another issuance. |
| `rental/batch.go`: Merkle leaves/root/commitment over signed-envelope IDs | Batch audit membership proofs | The exact anchored root and count authenticate membership; batch data is explicitly not issuance authority | Two signature variants are distinct leaves and consume capacity. Membership cannot admit either envelope or bypass its kernel binding. |
| `rental-gateway/kernel/presentation.go`: `PresentationID()` | Gateway presentation framing, expected grant ID passed to the real kernel | The real kernel checks the complete schema, signatures, grantee, policy, confirmed issuance and seal index; this helper is not an authority check | Both canonical signatures can receive different framing IDs. The uncommitted variant cannot pass `kernelbind.Adapter.Present`, enter the cache or replace the original. |
| `agent-wallet/grant.go`: propagated signed-grant ID | Wallet grant/nonce lookup, reservations and budget accounting | Real `KernelAuthority.Check` before reservation and effect, exact chain issuance, grant grantee and signed nonce | A new parsed ID is not live authority. The uncommitted variant cannot create a wallet reservation or reset its budget/nonce namespace. |
| `agent-wallet/single_use.go`: `Hash(oneoff envelope)` | External grant reference and wallet reservation; generation state formerly used this ID too | Confirmed grantee seal spend commits to the exact request containing that external ID; wallet reserves each use seal once. **Option (b):** private generation state now keys on `OneoffDigest(inner grant)`, excluding the outer signature | Signature variants retain different external IDs but share one generation-state record and sticky closure. An alternate external ID cannot reuse the original request commitment. Legacy signature-keyed generation state refuses pending explicit migration, without new state records or overwritten history. |
| `agent-wallet/wallet.go`: W1 `Hash(requestRaw)` in both W2 and G2 paths | Request conflict evidence in wallet records/journal | Lookup first binds grant ID plus the signed logical nonce, independently of the raw hash; G2 ledger does the same | Identical content with a new valid outer signature has the same nonce and is refused as `NONCE_CONFLICT`; it creates no extra payment, debit or record. Exact-byte replay returns the existing reservation. The hash is conflict evidence, not a dedup namespace. |
| `agent-wallet/service.go`: `Hash(raw)` on unauthenticated/peer-refused input | Refusal receipt request reference | These branches never reach reservation/effect; authenticated service requests hash the unsigned request and deduplicate by grantee/nonce | Another signature can change the refusal's correlation hash, not create a journal reservation or payment. |
| `agent-wallet/px1_journal.go`: segment SHA-256; `px1_journal_api.go`: reconcile digest | Segment integrity/previous-segment chain; authenticated releases | Segment sequence, journal binding, grant/nonce, target sequence and release state; reconcile digest clears its own signature | Segment hashes may include receipt/reconcile signatures. They are integrity hashes, not operation identities. Re-signing cannot release a target twice. The excepted frozen parser is unchanged. |
| `rental-booking/nostr.go`, `rental/issuance.go`, `rental/paygrant_v2.go`: Nostr event IDs with signed package content | Package/consent references and issuance authentication | Each event ID excludes its own outer signature; nested package signatures remain content. Booking/contract/payment identity and issuer reservations bind the logical operation | Re-signing only the outer event preserves its ID. Re-signing a nested proof changes package content; the existing booking/issuance record cannot become a second issue. |
| `rental-booking/outbox_v2.go`: `Hash(signerItem)` including signed publication | Immutable outbox filenames/index and signer intake | Item ID derives from operation kind plus booking ID; signer enforces exact source bytes and booking operation uniqueness | Different publication bytes give a different blob hash, but the same item/booking ID conflicts rather than starting a second operation. |
| `signer-service/loop.go`, `process.go`, `engine.go`, `outbox.go`: intake/source hashes, record blobs, prefix hashes, signed-grant/store hashes | Intake conflict checks, content-addressed filenames, replay records, grant-store integrity and cursors | Intake item ID/source, booking-derived operation ID, reserved seal/funding, and durable exact-byte record | Changed signed bytes either conflict with that logical operation or fail integrity verification. A new blob hash or cursor hash does not authorize another issue, spend or revoke. |
| `grant-store/store.go`, `http.go`, `client.go`: `Hash(blob)` | Content-addressed blob filenames, descriptors and download integrity | Signed authorization event ID/nonce controls replay, caller ownership/readers and byte/count quotas control storage; grant authority is checked elsewhere | Re-signing the same authorization does not change its event ID. Uploading a different signed object is a different charged storage blob under the same quotas, not another admitted grant or a rate-limit reset. |
| `rental-gateway/journal/delivery.go`: delivery checksum over persisted signed `Wire` | Durable delivery integrity | Slot plus unsigned inner-rumor ID identifies delivery; operation ID fixes the outbound event bytes before publishing | Re-signing/re-wrapping cannot replace the persisted operation or deliver the same inner rumor twice. The checksum is not its dedup key. |
| `rental-gateway/nostr/event.go` and other Nostr event hash helpers | Relay dedup, grant-store authentication, booking consent, executor request IDs | NIP-01 preimage excludes its own signature; gateway effects deduplicate the inner rumor, executor reservations bind slot/nonce | Same content plus a different outer signature retains the event ID. Nested signed content/ciphertext is not claimed signature independent. |
| `single-use/transaction.go`, wallet/executor transaction builders and chain readers | Transaction IDs and exact signed request commitments | Consensus outpoint spends, exact request hash, confirmed own-node observation and durable seal/input reservations | Transaction signatures and W1 request signatures can affect bytes/IDs; they do not create a second spend of a reserved seal/input or another effect from the same logical request. |
| `m5-host-smoke/receipt.go`, `runner.go`, `files.go` | Request hashes containing grant presentations; presentation/report/artifact digests | Run/stage/sequence/deadline and exact expected artifact bytes bind evidence; independent kernels still decide authority | Another signature changes the evidence being asserted. A receipt hash is neither grant admission nor a dedup/payment key. |
| TLS certificate hashes in `rental-gateway/cmd/gateway/tls.go`, `station-lifecycle/transport.go`, `station-payload/client.go`, `model-proxy/cmd/model-proxy/main.go`; generic file digests in config/release tools | Pinned peer certificate identity, installed/release file integrity | Independently configured exact certificate/file digest, TLS validation and installation policy | A re-signed certificate/file has another digest and fails the old pin. These are exact-byte trust/integrity bindings, not BIP-340 replay identifiers. |

Hashes of unsigned terms, names, configuration, tokens and contract payloads
that contain no signature field are not signature-bearing identifiers. Receipt
signing preimages exclude their own outer signature. Generic raw-byte integrity
hashes can cover arbitrary signed artifacts; their role is byte equality, not
logical-operation uniqueness.

## Regression evidence and limits

### Accepted detached-v2 exception

Only the grant-key holder can make two valid signature twins over identical
detached-v2 content. Both twins bind the same grant key, funded seal and name
generation. Each observer admits a seal at most once: after one twin is admitted,
the other is refused as `SEAL_ALREADY_SEEN`, with cache and state unchanged.
Two **fresh** observers may record **different envelope IDs**. The detached-v2
envelope ID is **not a cross-observer identity**; nothing may key payment,
deduplication, journals or audit across observers on it. Exact-envelope replay
within one observer remains supported.

A new detached profile with a per-certificate commitment is the fix, out of
scope here (grants v4's content-only stable object IDs remove the issue).

`TestCoreDetachedFreshObserversRecordSignatureTwins` admits one twin in each
of two empty observer states against genuine Core and compares their grant
keys, funded seals, name generations and recorded IDs.
`TestCoreDetachedSecondSignatureSealBinding` retains the same-observer refusal
and unchanged-cache/state checks.

The automatic rental check runs `.scripts/check-detached-v2-consumers.py` and
its detector controls. It inventories production Go references to detached-v2
entry points, types and certificate-ID fields across the repository, and pins
the reviewed consumer files by SHA-256. New references, missing paths or changed
consumer bytes require a new read-site audit. This is a bounded lexical guard,
not semantic taint analysis: dynamically constructed field names, arbitrary
aliases and external consumers are outside its claim. Planted cross-observer
payment uses in every real inventoried file must be detected; an ignored-path
mutant must fail that control. The inventory records the observer-local reason
for each file, including shared fields whose other callers use v1/v3.

`rental/signature_identity_test.go`, `agent-wallet/signature_identity_test.go`
and `rental-gateway/kernelbind/signature_identity_test.go` use fixture keys and
fresh auxiliary randomness, assert different signatures and verify both over
the same content. They cover v1/v3 commitment refusal, v2's explicitly weaker
seal-index boundary, gateway cache refusal, wallet grant/nonce lookup and
one-off seal-spend commitments. `TestW1SecondSignatureChargedOnce` and `TestG2SecondSignatureChargedOnce` run without
Core and asserts journal bytes, reserved debit, broadcast count and absence of
new RPC calls. Its Core counterpart also checks the actual mempool and durable
reopen behavior. `TestOneoffSecondSignatureSharesGenerationState` also proves one durable generation record, retained closure across valid signature variants, and refusal of legacy state without writes. No signature-independent external grant ID is claimed.

Run from each relevant module:

```sh
go test -race -run 'TestGrantSecondSignatureCommitment|TestW1SecondSignatureChargedOnce' .
```

The Core cases are opt-in and require the existing isolated fixture variables:
`M1_REGTEST=1` / `M1_RUN_ROOT` / `M1_CORE_DAEMON` / `M1_CORE_CLI` for rental,
`W1_REGTEST=1` / `W1_RUN_ROOT` / `W1_CORE_DAEMON` / `W1_CORE_CLI` for wallet,
and `GW_E2E_REGTEST=1` / `GW_E2E_RUN_ROOT` / `GW_E2E_CORE_DAEMON` /
`GW_E2E_CORE_CLI` for kernelbind. Use a fresh absolute run root for each named
Core test and pinned Core 28.0 release executables. Logs go to stdout and the
fixture's public evidence directory; retain local command logs under `.temp/`.
