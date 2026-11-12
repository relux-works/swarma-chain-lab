# Terms-v2 pay grant issuance (PX1 S4)

This helper issues the **pay grant** of the G2 demo: a v3 grant from the
landlord to Cedar's action key, scope `["pay"]`, whose `contract_sha256` is the
SHA-256 of wallet terms v2. `agent-walletd` (experiments/agent-wallet, the G2
profile) enforces those terms; this module only issues the grant.

G2 has two grants (co-lead review, Q1(a)):

1. the renter's rental grant (scope `deliver`, renter consent), issued by the
   existing booking/issuance V2 path, unchanged;
2. Cedar's pay grant, issued here, with Cedar's own kind-8181 consent.

The frozen contract is `paygrant_v2_api.go`; this file documents the
implementation in `paygrant_v2.go` and the ceremony CLI in `cmd/paygrant-v2`.

## What the helper never does

- It reads, derives and holds **no private key**. Each signature comes from a
  `DigestSigner` and is verified with `VerifySignature` before use.
- It returns **no partial result**. Any refusal returns the zero
  `PayGrantV2Result` and a bounded code.
- It does not plan, sign or broadcast a chain transaction. The issuance
  transaction is planned by the existing `MakeGrantIssuancePlan` (CLI:
  `rental-plan grant-issue`) and signed and broadcast by the lead node.
- It does not decide amounts, the window or the allow-list. Ivan does; the
  helper only validates them.

## Terms v2 bytes

`EncodePayTermsV2` returns compact `json.Marshal` bytes of `PayTermsV2`. It
applies the agent-wallet `ParseTermsV2` rows 3-10, in the same order and with
the same codes, except:

- row 6 (executor pin): the issuer has no executor pin; the executor checks it;
- row 10 `spend_cap <= grant budget`: applied by `ValidatePayGrantV2Input`;
  the encoder bounds `spend_cap` by `MaxMoney` instead.

| Row | Refusal | Code |
| --- | --- | --- |
| 4 | `version != 2`, `service != "wallet.nmc"`, `day_basis != "utc-calendar"`, `executor_key` not a valid x-only key | `CONTRACT_SCHEMA` |
| 5 | `network`/`genesis` not a pinned pair | `TERMS_NETWORK` |
| 7 | mode not `allow`/`any`; `recipients` null; `allow` with 0 or more than 32 or unsorted; `any` non-empty | `CONTRACT_SCHEMA` |
| 8 | allow-list member not canonical P2PKH of the network | `ADDRESS_MAIN` / `ADDRESS_REGTEST` / `ADDRESS_P2PKH_ONLY` |
| 9 | duplicate allow-list member | `CONTRACT_RECIPIENTS` |
| 10 | not `0 < transfer <= day <= spend <= MaxMoney`; `day_count_cap` not 1..1000; `fee_cap_sat` not 1..1,000,000 | `CONTRACT_BUDGET` |

The address check mirrors agent-wallet `addressScriptForNetwork`. The
agent-wallet parser stays the authority; the shared golden fixtures
(`testdata/px1/terms-v2-*.json`) pin both modules to the same bytes.

## Input validation

`ValidatePayGrantV2Input` refuses, in order:

| Check | Code |
| --- | --- |
| terms (above) | terms code |
| `Network`/`Genesis` not pinned or not equal to the terms' pair | `PAY_GRANT_NETWORK` |
| agent or landlord name not an `id/` station name, or both equal | `GRANT_NAME` |
| issuer or grantee key not a valid x-only key | `GRANT_KEY` |
| any two of issuer, grantee and `terms.executor_key` equal | `PAY_GRANT_KEY_ROLES` |
| seal txid not 64 lowercase hex | `GRANT_HASH` |
| window: `not_before < 0`, `not_after <= not_before`, or after year 9999 | `GRANT_TIME` |
| budget above `MaxMoney` | `GRANT_BUDGET` |
| budget below `spend_cap_sat` (an absent budget is 0) | `CONTRACT_BUDGET` |
| consent `created_at` outside `[not_before, not_after)` or below 1 | `PAY_GRANT_CONSENT_TIME` |
| privacy notice hash not 64 lowercase hex | `PAY_GRANT_PRIVACY` |

A multi-day window is allowed; there is no 3600 s booking cap (Q5(a)).

## The grant

| Member | Value |
| --- | --- |
| `version` | 3 |
| `network`, `genesis`, `agent_name`, `landlord_name`, `issuer_key`, `grantee_key`, `not_before`, `not_after`, `seal` | from the input |
| `grantee_name` | absent |
| `contract_sha256` | SHA-256 of the terms bytes |
| `scope` | `["pay"]` |
| `budget` | the input budget (always present) |
| `consent.consent_event` | Cedar's kind-8181 event, below |
| `consent.landlord_sig` | landlord BIP-340 signature over the raw `contract_sha256` |

The consent event is the existing v3 shape: kind 8181, empty content,
`pubkey = grantee_key`, `created_at = ConsentCreatedAt`, tags

```
[["t","swarma-rental-consent-v1"],["contract",<contract_sha256>],
 ["booking",<PayGrantBookingRef(terms)>],["privacy",<privacy notice sha256>]]
```

A pay grant has no booking. Its `booking` tag is
`SHA256("swarma-g2-pay-booking-v1" || terms bytes)`, so the consent binds the
terms twice and can never be confused with a booking id.

The result carries `grant_id` (`SignedGrant.ID()`), `contract_sha256`, the
terms bytes, the canonical `SignedGrant` (`ParseSignedGrant`-valid) and
`IssuanceCommitment(SignedGrant)`, the value the issuance transaction commits.

## Signer protocol

`IssuePayGrantV2` binds both signers by `XOnlyKey()` before the first request,
then asks for exactly three signatures, in this order:

| # | Signer | `purpose` | `digest` | `payload` |
| --- | --- | --- | --- | --- |
| 1 | grantee (Cedar) | `pay-grant-consent-event` | NIP-01 event id | the unsigned event with `id`: `{"id","pubkey","created_at","kind","tags","content"}` |
| 2 | landlord | `pay-grant-contract-countersign` | `contract_sha256` | `{"contract_sha256":...}` |
| 3 | landlord | `pay-grant-v3` | `SHA256("swarma-grant-v3" \|\| canonical grant)` | the canonical grant without signature |

Each request (`PayGrantSigningRequest`, `v: 1`) also carries the canonical
terms bytes. The answer (`PayGrantSignature`) must echo `v`, `purpose`,
`signer_key` and `digest` exactly and carry a 128-hex BIP-340 signature that
verifies; otherwise the helper refuses:

| Fault | Code |
| --- | --- |
| a signer is nil or its key is not the input key (checked before any request) | `PAY_GRANT_SIGNER_KEY` |
| the context ended, or the signer returned an error | `PAY_GRANT_SIGNER` (the cause stays reachable with `errors.Is`) |
| the answer does not echo the request | `PAY_GRANT_SIGNATURE_ECHO` |
| the signature does not verify for that key and digest | `PAY_GRANT_SIGNATURE` |

Each request holds copies of the terms and payload, so a signer cannot rewrite
the helper's state.

### Conforming signer

A conforming signer never signs a bare digest. Before it shows anything to the
key holder it calls `VerifyPayGrantSigningRequest` (an additive export, not
part of the frozen surface), or performs the same steps:

1. `v == 1`, `signer_key` an x-only key, `digest` 64 hex;
2. `terms` canonical and valid by rows 3-10 (`SIGNING_REQUEST_TERMS`);
3. per purpose, the payload must be canonical and bound to those terms
   (`SIGNING_REQUEST_PAYLOAD`):
   - consent: `pubkey == signer_key`, kind 8181, empty content, the four tags
     with this contract hash and booking ref;
   - countersign: `contract_sha256 == SHA256(terms)`;
   - grant: a valid v3 grant for this contract, `issuer_key == signer_key`,
     scope exactly `["pay"]`, budget present and `>= spend_cap_sat`, the
     terms' network;
4. the digest recomputed from the payload equals `digest`
   (`SIGNING_REQUEST_DIGEST`). An unknown purpose is `SIGNING_REQUEST_PURPOSE`.

It returns the parsed terms, which the signer shows to the key holder.

## Offline file exchange

`NewFileExchangeSigner(outbox, inbox, key, poll)` is the transport to a
signer on another machine. It holds no key.

- It refuses a request for another key (`PAY_GRANT_SIGNER_KEY`), an unknown
  purpose (`SIGNING_REQUEST_PURPOSE`) and a digest that is not 64 lowercase
  hex (`SIGNING_REQUEST_KEY`) before writing anything; the purpose and digest
  form the file names.
- It writes `outbox/<purpose>-<digest>.request.json` (mode 0600) by rename, so
  the remote side never reads a partial file. An existing request file is
  accepted only with identical bytes (a re-run); otherwise
  `SIGNING_REQUEST_CONFLICT`.
- It polls `inbox/<purpose>-<digest>.signature.json` every `poll` (1 s when
  `poll <= 0`) until the context ends (`SIGNATURE_WAIT`). A symlink, a
  non-regular, empty or oversized file is `SIGNATURE_FILE`; a non-canonical
  answer is `SIGNATURE_FILE_ENCODING`. The remote side must publish the answer
  by rename as well.

## Ceremony (CLI)

```bash
cd experiments/rental
go build -o "$OUT/paygrant-v2" ./cmd/paygrant-v2

# 1. Terms: validate, print contract hash and booking ref, write <sha>.json.
"$OUT/paygrant-v2" terms -terms terms.json -out-dir "$OUT/objects"

# 2. Issue: three requests appear in OUTBOX; the signers answer in INBOX.
"$OUT/paygrant-v2" issue -input input.json -outbox "$OUTBOX" -inbox "$INBOX" \
  -out-dir "$OUT/issued" -timeout 2h -poll 2s

# On each signer machine, before signing a request:
"$OUT/paygrant-v2" check-request -request "$OUTBOX/<purpose>-<digest>.request.json"

# 3. Plan the issuance transaction with the existing planner, then sign and
#    broadcast it on the lead node and wait for confirmation.
rental-plan grant-issue -policy policy.json -spec spec.json -grant "$OUT/issued/signed-grant.json"

# 4. Presentation for the wallet service objects directory.
"$OUT/paygrant-v2" present -grant "$OUT/issued/signed-grant.json" -txid <txid> \
  -out "$OUT/objects/<grant_id>.json"
```

`input.json` is `PayGrantV2Input` with Go member names (`"Network"`,
`"IssuerKey"`, ...); `Terms` uses the terms JSON names and `Seal` is
`{"txid","vout"}`. Every command prints one JSON object; outputs are written
once and never overwritten. Exit 0 never means "live": only `rental.Check` on
an own node decides that. Install `<contract_sha256>.json` (terms bytes) and
`<grant_id>.json` (presentation) in the wallet service objects directory.

## Tests

| Test | Claim |
| --- | --- |
| `TestPayGrantV2TermsGolden` | encoder bytes equal both golden fixtures |
| `TestPayGrantV2TermsRefusals` | every rows 3-10 violation refuses with its code, next to valid boundary neighbours |
| `TestPayGrantV2BookingRef` | the booking tag is domain separated and terms bound |
| `TestPayGrantV2ValidateInput` | each input violation refuses; the smoke input, a year window and boundary values pass |
| `TestPayGrantV2SignerOrder` | three calls in the frozen order, with golden terms bytes |
| `TestPayGrantV2RoundTrip` | `ParseSignedGrant` round trip, field binding, `IssuanceCommitment` (library and independent recomputation), presentation |
| `TestPayGrantV2DigestRecomputation` | the conforming check accepts the real requests and refuses each tampered variant |
| `TestPayGrantV2SignerRefusals` | wrong key, nil signer, signer error, cancellation, invalid or non-echoing signatures: refusal, zero result, no later step |
| `TestPayGrantV2SignerCannotRewrite` | a signer rewriting its buffers cannot change the grant |
| `TestPayGrantV2FileExchangeIssue` / `...Refusals` | the file exchange carries a full issuance; its refusals |
| `cmd/paygrant-v2` `TestCLITerms`, `TestCLIIssueCeremony` | the CLI ceremony end to end and its refusals |
| `TestCorePayGrantV2Issuance` (Core) | on genuine Namecoin Core 28 regtest, the issued grant is planned by `MakeGrantIssuancePlan`, pending until mined, then `LIVE` with scope `["pay"]` and its budget; another sender is refused; a seal spend closes it |

Run the Core test with `M1_REGTEST=1`, a fresh absolute `M1_RUN_ROOT`, and
`M1_CORE_DAEMON`/`M1_CORE_CLI`. It accepts the repository Core pin pair and
the official Namecoin Core 28.0 x86_64-linux-gnu release pair.

Guard-removal controls: `testdata/px1-mutations-s4.json`, run by
`TestPayGrantV2GuardPlants` with `W1_MUTATIONS=1` and a fresh absolute
`W1_MUTATION_ROOT` (plus the `M1_CORE_*` binaries for the Core plant). Each
plant must fail its named assertion; a build failure, panic or timeout is not
a detection.

## Limits

- The real issuance waits for the rotated landlord key in Ivan's Mac Keychain;
  the tests use public test scalars through in-memory and file signers.
- The Mac-side signer itself (Keychain access, display to the key holder) is
  outside this repository. It must run the conforming check and publish its
  answer by rename.
- The helper does not check chain state. Seal liveness, the identity names and
  the issuance confirmation are checked by `rental.Check` on the executor's own
  node.
- Step 2 of the mainnet smoke (issue one grant) runs only after Ivan approves
  and funds it. Nothing here authorizes it.
