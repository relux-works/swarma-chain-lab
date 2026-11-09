# Payment-bound contract and request v2

The disjoint ContractV2 and IssuanceRequestV2 types bind booking fees to a coin.
Legacy v1 wire, APIs and frozen fixtures are unchanged. There is no implicit
conversion or reinterpretation of a v1 Namecoin fee.

The v2 contract keeps identity, scope, slot, template/profile pins and budget
fields in their existing order. The NMC-specific price/rate/address fields are
replaced by one payment object with this exact order:

coin, network, genesis, price_usd_cents, usd_micros_per_coin, rate_as_of,
max_rate_age_seconds, amount_atoms, address, min_confirmations.

payment_policy follows payment, then privacy_sha256. Contract version is 2.
The request version is 2 and adds payment_coin, payment_network, payment_genesis
immediately before payment_txid. Those fields must equal the signed contract.
Scope, NMC execution budget, times and all identity/hash references must also
match. Historical payment height/block/txid are hints for independent lookup.

Canonical JSON uses declared field order, no extra fields or duplicate keys,
no whitespace suffix, and unescaped printable ASCII. Frozen deterministic public
vectors for BTC/LTC/NMC live in testdata/wire-v2. Synthetic payment IDs in those
vectors prove encoding and signatures only, never an actual payment.

Renter consent remains NIP-01 kind8181 with the existing domain tag, committing
the SHA256 of the complete v2 contract. The provider countersigns that hash and
publishes the existing kind8182 package shape/domain. Package version stays1;
the independently typed nested contract is version2. A provider cannot re-sign
changed payment terms and reuse the previous renter consent.

Quotes use ceil(cents*10^12/micros_per_coin), fixed at hold creation. A package
checks quote freshness at that time. The issuer also enforces its own rate-age
and confirmation minima; a signed request cannot weaken them. Budget_sat remains
NMC execution authority, never the fee currency. All three profiles are regtest
only. The observer module defines exact address families and integer bounds.

Producer entry points: ContractV2.Validate, ConsentV2, CheckConsentV2,
NewPackageV2, DecodePackageV2 and NewIssuanceRequestV2. Issuer-side independently
typed entry points are rental.VerifyIssuancePackageV2 and AdmitIssuanceV2. The
latter selects a payment node only from a trusted per-coin map after package
authentication, then independently checks current payment evidence. It emits
no signature or journal mutation. IssueGrantWithNodes connects this gate to the existing durable grant issuer.

The booking CLI selects ServiceV2 explicitly through its versioned config;
legacy flat configs keep v1. ServiceV2 provides the v2 library and HTTP API with one cross-coin calendar, per-coin counters, frozen terms,
restart validation and immutable outbox requests. Configured confirmation
minima default to one when omitted; an explicitly signed zero always refuses.
NewIssuerRPC requires the payment-issuer principal; NewRPC uses the separate
payment-observer principal. Provision different secrets with the documented
read-only server whitelist. Both wrappers reject wallet and name methods.

Issuer identity, pool and funding observations remain on the explicit Namecoin
node. IssueGrantWithNodes accepts an independently configured payment-node map.
It authenticates the original signed bytes and records denominated evidence in
payment_admission, never in the legacy NMC surplus_sat field. Both v1/v2 paths
share booking/pool burns, uncertain-stop recovery and L5 plan construction:
new grants use framed output, old completed bare records replay exact bytes.
A successful prepare still requires operator broadcast and current Check before
live authority; a booking revoke request does not itself spend a seal.

## Tools

Run `go test -race -count=1 ./...` and `go vet ./...` from rental-booking; repeat
in rental for independent consumer tests. Use GOWORK= with actual sibling
payment-chain, single-use and sealwatch modules. No node or credential is needed
for the wire suite. Existing frozen v1 tests run in the same suite.
