# P1 adapter-facing API

This is the stable type/codec surface for the E1 booking adapter. The v2 durable
booking service exposes the methods below; deployment and independent review
remain separate from the API contract. Keep v1/v2 conversion in
bookingbind and signed-wire interpretation out of the exchange itself.

## Coin and quote

Import `github.com/relux-works/swarma-chain-lab/experiments/payment-chain` as paymentchain.

```go
type Coin string
const (
    CoinNMC Coin = "nmc"
    CoinBTC Coin = "btc"
    CoinLTC Coin = "ltc"
)
func ParseCoin(raw string) (Coin, error)
func (c Coin) Validate() error
func (c Coin) Profile() (Profile, error)
func ForCoin(coin string) (Profile, error)
func Quote(p Profile, cents, micros, asOf, maxAge, now int64) (int64, error)
```

Parse external coin strings: a Go cast alone cannot enforce a closed set.
Unknown, uppercase, alias, whitespace-padded and empty values refuse. There is
no default currency. The profile is regtest-only. Quote returns integer atoms,
using ceil(cents*10^12/micros); all three coins have 10^8 atoms per coin.

The signed payment object is `paymentchain.Terms`, with these fields in order:

```go
Coin              string
Network           string
Genesis           string
PriceUSDCents     int64
USDMicrosPerCoin  int64
RateAsOf          int64
MaxRateAgeSeconds int64
AmountAtoms       int64
Address           string
MinConfirmations  int64
```

Its wire keys and semantics are fixed in PAYMENT-V2.md. Coin remains a JSON
string; adding the adapter enum does not change signed bytes. ValidateAt binds
terms to hold creation and trusted maximum age/minimum confirmations:

```go
func (t Terms) ValidateAt(holdCreated, maxAge, minConfirmations int64) error
```

A catalogue USD price or rate estimate is not a held quote. An address-bearing
Terms object must come from an atomically reserved booking/index; the exchange
must not invent an address or re-quote a signed contract. BudgetSat remains the
NMC execution budget and is never converted to the chosen payment currency.

## Opaque contract handle

Import `github.com/relux-works/swarma-chain-lab/experiments/rental-booking` as booking.

```go
type ContractHandleV2 struct {
    BookingID      string          `json:"booking_id"`
    ContractSHA256 string          `json:"contract_sha256"`
    ContractJSON   json.RawMessage `json:"contract"`
}
func (c ContractV2) Handle() (ContractHandleV2, error)
func (h ContractHandleV2) Validate() error
func (c ContractV2) Bytes() []byte
func (c ContractV2) Hash() string
```

Handle returns a detached canonical byte slice; Validate enforces version2,
static contract validity, exact canonical encoding, hash and booking binding.
It does not authenticate signatures, reserve a hold or prove payment. Keep its
ContractJSON bytes verbatim. Do not parse and reserialize them in the exchange.

Within bookingbind only, the consent/package APIs are:

```go
func ConsentV2(c ContractV2, at int64) Event
func CheckConsentV2(c ContractV2, e Event, created, expires, now int64) error
func NewPackageV2(c ContractV2, e Event, created, expires, now int64,
    key *btcec.PrivateKey) (PackageV2, Event, error)
func DecodePackageV2(b []byte, provider string, created, expires int64) (PackageV2, error)
```

Exchange/adapter code must not obtain the provider key to call NewPackageV2.
That call belongs inside the booking service. The renter signs the consent
Event; the adapter passes the original event bytes to the booking backend.
Outer NIP-01 consent/package domains remain v1; nested contract version is2.
No signed-wire change is required for this handle or the read-only catalogue.

## Catalogue and integration boundary

E1 owns the approved narrow read-only Catalogue method in its own booking file:
template identity, profile pin, USD price, slot lengths and free slots within a
bounded window. P1 will preserve that landed API and apply equivalent semantics
to its single global v2 calendar. Availability is advisory until Book atomically
reserves the interval. Separate payment coins never create separate calendars.
ServiceV2.Catalogue(until int64, limit int) returns (CatalogueV2, error).
Until bounds slot start: include slots intersecting [owned now, until), then
apply the booking capacity/start filters. SlotLengths describes all configured
durations, sorted and deduplicated, even when no slot is currently available.
The window is at most seven days, limit is 1..64, and returned data is detached.

Until ServiceV2 is independently reviewed and landed, E1 can use the existing v1 backend
through its narrow adapter. Do not link a private development snapshot into the
exchange or pretend that v2 wire types alone provide booking operations.

## Validation

`GOWORK= go test -race -count=1 -run '^(TestCoinBoundary|TestProfiles)$' .`
from payment-chain checks the closed coin vocabulary and quote/profile controls.
From rental-booking, run
`GOWORK= go test -race -count=1 -run '^(TestContractHandleV2|TestFrozenWireV2|TestFrozenPublicFixture|TestWireV2Binding|TestWireV2Eligibility)$' .`.
The handle controls reject mismatched hashes/IDs, noncanonical bytes, oversized
input and legacy versions beside valid per-coin controls. Frozen v1/v2 signed
vectors remain unchanged. These are static API tests, not end-to-end bookings.

## ServiceV2

NewServiceV2 accepts ConfigV2, pinned public profile bytes, the service-owned
provider signing key, trusted per-coin payment nodes, a separate optional
Namecoin renter-name node, relay Publisher and an owned clock. It requires a
fresh private state root; an existing v1 root refuses without migration.

Book(context.Context, BookInputV2) returns (BookingV2, error); BookInputV2 has
SlotID, Coin, RenterPubkey, RenterName and PrivacyAcknowledged. Get(bookingID),
AcceptConsent(context.Context, bookingID, Event), Refresh(context.Context) and
PublishPending(context.Context) retain the v1 service operation shapes with v2
results. Close releases the global ledger lock and zeros its own key copy.
Book persists the cross-coin interval and per-coin address counter before
returning an address. Get returns a detached snapshot, not a current-chain proof.
The adapter must not call signing helpers with its own provider key.

A complete confirmation threshold must be observed before hold expiry. No
aggregation is performed. A pre-issuance reorg clears selection; a post-issuance
reorg emits a sticky revoke request and never reissues that booking, including
after restart. Issuance/revoke outbox bytes are immutable once written.
