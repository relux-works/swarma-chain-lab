package booking

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	pc "relux.works/swarma-chain-lab/experiments/payment-chain"
)

// CoinConfig contains a watch-only branch and trusted quote policy. Current
// quotes may change on restart; each existing hold keeps its signed terms.
type CoinConfig struct {
	PublicBranch       string `json:"public_branch"`
	PublicBranchSHA256 string `json:"public_branch_sha256"`
	USDMicrosPerCoin   int64  `json:"usd_micros_per_coin"`
	RateAsOf           int64  `json:"rate_as_of"`
	MaxRateAgeSeconds  int64  `json:"max_rate_age_seconds"`
	MinConfirmations   int64  `json:"min_confirmations"`
}
type ConfigV2 struct {
	StateDir                    string                `json:"state_dir"`
	AgentPubkey                 string                `json:"agent_pubkey"`
	ProviderPubkey              string                `json:"provider_pubkey"`
	HoldSeconds                 int64                 `json:"hold_seconds"`
	MinStartNowRemainingSeconds int64                 `json:"min_start_now_remaining_seconds"`
	PriceUSDCents               int64                 `json:"price_usd_cents"`
	Template                    Template              `json:"template"`
	TemplateSHA256              string                `json:"template_sha256"`
	Slots                       []Slot                `json:"slots"`
	Coins                       map[string]CoinConfig `json:"coins"`
	Limits                      Limits                `json:"limits"`
}
type BookInputV2 struct {
	SlotID              string  `json:"slot_id"`
	Coin                pc.Coin `json:"coin"`
	RenterPubkey        string  `json:"renter_pubkey"`
	RenterName          string  `json:"renter_name"`
	PrivacyAcknowledged bool    `json:"privacy_acknowledged"`
}
type RevokeRequestV2 struct {
	Version         int    `json:"version"`
	BookingID       string `json:"booking_id"`
	ContractSHA256  string `json:"contract_sha256"`
	PaymentCoin     string `json:"payment_coin"`
	PaymentNetwork  string `json:"payment_network"`
	PaymentGenesis  string `json:"payment_genesis"`
	PaymentTxID     string `json:"payment_txid"`
	PaymentVout     uint32 `json:"payment_vout"`
	Reason          string `json:"reason"`
	ObservedTipHash string `json:"observed_tip_hash"`
}
type ReceiptV2 struct {
	Payment      pc.Payment `json:"payment"`
	FirstSeen    int64      `json:"first_seen"`
	EligibleAt   int64      `json:"eligible_at"`
	Disposition  string     `json:"disposition"`
	SurplusAtoms int64      `json:"surplus_atoms"`
	RefundReview bool       `json:"refund_review"`
}
type BookingV2 struct {
	Contract         ContractV2         `json:"contract"`
	AddressIndex     uint32             `json:"address_index"`
	Script           string             `json:"script"`
	CheckpointHeight int64              `json:"checkpoint_height"`
	HoldCreatedAt    int64              `json:"hold_created_at"`
	HoldExpiresAt    int64              `json:"hold_expires_at"`
	PrivacyAckAt     int64              `json:"privacy_ack_at"`
	Status           string             `json:"status"`
	Receipts         []ReceiptV2        `json:"receipts"`
	Payment          *pc.Payment        `json:"payment,omitempty"`
	Package          *PackageV2         `json:"package,omitempty"`
	PackageEvent     *Event             `json:"package_event,omitempty"`
	Published        bool               `json:"published"`
	Issuance         *IssuanceRequestV2 `json:"issuance,omitempty"`
	Revoke           *RevokeRequestV2   `json:"revoke,omitempty"`
}
type stateV2 struct {
	Version        int               `json:"version"`
	Binding        string            `json:"binding"`
	ClockHighWater int64             `json:"clock_high_water"`
	NextIndices    map[string]uint32 `json:"next_indices"`
	Bookings       []BookingV2       `json:"bookings"`
}

// ServiceV2 owns one durable calendar and lock across all enabled coins. The
// separate Namecoin identity route is never selected from a payment request.
type ServiceV2 struct {
	mu       sync.Mutex
	cfg      ConfigV2
	key      *btcec.PrivateKey
	derivers map[string]*pc.AddressDeriver
	nodes    map[string]Node
	nameNode Node
	store    *fileStore
	state    stateV2
	relay    Publisher
	clock    func() time.Time
}

func NewServiceV2(cfg ConfigV2, profile []byte, key *btcec.PrivateKey, paymentNodes map[string]Node, nameNode Node, relay Publisher, clock func() time.Time) (*ServiceV2, error) {
	var owned ConfigV2
	if json.Unmarshal(canonical(cfg), &owned) != nil {
		return nil, refuse("SERVICE_CONFIG")
	}
	cfg = owned
	if cfg.HoldSeconds == 0 {
		cfg.HoldSeconds = DefaultHoldSeconds
	}
	if cfg.MinStartNowRemainingSeconds == 0 {
		cfg.MinStartNowRemainingSeconds = DefaultMinStartNowRemainingSeconds
	}
	if cfg.MinStartNowRemainingSeconds < 1 || cfg.MinStartNowRemainingSeconds > 3600 {
		return nil, refuse("START_WINDOW_CONFIG")
	}
	if key == nil || keyHex(key) != cfg.ProviderPubkey || !pubkey(cfg.AgentPubkey) || cfg.HoldSeconds < 1200 || cfg.HoldSeconds > 1800 || cfg.PriceUSDCents <= 0 || !cfg.Limits.valid() || relay == nil || clock == nil || len(cfg.Coins) < 1 || len(cfg.Coins) > 3 {
		return nil, refuse("SERVICE_CONFIG")
	}
	if e := cfg.Template.Validate(profile, cfg.TemplateSHA256); e != nil {
		return nil, e
	}
	if len(cfg.Slots) < 1 || len(cfg.Slots) > 1000 {
		return nil, refuse("CALENDAR_CONFIG")
	}
	ids := map[string]bool{}
	for _, slot := range cfg.Slots {
		if !identifier(slot.ID) || ids[slot.ID] || !stationName(slot.StationName) || slot.NotBefore <= 0 || slot.NotAfter <= slot.NotBefore || slot.NotAfter-slot.NotBefore > 3600 || slot.PaymentPolicy != "advance" && slot.PaymentPolicy != "start_now" {
			return nil, refuse("CALENDAR_CONFIG")
		}
		ids[slot.ID] = true
	}
	s := &ServiceV2{cfg: cfg, derivers: map[string]*pc.AddressDeriver{}, nodes: map[string]Node{}, nameNode: nameNode, relay: relay, clock: clock}
	type pin struct {
		Branch                   string
		MaxAge, MinConfirmations int64
	}
	pins := map[string]pin{}
	for coin, c := range cfg.Coins {
		if c.MinConfirmations == 0 {
			c.MinConfirmations = 1
			cfg.Coins[coin] = c
		}
		p, e := pc.ForCoin(coin)
		if e != nil {
			return nil, e
		}
		if c.MaxRateAgeSeconds <= 0 || c.MinConfirmations < 1 || c.MinConfirmations > 2016 || c.USDMicrosPerCoin <= 0 || c.RateAsOf <= 0 || paymentNodes[coin] == nil {
			return nil, refuse("COIN_CONFIG")
		}
		d, e := pc.NewAddressDeriver(p, c.PublicBranch, c.PublicBranchSHA256)
		if e != nil {
			return nil, e
		}
		s.derivers[coin], s.nodes[coin] = d, paymentNodes[coin]
		pins[coin] = pin{c.PublicBranchSHA256, c.MaxRateAgeSeconds, c.MinConfirmations}
	}
	now := clock().Unix()
	if now <= 0 || now > math.MaxInt64-1800 {
		return nil, refuse("CLOCK_RANGE")
	}
	f, e := openStore(cfg.StateDir)
	if e != nil {
		return nil, e
	}
	s.store = f
	s.key, _ = btcec.PrivKeyFromBytes(key.Serialize())
	binding := Hash(canonical(struct {
		Provider, Agent, Template string
		Coins                     map[string]pin
	}{cfg.ProviderPubkey, cfg.AgentPubkey, cfg.TemplateSHA256, pins}))
	raw, e := f.read("state.json", 8<<20)
	if e != nil {
		s.Close()
		return nil, e
	}
	if raw == nil {
		indices := map[string]uint32{}
		for coin := range cfg.Coins {
			indices[coin] = 0
		}
		if e = s.persistV2(stateV2{2, binding, now, indices, []BookingV2{}}); e != nil {
			s.Close()
			return nil, e
		}
	} else {
		if Strict(raw, &s.state) != nil || s.state.Version != 2 || s.state.Binding != binding || s.state.Bookings == nil {
			s.Close()
			return nil, refuse("STATE_BINDING")
		}
		if e = s.validateStateV2(); e != nil {
			s.Close()
			return nil, e
		}
		if now < s.state.ClockHighWater {
			s.Close()
			return nil, refuse("CLOCK_REVERSED")
		}
	}
	if e = s.exportV2(); e != nil {
		s.Close()
		return nil, e
	}
	return s, nil
}
func (s *ServiceV2) Close() { s.mu.Lock(); defer s.mu.Unlock(); s.store.close(); s.key.Zero() }
func (s *ServiceV2) nowV2() (int64, error) {
	if s.store.poisoned {
		return 0, refuse("STATE_UNAVAILABLE")
	}
	now := s.clock().Unix()
	if now <= 0 || now > math.MaxInt64-1800 {
		return 0, refuse("CLOCK_RANGE")
	}
	if now < s.state.ClockHighWater {
		return 0, refuse("CLOCK_REVERSED")
	}
	return now, nil
}
func copyStateV2(st stateV2) stateV2 {
	var out stateV2
	_ = json.Unmarshal(canonical(st), &out)
	return out
}
func copyBookingV2(b BookingV2) BookingV2 {
	var out BookingV2
	_ = json.Unmarshal(canonical(b), &out)
	return out
}
func (s *ServiceV2) persistV2(st stateV2) error {
	raw := canonical(st)
	if len(raw) > 8<<20 || len(st.Bookings) > 4096 {
		return refuse("STATE_CAPACITY")
	}
	if e := s.store.write("state.json", raw, false); e != nil {
		return e
	}
	s.state = st
	return nil
}
func paymentPoint(p pc.Payment) string { return fmt.Sprintf("%s:%d", p.TxID, p.Vout) }
func eligibleV2(p pc.Payment, c ContractV2, tip pc.Tip) bool {
	return p.ValueAtoms >= c.Payment.AmountAtoms && p.Height > 0 && p.Height <= tip.Height && tip.Height-p.Height+1 >= c.Payment.MinConfirmations
}
func (s *ServiceV2) exportV2() error {
	for _, b := range s.state.Bookings {
		for _, item := range []struct {
			name    string
			present bool
			value   any
		}{{"package", b.Package != nil, b.Package}, {"issue", b.Issuance != nil, b.Issuance}, {"revoke", b.Revoke != nil, b.Revoke}} {
			if item.present {
				if e := s.store.write(item.name+"-"+b.Contract.BookingID+".json", canonical(item.value), true); e != nil {
					return e
				}
			}
		}
	}
	return nil
}
func (s *ServiceV2) Book(ctx context.Context, in BookInputV2) (BookingV2, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now, e := s.nowV2()
	if e != nil {
		return BookingV2{}, e
	}
	if !in.PrivacyAcknowledged {
		return BookingV2{}, refuse("PRIVACY_REQUIRED")
	}
	if !pubkey(in.RenterPubkey) {
		return BookingV2{}, refuse("RENTER_KEY")
	}
	if e = in.Coin.Validate(); e != nil {
		return BookingV2{}, e
	}
	coin := string(in.Coin)
	cc, ok := s.cfg.Coins[coin]
	if !ok {
		return BookingV2{}, refuse("COIN_UNAVAILABLE")
	}
	var slot *Slot
	for _, v := range s.cfg.Slots {
		if v.ID == in.SlotID {
			slot = &v
			break
		}
	}
	if slot == nil {
		return BookingV2{}, refuse("SLOT_UNAVAILABLE")
	}
	if e = s.slotAvailableV2(*slot, now); e != nil {
		return BookingV2{}, e
	}
	if len(s.state.Bookings) >= 4096 {
		return BookingV2{}, refuse("STATE_CAPACITY")
	}
	p, _ := pc.ForCoin(coin)
	if _, e = pc.Quote(p, s.cfg.PriceUSDCents, cc.USDMicrosPerCoin, cc.RateAsOf, cc.MaxRateAgeSeconds, now); e != nil {
		return BookingV2{}, e
	}
	if in.RenterName != "" {
		if s.nameNode == nil {
			return BookingV2{}, refuse("RENTER_NAME_NODE")
		}
		if e = CheckRenterName(ctx, s.nameNode, s.cfg.Limits, in.RenterName, in.RenterPubkey); e != nil {
			return BookingV2{}, e
		}
	}
	tip, e := pc.ReadTip(ctx, s.nodes[coin], p, pc.Limits(s.cfg.Limits))
	if e != nil {
		return BookingV2{}, e
	}
	later, e := s.nowV2()
	if e != nil {
		return BookingV2{}, e
	}
	if later < now {
		return BookingV2{}, refuse("CLOCK_REVERSED")
	}
	now = later
	if e = s.slotAvailableV2(*slot, now); e != nil {
		return BookingV2{}, e
	}
	amount, e := pc.Quote(p, s.cfg.PriceUSDCents, cc.USDMicrosPerCoin, cc.RateAsOf, cc.MaxRateAgeSeconds, now)
	if e != nil {
		return BookingV2{}, e
	}
	index := s.state.NextIndices[coin]
	address, script, e := s.derivers[coin].Address(index)
	if e != nil {
		return BookingV2{}, e
	}
	var random [32]byte
	if _, e = rand.Read(random[:]); e != nil {
		return BookingV2{}, refuse("BOOKING_RANDOM")
	}
	t := s.cfg.Template
	c := ContractV2{Version: 2, BookingID: hex.EncodeToString(random[:]), RenterPubkey: in.RenterPubkey, RenterName: in.RenterName, AgentPubkey: s.cfg.AgentPubkey, StationName: slot.StationName, NotBefore: slot.NotBefore, NotAfter: slot.NotAfter, Allowed: append([]string{}, t.Allowed...), Forbidden: append([]string{}, t.Forbidden...), BudgetSat: t.BudgetSat, TemplateID: t.ID, TemplateSHA256: s.cfg.TemplateSHA256, ProfileID: t.ProfileID, ProfileVersion: t.ProfileVersion, ProfileSHA256: t.ProfileSHA256, Payment: pc.Terms{Coin: coin, Network: p.Network, Genesis: p.Genesis, PriceUSDCents: s.cfg.PriceUSDCents, USDMicrosPerCoin: cc.USDMicrosPerCoin, RateAsOf: cc.RateAsOf, MaxRateAgeSeconds: cc.MaxRateAgeSeconds, AmountAtoms: amount, Address: address, MinConfirmations: cc.MinConfirmations}, PaymentPolicy: slot.PaymentPolicy, PrivacySHA256: Hash([]byte(PrivacyNotice))}
	if e = c.Validate(); e != nil {
		return BookingV2{}, e
	}
	expires := min(now+s.cfg.HoldSeconds, slot.NotAfter)
	b := BookingV2{Contract: c, AddressIndex: index, Script: script, CheckpointHeight: tip.Height, HoldCreatedAt: now, HoldExpiresAt: expires, PrivacyAckAt: now, Status: "pending", Receipts: []ReceiptV2{}}
	st := copyStateV2(s.state)
	st.NextIndices[coin]++
	st.ClockHighWater = now
	for i := range st.Bookings {
		old := &st.Bookings[i]
		if old.HoldExpiresAt <= now && old.Issuance == nil {
			old.Status = "expired"
			old.Payment = nil
			annotateReceiptsV2(old)
		}
	}
	st.Bookings = append(st.Bookings, b)
	if e = s.persistV2(st); e != nil {
		return BookingV2{}, e
	}
	return copyBookingV2(b), nil
}
func (s *ServiceV2) slotAvailableV2(slot Slot, now int64) error {
	if slot.NotAfter <= now || slot.PaymentPolicy == "advance" && slot.NotBefore <= now {
		return refuse("SLOT_UNAVAILABLE")
	}
	if slot.PaymentPolicy == "start_now" && slot.NotAfter-now < s.cfg.MinStartNowRemainingSeconds {
		return refuse("SLOT_REMAINING_WINDOW")
	}
	for _, b := range s.state.Bookings {
		c := b.Contract
		if c.StationName == slot.StationName && c.NotBefore < slot.NotAfter && slot.NotBefore < c.NotAfter && (b.HoldExpiresAt > now || b.Issuance != nil) {
			return refuse("CAPACITY_FULL")
		}
	}
	return nil
}
func (s *ServiceV2) Get(id string) (BookingV2, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.store.poisoned {
		return BookingV2{}, refuse("STATE_UNAVAILABLE")
	}
	for _, b := range s.state.Bookings {
		if b.Contract.BookingID == id {
			return copyBookingV2(b), nil
		}
	}
	return BookingV2{}, refuse("BOOKING_NOT_FOUND")
}
func (s *ServiceV2) AcceptConsent(ctx context.Context, id string, event Event) (BookingV2, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now, e := s.nowV2()
	if e != nil {
		return BookingV2{}, e
	}
	st := copyStateV2(s.state)
	for i := range st.Bookings {
		b := &st.Bookings[i]
		if b.Contract.BookingID != id {
			continue
		}
		if b.Package != nil {
			if b.Package.Consent.ID != event.ID || event.Verify() != nil {
				return BookingV2{}, refuse("CONSENT_ALREADY_SET")
			}
			return copyBookingV2(*b), nil
		}
		p, evt, e := NewPackageV2(b.Contract, event, b.HoldCreatedAt, b.HoldExpiresAt, now, s.key)
		if e != nil {
			return BookingV2{}, e
		}
		b.Package = &p
		b.PackageEvent = &evt
		st.ClockHighWater = now
		if e = s.persistV2(st); e != nil {
			return BookingV2{}, e
		}
		if e = s.exportV2(); e != nil {
			return BookingV2{}, e
		}
		if e = s.publishLockedV2(ctx); e != nil {
			return copyBookingV2(*b), e
		}
		return copyBookingV2(s.state.Bookings[i]), nil
	}
	return BookingV2{}, refuse("BOOKING_NOT_FOUND")
}
func (s *ServiceV2) publishLockedV2(ctx context.Context) error {
	now, e := s.nowV2()
	if e != nil {
		return e
	}
	for i, b := range s.state.Bookings {
		if b.PackageEvent == nil || b.Published {
			continue
		}
		if e = s.relay.Publish(ctx, *b.PackageEvent); e != nil {
			return refuse("RELAY_UNAVAILABLE")
		}
		st := copyStateV2(s.state)
		st.Bookings[i].Published = true
		st.ClockHighWater = now
		if e = s.persistV2(st); e != nil {
			return e
		}
	}
	return nil
}
func (s *ServiceV2) PublishPending(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.publishLockedV2(ctx)
}

// All required coin snapshots succeed before any ledger write. One unavailable
// coin cannot commit another coin's new issuance or free its reserved interval.
func (s *ServiceV2) Refresh(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now, e := s.nowV2()
	if e != nil {
		return e
	}
	targets := map[string]map[string]pc.WatchTarget{}
	for _, b := range s.state.Bookings {
		if b.Contract.NotAfter > now {
			coin := b.Contract.Payment.Coin
			if targets[coin] == nil {
				targets[coin] = map[string]pc.WatchTarget{}
			}
			targets[coin][b.Contract.BookingID] = pc.WatchTarget{Script: b.Script, AfterHeight: b.CheckpointHeight}
		}
	}
	coins := []string{}
	for coin := range targets {
		coins = append(coins, coin)
	}
	sort.Strings(coins)
	snaps := map[string]pc.Snapshot{}
	for _, coin := range coins {
		p, _ := pc.ForCoin(coin)
		snap, e := pc.Discover(ctx, s.nodes[coin], p, pc.Limits(s.cfg.Limits), targets[coin])
		if e != nil {
			return e
		}
		snaps[coin] = snap
	}
	observed, e := s.nowV2()
	if e != nil {
		return e
	}
	if observed < now {
		return refuse("CLOCK_REVERSED")
	}
	now = observed
	st := copyStateV2(s.state)
	for i := range st.Bookings {
		b := &st.Bookings[i]
		if b.Contract.NotAfter <= now {
			continue
		}
		snap := snaps[b.Contract.Payment.Coin]
		if e = refreshBookingV2(b, snap, now); e != nil {
			return e
		}
	}
	later, e := s.nowV2()
	if e != nil {
		return e
	}
	if later < now {
		return refuse("CLOCK_REVERSED")
	}
	for i, b := range st.Bookings {
		if b.Issuance != nil && s.state.Bookings[i].Issuance == nil && (later >= b.HoldExpiresAt || later >= b.Contract.NotAfter) {
			return refuse("ISSUANCE_EXPIRED")
		}
	}
	st.ClockHighWater = later
	if e = s.persistV2(st); e != nil {
		return e
	}
	return s.exportV2()
}
func refreshBookingV2(b *BookingV2, snap pc.Snapshot, now int64) error {
	current := snap.Payments[b.Contract.BookingID]
	points := map[string]pc.Payment{}
	for _, p := range current {
		point := paymentPoint(p)
		points[point] = p
		index := -1
		for j, r := range b.Receipts {
			if paymentPoint(r.Payment) == point {
				index = j
				break
			}
		}
		if index < 0 {
			if len(b.Receipts) >= 4096 {
				return refuse("RECEIPT_CAPACITY")
			}
			b.Receipts = append(b.Receipts, ReceiptV2{Payment: p, FirstSeen: now, Disposition: "pending"})
			index = len(b.Receipts) - 1
		}
		r := &b.Receipts[index]
		if r.Payment.BlockHash != p.BlockHash || r.Payment.Height != p.Height || !eligibleV2(p, b.Contract, snap.Tip) {
			r.EligibleAt = 0
		}
		r.Payment = p
		if eligibleV2(p, b.Contract, snap.Tip) && r.EligibleAt == 0 {
			r.EligibleAt = now
		}
	}
	for j := range b.Receipts {
		if _, ok := points[paymentPoint(b.Receipts[j].Payment)]; !ok {
			b.Receipts[j].EligibleAt = 0
		}
	}
	b.Payment = nil
	if b.Issuance != nil {
		r := b.Issuance
		p, present := points[paymentPoint(pc.Payment{TxID: r.PaymentTxID, Vout: r.PaymentVout})]
		if !present || p.BlockHash != r.PaymentBlockHash || p.Height != r.PaymentHeight || !eligibleV2(p, b.Contract, snap.Tip) {
			if b.Revoke == nil {
				b.Revoke = &RevokeRequestV2{2, b.Contract.BookingID, b.Contract.Hash(), r.PaymentCoin, r.PaymentNetwork, r.PaymentGenesis, r.PaymentTxID, r.PaymentVout, "payment_reorged", snap.Tip.Hash}
			}
		} else if b.Revoke == nil {
			b.Payment = &p
		}
	} else if now < b.HoldExpiresAt {
		for _, p := range current {
			for _, r := range b.Receipts {
				if paymentPoint(r.Payment) == paymentPoint(p) && eligibleV2(p, b.Contract, snap.Tip) && r.EligibleAt > 0 && r.EligibleAt < b.HoldExpiresAt {
					b.Payment = &p
					break
				}
			}
			if b.Payment != nil {
				break
			}
		}
	}
	b.Status = "pending"
	if b.Payment != nil {
		b.Status = "paid"
	} else if now >= b.HoldExpiresAt {
		b.Status = "expired"
	}
	if b.Revoke != nil {
		b.Status = "revoked"
	}
	for j := range b.Receipts {
		r := &b.Receipts[j]
		r.Disposition = "refund_review"
		if b.Payment != nil && paymentPoint(r.Payment) == paymentPoint(*b.Payment) {
			r.Disposition = "selected"
		} else if b.Issuance == nil && now < b.HoldExpiresAt && r.FirstSeen < b.HoldExpiresAt && r.Payment.ValueAtoms >= b.Contract.Payment.AmountAtoms {
			if _, ok := points[paymentPoint(r.Payment)]; ok {
				r.Disposition = "pending"
			}
		}
	}
	annotateReceiptsV2(b)
	if b.Payment != nil && b.Package != nil && b.Published && b.Issuance == nil && b.Revoke == nil && now < b.HoldExpiresAt {
		r, e := NewIssuanceRequestV2(b.Contract, *b.Payment, snap.Tip, b.PackageEvent.ID)
		if e != nil {
			return e
		}
		b.Issuance = &r
	}
	return nil
}
func annotateReceiptsV2(b *BookingV2) {
	for i := range b.Receipts {
		r := &b.Receipts[i]
		if b.Payment == nil && r.Disposition == "selected" {
			r.Disposition = "refund_review"
		}
		r.SurplusAtoms = max(int64(0), r.Payment.ValueAtoms-b.Contract.Payment.AmountAtoms)
		r.RefundReview = r.SurplusAtoms > 0 || r.Disposition == "refund_review"
	}
}
