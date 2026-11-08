package booking

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
)

type Slot struct {
	ID            string `json:"id"`
	StationName   string `json:"station_name"`
	NotBefore     int64  `json:"not_before"`
	NotAfter      int64  `json:"not_after"`
	PaymentPolicy string `json:"payment_policy"`
}
type Config struct {
	StateDir                    string   `json:"state_dir"`
	PublicBranch                string   `json:"public_branch"`
	PublicBranchSHA256          string   `json:"public_branch_sha256"`
	AgentPubkey                 string   `json:"agent_pubkey"`
	ProviderPubkey              string   `json:"provider_pubkey"`
	HoldSeconds                 int64    `json:"hold_seconds"`
	MinStartNowRemainingSeconds int64    `json:"min_start_now_remaining_seconds"`
	PriceUSDCents               int64    `json:"price_usd_cents"`
	USDMicrosPerNMC             int64    `json:"usd_micros_per_nmc"`
	RateAsOf                    int64    `json:"rate_as_of"`
	MaxRateAge                  int64    `json:"max_rate_age_seconds"`
	Template                    Template `json:"template"`
	TemplateSHA256              string   `json:"template_sha256"`
	Slots                       []Slot   `json:"slots"`
	Limits                      Limits   `json:"limits"`
}
type IssuanceRequest struct {
	Version          int      `json:"version"`
	BookingID        string   `json:"booking_id"`
	StationName      string   `json:"station_name"`
	AgentPubkey      string   `json:"agent_pubkey"`
	RenterPubkey     string   `json:"renter_pubkey"`
	ContractSHA256   string   `json:"contract_sha256"`
	Scope            []string `json:"scope"`
	BudgetSat        int64    `json:"budget_sat"`
	NotBefore        int64    `json:"not_before"`
	NotAfter         int64    `json:"not_after"`
	PaymentPolicy    string   `json:"payment_policy"`
	PaymentTxID      string   `json:"payment_txid"`
	PaymentVout      uint32   `json:"payment_vout"`
	PaymentHeight    int64    `json:"payment_height"`
	PaymentBlockHash string   `json:"payment_block_hash"`
	ObservedTipHash  string   `json:"observed_tip_hash"`
	PackageEventID   string   `json:"package_event_id"`
}
type RevokeRequest struct {
	Version         int    `json:"version"`
	BookingID       string `json:"booking_id"`
	ContractSHA256  string `json:"contract_sha256"`
	PaymentTxID     string `json:"payment_txid"`
	PaymentVout     uint32 `json:"payment_vout"`
	Reason          string `json:"reason"`
	ObservedTipHash string `json:"observed_tip_hash"`
}
type Receipt struct {
	Payment      Payment `json:"payment"`
	FirstSeen    int64   `json:"first_seen"`
	ConfirmedAt  int64   `json:"confirmed_at"`
	Disposition  string  `json:"disposition"`
	SurplusSat   int64   `json:"surplus_sat"`
	RefundReview bool    `json:"refund_review"`
}
type Booking struct {
	Contract         Contract         `json:"contract"`
	AddressIndex     uint32           `json:"address_index"`
	Script           string           `json:"script"`
	CheckpointHeight int64            `json:"checkpoint_height"`
	HoldCreatedAt    int64            `json:"hold_created_at"`
	HoldExpiresAt    int64            `json:"hold_expires_at"`
	PrivacyAckAt     int64            `json:"privacy_ack_at"`
	Status           string           `json:"status"`
	Receipts         []Receipt        `json:"receipts"`
	Payment          *Payment         `json:"payment,omitempty"`
	Package          *Package         `json:"package,omitempty"`
	PackageEvent     *Event           `json:"package_event,omitempty"`
	Published        bool             `json:"published"`
	Issuance         *IssuanceRequest `json:"issuance,omitempty"`
	Revoke           *RevokeRequest   `json:"revoke,omitempty"`
}
type state struct {
	Version   int       `json:"version"`
	Binding   string    `json:"binding"`
	NextIndex uint32    `json:"next_index"`
	Bookings  []Booking `json:"bookings"`
}
type Publisher interface {
	Publish(context.Context, Event) error
}
type Service struct {
	mu      sync.Mutex
	cfg     Config
	key     *btcec.PrivateKey
	deriver *AddressDeriver
	store   *fileStore
	state   state
	node    Node
	relay   Publisher
	clock   func() time.Time
}

const DefaultHoldSeconds int64 = 1800
const DefaultMinStartNowRemainingSeconds int64 = 1500

func NewService(cfg Config, profile []byte, key *btcec.PrivateKey, node Node, relay Publisher, clock func() time.Time) (*Service, error) {
	if cfg.HoldSeconds == 0 {
		cfg.HoldSeconds = DefaultHoldSeconds
	}
	if cfg.MinStartNowRemainingSeconds == 0 {
		cfg.MinStartNowRemainingSeconds = DefaultMinStartNowRemainingSeconds
	}
	if cfg.MinStartNowRemainingSeconds < 1 || cfg.MinStartNowRemainingSeconds > 3600 {
		return nil, refuse("START_WINDOW_CONFIG")
	}
	if key == nil || keyHex(key) != cfg.ProviderPubkey || !pubkey(cfg.AgentPubkey) || cfg.HoldSeconds < 1200 || cfg.HoldSeconds > 1800 || !cfg.Limits.valid() || node == nil || relay == nil || clock == nil {
		return nil, refuse("SERVICE_CONFIG")
	}
	if e := cfg.Template.Validate(profile, cfg.TemplateSHA256); e != nil {
		return nil, e
	}
	if len(cfg.Slots) == 0 || len(cfg.Slots) > 1000 {
		return nil, refuse("CALENDAR_CONFIG")
	}
	ids := map[string]bool{}
	for _, slot := range cfg.Slots {
		if !identifier(slot.ID) || ids[slot.ID] || !stationName(slot.StationName) || slot.NotBefore <= 0 || slot.NotAfter <= slot.NotBefore || slot.NotAfter-slot.NotBefore > 3600 || slot.PaymentPolicy != "advance" && slot.PaymentPolicy != "start_now" {
			return nil, refuse("CALENDAR_CONFIG")
		}
		ids[slot.ID] = true
	}
	d, e := NewAddressDeriver(cfg.PublicBranch, cfg.PublicBranchSHA256)
	if e != nil {
		return nil, e
	}
	f, e := openStore(cfg.StateDir)
	if e != nil {
		return nil, e
	}
	s := &Service{cfg: cfg, key: key, deriver: d, store: f, node: node, relay: relay, clock: clock}
	binding := Hash(canonical([]string{cfg.PublicBranchSHA256, cfg.ProviderPubkey, cfg.AgentPubkey, cfg.TemplateSHA256}))
	raw, e := f.read("state.json", 8<<20)
	if e != nil {
		f.close()
		return nil, e
	}
	if raw == nil {
		s.state = state{1, binding, 0, []Booking{}}
		if e = s.persist(s.state); e != nil {
			f.close()
			return nil, e
		}
	} else {
		if Strict(raw, &s.state) != nil || s.state.Version != 1 || s.state.Binding != binding || s.state.Bookings == nil {
			s.Close()
			return nil, refuse("STATE_BINDING")
		}
		if e = s.validateState(); e != nil {
			s.Close()
			return nil, e
		}
		// Review metadata is derived from existing receipts, never new authority.
		changed := false
		for i := range s.state.Bookings {
			changed = annotateReceipts(&s.state.Bookings[i]) || changed
		}
		if changed {
			if e = s.persist(s.state); e != nil {
				s.Close()
				return nil, e
			}
		}
	}
	if e = s.export(); e != nil {
		s.Close()
		return nil, e
	}
	return s, nil
}
func (s *Service) Close()      { s.mu.Lock(); defer s.mu.Unlock(); s.store.close() }
func copyState(st state) state { var out state; _ = json.Unmarshal(canonical(st), &out); return out }
func copyBooking(b Booking) Booking {
	var out Booking
	_ = json.Unmarshal(canonical(b), &out)
	return out
}
func (s *Service) persist(st state) error {
	raw := canonical(st)
	if len(raw) > 8<<20 {
		return refuse("STATE_CAPACITY")
	}
	if e := s.store.write("state.json", raw, false); e != nil {
		return e
	}
	s.state = st
	return nil
}
func (s *Service) validateState() error {
	ids := map[string]bool{}
	indices := map[uint32]bool{}
	for _, b := range s.state.Bookings {
		c := b.Contract
		t := s.cfg.Template
		address, script, e := s.deriver.Address(b.AddressIndex)
		if e != nil || c.Validate() != nil || ids[c.BookingID] || indices[b.AddressIndex] || b.AddressIndex >= s.state.NextIndex || c.PaymentAddress != address || b.Script != script || b.CheckpointHeight < 0 || b.HoldCreatedAt <= 0 || b.HoldExpiresAt <= b.HoldCreatedAt || b.PrivacyAckAt != b.HoldCreatedAt || b.Receipts == nil || c.AgentPubkey != s.cfg.AgentPubkey || c.TemplateSHA256 != s.cfg.TemplateSHA256 {
			return refuse("STATE_CORRUPT")
		}
		ids[c.BookingID] = true
		indices[b.AddressIndex] = true
		if c.TemplateID != t.ID || c.ProfileID != t.ProfileID || c.ProfileVersion != t.ProfileVersion || c.ProfileSHA256 != t.ProfileSHA256 || c.BudgetSat != t.BudgetSat || string(canonical(c.Allowed)) != string(canonical(t.Allowed)) || string(canonical(c.Forbidden)) != string(canonical(t.Forbidden)) {
			return refuse("STATE_TEMPLATE")
		}
		if b.Status != "pending" && b.Status != "paid" && b.Status != "expired" && b.Status != "revoked" {
			return refuse("STATE_CORRUPT")
		}
		if b.Package != nil {
			if b.Package.Validate(s.cfg.ProviderPubkey, b.HoldCreatedAt, b.HoldExpiresAt) != nil || b.Package.Contract.Hash() != c.Hash() || b.PackageEvent == nil || b.PackageEvent.Verify() != nil || b.PackageEvent.Pubkey != s.cfg.ProviderPubkey || b.PackageEvent.Kind != PackageKind || b.PackageEvent.Content != string(canonical(b.Package)) {
				return refuse("STATE_PACKAGE")
			}
		} else if b.PackageEvent != nil || b.Published {
			return refuse("STATE_PACKAGE")
		}
		if b.Issuance != nil {
			r := b.Issuance
			if !b.Published || b.Package == nil || r.BookingID != c.BookingID || r.ContractSHA256 != c.Hash() || r.PackageEventID != b.PackageEvent.ID || !hexSize(r.PaymentTxID, 32) {
				return refuse("STATE_ISSUANCE")
			}
			p := Payment{TxID: r.PaymentTxID, Vout: r.PaymentVout, Height: r.PaymentHeight, BlockHash: r.PaymentBlockHash}
			if r.PaymentHeight <= 0 || !hexSize(r.PaymentBlockHash, 32) || !hexSize(r.ObservedTipHash, 32) || string(canonical(newIssuance(b, p, r.ObservedTipHash))) != string(canonical(r)) {
				return refuse("STATE_ISSUANCE")
			}
		}
		if b.Revoke != nil && (b.Issuance == nil || b.Revoke.BookingID != c.BookingID || b.Revoke.ContractSHA256 != c.Hash()) {
			return refuse("STATE_REVOKE")
		}
	}
	return nil
}
func (s *Service) export() error {
	for _, b := range s.state.Bookings {
		if b.Package != nil {
			if e := s.store.write("package-"+b.Contract.BookingID+".json", canonical(b.Package), true); e != nil {
				return e
			}
		}
		if b.Issuance != nil {
			if e := s.store.write("issue-"+b.Contract.BookingID+".json", canonical(b.Issuance), true); e != nil {
				return e
			}
		}
		if b.Revoke != nil {
			if e := s.store.write("revoke-"+b.Contract.BookingID+".json", canonical(b.Revoke), true); e != nil {
				return e
			}
		}
	}
	return nil
}

type BookInput struct {
	SlotID              string `json:"slot_id"`
	RenterPubkey        string `json:"renter_pubkey"`
	RenterName          string `json:"renter_name"`
	PrivacyAcknowledged bool   `json:"privacy_acknowledged"`
}

func (s *Service) Book(ctx context.Context, in BookInput) (Booking, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !in.PrivacyAcknowledged {
		return Booking{}, refuse("PRIVACY_REQUIRED")
	}
	if !pubkey(in.RenterPubkey) {
		return Booking{}, refuse("RENTER_KEY")
	}
	now := s.clock().Unix()
	var slot *Slot
	for _, v := range s.cfg.Slots {
		if v.ID == in.SlotID {
			v := v
			slot = &v
			break
		}
	}
	if slot == nil || slot.NotAfter <= now || slot.PaymentPolicy == "advance" && slot.NotBefore <= now {
		return Booking{}, refuse("SLOT_UNAVAILABLE")
	}
	if s.startWindowClosed(*slot, now) {
		return Booking{}, refuse("SLOT_REMAINING_WINDOW")
	}
	for _, b := range s.state.Bookings {
		c := b.Contract
		if c.StationName == slot.StationName && c.NotBefore < slot.NotAfter && slot.NotBefore < c.NotAfter && (b.HoldExpiresAt > now || b.Issuance != nil) {
			return Booking{}, refuse("CAPACITY_FULL")
		}
	}
	quote, e := NewQuote(s.cfg.PriceUSDCents, s.cfg.USDMicrosPerNMC, s.cfg.RateAsOf, s.cfg.MaxRateAge, now)
	if e != nil {
		return Booking{}, e
	}
	if in.RenterName != "" {
		if e = CheckRenterName(ctx, s.node, s.cfg.Limits, in.RenterName, in.RenterPubkey); e != nil {
			return Booking{}, e
		}
	}
	tip, e := ReadTip(ctx, s.node, s.cfg.Limits)
	if e != nil {
		return Booking{}, e
	}
	later := s.clock().Unix()
	if later < now || slot.NotAfter <= later || slot.PaymentPolicy == "advance" && slot.NotBefore <= later {
		return Booking{}, refuse("BOOKING_CLOCK_CHANGED")
	}
	if s.startWindowClosed(*slot, later) {
		return Booking{}, refuse("SLOT_REMAINING_WINDOW")
	}
	now = later
	quote, e = NewQuote(s.cfg.PriceUSDCents, s.cfg.USDMicrosPerNMC, s.cfg.RateAsOf, s.cfg.MaxRateAge, now)
	if e != nil {
		return Booking{}, e
	}
	address, script, e := s.deriver.Address(s.state.NextIndex)
	if e != nil {
		return Booking{}, e
	}
	var random [32]byte
	if _, e = rand.Read(random[:]); e != nil {
		return Booking{}, refuse("BOOKING_RANDOM")
	}
	t := s.cfg.Template
	c := Contract{1, hex.EncodeToString(random[:]), in.RenterPubkey, in.RenterName, s.cfg.AgentPubkey, slot.StationName, slot.NotBefore, slot.NotAfter, append([]string{}, t.Allowed...), append([]string{}, t.Forbidden...), t.BudgetSat, t.ID, s.cfg.TemplateSHA256, t.ProfileID, t.ProfileVersion, t.ProfileSHA256, quote.PriceUSDCents, quote.USDMicrosPerNMC, quote.RateAsOf, quote.PriceNMCSat, slot.PaymentPolicy, address, Hash([]byte(PrivacyNotice))}
	if e = c.Validate(); e != nil {
		return Booking{}, e
	}
	expires := now + s.cfg.HoldSeconds
	if expires > slot.NotAfter {
		expires = slot.NotAfter
	}
	b := Booking{Contract: c, AddressIndex: s.state.NextIndex, Script: script, CheckpointHeight: tip.Height, HoldCreatedAt: now, HoldExpiresAt: expires, PrivacyAckAt: now, Status: "pending", Receipts: []Receipt{}}
	st := copyState(s.state)
	st.NextIndex++
	for i := range st.Bookings {
		old := &st.Bookings[i]
		if old.HoldExpiresAt <= now && old.Issuance == nil {
			old.Status = "expired"
			old.Payment = nil
		}
	}
	st.Bookings = append(st.Bookings, b)
	if e = s.persist(st); e != nil {
		return Booking{}, e
	}
	return copyBooking(b), nil
}
func (s *Service) Get(id string) (Booking, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.store.poisoned {
		return Booking{}, refuse("STATE_UNAVAILABLE")
	}
	for _, b := range s.state.Bookings {
		if b.Contract.BookingID == id {
			return copyBooking(b), nil
		}
	}
	return Booking{}, refuse("BOOKING_NOT_FOUND")
}
func (s *Service) AcceptConsent(ctx context.Context, id string, event Event) (Booking, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := copyState(s.state)
	for i := range st.Bookings {
		b := &st.Bookings[i]
		if b.Contract.BookingID != id {
			continue
		}
		if b.Package != nil {
			if b.Package.Consent.ID != event.ID || event.Verify() != nil {
				return Booking{}, refuse("CONSENT_ALREADY_SET")
			}
			return copyBooking(*b), nil
		}
		p, evt, e := NewPackage(b.Contract, event, b.HoldCreatedAt, b.HoldExpiresAt, s.clock().Unix(), s.key)
		if e != nil {
			return Booking{}, e
		}
		b.Package = &p
		b.PackageEvent = &evt
		if e = s.persist(st); e != nil {
			return Booking{}, e
		}
		if e = s.export(); e != nil {
			return Booking{}, e
		}
		if e = s.publishLocked(ctx); e != nil {
			return copyBooking(*b), e
		}
		return copyBooking(s.state.Bookings[i]), nil
	}
	return Booking{}, refuse("BOOKING_NOT_FOUND")
}
func (s *Service) publishLocked(ctx context.Context) error {
	for i := range s.state.Bookings {
		b := s.state.Bookings[i]
		if b.PackageEvent == nil || b.Published {
			continue
		}
		if e := s.relay.Publish(ctx, *b.PackageEvent); e != nil {
			return refuse("RELAY_UNAVAILABLE")
		}
		st := copyState(s.state)
		st.Bookings[i].Published = true
		if e := s.persist(st); e != nil {
			return e
		}
	}
	return nil
}
func (s *Service) PublishPending(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.publishLocked(ctx)
}
func newIssuance(b Booking, p Payment, tip string) IssuanceRequest {
	c := b.Contract
	return IssuanceRequest{1, c.BookingID, c.StationName, c.AgentPubkey, c.RenterPubkey, c.Hash(), append([]string{}, c.Allowed...), c.BudgetSat, c.NotBefore, c.NotAfter, c.PaymentPolicy, p.TxID, p.Vout, p.Height, p.BlockHash, tip, b.PackageEvent.ID}
}

func (s *Service) Refresh(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock().Unix()
	targets := map[string]WatchTarget{}
	for _, b := range s.state.Bookings {
		if b.Contract.NotAfter > now {
			targets[b.Contract.BookingID] = WatchTarget{b.Script, b.CheckpointHeight}
		}
	}
	snap, e := Discover(ctx, s.node, s.cfg.Limits, targets)
	if e != nil {
		return e
	}
	observedAt := s.clock().Unix()
	if observedAt < now {
		return refuse("CLOCK_REVERSED")
	}
	now = observedAt
	st := copyState(s.state)
	for i := range st.Bookings {
		b := &st.Bookings[i]
		if b.Contract.NotAfter <= now {
			continue
		}
		current := snap.Payments[b.Contract.BookingID]
		currentPoints := map[string]Payment{}
		for _, p := range current {
			currentPoints[p.point()] = p
			found := false
			for j := range b.Receipts {
				r := &b.Receipts[j]
				if r.Payment.point() == p.point() {
					found = true
					r.Payment = p
					if p.Height > 0 && r.ConfirmedAt == 0 {
						r.ConfirmedAt = now
					}
					break
				}
			}
			if !found {
				confirmed := int64(0)
				if p.Height > 0 {
					confirmed = now
				}
				b.Receipts = append(b.Receipts, Receipt{Payment: p, FirstSeen: now, ConfirmedAt: confirmed, Disposition: "pending"})
			}
		}
		previous := b.Payment
		b.Payment = nil
		if b.Issuance == nil && now >= b.HoldExpiresAt {
			b.Status = "expired"
		}
		if b.Issuance != nil {
			point := Payment{TxID: b.Issuance.PaymentTxID, Vout: b.Issuance.PaymentVout}.point()
			p, present := currentPoints[point]
			reorged := present && previous != nil && previous.Height > 0 && (p.Height == 0 || p.BlockHash != previous.BlockHash)
			if !present || reorged {
				reason := "payment_disappeared"
				if reorged || !present && previous != nil && previous.Height > 0 {
					reason = "payment_reorged"
				}
				if b.Revoke == nil {
					b.Revoke = &RevokeRequest{1, b.Contract.BookingID, b.Contract.Hash(), b.Issuance.PaymentTxID, b.Issuance.PaymentVout, reason, snap.Tip.Hash}
				}
			}
			if present && b.Revoke == nil {
				b.Payment = &p
			}
		} else if b.Status != "expired" {
			for _, p := range current {
				for _, r := range b.Receipts {
					if r.Payment.point() != p.point() {
						continue
					}
					eligible := p.ValueSat >= b.Contract.PriceNMCSat && p.Height > 0 && r.ConfirmedAt > 0 && r.ConfirmedAt < b.HoldExpiresAt
					if eligible {
						p := p
						b.Payment = &p
						break
					}
				}
				if b.Payment != nil {
					break
				}
			}
		}
		for j := range b.Receipts {
			r := &b.Receipts[j]
			r.Disposition = "refund_review"
			if b.Payment != nil && r.Payment.point() == b.Payment.point() {
				r.Disposition = "selected"
			} else if r.Payment.ValueSat >= b.Contract.PriceNMCSat && r.FirstSeen < b.HoldExpiresAt && b.Issuance == nil && now < b.HoldExpiresAt {
				r.Disposition = "pending"
			}
		}
		annotateReceipts(b)
		b.Status = "pending"
		if b.Payment != nil {
			b.Status = "paid"
		} else if now >= b.HoldExpiresAt {
			b.Status = "expired"
		}
		if b.Revoke != nil {
			b.Status = "revoked"
		}
		if b.Payment != nil && b.Package != nil && b.Published && b.Issuance == nil && b.Revoke == nil && now < b.HoldExpiresAt {
			r := newIssuance(*b, *b.Payment, snap.Tip.Hash)
			b.Issuance = &r
		}
	}
	if e = s.persist(st); e != nil {
		return e
	}
	return s.export()
}

func (s *Service) startWindowClosed(slot Slot, now int64) bool {
	return slot.PaymentPolicy == "start_now" && slot.NotAfter-now < s.cfg.MinStartNowRemainingSeconds
}

// Surplus is the excess of an individual receipt over the signed price.
// A selected overpayment remains selected; its excess still needs review.
func annotateReceipts(b *Booking) bool {
	changed := false
	for i := range b.Receipts {
		r := &b.Receipts[i]
		surplus := int64(0)
		if r.Payment.ValueSat > b.Contract.PriceNMCSat {
			surplus = r.Payment.ValueSat - b.Contract.PriceNMCSat
		}
		review := surplus > 0 || r.Disposition == "refund_review"
		changed = changed || r.SurplusSat != surplus || r.RefundReview != review
		r.SurplusSat, r.RefundReview = surplus, review
	}
	return changed
}
