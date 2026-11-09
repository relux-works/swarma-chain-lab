package booking

import (
	pc "github.com/relux-works/swarma-chain-lab/experiments/payment-chain"
	"math"
)

// Validate persisted invariants before exporting any package or request. Version
// one roots and unknown coin routes never undergo implicit migration.
func (s *ServiceV2) validateStateV2() error {
	st := s.state
	if st.ClockHighWater <= 0 || st.ClockHighWater > math.MaxInt64-1800 || len(st.Bookings) > 4096 || len(st.NextIndices) != len(s.cfg.Coins) {
		return refuse("STATE_CORRUPT")
	}
	for coin, index := range st.NextIndices {
		if _, ok := s.cfg.Coins[coin]; !ok || index > 1<<31 {
			return refuse("STATE_CORRUPT")
		}
	}
	ids := map[string]bool{}
	indices := map[string]map[uint32]bool{}
	for _, b := range st.Bookings {
		c := b.Contract
		coin := c.Payment.Coin
		policy, ok := s.cfg.Coins[coin]
		if !ok || c.Validate() != nil || c.Payment.ValidateAt(b.HoldCreatedAt, policy.MaxRateAgeSeconds, policy.MinConfirmations) != nil {
			return refuse("STATE_CORRUPT")
		}
		address, script, e := s.derivers[coin].Address(b.AddressIndex)
		if indices[coin] == nil {
			indices[coin] = map[uint32]bool{}
		}
		if e != nil || ids[c.BookingID] || indices[coin][b.AddressIndex] || b.AddressIndex >= st.NextIndices[coin] || c.Payment.Address != address || b.Script != script || b.CheckpointHeight < 0 || b.CheckpointHeight > 2147483647 || b.HoldCreatedAt <= 0 || b.HoldCreatedAt > st.ClockHighWater || b.HoldExpiresAt <= b.HoldCreatedAt || b.HoldExpiresAt-b.HoldCreatedAt > 1800 || b.HoldExpiresAt > c.NotAfter || b.PrivacyAckAt != b.HoldCreatedAt || b.Receipts == nil || len(b.Receipts) > 4096 {
			return refuse("STATE_CORRUPT")
		}
		ids[c.BookingID] = true
		indices[coin][b.AddressIndex] = true
		t := s.cfg.Template
		if c.AgentPubkey != s.cfg.AgentPubkey || c.TemplateSHA256 != s.cfg.TemplateSHA256 || c.TemplateID != t.ID || c.ProfileID != t.ProfileID || c.ProfileVersion != t.ProfileVersion || c.ProfileSHA256 != t.ProfileSHA256 || c.BudgetSat != t.BudgetSat || string(canonical(c.Allowed)) != string(canonical(t.Allowed)) || string(canonical(c.Forbidden)) != string(canonical(t.Forbidden)) {
			return refuse("STATE_TEMPLATE")
		}
		if b.Status != "pending" && b.Status != "paid" && b.Status != "expired" && b.Status != "revoked" {
			return refuse("STATE_CORRUPT")
		}
		profile, _ := pc.ForCoin(coin)
		points := map[string]ReceiptV2{}
		selected := 0
		for _, r := range b.Receipts {
			p := r.Payment
			point := paymentPoint(p)
			if _, ok := points[point]; ok {
				return refuse("STATE_RECEIPT")
			}
			if !hexSize(p.TxID, 32) || p.ValueAtoms < 0 || p.ValueAtoms > profile.MaxAtoms || p.Height < 0 || p.Height > 2147483647 || p.Height > 0 && !hexSize(p.BlockHash, 32) || p.Height == 0 && p.BlockHash != "" || r.FirstSeen < b.HoldCreatedAt || r.FirstSeen > st.ClockHighWater || r.EligibleAt < 0 || r.EligibleAt > st.ClockHighWater || r.EligibleAt > 0 && (r.EligibleAt < r.FirstSeen || p.Height == 0 || p.ValueAtoms < c.Payment.AmountAtoms) {
				return refuse("STATE_RECEIPT")
			}
			if r.Disposition != "pending" && r.Disposition != "selected" && r.Disposition != "refund_review" || r.SurplusAtoms != max(int64(0), p.ValueAtoms-c.Payment.AmountAtoms) || r.RefundReview != (r.SurplusAtoms > 0 || r.Disposition == "refund_review") {
				return refuse("STATE_RECEIPT")
			}
			if r.Disposition == "selected" {
				selected++
				if b.Payment == nil || *b.Payment != p {
					return refuse("STATE_PAYMENT")
				}
			}
			points[point] = r
		}
		if b.Payment != nil {
			r, ok := points[paymentPoint(*b.Payment)]
			if !ok || r.Payment != *b.Payment || selected != 1 || r.EligibleAt <= 0 || b.Payment.Height <= 0 || b.Payment.ValueAtoms < c.Payment.AmountAtoms || b.Status != "paid" || b.Revoke != nil || b.Issuance == nil && r.EligibleAt >= b.HoldExpiresAt {
				return refuse("STATE_PAYMENT")
			}
		} else if selected != 0 || b.Status == "paid" {
			return refuse("STATE_PAYMENT")
		}
		if b.Package != nil {
			p, e := b.Package, b.PackageEvent
			if p.Validate(s.cfg.ProviderPubkey, b.HoldCreatedAt, b.HoldExpiresAt) != nil || p.Contract.Hash() != c.Hash() || e == nil || e.Verify() != nil || e.Pubkey != s.cfg.ProviderPubkey || e.Kind != PackageKind || e.Content != string(canonical(p)) || e.CreatedAt < p.Consent.CreatedAt || e.CreatedAt >= b.HoldExpiresAt || e.CreatedAt > st.ClockHighWater {
				return refuse("STATE_PACKAGE")
			}
			tags := [][]string{{"t", "swarma-rental-package-v1"}, {"contract", c.Hash()}, {"booking", c.BookingID}, {"e", p.Consent.ID}}
			if string(canonical(e.Tags)) != string(canonical(tags)) {
				return refuse("STATE_PACKAGE")
			}
		} else if b.PackageEvent != nil || b.Published {
			return refuse("STATE_PACKAGE")
		}
		if b.Issuance != nil {
			r := b.Issuance
			if !b.Published || b.Package == nil || r.Validate(c, b.PackageEvent.ID) != nil {
				return refuse("STATE_ISSUANCE")
			}
			point := paymentPoint(pc.Payment{TxID: r.PaymentTxID, Vout: r.PaymentVout})
			receipt, ok := points[point]
			if !ok || receipt.FirstSeen >= b.HoldExpiresAt || receipt.Payment.ValueAtoms < c.Payment.AmountAtoms {
				return refuse("STATE_ISSUANCE")
			}
			if b.Revoke == nil && (b.Payment == nil || paymentPoint(*b.Payment) != point || b.Payment.Height != r.PaymentHeight || b.Payment.BlockHash != r.PaymentBlockHash) {
				return refuse("STATE_ISSUANCE")
			}
		}
		if b.Revoke != nil {
			r := b.Revoke
			i := b.Issuance
			if i == nil || r.Version != 2 || r.BookingID != c.BookingID || r.ContractSHA256 != c.Hash() || r.PaymentCoin != i.PaymentCoin || r.PaymentNetwork != i.PaymentNetwork || r.PaymentGenesis != i.PaymentGenesis || r.PaymentTxID != i.PaymentTxID || r.PaymentVout != i.PaymentVout || r.Reason != "payment_reorged" || !hexSize(r.ObservedTipHash, 32) || b.Status != "revoked" || b.Payment != nil {
				return refuse("STATE_REVOKE")
			}
		} else if b.Status == "revoked" {
			return refuse("STATE_REVOKE")
		}
	}
	for coin, next := range st.NextIndices {
		if uint32(len(indices[coin])) != next {
			return refuse("STATE_CORRUPT")
		}
	}
	for i, a := range st.Bookings {
		if a.HoldExpiresAt <= st.ClockHighWater && a.Issuance == nil {
			continue
		}
		for _, b := range st.Bookings[i+1:] {
			if b.HoldExpiresAt <= st.ClockHighWater && b.Issuance == nil {
				continue
			}
			if a.Contract.StationName == b.Contract.StationName && a.Contract.NotBefore < b.Contract.NotAfter && b.Contract.NotBefore < a.Contract.NotAfter {
				return refuse("STATE_CAPACITY")
			}
		}
	}
	return nil
}
