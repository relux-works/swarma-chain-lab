package gateway

import (
	"context"
	"encoding/base64"
	"errors"

	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/exchange"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernel"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
)

// Non-grantees may enqueue only deterministic exchange work. This function
// cannot screen, start a station, or wait for booking/publication/queue space.
func (g *Gateway) nonGrantee(r *nostr.Event, res Result) Result {
	if g.cfg.Exchange == nil {
		return res
	}
	res.Refused = true
	res.ExchangeQueued = g.cfg.Exchange.Submit(r)
	res.Reason = "exchange_dropped"
	if res.ExchangeQueued {
		res.Reason = "exchange_queued"
	}
	return res
}
func (g *Gateway) registerIssued(ctx context.Context, i exchange.Issued) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	id, err := kernel.PresentationID(i.Presentation)
	if err != nil || id != i.GrantID || i.AgentName != g.cfg.AgentName {
		return errors.New("issued binding")
	}
	if old, ok := g.cfg.Journal.Get(i.BookingID); ok {
		if old.RenterPubKey != i.Sender || old.ContractSHA256 != i.ContractSHA256 || old.NotBefore != i.NotBefore || old.NotAfter != i.NotAfter || old.CertificateB64 != base64.StdEncoding.EncodeToString(i.Presentation) || old.StationName != i.StationName {
			return errors.New("issued slot conflict")
		}
		return nil // preserve Started/Ended/Destroyed and all durable replay facts
	}
	return g.RegisterSlot(SlotSpec{ID: i.BookingID, StationName: i.StationName, RenterPubKey: i.Sender, Certificate: i.Presentation, ContractSHA256: i.ContractSHA256, BookingID: i.BookingID, NotBefore: i.NotBefore, NotAfter: i.NotAfter})
}
func (g *Gateway) checkExchangeGrant(ctx context.Context, h exchange.Hold, now int64) (bool, error) {
	slot, ok := g.cfg.Journal.Get(h.BookingID)
	if !ok || slot.Ended || slot.Destroyed || slot.RenterPubKey != h.Sender || slot.ContractSHA256 != h.ContractSHA256 || now < slot.NotBefore || now >= slot.NotAfter {
		return false, nil
	}
	raw, err := base64.StdEncoding.DecodeString(slot.CertificateB64)
	if err != nil {
		return false, err
	}
	// Use the exact issued presentation, not another sender-cache entry.
	receipt, err := g.cfg.Kernel.Check(ctx, raw, g.agentNameFor(slot), h.Sender, now)
	return err == nil && receipt.Admits(), err
}
