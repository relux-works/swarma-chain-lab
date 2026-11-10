package gateway

import (
	"context"
	"encoding/json"
	"unicode/utf8"

	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/journal"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
)

// replyDelivery runs under deliveryMu after the current grant/window check.
// Relay acceptance is not renter display. Only the original signed bytes retry.
func (g *Gateway) replyDelivery(ctx context.Context, slot *journal.Slot, id, content string) error {
	if !utf8.ValidString(content) || len(content) > 32768 {
		return journal.ErrDelivery
	}
	original := content
	content = nostr.BoundDeliveryReply(content, g.cfg.RelayMaxEventBytes)
	d, ok := g.cfg.Journal.Delivery(slot.ID, id)
	if !ok {
		return journal.ErrDelivery
	}
	switch d.Phase {
	case journal.DeliveryReceived:
		wrap, _, e := nostr.WrapDM(g.cfg.AgentKey, slot.RenterPubKey, content, [][]string{{"e", id}}, g.cfg.Now().Unix())
		if e != nil {
			return e
		}
		wire, e := json.Marshal(wrap)
		if e != nil {
			return e
		}
		if e = g.cfg.Journal.ChangeDelivery(slot.ID, id, journal.DeliveryReady, content, wire); e != nil {
			return e
		}
		d.Wire = wire
	case journal.DeliveryReady, journal.DeliveryAccepted:
		// Preserve an exact legacy reply whose actual immutable wire fits the cap,
		// even if the new reserved-metadata preflight is more conservative.
		if d.Reply != content && d.Reply != original {
			return journal.ErrDelivery
		}
		if d.Phase == journal.DeliveryAccepted {
			return nil
		}
	default:
		return journal.ErrDelivery
	}
	// The persisted wire event is the sole source of every publication attempt.
	event, e := nostr.ParseEvent(d.Wire)
	if e != nil {
		return journal.ErrDelivery
	}
	if e = g.cfg.Publisher.Publish(ctx, event); e != nil {
		return e
	}
	return g.cfg.Journal.ChangeDelivery(slot.ID, id, journal.DeliveryAccepted, "", nil)
}
