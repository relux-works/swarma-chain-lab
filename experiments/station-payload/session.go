package payload

import (
	"context"
	"crypto/x509"

	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/stationlink"
	lifecycle "github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle"
)

// Run preserves the existing scripted echo/end/extend behavior for v1 and sends
// ordinary v2 deliveries through the model proxy. The station always initiates
// verified TLS, then authenticates with the per-slot HMAC channel credential.
func (c *Client) Run(ctx context.Context, address, pin string, roots *x509.CertPool) error {
	journal, err := openTurns(c.journalDir, c.journalBinding)
	if err != nil {
		return err
	}
	defer journal.close()
	conn, err := lifecycle.DialPayload(ctx, address, pin, roots)
	if err != nil {
		return ErrChannel
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	cl := stationlink.NewClient(conn)
	b := c.bootstrap
	f, err := cl.Hello(b.BookingID, b.StationName, b.ChannelSecret.Reveal())
	if err != nil || f.Type != stationlink.TypeSystem || f.SlotID != b.BookingID || !nostr.ValidDeliveryEventLimit(f.RelayMaxEventBytes) {
		return ErrChannel
	}
	relayMaxEventBytes := f.RelayMaxEventBytes
	for {
		f, err = cl.Pull()
		if err != nil {
			return ErrChannel
		}
		switch f.Type {
		case stationlink.TypeEnd:
			return nil
		case stationlink.TypeNone, stationlink.TypeNotice:
			continue
		case stationlink.TypeDeliver:
			if f.SlotID != b.BookingID {
				return ErrChannel
			}
			t, e := journal.receive(f.DeliveryID, f.Content)
			if e != nil {
				return e
			}
			// No ACK exists until the exact input has reached durable private state.
			received, e := cl.Received(t.ID)
			if e != nil || received.Type != stationlink.TypeAck || received.DeliveryID != t.ID || received.SlotID != b.BookingID {
				return ErrChannel
			}
			var reply string
			if t.Phase == "received" {
				t.Phase = "in-flight"
				if e := journal.save(t); e != nil {
					return e
				}
				switch f.Content {
				case "__end_early__":
					end, e := cl.EndEarly()
					if e != nil || end.Type != stationlink.TypeEnd {
						return ErrChannel
					}
					return nil
				case "__extend__":
					ext, e := cl.Extend()
					if e != nil || ext.Type != stationlink.TypeError {
						return ErrChannel
					}
					reply = "extend answered: " + ext.Type
				default:
					reply, err = c.Respond(ctx, f.Content)
					if err != nil {
						reply = err.Error()
					}
				}
				reply = nostr.BoundDeliveryReply(reply, relayMaxEventBytes)
				t.Phase, t.Reply = "ready", reply
				if e := journal.save(t); e != nil {
					return e
				}
			}
			ack, e := cl.Reply(t.ID, t.Reply)
			if e != nil || ack.Type != stationlink.TypeAck || ack.DeliveryID != t.ID || ack.SlotID != b.BookingID {
				return ErrChannel
			}
			t.Phase = "accepted"
			if e := journal.save(t); e != nil {
				return e
			}
		default:
			return ErrChannel
		}
	}
}
