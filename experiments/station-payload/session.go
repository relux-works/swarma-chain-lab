package payload

import (
	"context"
	"crypto/x509"

	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/stationlink"
	lifecycle "github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle"
)

// Run preserves the existing scripted echo/end/extend behavior for v1 and sends
// ordinary v2 deliveries through the model proxy. The station always initiates
// verified TLS, then authenticates with the per-slot HMAC channel credential.
func (c *Client) Run(ctx context.Context, address, pin string, roots *x509.CertPool) error {
	conn, err := lifecycle.DialPayload(ctx, address, pin, roots)
	if err != nil {
		return ErrChannel
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	cl := stationlink.NewClient(conn)
	b := c.bootstrap
	f, err := cl.Hello(b.BookingID, b.StationName, b.ChannelSecret)
	if err != nil || f.Type != stationlink.TypeSystem || f.SlotID != b.BookingID {
		return ErrChannel
	}
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
			var reply string
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
			ack, e := cl.Reply(reply)
			if e != nil || ack.Type != stationlink.TypeAck {
				return ErrChannel
			}
		default:
			return ErrChannel
		}
	}
}
