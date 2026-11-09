package rehearsal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	booking "github.com/relux-works/swarma-chain-lab/experiments/rental-booking"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/exchange"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/gateway"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/journal"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
)

// The caller uses the actual deployable relay CLI. Exchange and booking remain
// actual product processes.
func (l *lab) converse(url, bookingURL string, agent, renter *nostr.PrivKey, v2Boundary bool) booking.Contract {
	t := l.t
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	peer := &gateway.RelayClient{URL: url}
	defer peer.Close()
	inbox := make(chan *nostr.Event, 64)
	done := make(chan error, 1)
	go func() {
		done <- peer.SubscribeGiftWraps(ctx, renter.PubKeyHex(), func(_ context.Context, ev *nostr.Event) {
			select {
			case inbox <- ev:
			default:
				t.Error("fixture inbox overflow")
			}
		})
	}()
	defer func() {
		cancel()
		peer.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("fixture subscriber leaked")
		}
	}()
	send := func(text string, work bool) {
		t.Helper()
		r := &nostr.Event{PubKey: renter.PubKeyHex(), CreatedAt: time.Now().Unix(), Kind: nostr.KindRumor, Content: text, Tags: [][]string{{"p", agent.PubKeyHex()}}}
		if work {
			r.Tags = append(r.Tags, []string{"nonce", "0", "4"})
			for n := 0; ; n++ {
				r.Tags[1][1] = strconv.Itoa(n)
				r.ID = r.ComputeID()
				if exchange.CheckWork(r, 4) {
					break
				}
			}
		} else {
			r.ID = r.ComputeID()
		}
		wrap, e := nostr.GiftWrap(r, renter, agent.PubKeyHex(), time.Now().Unix())
		checked(t, e, "fixture gift wrap")
		call, c := context.WithTimeout(ctx, 3*time.Second)
		defer c()
		checked(t, peer.Publish(call, wrap), "exchange publish")
	}
	receive := func(prefix string) string {
		t.Helper()
		timer := time.NewTimer(10 * time.Second)
		defer timer.Stop()
		for {
			select {
			case ev := <-inbox:
				u, e := nostr.UnwrapDM(ev, renter)
				checked(t, e, "exchange unwrap")
				if u.SenderHex != agent.PubKeyHex() {
					t.Fatal("foreign response")
				}
				if !strings.HasPrefix(u.Rumor.Content, prefix) {
					t.Fatal("unexpected fixed exchange response")
				}
				return u.Rumor.Content
			case <-timer.C:
				t.Fatal("missing exchange response: " + prefix)
			}
		}
	}
	noSlot := func() {
		s, e := journal.Open(filepath.Join(l.private, "journal"))
		checked(t, e, "journal snapshot")
		if len(s.All()) != 0 {
			t.Fatal("non-grantee allocated a slot")
		}
	}
	send("terms", true)
	var terms exchange.Terms
	checked(t, json.Unmarshal([]byte(strings.TrimPrefix(receive("terms\n"), "terms\n")), &terms), "terms JSON")
	if len(terms.Slots) != 1 {
		t.Fatal("terms slots")
	}
	noSlot()
	send("book demo one", false)
	if v2Boundary {
		if receive(exchange.BookPending) != exchange.BookPending {
			t.Fatal("G6 booking did not stop at exact pending response")
		}
		noSlot()
		l.evidence["v2_exchange_boundary"] = map[string]any{"real_relay_terms": true, "real_relay_book_response": "BookPending", "pregrant_slots": 0}
		return booking.Contract{}
	}
	var reply struct {
		ID       string `json:"booking_id"`
		Hash     string `json:"contract_sha256"`
		Contract string `json:"contract_base64"`
	}
	checked(t, json.Unmarshal([]byte(strings.TrimPrefix(receive("contract\n"), "contract\n")), &reply), "exchange contract")
	raw, e := base64.StdEncoding.DecodeString(reply.Contract)
	checked(t, e, "contract encoding")
	var c booking.Contract
	checked(t, booking.Strict(raw, &c), "contract schema")
	if c.Hash() != reply.Hash || c.BookingID != reply.ID || c.RenterPubkey != renter.PubKeyHex() {
		t.Fatal("contract identity")
	}
	wrong, e := nostr.GeneratePrivKey()
	checked(t, e, "foreign key")
	l.secret(wrong.Bytes())
	wk, _ := btcec.PrivKeyFromBytes(wrong.Bytes())
	bad := booking.Consent(c, time.Now().Unix())
	checked(t, bad.Sign(wk), "foreign consent sign")
	send("consent "+string(encoded(bad)), false)
	if receive(exchange.Help) != exchange.Help {
		t.Fatal("foreign consent response")
	}
	var before booking.Booking
	if l.http("GET", bookingURL+"/booking?id="+c.BookingID, nil, &before) != 200 || before.Package != nil {
		t.Fatal("foreign consent mutated package")
	}
	noSlot()
	rk, _ := btcec.PrivKeyFromBytes(renter.Bytes())
	consent := booking.Consent(c, time.Now().Unix())
	checked(t, consent.Sign(rk), "valid consent sign")
	send("consent "+string(encoded(consent)), false)
	var pay struct {
		Address string `json:"address"`
		Amount  int64  `json:"amount_atomic"`
		Coin    string `json:"coin"`
	}
	checked(t, json.Unmarshal([]byte(strings.TrimPrefix(receive("pay\n"), "pay\n")), &pay), "pay response")
	if pay.Address != c.PaymentAddress || pay.Amount != c.PriceNMCSat || pay.Coin != "nmc" {
		t.Fatal("payment binding")
	}
	noSlot()
	l.evidence["real_relay_exchange"] = map[string]any{"terms": true, "book": true, "foreign_consent_refused_without_package": true, "valid_consent": true, "pay_instructions": true, "pregrant_slots": 0}
	return c
}
