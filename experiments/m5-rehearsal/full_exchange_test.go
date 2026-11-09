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

// A conversation survives booking so the same real relay subscription receives
// issued/ready and payload replies. No HTTP booking or presentation is fabricated.
type conversation struct {
	l      *lab
	peer   *gateway.RelayClient
	key    *nostr.PrivKey
	agent  string
	ctx    context.Context
	cancel context.CancelFunc
	inbox  chan *nostr.Event
	done   chan error
}

func (l *lab) conversation(url string, key *nostr.PrivKey, agent string) *conversation {
	ctx, cancel := context.WithCancel(context.Background())
	c := &conversation{l: l, peer: &gateway.RelayClient{URL: url}, key: key, agent: agent, ctx: ctx, cancel: cancel, inbox: make(chan *nostr.Event, 64), done: make(chan error, 1)}
	go func() {
		c.done <- c.peer.SubscribeGiftWraps(ctx, key.PubKeyHex(), func(_ context.Context, ev *nostr.Event) {
			select {
			case c.inbox <- ev:
			default:
				l.t.Error("rehearsal inbox overflow")
			}
		})
	}()
	return c
}
func (c *conversation) close() {
	c.cancel()
	c.peer.Close()
	select {
	case <-c.done:
	case <-time.After(time.Second):
		c.l.t.Error("rehearsal subscription did not stop")
	}
}
func (c *conversation) send(text string, work bool, tags ...[]string) {
	t := c.l.t
	t.Helper()
	r := &nostr.Event{PubKey: c.key.PubKeyHex(), CreatedAt: time.Now().Unix(), Kind: nostr.KindRumor, Content: text, Tags: append([][]string{{"p", c.agent}}, tags...)}
	if work {
		r.Tags = append(r.Tags, []string{"nonce", "0", "4"})
		for n := 0; ; n++ {
			r.Tags[len(r.Tags)-1][1] = strconv.Itoa(n)
			r.ID = r.ComputeID()
			if exchange.CheckWork(r, 4) {
				break
			}
		}
	} else {
		r.ID = r.ComputeID()
	}
	ev, e := nostr.GiftWrap(r, c.key, c.agent, time.Now().Unix())
	checked(t, e, "rehearsal gift wrap")
	ctx, cancel := context.WithTimeout(c.ctx, 3*time.Second)
	defer cancel()
	checked(t, c.peer.Publish(ctx, ev), "rehearsal relay publish")
}
func (c *conversation) receive(prefix string, timeout time.Duration) string {
	t := c.l.t
	t.Helper()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case ev := <-c.inbox:
		u, e := nostr.UnwrapDM(ev, c.key)
		checked(t, e, "rehearsal unwrap")
		if u.SenderHex != c.agent || !strings.HasPrefix(u.Rumor.Content, prefix) {
			t.Fatal("unexpected authenticated response while awaiting " + prefix)
		}
		return u.Rumor.Content
	case <-timer.C:
		t.Fatal("missing rehearsal response: " + prefix)
	}
	return ""
}
func (l *lab) noSlot() {
	l.t.Helper()
	s, e := journal.Open(filepath.Join(l.private, "journal"))
	checked(l.t, e, "rehearsal journal")
	if len(s.All()) != 0 {
		l.t.Fatal("non-grantee allocated a slot")
	}
}
func (l *lab) slot(id string) *journal.Slot {
	l.t.Helper()
	s, e := journal.Open(filepath.Join(l.private, "journal"))
	checked(l.t, e, "rehearsal journal")
	v, ok := s.Get(id)
	if !ok {
		l.t.Fatal("grant slot missing")
	}
	return v
}

// Missing and unoffered coins and foreign consent must preserve the available
// slot/package. The neighboring explicit NMC selection returns a frozen V2
// contract and exactly bound payment instructions; no money is sent here.
func (c *conversation) bookV2(origin, slot string) booking.ContractV2 {
	l, t := c.l, c.l.t
	t.Helper()
	c.send("terms", true)
	var terms exchange.Terms
	checked(t, json.Unmarshal([]byte(strings.TrimPrefix(c.receive("terms\n", 10*time.Second), "terms\n")), &terms), "V2 terms")
	offered := false
	for _, s := range terms.Slots {
		if s.ID == slot {
			offered = len(s.Coins) == 1 && s.Coins[0] == exchange.NMC
		}
	}
	if !offered {
		t.Fatal("V2 provisioned NMC offer missing")
	}
	l.noSlot()
	c.send("book demo "+slot, false)
	if c.receive(exchange.Help, 10*time.Second) != exchange.Help {
		t.Fatal("missing coin response")
	}
	c.send("book demo "+slot+" btc", false)
	if c.receive(exchange.CoinNotOffered, 10*time.Second) != exchange.CoinNotOffered {
		t.Fatal("unoffered coin response")
	}
	var cat booking.CatalogueV2
	if l.http("GET", origin+"/catalogue?until="+strconv.FormatInt(time.Now().Unix()+86400, 10)+"&limit=16", nil, &cat) != 200 {
		t.Fatal("catalogue after refused coins")
	}
	available := false
	for _, s := range cat.Slots {
		if s.ID == slot {
			available = true
		}
	}
	if !available {
		t.Fatal("refused coin reserved slot")
	}
	l.noSlot()
	c.send("book demo "+slot+" nmc", false)
	var reply struct {
		ID       string `json:"booking_id"`
		Hash     string `json:"contract_sha256"`
		Contract string `json:"contract_base64"`
	}
	checked(t, json.Unmarshal([]byte(strings.TrimPrefix(c.receive("contract\n", 10*time.Second), "contract\n")), &reply), "V2 contract response")
	raw, e := base64.StdEncoding.DecodeString(reply.Contract)
	checked(t, e, "V2 contract encoding")
	var contract booking.ContractV2
	checked(t, booking.Strict(raw, &contract), "V2 contract schema")
	if contract.Version != 2 || contract.Hash() != reply.Hash || contract.BookingID != reply.ID || contract.RenterPubkey != c.key.PubKeyHex() || string(contract.Payment.Coin) != "nmc" {
		t.Fatal("V2 contract binding")
	}
	wrong, e := nostr.GeneratePrivKey()
	checked(t, e, "foreign consent key")
	l.secret(wrong.Bytes())
	wk, _ := btcec.PrivKeyFromBytes(wrong.Bytes())
	bad := booking.ConsentV2(contract, time.Now().Unix())
	checked(t, bad.Sign(wk), "foreign V2 consent")
	c.send("consent "+string(encoded(bad)), false)
	if c.receive(exchange.Help, 10*time.Second) != exchange.Help {
		t.Fatal("foreign V2 consent response")
	}
	var before booking.BookingV2
	if l.http("GET", origin+"/booking?id="+contract.BookingID, nil, &before) != 200 || before.Package != nil || before.Issuance != nil {
		t.Fatal("foreign consent mutated booking")
	}
	l.noSlot()
	key, _ := btcec.PrivKeyFromBytes(c.key.Bytes())
	consent := booking.ConsentV2(contract, time.Now().Unix())
	checked(t, consent.Sign(key), "valid V2 consent")
	c.send("consent "+string(encoded(consent)), false)
	var pay struct {
		Address string `json:"address"`
		Amount  int64  `json:"amount_atomic"`
		Coin    string `json:"coin"`
		Min     int64  `json:"min_confirmations"`
	}
	checked(t, json.Unmarshal([]byte(strings.TrimPrefix(c.receive("pay\n", 10*time.Second), "pay\n")), &pay), "V2 pay response")
	if pay.Address != contract.Payment.Address || pay.Amount != contract.Payment.AmountAtoms || pay.Coin != "nmc" || pay.Min != 2 {
		t.Fatal("V2 payment binding")
	}
	l.noSlot()
	l.evidence["v2_exchange_controls"] = map[string]any{"missing_coin_refused": true, "unoffered_coin_preserved_slot": true, "foreign_consent_preserved_package": true, "valid_explicit_nmc_contract": true, "pregrant_slots": 0}
	return contract
}
