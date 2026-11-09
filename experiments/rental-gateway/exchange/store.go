package exchange

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"relux.works/swarma-chain-lab/experiments/rental-gateway/nostr"
	"relux.works/swarma-chain-lab/experiments/single-use/durable"
)

type seen struct {
	ID    string `json:"id"`
	Until int64  `json:"until"`
}
type client struct {
	Version     int          `json:"version"`
	Sender      string       `json:"sender"`
	Tokens      int          `json:"tokens"`
	Refilled    int64        `json:"refilled"`
	KnownUntil  int64        `json:"known_until"`
	Seen        []seen       `json:"seen"`
	TermsPin    string       `json:"terms_pin"`
	Phase       string       `json:"phase"`
	Hold        *Hold        `json:"hold,omitempty"`
	ConsentID   string       `json:"consent_id,omitempty"`
	Pending     *nostr.Event `json:"pending,omitempty"`
	PendingKind string       `json:"pending_kind,omitempty"`
	// A started external booking with no recorded result is never repeated.
	// The service retains any ambiguous hold; operator reconciliation is required.
}
type disk struct {
	store    *durable.Store
	cfg      Config
	binding  string
	clients  map[string]*client
	high     int64
	poisoned bool
}
type meta struct {
	Version int    `json:"version"`
	Binding string `json:"binding"`
	High    int64  `json:"high"`
}

func openDisk(c Config) (*disk, error) {
	s, e := durable.Open(c.StateDir, "exchange.lock")
	if e != nil {
		return nil, e
	}
	d := &disk{store: s, cfg: c, clients: map[string]*client{}}
	success := false
	defer func() {
		if !success {
			s.Close()
		}
	}()
	d.binding = hash(canonical([]any{c.AgentName, c.LandlordName, c.PowBits, c.MaxClients, c.Burst, c.MaxReplay, c.RefillSeconds, c.KnownSeconds, c.MessageAgeSeconds}))
	raw, e := s.Read("meta.json", 4096)
	if e != nil {
		return nil, e
	}
	if raw != nil {
		var m meta
		if json.Unmarshal(raw, &m) != nil || !bytes.Equal(raw, canonical(m)) || m.Version != 1 || m.Binding != d.binding || m.High < 0 {
			return nil, errors.New("exchange state binding")
		}
		d.high = m.High
	}
	ents, e := os.ReadDir(c.StateDir)
	if e != nil {
		return nil, e
	}
	if len(ents) > c.MaxClients+10 {
		return nil, errors.New("exchange state capacity")
	}
	for _, ent := range ents {
		name := ent.Name()
		if !strings.HasPrefix(name, "client-") {
			continue
		}
		if len(d.clients) >= c.MaxClients {
			return nil, errors.New("exchange state capacity")
		}
		b, e := s.Read(name, 65536)
		if e != nil {
			return nil, e
		}
		var v client
		if json.Unmarshal(b, &v) != nil || !bytes.Equal(b, canonical(v)) || !d.valid(&v) || name != "client-"+v.Sender+".json" {
			return nil, errors.New("exchange state corrupt")
		}
		d.clients[v.Sender] = &v
	}
	if raw == nil && len(d.clients) != 0 {
		return nil, errors.New("exchange clock missing")
	}
	success = true
	return d, nil
}
func (d *disk) valid(v *client) bool {
	if v.Version != 1 || nostr.ParseXOnlyPubKey(v.Sender) != nil || v.Tokens < 0 || v.Tokens > d.cfg.Burst || v.Refilled < 0 || v.Refilled > d.high || v.KnownUntil < v.Refilled || len(v.Seen) > d.cfg.MaxReplay || v.Seen == nil {
		return false
	}
	ids := map[string]bool{}
	for _, s := range v.Seen {
		if !digest(s.ID) || ids[s.ID] || s.Until < 0 {
			return false
		}
		ids[s.ID] = true
	}
	switch v.Phase {
	case "", "book_pending", "held", "consent_pending", "consented", "issued", "ready_done":
	default:
		return false
	}
	if v.Hold != nil && !v.Hold.valid(d.cfg, v.Sender) {
		return false
	}
	if v.Phase != "" && v.Phase != "book_pending" && v.Hold == nil {
		return false
	}
	if v.TermsPin != "" && !digest(v.TermsPin) {
		return false
	}
	if v.ConsentID != "" && !digest(v.ConsentID) {
		return false
	}
	if (v.Pending == nil) != (v.PendingKind == "") {
		return false
	}
	if v.Pending != nil && (v.Pending.Kind != nostr.KindGiftWrap || !v.Pending.CheckID() || nostr.VerifySignature(v.Pending) != nil) {
		return false
	}
	if v.Pending != nil && (len(v.Pending.Tags) != 1 || len(v.Pending.Tags[0]) != 2 || v.Pending.Tags[0][0] != "p" || v.Pending.Tags[0][1] != v.Sender) {
		return false
	}
	switch v.PendingKind {
	case "", "terms", "help", "book_pending", "unavailable", "coin_not_offered", "contract", "pay", "issued", "ready", "not_live", "not_yet":
	default:
		return false
	}
	return true
}
func (d *disk) clock(now int64) error {
	if d.poisoned || now < d.high || now < 1 || now > 1<<50 {
		return errors.New("exchange clock/state")
	}
	if now == d.high {
		return nil
	}
	if e := d.store.Write("meta.json", canonical(meta{1, d.binding, now})); e != nil {
		d.poisoned = true
		return e
	}
	d.high = now
	return nil
}
func clone(v *client) *client { var r client; _ = json.Unmarshal(canonical(v), &r); return &r }
func (d *disk) save(v *client) error {
	if d.poisoned || !d.valid(v) {
		return errors.New("exchange state invalid")
	}
	b := canonical(v)
	if len(b) > 65536 {
		return errors.New("exchange state capacity")
	}
	if e := d.store.Write("client-"+v.Sender+".json", b); e != nil {
		d.poisoned = true
		return e
	}
	d.clients[v.Sender] = clone(v)
	return nil
}
func (d *disk) prune(now int64) error {
	keys := []string{}
	for k, v := range d.clients {
		if v.KnownUntil <= now && v.Refilled+int64(d.cfg.Burst)*d.cfg.RefillSeconds <= now && v.Pending == nil && (v.Hold == nil || v.Hold.NotAfter <= now) && v.Phase != "book_pending" {
			expired := true
			for _, s := range v.Seen {
				expired = expired && s.Until < now
			}
			if expired {
				keys = append(keys, k)
			}
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		if e := os.Remove(filepath.Join(d.cfg.StateDir, "client-"+k+".json")); e != nil {
			d.poisoned = true
			return e
		}
		if e := durable.SyncDir(d.cfg.StateDir); e != nil {
			d.poisoned = true
			return e
		}
		delete(d.clients, k)
	}
	return nil
}

// Only unprogressed, fully acknowledged introductions may lose retained terms,
// replay and bucket state under capacity pressure. Booking/outbox facts survive.
// Removing and syncing first ensures replacement never exceeds the disk bound;
// a crash between removal and replacement loses only the idle introduction.
func (d *disk) evictIdle() error {
	if d.poisoned {
		return errors.New("exchange state invalid")
	}
	var oldest *client
	for _, v := range d.clients {
		if v.Phase != "" || v.Hold != nil || v.ConsentID != "" || v.Pending != nil {
			continue
		}
		if oldest == nil || v.KnownUntil < oldest.KnownUntil || (v.KnownUntil == oldest.KnownUntil && v.Sender < oldest.Sender) {
			oldest = v
		}
	}
	if oldest == nil {
		return errors.New("exchange state capacity")
	}
	if err := os.Remove(filepath.Join(d.cfg.StateDir, "client-"+oldest.Sender+".json")); err != nil {
		d.poisoned = true
		return err
	}
	if err := durable.SyncDir(d.cfg.StateDir); err != nil {
		d.poisoned = true
		return err
	}
	delete(d.clients, oldest.Sender)
	return nil
}
