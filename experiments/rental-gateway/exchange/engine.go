package exchange

import (
	"context"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"

	"relux.works/swarma-chain-lab/experiments/rental-gateway/nostr"
)

type Engine struct {
	cfg       Config
	disk      *disk
	queue     chan *nostr.Event
	key       *nostr.PrivKey
	publisher Publisher
	hooks     Hooks
	mu        sync.Mutex
	cancel    context.CancelFunc
	done      chan struct{}
	closed    bool
}

// AgentName is the immutable service identity that the gateway must share.
func (e *Engine) AgentName() string { return e.cfg.AgentName }

func New(c Config) (*Engine, error) {
	if e := c.validate(); e != nil {
		return nil, e
	}
	d, e := openDisk(c)
	if e != nil {
		return nil, e
	}
	return &Engine{cfg: c, disk: d, queue: make(chan *nostr.Event, c.QueueSize)}, nil
}

// Bind starts one worker. The gateway supplies only messaging and dormant-slot
// hooks; there is no model, station-start, chain-signing or broadcast capability.
func (e *Engine) Bind(key *nostr.PrivKey, pub Publisher, h Hooks) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.cancel != nil || key == nil || pub == nil || h.Register == nil || h.Check == nil {
		return errors.New("exchange bind")
	}
	raw, err := e.disk.store.Read("agent.json", 256)
	if err != nil {
		return err
	}
	binding := canonical(key.PubKeyHex())
	if raw != nil && string(raw) != string(binding) {
		return errors.New("exchange agent binding")
	}
	if raw == nil {
		if len(e.disk.clients) > 0 {
			return errors.New("exchange agent binding missing")
		}
		if err = e.disk.store.Write("agent.json", binding); err != nil {
			return err
		}
	}
	e.key, e.publisher, e.hooks = key, pub, h
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	e.done = make(chan struct{})
	go e.run(ctx)
	return nil
}
func (e *Engine) Close() {
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	e.closed = true
	cancel, done := e.cancel, e.done
	e.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
	e.disk.store.Close()
}

// Submit copies one already authenticated rumor and never waits for the worker.
// Live-grantee callers must bypass this method entirely.
func (e *Engine) Submit(r *nostr.Event) bool {
	if r == nil || r.Kind != nostr.KindRumor || len(r.Content) > 8192 || len(r.Tags) > 16 || len(r.Serialize()) > 12288 {
		return false
	}
	c := *r
	c.Tags = make([][]string, len(r.Tags))
	for i, t := range r.Tags {
		if len(t) > 4 {
			return false
		}
		c.Tags[i] = append([]string{}, t...)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || e.cancel == nil {
		return false
	}
	select {
	case e.queue <- &c:
		return true
	default:
		return false
	}
}
func (e *Engine) run(ctx context.Context) {
	defer close(e.done)
	tick := time.NewTicker(e.cfg.PollInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case r := <-e.queue:
			e.process(ctx, r)
		case <-tick.C:
			e.poll(ctx)
		}
	}
}
func (e *Engine) call(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, e.cfg.CallTimeout)
}
func (e *Engine) process(ctx context.Context, r *nostr.Event) {
	now := e.cfg.Now().Unix()
	if !r.CheckID() || nostr.ParseXOnlyPubKey(r.PubKey) != nil || r.CreatedAt < now-e.cfg.MessageAgeSeconds || r.CreatedAt > now+30 {
		return
	}
	old := e.disk.clients[r.PubKey]
	if (old == nil || old.KnownUntil <= now) && !CheckWork(r, e.cfg.PowBits) {
		return
	}
	if e.disk.clock(now) != nil || e.disk.prune(now) != nil {
		return
	}
	old = e.disk.clients[r.PubKey]
	var v *client
	if old == nil {
		if len(e.disk.clients) >= e.cfg.MaxClients {
			if e.disk.evictIdle() != nil {
				return
			}
		}
		v = &client{Version: 1, Sender: r.PubKey, Tokens: e.cfg.Burst, Refilled: now, KnownUntil: now + e.cfg.KnownSeconds, Seen: []seen{}}
	} else {
		v = clone(old)
	}
	for _, s := range v.Seen {
		if s.ID == r.ID {
			return
		}
	}
	retained := []seen{}
	for _, s := range v.Seen {
		if s.Until >= now {
			retained = append(retained, s)
		}
	}
	v.Seen = retained
	if len(v.Seen) >= e.cfg.MaxReplay {
		return
	}
	if v.KnownUntil <= now {
		v.KnownUntil = now + e.cfg.KnownSeconds
	}
	refill := (now - v.Refilled) / e.cfg.RefillSeconds
	if refill > 0 {
		if refill > int64(e.cfg.Burst) {
			refill = int64(e.cfg.Burst)
		}
		v.Tokens += int(refill)
		if v.Tokens >= e.cfg.Burst {
			v.Tokens = e.cfg.Burst
			v.Refilled = now
		} else {
			v.Refilled += refill * e.cfg.RefillSeconds
		}
	}
	if v.Tokens < 1 {
		return
	}
	v.Tokens--
	v.Seen = append(v.Seen, seen{r.ID, r.CreatedAt + e.cfg.MessageAgeSeconds})
	if e.disk.save(v) != nil {
		return
	}
	// A pending fixed response is retried as the same signed event before any
	// new command; the new command is consumed and has no booking side effect.
	if v.Pending != nil {
		e.flush(ctx, v)
		return
	}
	if v.Hold != nil && (v.Phase == "issued" || v.Phase == "ready_done") && now < v.Hold.NotBefore {
		e.respond(ctx, v, "not_yet", NotYet)
		return
	}
	if r.Content == "terms" {
		e.terms(ctx, v)
		return
	}
	if v.Phase == "book_pending" {
		e.respond(ctx, v, "book_pending", BookPending)
		return
	}
	if strings.HasPrefix(r.Content, "book ") {
		e.book(ctx, v, r.Content)
		return
	}
	if strings.HasPrefix(r.Content, "consent ") {
		e.consent(ctx, v, []byte(strings.TrimPrefix(r.Content, "consent ")))
		return
	}
	e.respond(ctx, v, "help", Help)
}
func (e *Engine) respond(ctx context.Context, v *client, kind, text string) {
	if len(text) > 24000 {
		return
	}
	wrap, _, err := nostr.WrapDM(e.key, v.Sender, text, nil, e.cfg.Now().Unix())
	if err != nil {
		return
	}
	v.Pending, v.PendingKind = wrap, kind
	if e.disk.save(v) != nil {
		return
	}
	e.flush(ctx, v)
}
func (e *Engine) flush(ctx context.Context, v *client) {
	if v.Pending == nil {
		return
	}
	c, cancel := e.call(ctx)
	err := e.publisher.Publish(c, v.Pending)
	cancel()
	if err != nil {
		return
	}
	v.Pending = nil
	v.PendingKind = ""
	_ = e.disk.save(v)
}
func (e *Engine) catalogue(ctx context.Context) (Terms, error) {
	c, cancel := e.call(ctx)
	defer cancel()
	t, err := e.cfg.Backend.Catalogue(c)
	if err != nil {
		return Terms{}, err
	}
	t.PowBits = e.cfg.PowBits
	if t.AgentName != e.cfg.AgentName || t.LandlordName != e.cfg.LandlordName || len(t.PrivacyNotice) < 1 || len(t.PrivacyNotice) > 2048 || hash([]byte(t.PrivacyNotice)) != t.PrivacySHA256 || len(t.Templates) < 1 || len(t.Templates) > 8 || len(t.Slots) > 64 {
		return Terms{}, errors.New("catalogue binding")
	}
	templates := map[string]bool{}
	for _, v := range t.Templates {
		if !identifier(v.ID) || templates[v.ID] || !digest(v.SHA256) || !identifier(v.ProfileID) || !identifier(v.ProfileVersion) || !digest(v.ProfileSHA256) || v.PriceUSDCents < 1 || len(v.SlotLengths) < 1 || len(v.SlotLengths) > 64 {
			return Terms{}, errors.New("template binding")
		}
		templates[v.ID] = true
		for _, n := range v.SlotLengths {
			if n < 1 || n > 3600 {
				return Terms{}, errors.New("slot length")
			}
		}
	}
	slots := map[string]bool{}
	for _, v := range t.Slots {
		if !identifier(v.ID) || slots[v.ID] || !templates[v.TemplateID] || v.NotBefore < 1 || v.NotAfter <= v.NotBefore || v.NotAfter-v.NotBefore > 3600 || len(v.Coins) < 1 || len(v.Coins) > 3 {
			return Terms{}, errors.New("slot binding")
		}
		slots[v.ID] = true
		coins := map[Coin]bool{}
		for _, coin := range v.Coins {
			if _, err := ParseCoin(string(coin)); err != nil || coins[coin] {
				return Terms{}, errors.New("coin binding")
			}
			coins[coin] = true
		}
	}
	if len(canonical(t)) > 16000 {
		return Terms{}, errors.New("catalogue size")
	}
	return t, nil
}
func termsPin(t Terms) string { t.Slots = nil; return hash(canonical(t)) }
func (e *Engine) terms(ctx context.Context, v *client) {
	t, err := e.catalogue(ctx)
	if err != nil {
		e.respond(ctx, v, "unavailable", Unavailable)
		return
	}
	v.TermsPin = termsPin(t)
	e.respond(ctx, v, "terms", "terms\n"+string(canonical(t)))
}
func (e *Engine) book(ctx context.Context, v *client, text string) {
	words := strings.Split(text, " ")
	if len(words) != 4 || words[0] != "book" || !identifier(words[1]) || !identifier(words[2]) || v.TermsPin == "" || v.Phase == "book_pending" || v.Phase == "consent_pending" {
		e.respond(ctx, v, "help", Help)
		return
	}
	now := e.cfg.Now().Unix()
	if v.Hold != nil && ((v.Phase == "issued" || v.Phase == "ready_done") && v.Hold.NotAfter > now || v.Hold.Expires > now) {
		e.respond(ctx, v, "help", Help)
		return
	}
	coin, err := ParseCoin(words[3])
	if err != nil {
		e.respond(ctx, v, "help", Help)
		return
	}
	t, err := e.catalogue(ctx)
	if err != nil {
		e.respond(ctx, v, "unavailable", Unavailable)
		return
	}
	available := false
	slotFound := false
	for _, s := range t.Slots {
		if s.ID == words[2] && s.TemplateID == words[1] {
			slotFound = true
			for _, c := range s.Coins {
				available = available || c == coin
			}
		}
	}
	if slotFound && !available {
		e.respond(ctx, v, "coin_not_offered", CoinNotOffered)
		return
	}
	if !available || termsPin(t) != v.TermsPin {
		e.respond(ctx, v, "help", Help)
		return
	}
	v.Phase = "book_pending"
	v.Hold = nil
	v.ConsentID = ""
	if e.disk.save(v) != nil {
		return
	}
	c, cancel := e.call(ctx)
	h, err := e.cfg.Backend.Book(c, v.Sender, Selection{words[1], words[2], coin})
	cancel()
	if err != nil {
		if errors.Is(err, ErrRejected) {
			v.Phase = ""
			if errors.Is(err, ErrCoinNotOffered) {
				e.respond(ctx, v, "coin_not_offered", CoinNotOffered)
			} else {
				e.respond(ctx, v, "unavailable", Unavailable)
			}
			return
		}
		e.respond(ctx, v, "book_pending", BookPending)
		return
	}
	if !h.valid(e.cfg, v.Sender) || h.Coin != coin || len(h.Contract) < 1 || len(h.Contract) > 8192 || hash(h.Contract) != h.ContractSHA256 || h.Expires <= e.cfg.Now().Unix() {
		e.respond(ctx, v, "book_pending", BookPending)
		return
	}
	v.Hold = &h
	v.Phase = "held"
	payload := struct {
		BookingID string `json:"booking_id"`
		Hash      string `json:"contract_sha256"`
		Contract  string `json:"contract_base64"`
		Expires   int64  `json:"hold_expires_at"`
	}{h.BookingID, h.ContractSHA256, base64.StdEncoding.EncodeToString(h.Contract), h.Expires}
	e.respond(ctx, v, "contract", "contract\n"+string(canonical(payload)))
}
func (e *Engine) consent(ctx context.Context, v *client, raw []byte) {
	if v.Hold == nil || (v.Phase != "held" && v.Phase != "consent_pending" && v.Phase != "consented") || v.Hold.Expires <= e.cfg.Now().Unix() {
		e.respond(ctx, v, "help", Help)
		return
	}
	ev, err := nostr.ParseEvent(raw)
	if err != nil || ev.Kind != 8181 || ev.PubKey != v.Sender || !ev.CheckID() || nostr.VerifySignature(ev) != nil || (v.ConsentID != "" && v.ConsentID != ev.ID) {
		e.respond(ctx, v, "help", Help)
		return
	}
	v.Phase = "consent_pending"
	v.ConsentID = ev.ID
	if e.disk.save(v) != nil {
		return
	}
	c, cancel := e.call(ctx)
	h, err := e.cfg.Backend.Consent(c, v.Hold.BookingID, raw)
	cancel()
	if err != nil {
		v.Phase = "held"
		v.ConsentID = ""
		e.respond(ctx, v, "help", Help)
		return
	}
	if !h.valid(e.cfg, v.Sender) || !sameHold(*v.Hold, h) || h.ConsentID != ev.ID || h.Expires <= e.cfg.Now().Unix() {
		e.respond(ctx, v, "unavailable", Unavailable)
		return
	}
	v.Hold = &h
	v.Phase = "consented"
	payload := struct {
		BookingID        string `json:"booking_id"`
		Coin             Coin   `json:"coin"`
		Address          string `json:"address"`
		Amount           int64  `json:"amount_atomic"`
		MinConfirmations int64  `json:"min_confirmations"`
		Expires          int64  `json:"hold_expires_at"`
	}{h.BookingID, h.Coin, h.Address, h.AmountAtomic, h.MinConfirmations, h.Expires}
	e.respond(ctx, v, "pay", "pay\n"+string(canonical(payload)))
}
func (e *Engine) poll(ctx context.Context) {
	now := e.cfg.Now().Unix()
	if e.disk.clock(now) != nil {
		return
	}
	for _, old := range e.disk.clients {
		if ctx.Err() != nil {
			return
		}
		v := clone(old)
		if v.Pending != nil {
			e.flush(ctx, v)
			continue
		}
		if v.Phase == "consented" || v.Phase == "consent_pending" {
			e.issue(ctx, v)
		}
		v = clone(e.disk.clients[v.Sender])
		if v.Phase == "issued" && v.Pending == nil && now >= v.Hold.NotBefore {
			c, cancel := e.call(ctx)
			live, err := e.hooks.Check(c, *v.Hold, e.cfg.Now().Unix())
			cancel()
			v.Phase = "ready_done"
			text, kind := NotLive, "not_live"
			if err == nil && live {
				text, kind = "ready", "ready"
			}
			e.respond(ctx, v, kind, text)
		}
	}
	_ = e.disk.prune(now)
}
func (e *Engine) issue(ctx context.Context, v *client) {
	c, cancel := e.call(ctx)
	h, err := e.cfg.Backend.Status(c, v.Hold.BookingID)
	cancel()
	if err != nil || !h.valid(e.cfg, v.Sender) || !sameHold(*v.Hold, h) || h.ConsentID != v.ConsentID || !h.Issuable || h.Revoked {
		return
	}
	c, cancel = e.call(ctx)
	issued, err := e.cfg.Grants.Lookup(c, h)
	cancel()
	if err != nil || issued == nil || issued.BookingID != h.BookingID || issued.ContractSHA256 != h.ContractSHA256 || issued.Sender != h.Sender || issued.AgentName != h.AgentName || issued.LandlordName != h.LandlordName || issued.StationName != h.StationName || issued.NotBefore != h.NotBefore || issued.NotAfter != h.NotAfter || !digest(issued.GrantID) || len(issued.Presentation) < 1 || len(issued.Presentation) > 16384 {
		return
	}
	c, cancel = e.call(ctx)
	err = e.hooks.Register(c, *issued)
	cancel()
	if err != nil {
		return
	}
	v.Hold = &h
	v.Phase = "issued"
	payload := struct {
		BookingID    string `json:"booking_id"`
		GrantID      string `json:"grant_id"`
		Presentation string `json:"presentation_base64"`
		NotBefore    int64  `json:"not_before"`
		NotAfter     int64  `json:"not_after"`
		Notice       string `json:"notice"`
	}{h.BookingID, issued.GrantID, base64.StdEncoding.EncodeToString(issued.Presentation), h.NotBefore, h.NotAfter, "Slot starts at " + strconv.FormatInt(h.NotBefore, 10) + "; verify the grant independently. This is not a live verdict."}
	e.respond(ctx, v, "issued", "issued\n"+string(canonical(payload)))
}
