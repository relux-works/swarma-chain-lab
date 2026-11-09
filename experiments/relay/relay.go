package relay

import (
	"crypto/rand"
	encodinghex "encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gorilla/websocket"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/exchange"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/nostr"
)

type bucket struct {
	at          int64
	used        int
	connections int
}
type peer struct {
	ws        *websocket.Conn
	out       chan []byte
	done      chan struct{}
	once      sync.Once
	ip        string
	challenge string
	auth      map[string]bool
	subs      map[string][]filter
	quota     bucket
}

func (p *peer) stop() { p.once.Do(func() { close(p.done); _ = p.ws.Close() }) }
func (p *peer) send(v any) {
	raw, _ := json.Marshal(v)
	select {
	case <-p.done:
		return
	default:
	}
	select {
	case p.out <- raw:
	default:
		p.stop()
	}
}
func (p *peer) write() {
	defer p.stop()
	for {
		select {
		case <-p.done:
			return
		case raw := <-p.out:
			_ = p.ws.SetWriteDeadline(time.Now().Add(3 * time.Second))
			if p.ws.WriteMessage(websocket.TextMessage, raw) != nil {
				return
			}
		}
	}
}

type Relay struct {
	mu          sync.Mutex
	cfg         Config
	now         func() time.Time
	store       *eventStore
	peers       map[*peer]bool
	ips         map[string]*bucket
	closed      bool
	connections int
	stop        chan struct{}
	wg          sync.WaitGroup
}

func New(c Config, now func() time.Time) (*Relay, error) {
	if e := c.Validate(); e != nil {
		return nil, e
	}
	if now == nil {
		return nil, fail("CLOCK")
	}
	s, e := openStore(c, now().Unix())
	if e != nil {
		return nil, e
	}
	c.KnownPubkeys = append([]string(nil), c.KnownPubkeys...)
	r := &Relay{cfg: c, now: now, store: s, peers: map[*peer]bool{}, ips: map[string]*bucket{}, stop: make(chan struct{})}
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		tick := time.NewTicker(time.Minute)
		defer tick.Stop()
		for {
			select {
			case <-r.stop:
				return
			case <-tick.C:
				r.mu.Lock()
				if !r.closed {
					_ = r.store.prune(r.now().Unix())
				}
				r.mu.Unlock()
			}
		}
	}()
	return r, nil
}

// Close owns all upgraded connections before releasing the single-writer lock.
func (r *Relay) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	close(r.stop)
	for p := range r.peers {
		p.stop()
	}
	r.mu.Unlock()
	r.wg.Wait()
	r.mu.Lock()
	r.store.close()
	r.mu.Unlock()
	return nil
}
func (r *Relay) clientIP(req *http.Request) (string, error) {
	host, _, e := net.SplitHostPort(req.RemoteAddr)
	ip, e2 := netip.ParseAddr(host)
	if e != nil || e2 != nil {
		return "", fail("PEER")
	}
	ip = ip.Unmap()
	if r.cfg.TrustedProxyIP != "" && ip.String() == r.cfg.TrustedProxyIP {
		v := req.Header.Values("X-Real-IP")
		// Local service clients may connect directly without a forwarding header;
		// they share the loopback budget. The proxy MUST overwrite public headers.
		if len(v) == 0 {
			return ip.String(), nil
		}
		if len(v) != 1 {
			return "", fail("PROXY")
		}
		forward, e := netip.ParseAddr(v[0])
		if e != nil || forward.IsUnspecified() || forward.IsMulticast() {
			return "", fail("PROXY")
		}
		ip = forward.Unmap()
	}
	return ip.String(), nil
}
func renew(b *bucket, now int64) {
	if now-b.at >= 60 {
		b.at = now
		b.used = 0
	}
}
func (r *Relay) reserve(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.connections >= r.cfg.MaxConnections {
		return false
	}
	now := r.now().Unix()
	for k, b := range r.ips {
		if b.connections == 0 && now-b.at >= 60 {
			delete(r.ips, k)
		}
	}
	b := r.ips[ip]
	if b == nil {
		if len(r.ips) >= r.cfg.MaxIPs {
			return false
		}
		b = &bucket{at: now}
		r.ips[ip] = b
	}
	renew(b, now)
	if b.connections >= r.cfg.MaxConnectionsPerIP || b.used >= r.cfg.FramesPerIPMinute {
		return false
	}
	b.connections++
	r.connections++
	b.used++
	return true
}
func (r *Relay) release(ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ips[ip].connections--
	r.connections--
}
func (r *Relay) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != "GET" || req.URL.Path != "/" || req.URL.RawQuery != "" {
		http.Error(w, "not found", 404)
		return
	}
	ip, e := r.clientIP(req)
	if e != nil {
		http.Error(w, "bad peer", 400)
		return
	}
	if !r.reserve(ip) {
		http.Error(w, "rate limited", 429)
		return
	}
	defer r.release(ip)
	u := websocket.Upgrader{HandshakeTimeout: 5 * time.Second, CheckOrigin: func(*http.Request) bool { return true }, EnableCompression: false}
	ws, e := u.Upgrade(w, req, nil)
	if e != nil {
		return
	}
	nonce := make([]byte, 32)
	if _, e = rand.Read(nonce); e != nil {
		ws.Close()
		return
	}
	p := &peer{ws: ws, out: make(chan []byte, r.cfg.Queue), done: make(chan struct{}), ip: ip, challenge: encodinghex.EncodeToString(nonce), auth: map[string]bool{}, subs: map[string][]filter{}}
	r.mu.Lock()
	if r.closed || len(r.peers) >= r.cfg.MaxConnections {
		r.mu.Unlock()
		ws.Close()
		return
	}
	r.peers[p] = true
	r.wg.Add(1)
	r.mu.Unlock()
	written := make(chan struct{})
	go func() { defer close(written); p.write() }()
	defer func() {
		p.stop()
		<-written
		r.mu.Lock()
		delete(r.peers, p)
		r.mu.Unlock()
		r.wg.Done()
	}()
	ws.SetReadLimit(int64(r.cfg.MaxEventBytes + 1024))
	_ = ws.SetReadDeadline(time.Now().Add(90 * time.Second))
	// Control-frame floods are not a second unmetered path. Count pings/pongs
	// through the same per-connection/IP admission as application frames.
	ws.SetPingHandler(func(string) error {
		if !r.allow(p) {
			return fail("RATE")
		}
		return ws.WriteControl(websocket.PongMessage, nil, time.Now().Add(time.Second))
	})
	ws.SetPongHandler(func(string) error {
		if !r.allow(p) {
			return fail("RATE")
		}
		return nil
	})
	challenged := r.cfg.RequireWriteAuth || r.cfg.RequireReadAuth || r.cfg.RestrictGiftWrapReads || r.cfg.UnknownPowBits > 0
	if challenged {
		p.send([]any{"AUTH", p.challenge})
	}
	for {
		kind, raw, e := ws.ReadMessage()
		if e != nil {
			return
		}
		if !r.allow(p) {
			p.send([]any{"NOTICE", "rate-limited: frame quota"})
			return
		}
		_ = ws.SetReadDeadline(time.Now().Add(90 * time.Second))
		if kind != websocket.TextMessage || !utf8.Valid(raw) {
			p.send([]any{"NOTICE", "invalid: text frame required"})
			continue
		}
		r.dispatch(p, raw)
		// Optional AUTH follows the first command response so legacy publishers
		// see their OK first. Required-auth policies challenge on connection.
		if !challenged {
			p.send([]any{"AUTH", p.challenge})
			challenged = true
		}
	}
}
func (r *Relay) allow(p *peer) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now().Unix()
	b := r.ips[p.ip]
	renew(&p.quota, now)
	renew(b, now)
	if p.quota.used >= r.cfg.FramesPerMinute || b.used >= r.cfg.FramesPerIPMinute {
		return false
	}
	p.quota.used++
	b.used++
	return true
}
func (r *Relay) dispatch(p *peer, raw []byte) {
	var msg []json.RawMessage
	if strict(raw, &msg) != nil || len(msg) < 1 {
		p.send([]any{"NOTICE", "invalid: message"})
		return
	}
	var kind string
	if json.Unmarshal(msg[0], &kind) != nil {
		p.send([]any{"NOTICE", "invalid: command"})
		return
	}
	switch kind {
	case "EVENT":
		if len(msg) != 2 {
			p.send([]any{"NOTICE", "invalid: event shape"})
			return
		}
		r.publish(p, msg[1])
	case "AUTH":
		if len(msg) != 2 {
			p.send([]any{"NOTICE", "invalid: auth shape"})
			return
		}
		r.authenticate(p, msg[1])
	case "REQ":
		r.subscribe(p, msg)
	case "CLOSE":
		if len(msg) != 2 {
			return
		}
		var id string
		if json.Unmarshal(msg[1], &id) != nil {
			return
		}
		r.mu.Lock()
		delete(p.subs, id)
		r.mu.Unlock()
	default:
		p.send([]any{"NOTICE", "unsupported: command"})
	}
}
func (r *Relay) authenticate(p *peer, raw []byte) {
	var v nostr.Event
	id := ""
	if strict(raw, &v) == nil && hex(v.ID, 64) {
		id = v.ID
	}
	reject := func() { p.send([]any{"OK", id, false, "restricted: invalid authentication"}) }
	e, err := nostr.ParseEvent(raw)
	if len(raw) > 8192 || err != nil || nostr.VerifySignature(e) != nil || e.Kind != 22242 || e.Content != "" || e.CreatedAt < r.now().Unix()-600 || e.CreatedAt > r.now().Unix()+600 || len(e.Tags) != 2 {
		reject()
		return
	}
	tags := map[string]string{}
	for _, t := range e.Tags {
		if len(t) != 2 || tags[t[0]] != "" {
			reject()
			return
		}
		tags[t[0]] = t[1]
	}
	if tags["challenge"] != p.challenge || tags["relay"] != r.cfg.PublicURL {
		reject()
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(p.auth) >= 8 && !p.auth[e.PubKey] {
		reject()
		return
	}
	p.auth[e.PubKey] = true
	p.send([]any{"OK", e.ID, true, ""})
}
func (r *Relay) readable(p *peer, e *nostr.Event) bool {
	if !r.cfg.RestrictGiftWrapReads || e.Kind != 1059 {
		return true
	}
	recipient, _ := e.TagFirst("p")
	return p.auth[recipient]
}
func (r *Relay) publish(p *peer, raw []byte) {
	e, err := validEvent(raw, r.cfg)
	if err != nil {
		var candidate struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(raw, &candidate)
		if !hex(candidate.ID, 64) {
			candidate.ID = ""
		}
		p.send([]any{"OK", candidate.ID, false, "invalid: event"})
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	refuse := func(code string) { p.send([]any{"OK", e.ID, false, code}) }
	if r.cfg.RequireWriteAuth && len(p.auth) == 0 {
		refuse("auth-required: authenticate first")
		return
	}
	if !live(e, r.cfg, r.now().Unix()) {
		refuse("invalid: created_at window")
		return
	}
	known := false
	for _, key := range r.cfg.KnownPubkeys {
		if p.auth[key] || len(p.auth) == 0 && e.PubKey == key {
			known = true
		}
	}
	if r.cfg.UnknownPowBits > 0 && !known && !exchange.CheckWork(e, r.cfg.UnknownPowBits) {
		refuse("pow: insufficient outer work")
		return
	}
	duplicate, err := r.store.put(e, r.now().Unix())
	if err != nil {
		if strings.Contains(err.Error(), "CAPACITY") {
			refuse("rate-limited: storage capacity")
		} else {
			refuse("error: durable store unavailable")
		}
		return
	}
	if duplicate {
		p.send([]any{"OK", e.ID, true, "duplicate: already stored"})
		return
	}
	p.send([]any{"OK", e.ID, true, ""})
	for other := range r.peers {
		if !r.readable(other, e) {
			continue
		}
		for id, filters := range other.subs {
			if matches(filters, e) {
				other.send([]any{"EVENT", id, e})
			}
		}
	}
}
func (r *Relay) subscribe(p *peer, msg []json.RawMessage) {
	id := ""
	if len(msg) > 1 {
		_ = json.Unmarshal(msg[1], &id)
	}
	refuse := func(code string) { p.send([]any{"CLOSED", id, code}) }
	r.mu.Lock()
	defer r.mu.Unlock()
	// Replacing an ID always removes its old subscription, even when refused.
	delete(p.subs, id)
	if len(msg) < 3 || len(msg) > 6 || id == "" || len(id) > 64 {
		refuse("invalid: subscription")
		return
	}
	filters := make([]filter, 0, len(msg)-2)
	gift := false
	for _, raw := range msg[2:] {
		f, e := parseFilter(raw)
		if e != nil {
			refuse("unsupported: filter")
			return
		}
		filters = append(filters, f)
		if f.Kinds == nil || contains(f.Kinds, 1059) {
			gift = true
		}
	}
	if (r.cfg.RequireReadAuth || r.cfg.RestrictGiftWrapReads && gift) && len(p.auth) == 0 {
		refuse("auth-required: authenticate first")
		return
	}
	if len(p.subs) >= r.cfg.Subscriptions {
		refuse("rate-limited: subscriptions")
		return
	}
	if r.store.poisoned {
		refuse("error: durable store unavailable")
		return
	}
	all := make([]*nostr.Event, 0, len(r.store.events))
	for _, e := range r.store.events {
		if live(e, r.cfg, r.now().Unix()) && r.readable(p, e) {
			all = append(all, e)
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].CreatedAt != all[j].CreatedAt {
			return all[i].CreatedAt > all[j].CreatedAt
		}
		return all[i].ID < all[j].ID
	})
	counts := make([]int, len(filters))
	sent := 0
	for _, e := range all {
		selected := false
		for i, f := range filters {
			limit := r.cfg.Backlog
			if f.Limit != nil && *f.Limit < limit {
				limit = *f.Limit
			}
			if counts[i] < limit && f.match(e) {
				counts[i]++
				selected = true
			}
		}
		if selected {
			p.send([]any{"EVENT", id, e})
			sent++
			if sent >= r.cfg.Backlog {
				break
			}
		}
	}
	p.send([]any{"EOSE", id})
	p.subs[id] = filters
}
