package executor

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"relux.works/swarma-chain-lab/experiments/rental"
	"relux.works/swarma-chain-lab/experiments/single-use"
)

type Slot struct {
	ID       string          `json:"slot"`
	Envelope json.RawMessage `json:"envelope"`
	Policy   rental.Policy   `json:"policy"`
	Wallet   Wallet          `json:"wallet"`
}
type Config struct {
	Network string `json:"network"`
	Slots   []Slot `json:"slots"`
	Prize   PrizeA `json:"prize_a"`
}
type Reservation struct {
	Slot        string  `json:"slot"`
	Nonce       string  `json:"nonce"`
	EventID     string  `json:"event_id"`
	Action      string  `json:"action"`
	TargetHash  string  `json:"target_sha256"`
	Debit       int64   `json:"debit_sat"`
	Inputs      []Point `json:"inputs"`
	Phase       string  `json:"phase"`
	TxID        string  `json:"txid"`
	FileHash    string  `json:"file_sha256"`
	RetainUntil int64   `json:"retain_until"`
}
type journal struct {
	Version      int           `json:"version"`
	Binding      string        `json:"binding"`
	Reservations []Reservation `json:"reservations"`
}
type Receipt struct {
	Status          string `json:"status"`
	Action          string `json:"action"`
	AuthorityReason string `json:"authority_reason,omitempty"`
	Reason          string `json:"reason"`
	Slot            string `json:"slot"`
	EventID         string `json:"event_id"`
	Phase           string `json:"phase"`
	TxID            string `json:"txid"`
	FileHash        string `json:"file_sha256"`
	Link            string `json:"local_link"`
	RetainUntil     int64  `json:"retain_until"`
}
type Broadcaster interface {
	Broadcast(context.Context, []byte) (string, error)
}
type Executor struct {
	mu        sync.Mutex
	store     *store
	config    Config
	slots     map[string]Slot
	certs     map[string]rental.Certificate
	journal   journal
	node      singleuse.Node
	broadcast Broadcaster
	now       func() time.Time
	// Tests inject crashes at the durable reservation boundary; CLI exposes none.
	hook func(string)
}

func Open(root string, c Config, node singleuse.Node, broadcast Broadcaster) (*Executor, error) {
	if c.Network != "regtest" || len(c.Slots) == 0 || len(c.Slots) > 256 || node == nil || broadcast == nil || !c.Prize.Point.valid() {
		return nil, fail("EXECUTOR_CONFIG")
	}
	pk, e := privateKey(c.Prize.Key)
	if e != nil || keyAddress(pk) != c.Prize.Address {
		return nil, fail("PRIZE_CONFIG")
	}
	// Copy all caller-owned configuration before accepting requests.
	var copy Config
	if json.Unmarshal(canonical(c), &copy) != nil {
		return nil, fail("EXECUTOR_CONFIG")
	}
	c = copy
	x := &Executor{config: c, slots: map[string]Slot{}, certs: map[string]rental.Certificate{}, node: node, broadcast: broadcast, now: time.Now}
	allInputs := map[string]bool{}
	for _, s := range c.Slots {
		if !hexN(s.ID, 32) {
			return nil, fail("SLOT_CONFIG")
		}
		if _, ok := x.slots[s.ID]; ok {
			return nil, fail("SLOT_CONFIG")
		}
		env, e := rental.ParseEnvelope(s.Envelope)
		if e != nil {
			return nil, fail("CERTIFICATE_CONFIG")
		}
		cert := env.Certificate
		if cert.Network != "regtest" || cert.Genesis != singleuse.RegtestGenesis || s.Policy.Network != cert.Network || s.Policy.Genesis != cert.Genesis || s.Policy.IssuerPubkey != cert.IssuerPubkey || s.Policy.AgentPubkey != cert.AgentPubkey || s.Policy.StationName != cert.StationName {
			return nil, fail("CERTIFICATE_POLICY")
		}
		if e = s.Wallet.validate(c.Prize); e != nil {
			return nil, e
		}
		for _, p := range s.Wallet.Inputs {
			if allInputs[p.key()] {
				return nil, fail("SHARED_BUDGET_INPUT")
			}
			allInputs[p.key()] = true
		}
		x.slots[s.ID] = s
		x.certs[s.ID] = cert
	}
	// The commitment includes only hashes of private configuration, never raw keys.
	binding := Hash(canonical(c))
	s, e := openStore(root)
	if e != nil {
		return nil, e
	}
	x.store = s
	b, e := s.read("journal.json")
	if e != nil {
		s.close()
		return nil, e
	}
	if b == nil {
		x.journal = journal{1, binding, []Reservation{}}
		if e = x.persist(); e != nil {
			s.close()
			return nil, e
		}
	} else {
		if Strict(b, &x.journal) != nil || x.journal.Version != 1 || x.journal.Binding != binding || len(x.journal.Reservations) > 10000 {
			s.close()
			return nil, fail("JOURNAL_BINDING")
		}
		seen := map[string]bool{}
		inputs := map[string]bool{}
		spent := map[string]int64{}
		for _, r := range x.journal.Reservations {
			cert, ok := x.certs[r.Slot]
			if !ok || !hexN(r.Nonce, 32) || !hexN(r.EventID, 32) || !hexN(r.TargetHash, 32) || seen[r.Slot+r.Nonce] || (r.Phase != "reserved" && r.Phase != "complete") || r.Debit < 0 || r.Debit > cert.BudgetSat-spent[r.Slot] || !slices.Contains(cert.Scope, r.Action) || r.Action == "secret.release" {
				s.close()
				return nil, fail("JOURNAL_CORRUPT")
			}
			if r.Action == "pay" {
				if r.Debit <= x.slots[r.Slot].Wallet.Fee || !hexN(r.TxID, 32) || len(r.Inputs) == 0 || r.FileHash != "" || r.RetainUntil != 0 {
					s.close()
					return nil, fail("JOURNAL_CORRUPT")
				}
			} else if r.Debit != 0 || len(r.Inputs) != 0 || r.TxID != "" {
				s.close()
				return nil, fail("JOURNAL_CORRUPT")
			}
			if r.Action == "deliver" {
				if !hexN(r.FileHash, 32) || r.RetainUntil <= 0 {
					s.close()
					return nil, fail("JOURNAL_CORRUPT")
				}
			} else if r.FileHash != "" || r.RetainUntil != 0 {
				s.close()
				return nil, fail("JOURNAL_CORRUPT")
			}
			for _, p := range r.Inputs {
				if inputs[p.key()] || !slices.Contains(x.slots[r.Slot].Wallet.Inputs, p) || p == c.Prize.Point {
					s.close()
					return nil, fail("JOURNAL_CORRUPT")
				}
				inputs[p.key()] = true
			}
			seen[r.Slot+r.Nonce] = true
			spent[r.Slot] += r.Debit
		}
	}
	return x, nil
}
func (x *Executor) persist() error {
	if e := x.store.write("journal.json", canonical(x.journal)); e != nil {
		x.store.poison = true
		return e
	}
	return nil
}
func (x *Executor) Close() { x.mu.Lock(); defer x.mu.Unlock(); x.store.close() }
func (x *Executor) Execute(ctx context.Context, event, file []byte) Receipt {
	x.mu.Lock()
	defer x.mu.Unlock()
	result := Receipt{Status: "refused"}
	refuse := func(reason string) Receipt { result.Reason = reason; return result }
	if x.store.poison {
		return refuse("STATE_UNAVAILABLE")
	}
	if ctx == nil {
		return refuse("CONTEXT")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	r, e := ParseRequest(event)
	if e != nil {
		return refuse(e.Error())
	}
	result.Slot = r.Slot
	result.EventID = r.Event.ID
	result.Action = r.Action
	s, ok := x.slots[r.Slot]
	if !ok {
		return refuse("SLOT_UNKNOWN")
	}
	cert := x.certs[r.Slot]
	if r.Event.Pubkey != cert.GranteePubkey {
		return refuse("GRANTEE_MISMATCH")
	}
	if r.Contract != cert.ContractSHA256 {
		return refuse("CONTRACT_MISMATCH")
	}
	if r.Action == "secret.release" {
		return refuse("SECRET_RELEASE_FORBIDDEN")
	}
	if !slices.Contains(cert.Scope, r.Action) {
		return refuse("ACTION_SCOPE")
	}
	if r.Event.CreatedAt < cert.NotBefore || r.Event.CreatedAt >= cert.NotAfter || r.Event.CreatedAt > x.now().Unix() {
		return refuse("REQUEST_TIME")
	}
	if len(file) > MaxFile || (r.Action != "deliver" && len(file) != 0) {
		return refuse("FILE_BOUND")
	}
	if r.Action == "deliver" && Hash(file) != r.Target[7:] {
		return refuse("FILE_HASH")
	}
	// Always use the configured own node and trusted clock, including duplicates.
	check := func() string {
		receipt := rental.Check(ctx, x.node, s.Policy, s.Envelope, s.Policy.StationName, r.Event.Pubkey, x.now().Unix())
		if receipt.Verdict != "live" {
			return "KERNEL_" + receipt.Reason
		}
		return ""
	}
	authorityReason := check()
	spent := int64(0)
	used := map[string]bool{}
	for _, prior := range x.journal.Reservations {
		if prior.Slot == r.Slot {
			if prior.Nonce == r.Nonce {
				result = x.receipt(prior)
				result.Status = "already-executed"
				result.Reason = "DURABLE_RESERVATION_NO_RETRY"
				result.AuthorityReason = authorityReason
				return result
			}
			spent += prior.Debit
		}
		for _, p := range prior.Inputs {
			used[p.key()] = true
		}
	}
	if authorityReason != "" {
		return refuse(authorityReason)
	}
	if len(x.journal.Reservations) >= 10000 {
		return refuse("JOURNAL_LIMIT")
	}
	reserve := Reservation{Slot: r.Slot, Nonce: r.Nonce, EventID: r.Event.ID, Action: r.Action, TargetHash: Hash([]byte(r.Target)), Inputs: []Point{}, Phase: "reserved"}
	var plan paymentPlan
	if r.Action == "pay" {
		if r.Amount > MaxMoney-s.Wallet.Fee || r.Amount+s.Wallet.Fee > cert.BudgetSat-spent {
			return refuse("BUDGET_EXCEEDED")
		}
		plan, e = buildPayment(ctx, x.node, s.Wallet, x.config.Prize, r.Target, r.Amount, used)
		if e != nil {
			return refuse(e.Error())
		}
		reserve.Debit = plan.Debit
		reserve.Inputs = plan.Inputs
		reserve.TxID = plan.TxID
	}
	if r.Action == "deliver" {
		reserve.FileHash = Hash(file)
		reserve.RetainUntil = x.now().Unix() + 7*24*60*60
	}
	// Planning can take time; recheck the real kernel immediately before commit.
	if reason := check(); reason != "" {
		return refuse(reason)
	}
	if ctx.Err() != nil || x.now().Unix() >= cert.NotAfter {
		return refuse("EFFECT_EXPIRED")
	}
	x.journal.Reservations = append(x.journal.Reservations, reserve)
	if e = x.persist(); e != nil {
		return refuse(e.Error())
	}
	index := len(x.journal.Reservations) - 1
	result.Phase = "reserved"
	if x.hook != nil {
		x.hook("reserved")
	}
	// An expired grant after fsync consumes the reservation without an effect.
	if ctx.Err() != nil || x.now().Unix() >= cert.NotAfter {
		return refuse("EFFECT_EXPIRED")
	}
	switch r.Action {
	case "pay":
		id, e := x.broadcast.Broadcast(ctx, plan.Raw)
		if e != nil || id != plan.TxID {
			return refuse("BROADCAST_UNCERTAIN")
		}
		result.TxID = id
	case "deliver":
		name := "file-" + r.Slot + "-" + r.Nonce
		if e = x.store.write(name, file); e != nil {
			return refuse("DELIVERY_UNCERTAIN")
		}
		result.FileHash = reserve.FileHash
		result.Link = "file://" + x.store.root + "/" + name
		result.RetainUntil = reserve.RetainUntil
	case "publish", "repository.push":
		if e = x.store.write("effect-"+r.Slot+"-"+r.Nonce+".json", canonical(struct{ Action, TargetHash, EventID string }{r.Action, reserve.TargetHash, r.Event.ID})); e != nil {
			return refuse("LOCAL_EFFECT_UNCERTAIN")
		}
	default:
		return refuse("ACTION_SCOPE")
	}
	if x.hook != nil {
		x.hook("effect")
	}
	x.journal.Reservations[index].Phase = "complete"
	if e = x.persist(); e != nil {
		return refuse(e.Error())
	}
	result.Status = "executed"
	result.Reason = "LIVE_RENTER_REQUEST"
	result.Phase = "complete"
	return result
}
func ExecutorHandler(x *Executor) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/slots/") {
			if r.Method != "GET" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
				respond(w, 400, map[string]string{"status": "refused", "reason": "HTTP_SCHEMA"})
				return
			}
			result, e := x.ListSlot(strings.TrimPrefix(r.URL.Path, "/slots/"))
			if e != nil {
				code := 503
				if e.Error() == "SLOT_UNKNOWN" {
					code = 404
				}
				if e.Error() == "SLOT_FORMAT" {
					code = 400
				}
				respond(w, code, map[string]string{"status": "refused", "reason": e.Error()})
				return
			}
			respond(w, 200, result)
			return
		}
		var q struct {
			Event json.RawMessage `json:"event"`
			File  string          `json:"file_base64"`
		}
		if r.URL.Path != "/execute" || readBody(r, &q) != nil {
			respond(w, 400, map[string]string{"status": "refused", "reason": "HTTP_SCHEMA"})
			return
		}
		file, e := base64.StdEncoding.Strict().DecodeString(q.File)
		if e != nil || base64.StdEncoding.EncodeToString(file) != q.File {
			respond(w, 400, map[string]string{"status": "refused", "reason": "FILE_ENCODING"})
			return
		}
		receipt := x.Execute(r.Context(), q.Event, file)
		respond(w, receiptHTTPStatus(receipt), receipt)
	})
}

// PublicKey derives a public key only; private configuration is never emitted.
func PublicKey(secret string) (string, error) {
	k, e := privateKey(secret)
	if e != nil {
		return "", e
	}
	return hex.EncodeToString(k.PubKey().SerializeCompressed()), nil
}

func (x *Executor) receipt(r Reservation) Receipt {
	out := Receipt{Status: "recorded", Reason: "DURABLE_RESERVATION", Slot: r.Slot, EventID: r.EventID, Action: r.Action, Phase: r.Phase, TxID: r.TxID, FileHash: r.FileHash, RetainUntil: r.RetainUntil}
	if r.Action == "deliver" && r.Phase == "complete" {
		out.Link = "file://" + x.store.root + "/file-" + r.Slot + "-" + r.Nonce
	}
	return out
}

type SlotExport struct {
	Slot         string    `json:"slot"`
	Effects      []Receipt `json:"effects"`
	Deliverables []Receipt `json:"deliverables"`
}

// ListSlot is a local journal projection: no kernel call, journal mutation,
// key release or effect. Reserved records remain explicitly uncertain.
func (x *Executor) ListSlot(slot string) (SlotExport, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	out := SlotExport{Slot: slot, Effects: []Receipt{}, Deliverables: []Receipt{}}
	if x.store.poison {
		return out, fail("STATE_UNAVAILABLE")
	}
	if !hexN(slot, 32) {
		return out, fail("SLOT_FORMAT")
	}
	if _, ok := x.slots[slot]; !ok {
		return out, fail("SLOT_UNKNOWN")
	}
	for _, r := range x.journal.Reservations {
		if r.Slot != slot {
			continue
		}
		out.Effects = append(out.Effects, x.receipt(r))
		if r.Action == "deliver" && r.Phase == "complete" {
			out.Deliverables = append(out.Deliverables, x.receipt(r))
		}
	}
	return out, nil
}
func receiptHTTPStatus(r Receipt) int {
	if r.Status != "refused" {
		return http.StatusOK
	}
	if r.Reason == "SLOT_UNKNOWN" {
		return http.StatusNotFound
	}
	if strings.Contains(r.Reason, "UNAVAILABLE") || strings.Contains(r.Reason, "UNCERTAIN") || strings.HasPrefix(r.Reason, "STATE_") {
		return http.StatusServiceUnavailable
	}
	if strings.HasPrefix(r.Reason, "EVENT_") || strings.HasPrefix(r.Reason, "REQUEST_") || strings.HasPrefix(r.Reason, "FILE_") {
		return http.StatusBadRequest
	}
	if strings.HasPrefix(r.Reason, "BUDGET_") || r.Reason == "JOURNAL_LIMIT" {
		return http.StatusConflict
	}
	return http.StatusForbidden
}
