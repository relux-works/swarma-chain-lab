package g1bench

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"time"

	cg "github.com/relux-works/swarma-chain-lab/experiments/grantcheck"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// Event's routing fields come from the trusted carrier adapter. MatrixSender
// is deliberately retained as untrusted diagnostic input, never authority.
type Event struct {
	Content                             []byte
	Text, Room, Recipient, MatrixSender string
	OwnerDM                             bool
}

// Result describes routing observations only; there is no effect callback.
type Result struct {
	Route   string
	Code    string
	Verdict cg.Verdict
}
type Gate struct {
	checker       *cg.Checker
	node          su.Node
	minimumHeight int64
	executor      string
	now           func() time.Time
	mu            sync.Mutex
	seen          map[string]bool
	bindings      map[string]string
}

func New(checker *cg.Checker, executor string, node su.Node, minimumHeight int64, now func() time.Time, bindings map[string]string) *Gate {
	if now == nil {
		now = time.Now
	}
	pins := make(map[string]string, len(bindings))
	for id, key := range bindings {
		pins[id] = key
	}
	return &Gate{bindings: pins, checker: checker, executor: executor, node: node, minimumHeight: minimumHeight, now: now, seen: map[string]bool{}}
}

func (g *Gate) Admit(ctx context.Context, event Event) Result {
	refuse := func(code string) Result { return Result{Route: "refused", Code: code} }
	if event.OwnerDM {
		return Result{Route: "outside_admission", Code: "owner_dm"}
	}
	if len(event.Content) == 0 || len(event.Content) > 60<<10 {
		return refuse("envelope_missing")
	}
	// Require the exact fixed carriage shape; aliases, duplicate members and
	// unrelated JSON are outside this small bench profile.
	var content map[string]any
	if json.Unmarshal(event.Content, &content) != nil || (len(content) != 3 && len(content) != 4) || content["msgtype"] != "m.text" || content["body"] != event.Text {
		return refuse("carriage_invalid")
	}
	encoded, ok := content[ContentKey].(string)
	if !ok || encoded == "" {
		return refuse("envelope_missing")
	}
	if string(Canonical(content)) != string(event.Content) {
		return refuse("carriage_invalid")
	}
	raw, err := decode(encoded, maxEnvelope)
	if err != nil {
		return refuse("envelope_invalid")
	}
	e, _, err := verify(raw, event.Text, event.Room, event.Recipient, g.now())
	if err != nil {
		return refuse("envelope_invalid")
	}
	// Envelope verification always precedes co-signature verification.
	co, exists := content[CosignatureContentKey]
	if !exists {
		return refuse("cosignature_missing")
	}
	key, err := (BIP340{}).Verify(raw, co)
	if err != nil {
		return refuse("cosignature_invalid")
	}
	proof, err := decode(e.Body.Arguments.Presentation, cg.MaxPresentationBytes)
	if err != nil {
		return refuse("presentation_invalid")
	}
	p := cg.Presentation{GrantID: e.Body.Arguments.GrantID, Bytes: proof}
	parsed, err := rental.ParseGrantPresentation(proof)
	if err != nil {
		return refuse("presentation_invalid")
	}
	terms, err := decode(e.Body.Arguments.Terms, cg.MaxPresentationBytes)
	if err != nil || rental.Hash(terms) != parsed.SignedGrant.Grant.ContractSHA256 {
		return refuse("terms_invalid")
	}
	var pay rental.PayTermsV2
	if json.Unmarshal(terms, &pay) != nil {
		return refuse("terms_invalid")
	}
	canonical, err := rental.EncodePayTermsV2(pay)
	if err != nil || string(canonical) != string(terms) {
		return refuse("terms_invalid")
	}
	if pay.ExecutorKey != g.executor {
		return refuse("executor_mismatch")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	replay := e.ID
	if g.seen[replay] {
		return refuse("replay")
	}
	if len(g.seen) >= 4096 {
		return refuse("replay_capacity")
	}
	if err := g.fresh(ctx); err != nil {
		return refuse("node_not_synced")
	}
	verdict := g.checker.InboundFrom(ctx, cg.SenderProof{Transport: cg.SwarmEnvelopeV2, Key: key}, &p)
	route, _, _ := verdict.A2ADecision()
	if route != "live" {
		return Result{Route: "refused", Code: string(verdict.Code), Verdict: verdict}
	}
	g.seen[replay] = true
	return Result{Route: "live", Code: "live", Verdict: verdict}
}
func Carry(raw []byte, text string, cosignature ...map[string]any) []byte {
	content := map[string]any{"msgtype": "m.text", "body": text, ContentKey: base64.RawURLEncoding.EncodeToString(raw)}
	if len(cosignature) == 1 {
		content[CosignatureContentKey] = cosignature[0]
	}
	return Canonical(content)
}

// Outbound checks exactly one signed recipient per envelope. Bindings are copied
// from the identity's protected harness config, never read from carrier content.
func (g *Gate) Outbound(ctx context.Context, event Event) Result {
	deny := func(code string) Result { return Result{Route: "refused", Code: code} }
	if len(event.Content) == 0 || len(event.Content) > 60<<10 {
		return deny("envelope_missing")
	}
	var content map[string]any
	if json.Unmarshal(event.Content, &content) != nil || len(content) != 4 || content["msgtype"] != "m.text" || content["body"] != event.Text || string(Canonical(content)) != string(event.Content) {
		return deny("carriage_invalid")
	}
	encoded, ok := content[ContentKey].(string)
	if !ok {
		return deny("envelope_missing")
	}
	raw, err := decode(encoded, maxEnvelope)
	if err != nil {
		return deny("envelope_invalid")
	}
	e, _, err := verify(raw, event.Text, event.Room, event.Recipient, g.now())
	if err != nil {
		return deny("envelope_invalid")
	}
	if _, err := (BIP340{}).Verify(raw, content[CosignatureContentKey]); err != nil {
		return deny("cosignature_invalid")
	}
	key, ok := g.bindings[e.Body.To]
	if !ok || key == "" {
		return deny("recipient_unresolved")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.seen["out:"+e.ID] {
		return deny("replay")
	}
	if len(g.seen) >= 4096 {
		return deny("replay_capacity")
	}
	if err := g.fresh(ctx); err != nil {
		return deny("node_not_synced")
	}
	verdict := g.checker.OutboundFrom(ctx, cg.RecipientProof{Transport: cg.SwarmEnvelopeV2, Keys: []string{key}})
	route, _, _ := verdict.A2ADecision()
	if route != "live" {
		return Result{Route: "refused", Code: string(verdict.Code), Verdict: verdict}
	}
	g.seen["out:"+e.ID] = true
	return Result{Route: "live", Code: "live", Verdict: verdict}
}

// fresh adds a conservative bench floor to the existing own-node checks. The
// floor is protected harness configuration, never a field in an envelope.
func (g *Gate) fresh(ctx context.Context) error {
	if g.node == nil {
		return errors.New("bench node missing")
	}
	raw, err := g.node.Call(ctx, "getblockchaininfo")
	var info su.ChainInfo
	if err != nil || json.Unmarshal(raw, &info) != nil {
		return errors.New("bench node unavailable")
	}
	if info.Chain != "regtest" || info.IBD || info.Blocks < g.minimumHeight || info.Headers > info.Blocks {
		return errors.New("bench node not synced")
	}
	return nil
}
