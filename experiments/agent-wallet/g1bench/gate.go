package g1bench

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"sync"
	"time"

	cg "github.com/relux-works/swarma-chain-lab/experiments/grantcheck"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
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
}

func New(checker *cg.Checker, executor string, node su.Node, minimumHeight int64, now func() time.Time) *Gate {
	if now == nil {
		now = time.Now
	}
	return &Gate{checker: checker, executor: executor, node: node, minimumHeight: minimumHeight, now: now, seen: map[string]bool{}}
}

// inbound is the only compatibility seam for the current main API. Its sender
// argument comes exclusively from verify, never a carrier identity or body field.
func inbound(ctx context.Context, c *cg.Checker, key string, p *cg.Presentation) cg.Verdict {
	return c.Inbound(ctx, key, p)
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
	var content map[string]string
	if json.Unmarshal(event.Content, &content) != nil || len(content) != 3 || content["msgtype"] != "m.text" || content["body"] != event.Text {
		return refuse("carriage_invalid")
	}
	encoded, ok := content[ContentKey]
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
	e, key, err := verify(raw, event.Text, event.Room, event.Recipient, g.now())
	if err != nil {
		return refuse("envelope_invalid")
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
	replay := key + ":" + e.Body.Nonce
	if g.seen[replay] {
		return refuse("replay")
	}
	if len(g.seen) >= 4096 {
		return refuse("replay_capacity")
	}
	if err := g.fresh(ctx); err != nil {
		return refuse("node_not_synced")
	}
	verdict := inbound(ctx, g.checker, key, &p)
	if verdict.Decision != cg.Live {
		return Result{Route: "refused", Code: string(verdict.Code), Verdict: verdict}
	}
	g.seen[replay] = true
	return Result{Route: "live", Code: "live", Verdict: verdict}
}
func Carry(raw []byte, text string) []byte {
	return Canonical(map[string]string{"msgtype": "m.text", "body": text, ContentKey: base64.RawURLEncoding.EncodeToString(raw)})
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
