package grantcheck

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	bitcoinwire "github.com/btcsuite/btcd/wire"
	"github.com/relux-works/swarma-chain-lab/experiments/grant-v4/identity"
	v4wire "github.com/relux-works/swarma-chain-lab/experiments/grant-v4/wire"
)

// A child's Required result stays reader-owned, while the reported proposal
// interpretation retains each undetermined root parent's refusal.
func TestV4ParentProposalOutcome(t *testing.T) {
	groups, rows := v4Vectors(t)
	c := v4Checker(t, nil)
	for _, parentRow := range append([]v4Vector{rows["grant-v-03"]}, groups["undetermined"]...) {
		t.Run(parentRow.ID, func(t *testing.T) {
			parent, err := v4Read(t, c, parentRow, rows)
			if err != nil {
				t.Fatal("parent control", err)
			}
			var payload map[string]any
			decoder := json.NewDecoder(strings.NewReader(rows["grant-v-05"].Payload))
			decoder.UseNumber()
			if err := decoder.Decode(&payload); err != nil {
				t.Fatal(err)
			}
			payload["parent"] = parent.Required.ID()
			encoded, err := v4wire.EncodeDocument(payload, v4wire.MaxGrantSize)
			if err != nil {
				t.Fatal(err)
			}
			digest, err := v4wire.TypedDigest(encoded)
			if err != nil {
				t.Fatal(err)
			}
			scalar := make([]byte, 32)
			scalar[31] = 9 // Published vector delegate scalar, never custody material.
			key, _ := btcec.PrivKeyFromBytes(scalar)
			signature := signHash(t, key, hex.EncodeToString(digest[:]))
			raw := append([]byte(`{"payload":`), encoded...)
			raw = append(raw, []byte(`,"signature":"`+signature+`"}`)...)
			reader, err := v4wire.VerifyGrant(raw, v4wire.GrantContext{Parent: parent.Required})
			if err != nil {
				t.Fatal("reader positive control", err)
			}
			child, err := c.VerifyV4Document(raw, V4DocumentContext{Parent: parent.Required})
			want := "ok"
			if strings.HasPrefix(parentRow.ID, "grant-u-") {
				want = "GRANT_DELEGATE"
			}
			if err != nil || child == nil || child.ProposalOutcome != want || !bytes.Equal(child.Required.Bytes(), reader.Bytes()) {
				t.Fatalf("parent proposal: document=%v error=%v want %s", child, err, want)
			}
		})
	}
}

// Cancelled/nil contexts win before the offline v4 admission refusal. Neither
// path creates a backend/cache; an active context still refuses unavailable.
func TestV4ProvisionCancelled(t *testing.T) {
	c := v4Checker(t, nil)
	if v := c.Provision(context.Background(), Presentation{}); v.Code != CodeVerifierUnavailable || v.Decision != Refused {
		t.Fatal(v)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, ctx} {
		if v := c.Provision(ctx, Presentation{}); v.Code != CodeCancelled || v.Decision != Refused || v.Closed {
			t.Fatal(v)
		}
	}
	if c.backend != nil || c.node != nil {
		t.Fatal("offline provision gained mutable state")
	}
}

type holderFixtureFunc func(context.Context, HolderSealRequest) (HolderSealObservation, error)

func (f holderFixtureFunc) ReadHolderSeal(ctx context.Context, request HolderSealRequest) (HolderSealObservation, error) {
	return f(ctx, request)
}

type holderRefusalFixture struct {
	ctx                   context.Context
	value, list           []byte
	landlord, name, owner string
	request               HolderSealRequest
	observation           HolderSealObservation
	tx                    *bitcoinwire.MsgTx
	seal                  identity.HolderOutpoint
	viewError             error
	cancelOnRead          bool
}

func (f *holderRefusalFixture) repin(t *testing.T) {
	t.Helper()
	f.list = []byte(fmt.Sprintf(`{"schema":"swarma-holders-list/1","network":"main","owner":"id/example","seq":1,"holders":[{"name":"id/example-agent","key":"%s","seal":{"txid":"%s","vout":%d}}]}`, f.owner, f.seal.TxID, f.seal.Vout))
	hash := sha256.Sum256(f.list)
	f.value = []byte(fmt.Sprintf(`{"swarma-holders":{"seq":1,"sha256":"%x"}}`, hash))
	f.request.Seal = f.seal
}
func (f *holderRefusalFixture) refund(t *testing.T) {
	t.Helper()
	var b bytes.Buffer
	if err := f.tx.Serialize(&b); err != nil {
		t.Fatal(err)
	}
	f.observation.funding = b.Bytes()
	f.seal.TxID = f.tx.TxHash().String()
	f.repin(t)
}
func newHolderRefusalFixture(t *testing.T) *holderRefusalFixture {
	t.Helper()
	f := &holderRefusalFixture{ctx: context.Background(), landlord: "id/example", name: "id/example-agent", owner: "022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01"}
	pin, err := identity.ParsePin(f.owner)
	if err != nil {
		t.Fatal(err)
	}
	hash := pin.Hash160()
	f.tx = bitcoinwire.NewMsgTx(2)
	f.tx.AddTxIn(bitcoinwire.NewTxIn(&bitcoinwire.OutPoint{Index: 1}, nil, nil))
	f.tx.AddTxOut(bitcoinwire.NewTxOut(1000, append([]byte{0, 20}, hash[:]...)))
	f.tx.AddTxOut(bitcoinwire.NewTxOut(1000, append([]byte{0, 20}, hash[:]...)))
	f.request = HolderSealRequest{Tip: HolderTip{strings.Repeat("a", 64), 200}, PinAnchor: HolderTip{strings.Repeat("b", 64), 150}}
	f.observation = HolderSealObservation{enforcementGrade: true, tip: f.request.Tip, fundingBlock: HolderTip{strings.Repeat("c", 64), 100}, unspent: true}
	f.refund(t)
	return f
}

// Each refusal is paired with the same live, hash-pinned fixture. These cases
// cover the opaque seam only; they establish no production adapter provenance.
func TestV4HolderRefusals(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*holderRefusalFixture)
		want   error
		noRead bool
	}{
		{"request-other-vout", func(f *holderRefusalFixture) { f.request.Seal.Vout = 1 }, ErrV4Unavailable, true},
		{"request-other-txid", func(f *holderRefusalFixture) { f.request.Seal.TxID = strings.Repeat("d", 64) }, ErrV4Unavailable, true},
		{"tip-mismatch", func(f *holderRefusalFixture) { f.observation.tip.Height++ }, ErrV4Unavailable, false},
		{"tip-hash-form", func(f *holderRefusalFixture) {
			f.request.Tip.Hash = strings.Repeat("A", 64)
			f.observation.tip = f.request.Tip
		}, ErrV4Unavailable, false},
		{"tip-height-form", func(f *holderRefusalFixture) {
			f.request.Tip.Height = v4wire.MaxNumber + 1
			f.observation.tip = f.request.Tip
		}, ErrV4Unavailable, false},
		{"anchor-hash-form", func(f *holderRefusalFixture) { f.request.PinAnchor.Hash = "ab" }, ErrV4Unavailable, false},
		{"anchor-height-form", func(f *holderRefusalFixture) { f.request.PinAnchor.Height = v4wire.MaxNumber + 1 }, ErrV4Unavailable, false},
		{"anchor-above-tip", func(f *holderRefusalFixture) { f.request.PinAnchor.Height = 201 }, ErrV4Unavailable, false},
		{"funding-empty", func(f *holderRefusalFixture) { f.observation.funding = nil }, ErrV4Unavailable, false},
		{"funding-oversized", func(f *holderRefusalFixture) { f.observation.funding = make([]byte, 4000001) }, ErrV4Unavailable, false},
		{"funding-truncated", func(f *holderRefusalFixture) { f.observation.funding = f.observation.funding[:8] }, ErrV4Unavailable, false},
		{"funding-trailing", func(f *holderRefusalFixture) { f.observation.funding = append(bytes.Clone(f.observation.funding), 0) }, ErrV4Unavailable, false},
		{"funding-txid", func(f *holderRefusalFixture) {
			f.tx.LockTime++
			var b bytes.Buffer
			if err := f.tx.Serialize(&b); err != nil {
				t.Fatal(err)
			}
			f.observation.funding = b.Bytes()
		}, ErrV4Unavailable, false},
		{"funding-block-form", func(f *holderRefusalFixture) { f.observation.fundingBlock.Hash = "bad" }, ErrV4SealNotLive, false},
		{"vout-out-of-range", func(f *holderRefusalFixture) { f.seal.Vout = 2; f.repin(t) }, ErrV4SealNotLive, false},
		{"funding-non-p2wpkh", func(f *holderRefusalFixture) { f.tx.TxOut[0].PkScript = []byte{0x51}; f.refund(t) }, ErrV4SealNotLive, false},
		{"funding-wrong-key", func(f *holderRefusalFixture) {
			f.tx.TxOut[0].PkScript = append([]byte{0, 20}, bytes.Repeat([]byte{1}, 20)...)
			f.refund(t)
		}, ErrV4SealNotLive, false},
		{"funding-negative-value", func(f *holderRefusalFixture) { f.tx.TxOut[0].Value = -1; f.refund(t) }, ErrV4SealNotLive, false},
		{"spenders", func(f *holderRefusalFixture) { f.observation.spenders = []HolderSpender{{}} }, ErrV4Unavailable, false},
		{"watcher-funding", func(f *holderRefusalFixture) { f.observation.watcherFunding = []byte{1} }, ErrV4Unavailable, false},
		{"watcher-spenders", func(f *holderRefusalFixture) { f.observation.watcherSpenders = []HolderSpender{{}} }, ErrV4Unavailable, false},
		{"cancelled-context", func(f *holderRefusalFixture) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			f.ctx = ctx
		}, ErrV4Unavailable, true},
		{"nil-context", func(f *holderRefusalFixture) { f.ctx = nil }, ErrV4Unavailable, true},
		{"cancelled-on-read", func(f *holderRefusalFixture) { f.cancelOnRead = true }, ErrV4Unavailable, false},
		{"view-error", func(f *holderRefusalFixture) { f.viewError = errors.New("fixture unavailable") }, ErrV4Unavailable, false},
		{"absent-pin", func(f *holderRefusalFixture) { f.value = []byte(`{}`) }, ErrV4Holder, true},
		{"nil-list", func(f *holderRefusalFixture) { f.list = nil }, ErrV4ListUnknown, true},
		{"name-mismatch", func(f *holderRefusalFixture) { f.name = "id/other" }, ErrV4Holder, true},
		{"key-mismatch", func(f *holderRefusalFixture) { f.owner = "03" + f.owner[2:] }, ErrV4Holder, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newHolderRefusalFixture(t)
			calls := 0
			var cancel context.CancelFunc
			c := v4Checker(t, holderFixtureFunc(func(ctx context.Context, request HolderSealRequest) (HolderSealObservation, error) {
				calls++
				if request != f.request {
					t.Fatal("view received a substitute request")
				}
				if f.cancelOnRead {
					cancel()
				}
				return f.observation, f.viewError
			}))
			check := func() error {
				return c.VerifyV4HolderDocument(f.ctx, f.value, f.list, f.landlord, f.name, f.owner, f.request)
			}
			if err := check(); err != nil || calls != 1 {
				t.Fatal("live fixture control", err, calls)
			}
			calls = 0
			tc.mutate(f)
			if f.cancelOnRead {
				f.ctx, cancel = context.WithCancel(context.Background())
				defer cancel()
			}
			beforeFunding, beforeList := bytes.Clone(f.observation.funding), bytes.Clone(f.list)
			if err := check(); !errors.Is(err, tc.want) {
				t.Fatalf("holder refusal: got %v want %v", err, tc.want)
			}
			if tc.noRead && calls != 0 {
				t.Fatal("refused context reached seal view")
			}
			if !bytes.Equal(beforeFunding, f.observation.funding) || !bytes.Equal(beforeList, f.list) {
				t.Fatal("holder refusal mutated input")
			}
			if c.backend != nil || c.node != nil {
				t.Fatal("holder refusal created mutable state")
			}
		})
	}
}
