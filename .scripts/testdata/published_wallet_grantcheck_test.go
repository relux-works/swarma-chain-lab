package published

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	gc "github.com/relux-works/swarma-chain-lab/experiments/grantcheck"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernel"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

func publishedFixture(t *testing.T) (*coreLab, []string, []gc.Presentation, int64, int64) {
	t.Helper()
	agent, err := nostr.GeneratePrivKey()
	if err != nil {
		t.Fatal(err)
	}
	l := newCoreLab(t, agent.PubKeyHex())
	var keys []string
	var proofs []gc.Presentation
	for _, label := range []string{"first", "second"} {
		peer, err := nostr.GeneratePrivKey()
		if err != nil {
			t.Fatal(err)
		}
		raw := l.grant(peer, label, l.seal(), true)
		id, err := kernel.PresentationID(raw)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, peer.PubKeyHex())
		proofs = append(proofs, gc.Presentation{GrantID: id, Bytes: raw})
	}
	var info su.ChainInfo
	if err := json.Unmarshal(l.rpc("", "getblockchaininfo"), &info); err != nil {
		t.Fatal(err)
	}
	var header struct {
		Time int64 `json:"time"`
	}
	if err := json.Unmarshal(l.rpc("", "getblockheader", info.Best), &header); err != nil {
		t.Fatal(err)
	}
	return l, keys, proofs, info.Blocks, header.Time
}

func publishedChecker(t *testing.T, l *coreLab, height int64, now func() time.Time) (*gc.Checker, string) {
	t.Helper()
	dir, err := os.MkdirTemp(l.private, "published-checker-")
	if err != nil {
		t.Fatal(err)
	}
	c, err := gc.New(gc.Config{ConstructionProfile: "W", Identity: "published-test", AgentName: e2eAgentName,
		LandlordName: e2eLandlordName, IssuerPubkey: l.issuerPub, ExecutorKey: xonly(9), Terms: unitTermsLookup,
		Freshness: testFreshness(time.Minute, 2*time.Minute, height), StateDir: dir, Node: l.observer, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return c, dir
}

func publishedState(t *testing.T, dir string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "grantcheck.json"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Claim: the wallet-selected public checker admits the exact-A control but
// refuses A+1ns reached only at the aggregate final clock sample without a write.
func TestPublishedFinalSampleFreshness(t *testing.T) {
	l, keys, proofs, height, tip := publishedFixture(t)
	for _, delta := range []time.Duration{0, time.Nanosecond} {
		t.Run(delta.String(), func(t *testing.T) {
			active, reads := false, 0
			c, dir := publishedChecker(t, l, height, func() time.Time {
				if !active {
					return time.Unix(tip, 0)
				}
				reads++
				at := time.Unix(tip+60, 0)
				if reads >= 7 {
					at = at.Add(delta)
				}
				return at
			})
			for _, proof := range proofs {
				if v := c.Provision(context.Background(), proof); v.Decision != gc.Live {
					t.Fatalf("published provision: %+v", v)
				}
			}
			before := publishedState(t, dir)
			active = true
			v := c.OutboundFrom(context.Background(), gc.RecipientProof{Transport: gc.NostrNIP17Seal, Keys: keys})
			if reads != 7 {
				t.Fatalf("published final sample not reached: %d", reads)
			}
			if delta == 0 {
				if v.Decision != gc.Live || v.Code != gc.CodeLive {
					t.Fatalf("published exact-A control: %+v", v)
				}
			} else {
				if v.Decision != gc.Refused || v.Code != gc.CodeTipStale || !v.Retryable {
					t.Fatalf("published final-sample stale admitted: %+v", v)
				}
				if len(v.Scope) != 0 || v.GrantID != "" || !bytes.Equal(before, publishedState(t, dir)) {
					t.Fatal("published stale refusal changed state or leaked live metadata")
				}
			}
		})
	}
}

// Claim: a public aggregate stages all durable state through final acceptance;
// the live control commits, while a missing second recipient preserves bytes.
func TestPublishedAggregateAtomic(t *testing.T) {
	l, keys, proofs, height, tip := publishedFixture(t)
	for _, missing := range []bool{false, true} {
		name := "Live"
		if missing {
			name = "Missing"
		}
		t.Run(name, func(t *testing.T) {
			active, staged := false, true
			var before []byte
			var dir string
			c, stateDir := publishedChecker(t, l, height, func() time.Time {
				if !active {
					return time.Unix(tip, 0)
				}
				staged = staged && bytes.Equal(before, publishedState(t, dir))
				return time.Unix(tip+60, 0)
			})
			dir = stateDir
			count := 2
			if missing {
				count = 1
			}
			for _, p := range proofs[:count] {
				v := c.Provision(context.Background(), p)
				if v.Decision != gc.Live {
					t.Fatalf("published provision: %+v", v)
				}
			}
			before = publishedState(t, dir)
			active = true
			v := c.OutboundFrom(context.Background(), gc.RecipientProof{Transport: gc.NostrNIP17Seal, Keys: keys})
			after := publishedState(t, dir)
			if missing {
				if v.Decision != gc.Refused || v.Code != gc.CodeNoGrant {
					t.Fatalf("published missing-recipient verdict: %+v", v)
				}
				if !bytes.Equal(before, after) {
					t.Fatal("published aggregate refusal changed durable state")
				}
			} else {
				if v.Decision != gc.Live || v.Code != gc.CodeLive || bytes.Equal(before, after) {
					t.Fatalf("published live aggregate control: %+v", v)
				}
				if !staged {
					t.Fatal("published aggregate wrote before final acceptance")
				}
			}
		})
	}
}
