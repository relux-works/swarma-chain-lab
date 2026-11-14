package grantcheck

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernel"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
)

type recordedVector struct {
	Name         string        `json:"name"`
	Direction    string        `json:"direction"`
	Peer         string        `json:"peer"`
	Supplied     bool          `json:"supplied"`
	Proof        *Presentation `json:"proof,omitempty"`
	VerifierTime int64         `json:"verifier_time"`
	Setup        string        `json:"setup"`
	Expected     Verdict       `json:"expected"`
}
type vectorFile struct {
	Version      int              `json:"version"`
	Producer     string           `json:"producer"`
	DaemonSHA256 string           `json:"daemon_sha256"`
	CLISHA256    string           `json:"cli_sha256"`
	AgentName    string           `json:"agent_name"`
	LandlordName string           `json:"landlord_name"`
	IssuerPubkey string           `json:"issuer_pubkey"`
	Vectors      []recordedVector `json:"vectors"`
}

// Every live observation uses New's real adapter and a grant produced by the
// real issuer on isolated pinned Core. Pending rotation and mempool spending
// have valid pre-transition controls; restart cannot reopen closed cached proof.
func TestCoreVectors(t *testing.T) {
	if os.Getenv("CG1_REGTEST") != "1" {
		t.Skip("requires CG1_REGTEST=1 and pinned isolated Core")
	}
	agent, err := nostr.GeneratePrivKey()
	if err != nil {
		t.Fatal(err)
	}
	l := newCoreLab(t, agent.PubKeyHex())
	renter1, err := nostr.GeneratePrivKey()
	if err != nil {
		t.Fatal(err)
	}
	renter2, err := nostr.GeneratePrivKey()
	if err != nil {
		t.Fatal(err)
	}
	seal1, seal2 := l.seal(), l.seal()
	raw1 := l.grant(renter1, "grant-one", seal1, true)
	raw2 := l.grant(renter2, "grant-two", seal2, true)
	presentation := func(raw []byte) Presentation {
		id, e := kernel.PresentationID(raw)
		if e != nil {
			t.Fatal(e)
		}
		return Presentation{GrantID: id, Bytes: raw}
	}
	p1, p2 := presentation(raw1), presentation(raw2)
	config := func(label string, now int64) Config {
		root := filepath.Join(l.private, label)
		if e := os.Mkdir(root, 0700); e != nil {
			t.Fatal(e)
		}
		return Config{ConstructionProfile: "W", Identity: label, AgentName: e2eAgentName, LandlordName: e2eLandlordName, IssuerPubkey: l.issuerPub, StateDir: root, Node: l.observer, Now: func() time.Time { return time.Unix(now, 0) }}
	}
	makeChecker := func(c Config) *Checker {
		v, e := New(c)
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	mainConfig := config("primary", 500)
	c := makeChecker(mainConfig)
	ctx := context.Background()
	file := vectorFile{Version: 1, Producer: "TestCoreVectors: rental.IssueGrant + grantcheck.New on isolated Namecoin Core regtest", DaemonSHA256: coreFileHash(t, l.daemon), CLISHA256: coreFileHash(t, l.cli), AgentName: e2eAgentName, LandlordName: e2eLandlordName, IssuerPubkey: l.issuerPub}
	record := func(name, direction, peer, setup string, proof *Presentation, supplied bool, now int64, v Verdict, decision Decision, code Code, closed, retry bool) {
		t.Helper()
		assertVerdict(t, v, decision, code, closed, retry)
		file.Vectors = append(file.Vectors, recordedVector{Name: name, Direction: direction, Peer: peer, Proof: proof, Supplied: supplied, VerifierTime: now, Setup: setup, Expected: v})
		t.Log("control " + name + " PASS")
	}
	peer := renter1.PubKeyHex()
	peer2 := renter2.PubKeyHex()
	record("absent-in", "in", peer, "fresh identity", nil, false, 500, c.Inbound(ctx, peer, nil), Exchange, CodeNoGrant, false, false)
	record("absent-out", "out", peer, "fresh identity", nil, false, 500, c.Outbound(ctx, peer), Refused, CodeNoGrant, false, false)
	record("live-in", "in", peer, "confirmed issuer-produced issuance", &p1, true, 500, c.Inbound(ctx, peer, &p1), Live, CodeLive, false, false)
	record("live-out", "out", peer, "after live-in", &p1, false, 500, c.Outbound(ctx, peer), Live, CodeLive, false, false)
	record("live-cache", "in", peer, "after live-in", &p1, false, 500, c.Inbound(ctx, peer, nil), Live, CodeLive, false, false)
	record("foreign", "in", peer2, "other grantee, no fallback", &p1, true, 500, c.Inbound(ctx, peer2, &p1), Refused, CodeBindingMismatch, false, false)
	for _, tc := range []struct {
		name string
		now  int64
		code Code
	}{{"not-yet", 299, CodeNotYet}, {"expired", 1000, CodeExpired}} {
		x := makeChecker(config(tc.name, tc.now))
		record(tc.name, "in", peer, "fresh state at boundary", &p1, true, tc.now, x.Inbound(ctx, peer, &p1), Exchange, tc.code, false, false)
	}
	isolated := makeChecker(config("other-identity", 500))
	record("identity-isolation", "out", peer, "another identity has no cache", nil, false, 500, isolated.Outbound(ctx, peer), Refused, CodeNoGrant, false, false)
	for _, tc := range []struct {
		name string
		p    Presentation
		code Code
	}{
		{"malformed", Presentation{Bytes: []byte("{broken")}, CodeInvalidPresentation},
		{"legacy", Presentation{GrantID: p1.GrantID, Bytes: []byte(strings.Replace(string(p1.Bytes), `"version":3`, `"version":2`, 1))}, CodeInvalidPresentation},
		{"oversize", Presentation{Bytes: make([]byte, MaxPresentationBytes+1)}, CodeOversize},
	} {
		copy := tc.p
		record(tc.name, "in", peer, "valid cached proof cannot rescue explicit bad input", &copy, true, 500, c.Inbound(ctx, peer, &copy), Refused, tc.code, false, false)
	}
	assertVerdict(t, c.Outbound(ctx, peer), Live, CodeLive, false, false)
	unavailable := mainConfig
	unavailable.Node = nodeFunc(func(context.Context, string, ...any) (json.RawMessage, error) {
		return nil, errors.New("sensitive-core-read-marker")
	})
	failed := makeChecker(unavailable)
	record("read-failure", "out", peer, "valid cached proof; node unavailable", &p1, false, 500, failed.Outbound(ctx, peer), Refused, CodeVerifierUnavailable, false, true)
	assertVerdict(t, c.Outbound(ctx, peer), Live, CodeLive, false, false)
	// Record an actual unconfirmed issuance, then confirm before other cases.
	seal3 := l.seal()
	raw3 := l.grant(renter1, "grant-pending", seal3, false)
	p3 := presentation(raw3)
	record("grant-pending", "in", peer, "issuance in mempool", &p3, true, 500, c.Inbound(ctx, peer, &p3), Refused, CodeGrantPending, false, true)
	assertVerdict(t, c.Outbound(ctx, peer), Live, CodeLive, false, false)
	l.mine(1)
	assertVerdict(t, c.Inbound(ctx, peer, &p3), Live, CodeLive, false, false)
	assertVerdict(t, c.Inbound(ctx, peer, &p1), Live, CodeLive, false, false)
	assertVerdict(t, c.Inbound(ctx, peer2, &p2), Live, CodeLive, false, false)
	l.revoke(seal1) // deliberately unconfirmed
	record("seal-mempool", "in", peer, "seal spend is in mempool after live-in", &p1, false, 500, c.Inbound(ctx, peer, nil), Exchange, CodeSealSpent, true, false)
	record("closed-out", "out", peer, "same mempool spend", &p1, false, 500, c.Outbound(ctx, peer), Refused, CodeSealSpent, true, false)
	c = makeChecker(mainConfig)
	record("closed-restart", "in", peer, "restart with persisted closure", &p1, false, 500, c.Inbound(ctx, peer, nil), Exchange, CodeSealSpent, true, false)
	assertVerdict(t, c.Outbound(ctx, peer2), Live, CodeLive, false, false)
	value, e := rental.LandlordValue(rental.LandlordBinding{Grant: xonly(9)})
	if e != nil {
		t.Fatal(e)
	}
	l.rpc("issuer", "name_update", e2eLandlordName, value)
	record("rotation-pending", "in", peer2, "landlord name_update in mempool after observed live generation", &p2, false, 500, c.Inbound(ctx, peer2, nil), Refused, CodeIdentityPending, false, true)
	record("rotation-pending-out", "out", peer2, "same pending name_update", &p2, false, 500, c.Outbound(ctx, peer2), Refused, CodeIdentityPending, false, true)
	l.mine(1)
	record("rotation-confirmed", "in", peer2, "same forward landlord rotation confirmed", &p2, false, 500, c.Inbound(ctx, peer2, nil), Exchange, CodeLandlordRotated, true, false)
	c = makeChecker(mainConfig)
	record("rotation-closed-out", "out", peer2, "restart after confirmed rotation closure", &p2, false, 500, c.Outbound(ctx, peer2), Refused, CodeLandlordRotated, true, false)
	b, e := json.MarshalIndent(file, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(l.root, "vectors.json"), append(b, '\n'), 0600); e != nil {
		t.Fatal(e)
	}
}
