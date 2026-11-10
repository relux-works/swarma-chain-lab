package rehearsal

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	booking "github.com/relux-works/swarma-chain-lab/experiments/rental-booking"
	signer "github.com/relux-works/swarma-chain-lab/experiments/signer-service"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

type canonicalNode struct {
	Role, Dir, Config, P2P   string
	Read, Payment, Broadcast su.Route
}

// This checks actual V2 composition with independent chain observers. It does
// not qualify DA1 crash recovery, Linux isolation, or the draft v4 profile.
func TestCanonicalComposition(t *testing.T) { runComposition(t, false, "canonical") }

func (l *lab) startObservers() {
	l.peers = map[string]*canonicalNode{}
	for _, role := range []string{"booking", "issuer", "gateway", "verifier"} {
		n := &canonicalNode{Role: role, Dir: l.dir("node-" + role), P2P: address(l.t)}
		port, e := strconv.Atoi(strings.Split(address(l.t), ":")[1])
		checked(l.t, e, "observer port")
		var auth strings.Builder
		for _, v := range []struct {
			name, methods string
			route         *su.Route
		}{
			{"w3-observer", "getblockchaininfo,getblockhash,getblockheader,getrawtransaction,gettxout,name_show,getrawmempool,getblock", &n.Read},
			{"payment-observer", "getnetworkinfo,getblockchaininfo,getblockhash,getblockheader,getrawtransaction,getrawmempool,getblock", &n.Payment},
			{"sg1-broadcaster", "sendrawtransaction", &n.Broadcast},
		} {
			// Booking never receives a broadcaster route; only issuer uses this principal.
			if v.name == "sg1-broadcaster" && role != "issuer" {
				continue
			}
			password := make([]byte, 32)
			_, e := rand.Read(password)
			checked(l.t, e, "node credential")
			pass := hex.EncodeToString(password)
			l.secret([]byte(pass))
			salt := hex.EncodeToString(password[:8])
			mac := hmac.New(sha256.New, []byte(salt))
			mac.Write([]byte(pass))
			fmt.Fprintf(&auth, "rpcauth=%s:%s$%x\nrpcwhitelist=%s:%s\n", v.name, salt, mac.Sum(nil), v.name, v.methods)
			*v.route = su.Route{Host: "127.0.0.1", Port: port, Username: v.name, Password: pass}
		}
		// Payment issuer has a different fixed client principal and also needs gettxout.
		if role == "issuer" {
			pass := make([]byte, 32)
			_, e := rand.Read(pass)
			checked(l.t, e, "issuer payment credential")
			secret := hex.EncodeToString(pass)
			l.secret([]byte(secret))
			salt := hex.EncodeToString(pass[:8])
			mac := hmac.New(sha256.New, []byte(salt))
			mac.Write([]byte(secret))
			fmt.Fprintf(&auth, "rpcauth=payment-issuer:%s$%x\nrpcwhitelist=payment-issuer:getnetworkinfo,getblockchaininfo,getblockhash,getblockheader,getrawtransaction,getrawmempool,getblock,gettxout\n", salt, mac.Sum(nil))
			n.Payment = su.Route{Host: "127.0.0.1", Port: port, Username: "payment-issuer", Password: secret}
		}
		n.Config = filepath.Join(n.Dir, "namecoin.conf")
		conf := "server=1\nlisten=1\ndnsseed=0\ndiscover=0\nnetworkactive=1\ntxindex=1\npersistmempool=0\nacceptnonstdtxn=1\nnameencoding=ascii\nvalueencoding=ascii\nrpcwhitelistdefault=0\n" + auth.String() + "[regtest]\nrpcbind=127.0.0.1\nrpcallowip=127.0.0.1\nrpcport=" + strconv.Itoa(port) + "\nbind=" + n.P2P + "\nport=" + strings.Split(n.P2P, ":")[1] + "\nconnect=" + l.minerP2P + "\n"
		l.write(n.Config, []byte(conf), 0600)
		l.bins["node-"+role] = os.Getenv("IT1_CORE_DAEMON")
		l.spawn("node-"+role, "-regtest", "-datadir="+n.Dir, "-conf="+n.Config)
		rpc, e := su.NewRPC(n.Read)
		checked(l.t, e, "observer route")
		l.await(role+" node readiness", func() bool {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_, e := rpc.Call(ctx, "getblockchaininfo")
			return e == nil
		})
		cookie, e := os.ReadFile(filepath.Join(n.Dir, "regtest/.cookie"))
		checked(l.t, e, "observer cookie registration")
		l.secret(bytes.TrimSpace(cookie))
		l.peers[role] = n
	}
	checked(l.t, validateObserverTopology(l.peers, l.nodeDir), "independent observer topology")
	l.bookingRead, l.bookingDir = l.peers["booking"].Read, l.peers["booking"].Dir
	l.payment = l.peers["booking"].Payment
	l.signerRead, l.broadcast, l.paymentIssuer = l.peers["issuer"].Read, l.peers["issuer"].Broadcast, l.peers["issuer"].Payment
	l.read = l.peers["gateway"].Read
	l.syncTips()
	l.evidence["canonical_scope"] = "implemented V2 order, not a spec-adopted profile"
	l.evidence["canonical_order"] = []string{"names", "booking/consent", "confirmed payment", "issuance", "independent verify", "gateway/station", "chat", "closure"}
	l.evidence["crash_cases"] = map[string]string{"gateway": "pending-DA1", "station": "pending-DA1", "issuer": "pending-barrier", "booking": "pending-barrier"}
}

func validateObserverTopology(nodes map[string]*canonicalNode, miner string) error {
	if len(nodes) != 4 {
		return fmt.Errorf("OBSERVER_COUNT")
	}
	dirs := map[string]bool{miner: true}
	ports := map[int]bool{}
	peers := map[string]bool{}
	for _, role := range []string{"booking", "issuer", "gateway", "verifier"} {
		n := nodes[role]
		if n == nil || n.Role != role {
			return fmt.Errorf("OBSERVER_ROLE")
		}
		if !filepath.IsAbs(n.Dir) || dirs[n.Dir] {
			return fmt.Errorf("OBSERVER_DATADIR")
		}
		dirs[n.Dir] = true
		if n.Read.Port < 1 || ports[n.Read.Port] {
			return fmt.Errorf("OBSERVER_RPC")
		}
		ports[n.Read.Port] = true
		if n.P2P == "" || peers[n.P2P] {
			return fmt.Errorf("OBSERVER_P2P")
		}
		peers[n.P2P] = true
	}
	return nil
}

// Duplicate role/datadir/RPC/P2P assignments must refuse; a distinct topology
// must pass. These are metadata controls, not proof of running independent nodes.
func TestCanonicalTopologyContract(t *testing.T) {
	fresh := func() map[string]*canonicalNode {
		m := map[string]*canonicalNode{}
		for i, r := range []string{"booking", "issuer", "gateway", "verifier"} {
			m[r] = &canonicalNode{Role: r, Dir: "/fixture/" + r, P2P: fmt.Sprint("127.0.0.1:", 3000+i), Read: su.Route{Port: 4000 + i}}
		}
		return m
	}
	if e := validateObserverTopology(fresh(), "/fixture/miner"); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		name, reason string
		plant        func(map[string]*canonicalNode)
	}{
		{"missing", "OBSERVER_COUNT", func(m map[string]*canonicalNode) { delete(m, "verifier") }},
		{"role", "OBSERVER_ROLE", func(m map[string]*canonicalNode) { m["verifier"].Role = "issuer" }},
		{"shared-node", "OBSERVER_DATADIR", func(m map[string]*canonicalNode) { m["verifier"].Dir = m["issuer"].Dir }},
		{"miner", "OBSERVER_DATADIR", func(m map[string]*canonicalNode) { m["verifier"].Dir = "/fixture/miner" }},
		{"rpc", "OBSERVER_RPC", func(m map[string]*canonicalNode) { m["verifier"].Read.Port = m["issuer"].Read.Port }},
		{"p2p", "OBSERVER_P2P", func(m map[string]*canonicalNode) { m["verifier"].P2P = m["issuer"].P2P }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := fresh()
			tc.plant(m)
			e := validateObserverTopology(m, "/fixture/miner")
			if e == nil || e.Error() != tc.reason {
				t.Fatal("topology plant not detected", e)
			}
		})
	}
}

func (l *lab) peerRPC(n *canonicalNode, method string, args ...any) json.RawMessage {
	argv := []string{"-regtest", "-datadir=" + n.Dir, "-conf=" + n.Config, method}
	for _, a := range args {
		if s, ok := a.(string); ok {
			argv = append(argv, s)
		} else {
			argv = append(argv, string(encoded(a)))
		}
	}
	b, code := l.command("observer "+n.Role+" "+method, l.cli, argv...)
	if code != 0 {
		l.t.Fatal("observer RPC refused: " + n.Role + " " + method)
	}
	if !json.Valid(b) {
		b = encoded(strings.TrimSpace(string(b)))
	}
	return b
}
func (l *lab) syncTips() {
	if len(l.peers) == 0 {
		return
	}
	tip := str(l.t, l.rpc("", "getbestblockhash"))
	l.await("independent active tips converge", func() bool {
		for role, n := range l.peers {
			if role == "verifier" && l.verifierPaused {
				continue
			}
			if str(l.t, l.peerRPC(n, "getbestblockhash")) != tip {
				return false
			}
		}
		return true
	})
	var rows []map[string]any
	for _, role := range []string{"booking", "issuer", "gateway", "verifier"} {
		n := l.peers[role]
		rows = append(rows, map[string]any{"role": role, "datadir": n.Dir, "rpc_port": n.Read.Port, "p2p": n.P2P, "tip": str(l.t, l.peerRPC(n, "getbestblockhash")), "paused": role == "verifier" && l.verifierPaused})
	}
	l.evidence["independent_nodes"] = rows
}

// Before mining or observing revocation, every transaction currently accepted
// by the issuer must reach the miner and gateway. Identical whole mempools are
// not a P2P guarantee; block/tip convergence is checked separately for all nodes.
func (l *lab) syncMempools() {
	if len(l.peers) == 0 {
		return
	}
	pool := func(raw []byte) []string {
		var ids []string
		checked(l.t, json.Unmarshal(raw, &ids), "mempool shape")
		sort.Strings(ids)
		return ids
	}
	required := pool(l.peerRPC(l.peers["issuer"], "getrawmempool"))
	l.await("issuer transactions reach miner and gateway", func() bool {
		miner := pool(l.rpc("", "getrawmempool"))
		gateway := pool(l.peerRPC(l.peers["gateway"], "getrawmempool"))
		l.evidence["last_pending_relay"] = map[string]any{"issuer": required, "miner": miner, "gateway": gateway}
		for _, id := range required {
			for _, ids := range [][]string{miner, gateway} {
				i := sort.SearchStrings(ids, id)
				if i == len(ids) || ids[i] != id {
					return false
				}
			}
		}
		return true
	})
}
func (l *lab) pauseVerifier() {
	l.peerRPC(l.peers["verifier"], "setnetworkactive", false)
	l.verifierPaused = true
}

// Observe the failing call on the real read-only client; no RPC result is forged.
type verifierTrace struct {
	su.Node
	failedMethod, failedID string
}

func (n *verifierTrace) Call(ctx context.Context, method string, args ...any) (json.RawMessage, error) {
	raw, e := n.Node.Call(ctx, method, args...)
	if e != nil {
		n.failedMethod = method
		if len(args) > 0 {
			n.failedID, _ = args[0].(string)
		}
	}
	return raw, e
}
func (l *lab) verifyIndependent(raw []byte, config string) {
	var fc signer.FileConfig
	b, e := os.ReadFile(config)
	checked(l.t, e, "verifier trusted policy")
	checked(l.t, json.Unmarshal(b, &fc), "verifier policy shape")
	p := fc.Config.Policy.Policy
	p.StateDir = l.dir("independent-verifier")
	grant, e := rental.ParseGrantPresentation(raw)
	checked(l.t, e, "independent presentation")
	if time.Until(time.Unix(grant.SignedGrant.Grant.NotBefore, 0)) > 90*time.Second {
		l.t.Fatal("independent verifier window beyond fixture bound")
	}
	for time.Now().Unix() < grant.SignedGrant.Grant.NotBefore {
		time.Sleep(100 * time.Millisecond)
	}
	node, e := su.NewRPC(l.peers["verifier"].Read)
	checked(l.t, e, "independent read route")
	trace := &verifierTrace{Node: node}
	check := func() rental.Receipt {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return rental.Check(ctx, trace, p, raw, agentName, grant.SignedGrant.Grant.GranteeKey, time.Now().Unix())
	}
	old := str(l.t, l.peerRPC(l.peers["verifier"], "getbestblockhash"))
	if old == str(l.t, l.rpc("", "getbestblockhash")) {
		l.t.Fatal("stale-node control was not applied")
	}
	refusal := check()
	if refusal.Verdict != "refused" || refusal.Reason != "NODE_UNAVAILABLE" {
		l.t.Fatalf("stale verifier unexpected verdict/reason: %s/%s", refusal.Verdict, refusal.Reason)
	}
	if trace.failedMethod != "getrawtransaction" || trace.failedID != grant.Issuance.TxID {
		l.t.Fatal("stale verifier failed outside missing anchor lookup")
	}
	entries, e := os.ReadDir(p.StateDir)
	checked(l.t, e, "stale verifier state")
	for _, v := range entries {
		if v.Name() != "rental.lock" {
			l.t.Fatal("stale verifier persisted admission state")
		}
	}
	l.peerRPC(l.peers["verifier"], "setnetworkactive", true)
	l.verifierPaused = false
	l.syncTips()
	l.syncMempools()
	live := check()
	if live.Verdict != "live" || live.Reason != "LIVE" {
		l.t.Fatalf("independent verifier positive refused: %s/%s", live.Verdict, live.Reason)
	}
	l.rejectNonW(raw, p, node)
	live = check()
	if live.Verdict != "live" || live.Reason != "LIVE" {
		l.t.Fatal("original W grant no longer live after negative control")
	}
	before, e := os.ReadFile(filepath.Join(p.StateDir, "grant-"+live.GrantID+".json"))
	checked(l.t, e, "verifier admission journal")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	wrong := rental.Check(ctx, node, p, raw, "id/other-executor", grant.SignedGrant.Grant.GranteeKey, time.Now().Unix())
	cancel()
	after, e := os.ReadFile(filepath.Join(p.StateDir, "grant-"+live.GrantID+".json"))
	checked(l.t, e, "verifier journal after wrong executor")
	if wrong.Verdict != "refused" || wrong.Reason != "GRANT_POLICY" || wrong.Calls != 0 || !bytes.Equal(before, after) {
		l.t.Fatal("wrong executor refused with side effect or wrong code")
	}
	l.evidence["wrong_executor"] = map[string]any{"reason": wrong.Reason, "node_calls": wrong.Calls, "journal_unchanged": true}
	l.evidence["independent_verifier"] = map[string]any{"stale_reason": refusal.Reason, "stale_tip": old, "stale_no_admission_state": true, "failed_method": trace.failedMethod, "missing_anchor": trace.failedID, "converged_verdict": live.Verdict, "converged_tip": live.TipHash, "grant_id": live.GrantID}
}

// A confirmed underquote is recorded for refund review, but cannot select a
// payment, export issuance or create a slot. The caller then pays the full quote
// through the same native flow as a valid positive control.
func (l *lab) underquote(origin string, contract booking.ContractV2) {
	before := booking.BookingV2{}
	if l.http("GET", origin+"/booking?id="+contract.BookingID, nil, &before) != 200 || before.Package == nil || before.PackageEvent == nil || before.Issuance != nil {
		l.t.Fatal("underquote baseline")
	}
	id := str(l.t, l.rpc("rehearsal", "sendtoaddress", contract.Payment.Address, su.Coins(contract.Payment.AmountAtoms-1)))
	l.mine(2)
	var transaction struct {
		Confirmations int64 `json:"confirmations"`
	}
	checked(l.t, json.Unmarshal(l.peerRPC(l.peers["booking"], "getrawtransaction", id, true), &transaction), "underquote confirmed transaction")
	if transaction.Confirmations < 2 {
		l.t.Fatal("underquote confirmation depth")
	}
	var after booking.BookingV2
	l.await("confirmed underquote recorded", func() bool {
		if l.http("GET", origin+"/booking?id="+contract.BookingID, nil, &after) != 200 {
			return false
		}
		for _, r := range after.Receipts {
			if r.Payment.TxID == id && r.Payment.Height > 0 && r.Payment.BlockHash != "" {
				return true
			}
		}
		return false
	})
	if after.Payment != nil || after.Issuance != nil || after.Revoke != nil || !bytes.Equal(encoded(before.Package), encoded(after.Package)) || before.PackageEvent.ID != after.PackageEvent.ID {
		l.t.Fatal("underquote changed authority or package")
	}
	found := false
	for _, r := range after.Receipts {
		if r.Payment.TxID == id {
			if r.Payment.ValueAtoms != contract.Payment.AmountAtoms-1 || r.EligibleAt != 0 || r.Disposition != "refund_review" || !r.RefundReview {
				l.t.Fatal("underquote disposition")
			}
			found = true
		}
	}
	if !found {
		l.t.Fatal("underquote receipt missing")
	}
	l.noSlot()
	l.evidence["underquote"] = map[string]any{"disposition": "refund_review", "issuance_absent": true, "selected_payment_absent": true, "package_unchanged": true, "slot_absent": true}
}

// The independent verifier rechecks the identical grant after actual closure.
// Revocation is local mempool evidence; no global latest-chain claim is made.
func (l *lab) verifyClosed(raw []byte, config, scenario string) {
	var fc signer.FileConfig
	b, e := os.ReadFile(config)
	checked(l.t, e, "closed verifier policy")
	checked(l.t, json.Unmarshal(b, &fc), "closed policy shape")
	p := fc.Config.Policy.Policy
	p.StateDir = l.dir("independent-verifier")
	grant, e := rental.ParseGrantPresentation(raw)
	checked(l.t, e, "closed presentation")
	node, e := su.NewRPC(l.peers["verifier"].Read)
	checked(l.t, e, "closed node")
	want := "SEAL_SPENT"
	if scenario == "expiry" {
		want = "EXPIRED"
	}
	var got rental.Receipt
	l.await("independent grant closure", func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		got = rental.Check(ctx, node, p, raw, agentName, grant.SignedGrant.Grant.GranteeKey, time.Now().Unix())
		return got.Verdict == "refused" && got.Reason == want
	})
	if scenario == "revoke" && !got.Closed {
		l.t.Fatal("revoked verifier lacks durable closure")
	}
	l.evidence["independent_closed"] = map[string]any{"verdict": got.Verdict, "reason": got.Reason, "durable_closed": got.Closed}
}

func (l *lab) publishVerified(raw []byte, dir, id string) {
	target := filepath.Join(dir, id+".json")
	if _, e := os.Stat(target); !os.IsNotExist(e) {
		l.t.Fatal("presentation mirror existed before independent verification")
	}
	f, e := os.OpenFile(filepath.Join(dir, ".verified.tmp"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	checked(l.t, e, "verified mirror create")
	_, e = f.Write(raw)
	checked(l.t, e, "verified mirror bytes")
	checked(l.t, f.Sync(), "verified mirror fsync")
	checked(l.t, f.Close(), "verified mirror close")
	checked(l.t, os.Rename(filepath.Join(dir, ".verified.tmp"), target), "verified mirror publish")
	d, e := os.Open(dir)
	checked(l.t, e, "verified mirror parent")
	checked(l.t, d.Sync(), "verified mirror parent fsync")
	checked(l.t, d.Close(), "verified mirror parent close")
	b, e := os.ReadFile(target)
	checked(l.t, e, "verified mirror readback")
	if !bytes.Equal(b, raw) {
		l.t.Fatal("verified mirror changed original SG1 bytes")
	}
	l.evidence["verified_presentation_mirror"] = map[string]any{"original_bytes": true, "sha256": rental.Hash(raw), "published_after_independent_live": true}
}
