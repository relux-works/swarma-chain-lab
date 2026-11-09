package rental

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

func (l *coreLab) detachedIssueInputs(p Policy, label string, confirmed bool) (IssuerPolicy, []byte, []byte, string) {
	l.t.Helper()
	paymentID := text(l.t, l.rpc("issuer", "sendtoaddress", l.address, su.Coins(1000000)))
	if confirmed {
		l.mine(1)
	}
	var tx su.TransactionView
	if e := json.Unmarshal(l.rpc("", "getrawtransaction", paymentID, true), &tx); e != nil {
		l.t.Fatal(e)
	}
	var payment Point
	found := false
	for _, out := range tx.Vout {
		if out.Script.Hex == l.script && int64(out.Value) == 1000000 {
			payment = Point{paymentID, out.N}
			found = true
			break
		}
	}
	if !found {
		l.t.Fatal("payment fixture absent")
	}
	var height int64
	if confirmed {
		var h su.Header
		if e := json.Unmarshal(l.rpc("", "getblockheader", tx.Block), &h); e != nil {
			l.t.Fatal(e)
		}
		height = h.Height
	}
	legacy := testCertificate()
	legacy.StationName = l.station
	_, req, pub := packageFixture(l.t, legacy, l.address, payment, height, tx.Block, "advance", Hash([]byte(label)))
	request, _ := json.Marshal(req)
	_, provider := testKey(4)
	keyPath := filepath.Join(l.private, "grant-key")
	key, _ := testKey(1)
	if e := os.WriteFile(keyPath, key.Serialize(), 0600); e != nil {
		l.t.Fatal(e)
	}
	return IssuerPolicy{p, provider}, request, eventBytes(pub), keyPath
}
func assertNoIssuerBurn(t *testing.T, root string) {
	t.Helper()
	entries, e := os.ReadDir(root)
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range entries {
		if entry.Name() != "rental.lock" {
			t.Fatalf("refusal left unexpected state: %s", entry.Name())
		}
	}
}
func requireIssued(t *testing.T, r IssueResult) {
	t.Helper()
	if r.Verdict != "issued" || r.ID != Hash(r.Envelope) {
		t.Fatalf("issuance: %+v", r)
	}
}

// Genuine Core admission issues without a name transaction. Retries return
// identical persisted bytes without node or key access; a second booking cannot
// reuse its seal, and the same booking cannot switch seals. Expiry is time-only.
func TestCoreDetachedIssuer(t *testing.T) {
	l := newCore(t)
	l.agentValue(1, 3, true)
	seal := l.detachedPool(1, true)
	p, _, _ := l.detached("issuer", seal, 2)
	ip, request, event, keyPath := l.detachedIssueInputs(p, "first", true)
	before := text(t, l.rpc("", "getbestblockhash"))
	result := IssueDetached(context.Background(), l.observer, ip, request, event, seal, keyPath, 500)
	requireIssued(t, result)
	l.save("issued.json", result)
	if text(t, l.rpc("", "getbestblockhash")) != before {
		t.Fatal("issuer changed chain")
	}
	replay := IssueDetached(context.Background(), nil, ip, request, event, seal, "", 1001)
	requireIssued(t, replay)
	if !replay.Replay || !bytes.Equal(replay.Envelope, result.Envelope) {
		t.Fatal("replay differs")
	}
	env, e := ParseDetachedEnvelope(result.Envelope)
	if e != nil {
		t.Fatal(e)
	}
	l.checkDetached("issued-live", p, env.Certificate, result.Envelope, 500, "live", "LIVE", false)
	l.checkDetached("issued-expired", p, env.Certificate, result.Envelope, 1000, "refused", "EXPIRED", false)
	other := l.detachedPool(1, true)
	changed := IssueDetached(context.Background(), l.observer, ip, request, event, other, keyPath, 500)
	if changed.Reason != "ISSUANCE_CONFLICT" || len(changed.Envelope) != 0 {
		t.Fatal("booking switched seal")
	}
	_, r2, e2, _ := l.detachedIssueInputs(p, "second", true)
	reused := IssueDetached(context.Background(), l.observer, ip, r2, e2, seal, keyPath, 500)
	if reused.Reason != "POOL_ALREADY_RESERVED" || len(reused.Envelope) != 0 {
		t.Fatalf("seal reuse: %+v", reused)
	}
	neighbor := IssueDetached(context.Background(), l.observer, ip, r2, e2, other, keyPath, 500)
	requireIssued(t, neighbor)
	l.save("result.json", map[string]any{"status": "PASS", "no_per_grant_transaction": true, "exact_replay": true})
}

// Real payment and pool fixtures prove fresh admission/key denials leave no
// burn or certificate. Each refusal has a repaired valid issuance beside it.
func TestCoreDetachedIssuerDenials(t *testing.T) {
	l := newCore(t)
	l.agentValue(1, 3, true)
	for _, mode := range []string{"mempool-payment", "expired-hold", "bad-package", "bad-key-mode", "wrong-key", "missing-payment", "unconfirmed-pool"} {
		t.Run(mode, func(t *testing.T) {
			seal := l.detachedPool(1, mode != "unconfirmed-pool")
			p, _, _ := l.detached(mode, seal, 2)
			ip, req, event, keyPath := l.detachedIssueInputs(p, mode, mode != "mempool-payment" && mode != "unconfirmed-pool")
			// In the unconfirmed-seal case the payment is confirmed first, then a
			// fresh seal is created without mining, so payment admission is not the cause.
			if mode == "unconfirmed-pool" {
				l.mine(1)
				seal = l.detachedPool(1, false)
			}
			at := int64(500)
			badRequest := req
			badEvent := event
			want := ""
			switch mode {
			case "mempool-payment":
				want = "payment_unconfirmed"
			case "expired-hold":
				at = 900
				want = "hold_expired_at_admission"
			case "bad-package":
				badEvent = []byte(`{}`)
				want = "PACKAGE_EVENT"
			case "bad-key-mode":
				if e := os.Chmod(keyPath, 0644); e != nil {
					t.Fatal(e)
				}
				want = "KEY_FILE"
			case "wrong-key":
				key, _ := testKey(3)
				if e := os.WriteFile(keyPath, key.Serialize(), 0600); e != nil {
					t.Fatal(e)
				}
				want = "KEY_PIN"
			case "missing-payment":
				var r IssuanceRequest
				_ = json.Unmarshal(req, &r)
				r.PaymentTxID = Hash([]byte("missing"))
				badRequest, _ = json.Marshal(r)
				// The shared own-node boundary deliberately maps RPC errors to
				// NODE_UNAVAILABLE; this is not proof that a payment never existed.
				want = "NODE_UNAVAILABLE"
			case "unconfirmed-pool":
				want = "POOL_UNCONFIRMED"
			}
			got := IssueDetached(context.Background(), l.observer, ip, badRequest, badEvent, seal, keyPath, at)
			l.save(mode+"-refusal.json", got)
			if got.Verdict != "refused" || got.Reason != want || len(got.Envelope) != 0 {
				t.Fatalf("want %s got %+v", want, got)
			}
			assertNoIssuerBurn(t, p.StateDir)
			key, _ := testKey(1)
			if e := os.Chmod(keyPath, 0600); e != nil {
				t.Fatal(e)
			}
			if e := os.WriteFile(keyPath, key.Serialize(), 0600); e != nil {
				t.Fatal(e)
			}
			if mode == "mempool-payment" || mode == "unconfirmed-pool" {
				l.mine(1)
			}
			neighbor := IssueDetached(context.Background(), l.observer, ip, req, event, seal, keyPath, 500)
			requireIssued(t, neighbor)
			l.save(mode+"-valid.json", neighbor)
		})
	}
}

// Child exits at a real durable boundary, not an error-return simulation.
func TestDetachedIssuerCrashChild(t *testing.T) {
	if os.Getenv("M1_04_ISSUER_CHILD") != "1" {
		t.Skip("subprocess crash helper")
	}
	root := os.Getenv("M1_04_ISSUER_INPUT")
	read := func(name string) []byte {
		b, e := os.ReadFile(filepath.Join(root, name))
		if e != nil {
			t.Fatal("child input")
		}
		return b
	}
	var ip IssuerPolicy
	var route su.Route
	var seal Point
	if json.Unmarshal(read("policy.json"), &ip) != nil || json.Unmarshal(read("route.json"), &route) != nil || json.Unmarshal(read("seal.json"), &seal) != nil {
		t.Fatal("child encoding")
	}
	node, e := su.NewRPC(route)
	if e != nil {
		t.Fatal(e)
	}
	stage := os.Getenv("M1_04_ISSUER_STAGE")
	result := issueDetached(context.Background(), node, ip, read("request.json"), read("event.json"), seal, filepath.Join(root, "grant-key"), 500, func(at string) {
		if at == stage {
			os.Exit(73)
		}
	})
	t.Fatalf("crash stage not reached: %s", result.Reason)
}

// Genuine Core with abrupt subprocess exits proves reserved/signed-but-not-
// persisted attempts never re-sign, while completed attempts replay exact bytes.
func TestCoreDetachedIssuerCrash(t *testing.T) {
	l := newCore(t)
	l.agentValue(1, 3, true)
	for _, stage := range []string{"reserved", "signed", "complete"} {
		t.Run(stage, func(t *testing.T) {
			seal := l.detachedPool(1, true)
			p, _, _ := l.detached("crash-"+stage, seal, 2)
			ip, request, event, keyPath := l.detachedIssueInputs(p, "crash-"+stage, true)
			inputs := filepath.Join(l.private, "crash-"+stage)
			if e := os.Mkdir(inputs, 0700); e != nil {
				t.Fatal(e)
			}
			for name, v := range map[string]any{"policy.json": ip, "route.json": l.route, "seal.json": seal} {
				b, _ := json.Marshal(v)
				if e := os.WriteFile(filepath.Join(inputs, name), b, 0600); e != nil {
					t.Fatal(e)
				}
			}
			key, _ := testKey(1)
			for name, b := range map[string][]byte{"request.json": request, "event.json": event, "grant-key": key.Serialize()} {
				if e := os.WriteFile(filepath.Join(inputs, name), b, 0600); e != nil {
					t.Fatal(e)
				}
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestDetachedIssuerCrashChild$")
			cmd.Env = append(os.Environ(), "M1_04_ISSUER_CHILD=1", "M1_04_ISSUER_INPUT="+inputs, "M1_04_ISSUER_STAGE="+stage)
			out, e := cmd.CombinedOutput()
			ee, ok := e.(*exec.ExitError)
			if !ok || ee.ExitCode() != 73 {
				t.Fatalf("child did not reach boundary: %v %s", e, out)
			}
			l.rows = append(l.rows, map[string]any{"crash_child_pid": cmd.ProcessState.Pid(), "stage": stage, "exit": 73})
			result := IssueDetached(context.Background(), nil, ip, request, event, seal, keyPath, 500)
			if stage == "complete" {
				requireIssued(t, result)
				if !result.Replay {
					t.Fatal("missing replay")
				}
			} else if result.Reason != "ISSUANCE_UNCERTAIN" || len(result.Envelope) != 0 {
				t.Fatalf("reservation retried: %+v", result)
			}
			l.save(stage+"-recovery.json", result)
			fresh := l.detachedPool(1, true)
			p2, _, _ := l.detached("valid-"+stage, fresh, 2)
			ip2, r2, e2, k2 := l.detachedIssueInputs(p2, "valid-"+stage, true)
			requireIssued(t, IssueDetached(context.Background(), l.observer, ip2, r2, e2, fresh, k2, 500))
		})
	}
}
