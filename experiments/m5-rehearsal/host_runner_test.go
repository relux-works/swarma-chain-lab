package rehearsal

import (
	"context"
	"encoding/json"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	smoke "github.com/relux-works/swarma-chain-lab/experiments/m5-host-smoke"
	proxy "github.com/relux-works/swarma-chain-lab/experiments/model-proxy"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	booking "github.com/relux-works/swarma-chain-lab/experiments/rental-booking"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle/gatewaybind"
)

// The new external-client runner uses the actual IT2 services and genuine Core.
// Only this adapter holds disposable fixture custody. Its small-window/two-call
// result is PASS_SELF_TEST; it cannot prove Linux users, peer policy or erasure.
func TestHostRunnerComposition(t *testing.T) { runComposition(t, false, "host-runner") }

func (l *lab) hostRunner(scenario string, cfg booking.ConfigV2, relayURL, bookingURL, issuer, signerConfig, presentations, modelState, gatewayConfig string, p tlsPaths, helper *fakeHelper, managerProcess, gatewayProcess *process, calls *atomic.Int32) {
	t := l.t
	c := smoke.Config{ModelCaps: cfg.Template.ModelCaps, Scenario: scenario, Relay: relayURL, Booking: bookingURL, AgentPubkey: cfg.AgentPubkey, IssuerPubkey: issuer, AgentName: agentName, LandlordName: landlordName, TemplateSHA256: cfg.TemplateSHA256, ProfileSHA256: cfg.Template.ProfileSHA256, ProfileID: cfg.Template.ProfileID, ProfileVersion: cfg.Template.ProfileVersion, PayloadSHA256: helper.hash, EvidenceSHA256: rental.Hash([]byte("IT2 fixture inventory; NOT a host manifest")), EnvironmentSHA256: rental.Hash([]byte(l.root)), Allowed: cfg.Template.Allowed, Forbidden: cfg.Template.Forbidden, BudgetSat: cfg.Template.BudgetSat, NotBefore: cfg.Slots[0].NotBefore, NotAfter: cfg.Slots[0].NotAfter}
	var proof []byte
	var boot gatewaybind.PayloadBootstrap
	var paymentTX string
	var seen int64
	var payloadPID int
	var row struct {
		Phase    string          `json:"phase"`
		Exposure proxy.Counts    `json:"exposure"`
		Observed proxy.Usage     `json:"observed"`
		Pending  json.RawMessage `json:"pending"`
	}
	readRow := func(id string) {
		var ledger struct {
			Records map[string]json.RawMessage `json:"records"`
		}
		b, e := os.ReadFile(filepath.Join(modelState, "registry.json"))
		checked(t, e, "runner fixture accounting")
		checked(t, json.Unmarshal(b, &ledger), "runner fixture ledger shape")
		raw, ok := ledger.Records[id]
		if !ok {
			t.Fatal("runner fixture record missing")
		}
		checked(t, json.Unmarshal(raw, &row), "runner fixture selected record")
	}
	operator := smoke.OperatorFunc(func(ctx context.Context, q smoke.Request) (smoke.Receipt, error) {
		t.Log("runner operator stage", q.Stage)
		r := smoke.Receipt{RequestSHA256: q.SHA256(), Checks: map[string]bool{}, Numbers: map[string]int64{}, Hashes: map[string]string{}}
		// Each stage validates real fixture observations first. Unsupported host
		// checks are never requested by self-test mode and cannot be attested here.
		switch q.Stage {
		case "preflight":
			l.noSlot()
			var info struct {
				Chain string `json:"chain"`
			}
			checked(t, json.Unmarshal(l.rpc("", "getblockchaininfo"), &info), "fixture network")
			if info.Chain != "regtest" || str(t, l.rpc("", "getblockhash", 0)) != su.RegtestGenesis {
				t.Fatal("fixture regtest")
			}
			r.Hashes["selected_block"] = str(t, l.rpc("", "getbestblockhash"))
			r.Hashes["manifest"] = c.EvidenceSHA256
		case "pregrant":
			l.noSlot()
		case "unconfirmed_payment":
			l.noSlot()
			paymentTX = str(t, l.rpc("rehearsal", "sendtoaddress", q.Contract.Payment.Address, su.Coins(q.Contract.Payment.AmountAtoms)))
			var paid booking.BookingV2
			if l.http("GET", bookingURL+"/booking?id="+q.Contract.BookingID, nil, &paid) != 200 || paid.Issuance != nil {
				t.Fatal("unconfirmed issuance")
			}
			if _, e := os.Stat(filepath.Join(presentations, q.Contract.BookingID+".json")); !os.IsNotExist(e) {
				t.Fatal("unconfirmed presentation")
			}
		case "issue":
			l.mine(2)
			var paid booking.BookingV2
			l.await("runner native outbox", func() bool {
				return l.http("GET", bookingURL+"/booking?id="+q.Contract.BookingID, nil, &paid) == 200 && paid.Issuance != nil
			})
			proof = l.confirmedPresentation(signerConfig, q.Contract.BookingID, presentations)
			// The native signer shares the original fixture outbox directory. No mirror
			// hop is simulated; host transfer equality remains a separate host gate.
			var index []string
			b, e := os.ReadFile(filepath.Join(cfg.StateDir, "index.json"))
			checked(t, e, "original outbox index")
			checked(t, json.Unmarshal(b, &index), "original outbox index shape")
			if len(index) != 1 {
				t.Fatal("original outbox cardinality")
			}
			item, e := os.ReadFile(filepath.Join(cfg.StateDir, index[0]+".json"))
			checked(t, e, "original item")
			if rental.Hash(item) != index[0] {
				t.Fatal("original item hash")
			}
			r.Hashes["original_outbox"] = index[0]
			r.Hashes["payment_txid"] = paymentTX
			r.Hashes["selected_block"] = str(t, l.rpc("", "getbestblockhash"))
			r.Hashes["presentation"] = rental.Hash(proof)
		case "running":
			slot := l.slot(q.Contract.BookingID)
			if !slot.Started || slot.Starting || slot.Ended {
				t.Fatal("runner start")
			}
			var ok bool
			boot, ok = helper.bootstrap(q.Contract.BookingID)
			if !ok {
				t.Fatal("runner bootstrap")
			}
			l.secret([]byte(boot.ModelBearer))
			l.secret([]byte(boot.ChannelSecret))
			bad := boot
			bad.ModelBearer = proxy.Secret(strings.Repeat("0", len(boot.ModelBearer)))
			l.checkProxyRefusal(p, bad, "wrong-credential")
			l.checkProxyRefusal(p, boot, "wrong-pin")
			if calls.Load() != 1 {
				t.Fatal("runner negative probe upstream leak")
			}
			helper.mu.Lock()
			if len(helper.records) != 1 {
				helper.mu.Unlock()
				t.Fatal("runner helper count")
			}
			for _, record := range helper.records {
				if record.process == nil || record.response.PayloadSHA256 != helper.hash || record.response.BootstrapSHA256 != rental.Hash(record.bootstrap) {
					helper.mu.Unlock()
					t.Fatal("runner helper binding")
				}
				payloadPID = record.process.cmd.Process.Pid
				r.Hashes["bootstrap"] = rental.Hash(record.bootstrap)
			}
			helper.mu.Unlock()
			if syscall.Kill(payloadPID, 0) != nil {
				t.Fatal("runner payload absent")
			}
			r.Numbers["payload_pid"] = int64(payloadPID)
			r.Numbers["upstream_calls"] = int64(calls.Load())
			r.Hashes["payload_binary"] = helper.hash
		case "caps":
			readRow(q.Contract.BookingID)
			seen = int64(len(l.slot(q.Contract.BookingID).SeenRumorIDs))
		case "revoke":
			l.revokeNative(signerConfig, *q.Contract, proof)
			var index []string
			b, e := os.ReadFile(filepath.Join(l.private, "operator-outbox", "index.json"))
			checked(t, e, "native revoke index")
			checked(t, json.Unmarshal(b, &index), "native revoke index shape")
			if len(index) != 1 {
				t.Fatal("native revoke item count")
			}
			r.Hashes["revoke_item"] = index[0]
			// A mempool spend is the closure trigger; the existing native helper already
			// checked exact gettxout object -> literal null. Keep the fixture locator.
			var txs []string
			checked(t, json.Unmarshal(l.rpc("", "getrawmempool"), &txs), "revoke mempool")
			for _, txid := range txs {
				var tx struct {
					Vin []struct {
						TxID string `json:"txid"`
						Vout uint32 `json:"vout"`
					} `json:"vin"`
				}
				checked(t, json.Unmarshal(l.rpc("", "getrawtransaction", txid, true), &tx), "revoke transaction shape")
				for _, input := range tx.Vin {
					if input.TxID == q.Grant.SignedGrant.Grant.Seal.TxID && input.Vout == q.Grant.SignedGrant.Grant.Seal.Vout {
						if r.Hashes["spend_txid"] != "" {
							t.Fatal("duplicate seal spender")
						}
						r.Hashes["spend_txid"] = txid
					}
				}
			}
			if r.Hashes["spend_txid"] == "" {
				t.Fatal("runner exact seal spender missing")
			}
			r.Hashes["selected_block"] = str(t, l.rpc("", "getbestblockhash"))
		case "close":
			tick := time.NewTicker(100 * time.Millisecond)
			defer tick.Stop()
			for !l.slot(q.Contract.BookingID).Ended || !helper.destroyed() {
				select {
				case <-ctx.Done():
					return r, ctx.Err()
				case <-tick.C:
				}
			}
			slot := l.slot(q.Contract.BookingID)
			if slot.ChannelSecretHex != "" || int64(len(slot.SeenRumorIDs)) != seen || syscall.Kill(payloadPID, 0) != syscall.ESRCH {
				t.Fatal("runner closure retained state")
			}
			if scenario == "expiry" && (slot.EndReason != "not_after" || time.Now().Unix() < q.Contract.NotAfter) {
				t.Fatal("runner expiry reason")
			}
			l.checkProxyRefusal(p, boot, "revoked-or-expired")
			l.checkProxyRefusal(p, boot, "wrong-pin")
			readRow(q.Contract.BookingID)
			if row.Phase != "revoked" {
				t.Fatal("runner model not revoked")
			}
			r.Numbers["gateway_destroyed"] = 0
			if slot.Destroyed {
				r.Numbers["gateway_destroyed"] = 1
			}
		case "restart":
			// Restart the fixture gateway/model registrar without deleting either
			// journal. The original helper/manager remains scoped to this owned lab.
			l.stop(gatewayProcess)
			restarted := l.spawn("gateway-restarted", "serve", "-config", gatewayConfig)
			_ = restarted
			origin, e := url.Parse(boot.ModelEndpoint)
			checked(t, e, "fixture endpoint")
			l.await("runner restarted proxy listener", func() bool {
				conn, e := net.DialTimeout("tcp", origin.Host, time.Second)
				if e != nil {
					return false
				}
				conn.Close()
				return true
			})
			l.checkProxyRefusal(p, boot, "revoked-or-expired")
			readRow(q.Contract.BookingID)
			if row.Phase != "revoked" || !l.slot(q.Contract.BookingID).Ended || int64(len(l.slot(q.Contract.BookingID).SeenRumorIDs)) != seen {
				t.Fatal("runner restart lost closure")
			}
		default:
			t.Fatal("unexpected runner operator stage")
		}
		if q.Stage == "caps" || q.Stage == "close" || q.Stage == "restart" {
			if row.Exposure.Requests != 2 || row.Observed.Input != 14 || row.Observed.Output != 6 || string(row.Pending) != "null" || calls.Load() != 2 {
				t.Fatal("runner accounting invariant")
			}
			r.Numbers["upstream_calls"] = int64(calls.Load())
			r.Numbers["requests"] = int64(row.Exposure.Requests)
			r.Numbers["input_tokens"] = int64(row.Observed.Input)
			r.Numbers["output_tokens"] = int64(row.Observed.Output)
			r.Numbers["pending"] = 0
			r.Numbers["seen_rumors"] = int64(len(l.slot(q.Contract.BookingID).SeenRumorIDs))
		}
		for _, name := range q.Checks {
			r.Checks[name] = true
		}
		r.ObservedMS = time.Now().UnixMilli()
		return r, nil
	})
	// spawn uses role -> binary mapping; only the disposable overlay is restarted.
	l.bins["gateway-restarted"] = l.bins["gateway"]
	report, e := smoke.RunSelfTest(context.Background(), c, operator)
	l.write(filepath.Join(l.public, "host-runner-self-test.json"), encoded(report), 0600)
	l.write(filepath.Join(l.public, "host-runner-public-config.json"), encoded(c), 0600)
	checked(t, e, "runner self-test: "+report.Failure)
	if report.Outcome != "PASS_SELF_TEST" || report.Mode != "self-test" {
		t.Fatal("runner mislabeled fixture as host")
	}
	l.evidence["outcome"] = "PASS_SELF_TEST"
	l.evidence["host_runner"] = report
	l.evidence["scenario"] = scenario
	l.evidence["full_scenario"] = "external client runner on Darwin composition; NOT Linux host qualification"
	l.stop(managerProcess)
}
