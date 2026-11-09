package rehearsal

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/gorilla/websocket"
	store "relux.works/swarma-chain-lab/experiments/grant-store"
	proxy "relux.works/swarma-chain-lab/experiments/model-proxy"
	"relux.works/swarma-chain-lab/experiments/rental"
	booking "relux.works/swarma-chain-lab/experiments/rental-booking"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/gateway"
	signer "relux.works/swarma-chain-lab/experiments/signer-service"
	su "relux.works/swarma-chain-lab/experiments/single-use"
	"relux.works/swarma-chain-lab/experiments/station-lifecycle/gatewaybind"
	payload "relux.works/swarma-chain-lab/experiments/station-payload"
)

// The native CLIs and genuine isolated Core must compose through original V2
// bytes. Only r4 host execution and the Linux admin transport use declared seams.
// Run expiry and revoke in separate fresh roots; neither proves Linux isolation.
func TestFullComposition(t *testing.T) { runComposition(t, false) }

// These explicit partial legs do not require a first model reply and must never
// be described as full-scenario success. Revoke observes the seal before payload
// startup; expiry checks ledger/manager cleanup after a control-only delivery.
func TestIndependentPartialLegs(t *testing.T) {
	if os.Getenv("IT2_PARTIAL") != "1" {
		t.Skip("requires explicit IT2_PARTIAL=1; partial evidence only")
	}
	runComposition(t, true)
}
func runComposition(t *testing.T, partial bool) {
	if os.Getenv("IT2_SCENARIO") == "" {
		t.Skip("requires explicit IT2_SCENARIO=expiry|revoke after G6 landing")
	}
	scenario := os.Getenv("IT2_SCENARIO")
	if scenario != "expiry" && scenario != "revoke" {
		t.Fatal("invalid full scenario")
	}
	l := newLab(t)
	l.evidence["partial_only"] = partial
	overlay := l.registrarOverlay()
	overlaid := filepath.Join(l.private, "bin", "gateway-overlay")
	_, code := l.command("gateway registrar overlay", "go", "-C", filepath.Join(l.repo, "experiments/rental-gateway"), "build", "-overlay", overlay, "-race", "-trimpath", "-buildvcs=false", "-o", overlaid, "./cmd/gateway")
	if code != 0 {
		t.Fatal("gateway overlay build failed")
	}
	raw, e := os.ReadFile(overlaid)
	checked(t, e, "overlay binary")
	l.evidence["gateway_overlay_binary_sha256"] = rental.Hash(raw)
	l.releaseIsolation(overlay)
	l.bins["gateway"] = overlaid
	agent, provider, grant, funding, renter := l.key("agent.key", false), l.key("provider.key", false), l.key("grant.key", true), l.key("funding.key", true), l.key("renter.key", true)
	l.startCore(agent.PubKeyHex(), grant.PubKeyHex())
	relayAddr, bookingAddr, storeAddr := address(t), address(t), address(t)
	relayURL, bookingURL, storeURL := "ws://"+relayAddr, "http://"+bookingAddr, "http://"+storeAddr
	var rc map[string]any
	l.template("relay", &rc)
	rc["state_dir"], rc["public_url"], rc["trusted_proxy_ip"] = l.dir("relay"), relayURL, ""
	rc["read_timeout_milliseconds"], rc["ping_interval_milliseconds"] = 90000, 30000
	l.spawn("relay", "-listen", relayAddr, "-config", l.json("relay.json", rc, 0600))
	l.await("relay", func() bool {
		c, _, e := websocket.DefaultDialer.Dial(relayURL, nil)
		if e == nil {
			c.Close()
		}
		return e == nil
	})
	var sc store.Config
	l.template("store", &sc)
	sc.Root = l.dir("store")
	sc.PublicURL = storeURL
	sc.Writers = []string{grant.PubKeyHex()}
	l.spawn("store", "serve", "-config", l.json("store.json", sc, 0600), "-listen", storeAddr)
	l.await("S1", func() bool { return l.http("OPTIONS", storeURL+"/", nil, nil) == 204 })
	profile := []byte("local full-path rehearsal profile\n")
	profilePath := filepath.Join(l.private, "profile.txt")
	l.write(profilePath, profile, 0600)
	seed := make([]byte, 32)
	_, e = rand.Read(seed)
	checked(t, e, "public branch seed")
	l.secret(seed)
	master, e := hdkeychain.NewMaster(seed, &chaincfg.RegressionNetParams)
	checked(t, e, "branch master")
	public, e := master.Neuter()
	checked(t, e, "public branch")
	tmpl := booking.Template{Version: 1, ID: "demo", ProfileID: "rehearsal", ProfileVersion: "1", ProfileSHA256: booking.Hash(profile), Allowed: []string{"deliver"}, Forbidden: []string{"pay", "publish", "repository.push", "secret.release"}, BudgetSat: 1000000}
	now := time.Now().Unix()
	cfg := booking.ConfigV2{StateDir: l.dir("booking"), AgentPubkey: agent.PubKeyHex(), ProviderPubkey: provider.PubKeyHex(), HoldSeconds: 1800, PriceUSDCents: 100, Template: tmpl, TemplateSHA256: booking.Hash(encoded(tmpl)), Slots: []booking.Slot{{ID: "one", StationName: agentName, NotBefore: now + 60, NotAfter: now + 160, PaymentPolicy: "advance"}}, Coins: map[string]booking.CoinConfig{"nmc": {PublicBranch: public.String(), PublicBranchSHA256: booking.Hash([]byte(public.String())), USDMicrosPerCoin: 100000000, RateAsOf: now, MaxRateAgeSeconds: 7200, MinConfirmations: 2}}, Limits: booking.Limits{MaxBlocks: 512, MaxMempool: 2000, MaxCalls: 10000, MaxBytes: 64 << 20}}
	if scenario == "expiry" {
		// Leave more than the real 90-second relay deadline after model controls.
		cfg.Slots[0].NotAfter = now + 210
	}
	observer := filepath.Join(l.private, "booking-node.conf")
	l.write(observer, []byte(fmt.Sprintf("rpcuser=%s\nrpcpassword=%s\n[regtest]\nrpcconnect=127.0.0.1\nrpcport=%d\n", l.read.Username, l.read.Password, l.read.Port)), 0600)
	operator := su.OperatorRoute{Network: "regtest", Genesis: su.RegtestGenesis, NodeCLI: l.cli, NodeCLISHA256: cliPin, NodeConfig: observer, NodeDataDir: l.nodeDir}
	selected := struct {
		Version int               `json:"service_version"`
		Config  booking.ConfigV2  `json:"config"`
		Routes  map[string]string `json:"payment_route_files"`
	}{2, cfg, map[string]string{"nmc": l.json("payment-observer.json", l.payment, 0600)}}
	l.spawn("booking", "-config", l.json("booking.json", selected, 0600), "-profile", profilePath, "-provider-key", filepath.Join(l.private, "provider.key"), "-route", l.json("operator-route.json", operator, 0600), "-listen", bookingAddr, "-relay", relayURL, "-poll", "1s")
	l.await("booking V2", func() bool { return l.http("GET", bookingURL+"/", nil, nil) == 200 })
	p := l.tlsFiles()
	managerAddr, payloadAddr, modelAddr := address(t), address(t), address(t)
	pair, e := tls.LoadX509KeyPair(p.server, p.key)
	checked(t, e, "fixture TLS")
	var upstreamCalls atomic.Int32
	apiKey := "rehearsal-only-upstream-key"
	l.secret([]byte(apiKey))
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		if r.URL.Path != "/v1/messages" || r.Header.Get("x-api-key") != apiKey || r.Header.Get("Authorization") != "" {
			t.Error("upstream route or credential boundary")
		}
		var q map[string]json.RawMessage
		body, e := io.ReadAll(io.LimitReader(r.Body, proxy.MaxBody+1))
		if e != nil || json.Unmarshal(body, &q) != nil || string(q["model"]) != `"fixture"` || string(q["stream"]) != "false" {
			t.Error("upstream request shape")
		}
		_, _ = io.WriteString(w, `{"id":"fixture","type":"message","role":"assistant","model":"fixture","content":[{"type":"text","text":"model fixture reply"}],"stop_reason":"end_turn","usage":{"input_tokens":7,"output_tokens":3}}`)
	}))
	upstream.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}
	upstream.StartTLS()
	defer upstream.Close()
	var gc map[string]any
	l.template("gateway", &gc)
	gc["agent_key_file"], gc["agent_pubkey"], gc["relay_url"], gc["journal_dir"] = filepath.Join(l.private, "agent.key"), agent.PubKeyHex(), relayURL, filepath.Join(l.private, "journal")
	seal, e := rental.GrantSealScript(grant.PubKeyHex())
	checked(t, e, "gateway seal")
	k := gc["kernel"].(map[string]any)
	k["agent_name"], k["landlord_name"], k["issuer_pubkey"], k["seal_script"], k["state_dir"], k["rpc_port"], k["rpc_route_file"] = agentName, landlordName, grant.PubKeyHex(), seal, filepath.Join(l.private, "kernel"), l.read.Port, l.json("observer.json", l.read, 0400)
	presentations := l.dir("presentations")
	checked(t, os.Chmod(presentations, 0755), "public presentation directory mode")
	x := gc["exchange"].(map[string]any)
	x["max_replay"] = 32
	x["state_dir"], x["booking_url"], x["presentations_dir"], x["privacy_sha256"], x["template_sha256"], x["profile_sha256"], x["pow_bits"], x["burst"] = filepath.Join(l.private, "exchange"), bookingURL, presentations, booking.Hash([]byte(booking.PrivacyNotice)), cfg.TemplateSHA256, tmpl.ProfileSHA256, 4, 32
	payloadBytes, e := os.ReadFile(l.bins["payload"])
	checked(t, e, "payload artifact")
	payloadHash := rental.Hash(payloadBytes)
	m := gc["station"].(map[string]any)["manager"].(map[string]any)
	m["state_dir"], m["payload_id"], m["payload_sha256"], m["listen"], m["payload_listen"] = filepath.Join(l.private, "broker"), "rehearsal-payload", payloadHash, managerAddr, payloadAddr
	mt := m["tls"].(map[string]any)
	mt["cert_file"], mt["key_file"], mt["cert_sha256"], mt["manager_ca_file"], mt["manager_cert_sha256"] = p.server, p.key, p.serverPin, p.ca, p.clientPin
	admin := filepath.Join(l.private, "model.sock")
	modelState := l.dir("model")
	gc["model_proxy"] = map[string]any{"admin_socket": admin, "server_uid": os.Geteuid(), "origin": "https://" + modelAddr, "cert_sha256": p.serverPin, "caps": proxy.Caps{InputTokens: 1000, OutputTokens: 100, Requests: 2, MaxTokens: 16, CostNanoUSD: 10000}}
	l.write(admin+".rehearsal.json", encoded(map[string]any{"StateDir": modelState, "Upstream": upstream.URL + "/v1/messages", "APIKey": apiKey, "CA": p.ca, "Cert": p.server, "Key": p.key, "Models": map[string]proxy.Model{"fixture": {ContextTokens: 100, InputNanoUSD: 2, OutputNanoUSD: 3, Source: "synthetic rehearsal pricing"}}}), 0600)
	gp := l.json("gateway.json", gc, 0600)
	out, code := l.command("gateway config", l.bins["gateway"], "validate", "-config", gp)
	if code != 0 || strings.TrimSpace(string(out)) != "valid-public-config" {
		t.Fatal("V2 gateway configuration")
	}
	gatewayProcess := l.spawn("gateway", "serve", "-config", gp)
	l.await("gateway manager mode", func() bool {
		b, _ := os.ReadFile(filepath.Join(l.private, "gateway.log"))
		return bytes.Contains(b, []byte("screening=off mode=regtest kernel=real station=manager"))
	})
	helper := l.startHelper(p, payloadAddr, payloadHash)
	defer helper.close()
	managerProcess := l.startManager(p, managerAddr, payloadHash, filepath.Join(helper.root, "s.sock"))
	defer l.stop(managerProcess)
	signerConfig := l.signerConfig(cfg, storeURL, presentations, grant, funding, provider)
	conversation := l.conversation(relayURL, renter, agent.PubKeyHex())
	defer conversation.close()
	contract := conversation.bookV2(bookingURL, "one")
	l.rpc("rehearsal", "sendtoaddress", contract.Payment.Address, su.Coins(contract.Payment.AmountAtoms))
	l.mine(2)
	var paid booking.BookingV2
	l.await("V2 original issuance export", func() bool {
		return l.http("GET", bookingURL+"/booking?id="+contract.BookingID, nil, &paid) == 200 && paid.Issuance != nil
	})
	proof := l.confirmedPresentation(signerConfig, contract.BookingID, presentations)
	conversation.receive("issued\n", 10*time.Second)
	l.evidence["stage"] = "confirmed presentation and issued"
	t.Log("native SG1 confirmed presentation and issued received")
	if partial && scenario == "revoke" {
		l.revokeNative(signerConfig, contract, proof)
		if l.slot(contract.BookingID).Started || upstreamCalls.Load() != 0 {
			t.Fatal("pre-start revoke unexpectedly started payload/model")
		}
		l.evidence["outcome"] = "PASS_PARTIAL"
		l.evidence["scenario"] = "native-revoke-before-start"
		l.evidence["full_scenario"] = "NOT RUN: partial native SG1 unspent-before/null-after revoke only; no payload/model or teardown completion claimed"
		l.evidence["stage"] = "native seal revoked before payload start"
		t.Log("PARTIAL PASS: native SG1 spent the unspent seal; no payload/model started")
		return
	}

	if time.Now().Unix() < contract.NotBefore && l.slot(contract.BookingID).Started {
		t.Fatal("slot started before grant window")
	}
	conversation.receive("ready", 75*time.Second)
	l.evidence["stage"] = "ready"
	t.Log("ready received; sending first grantee message")
	tag, e := gateway.GrantCertTag(proof)
	checked(t, e, "issued presentation tag")
	if partial {
		// This existing scripted control never calls the model, even if startup wins
		// the race. The probe requires only durable start and later expiry cleanup.
		conversation.send("__extend__", false, tag)
		l.await("partial durable start", func() bool { return l.slot(contract.BookingID).Started })
		l.evidence["stage"] = "partial expiry: durable start; first model reply not required"
		deadline := time.Unix(contract.NotAfter+25, 0)
		for !l.slot(contract.BookingID).Ended {
			if time.Now().After(deadline) {
				t.Fatal("partial expiry cleanup deadline")
			}
			time.Sleep(100 * time.Millisecond)
		}
		l.await("partial helper cleanup", helper.destroyed)
		boot, ok := helper.bootstrap(contract.BookingID)
		if !ok {
			t.Fatal("partial bootstrap receipt missing")
		}
		l.secret([]byte(boot.ModelBearer))
		l.secret([]byte(boot.ChannelSecret))
		l.checkProxyRefusal(p, boot, "revoked-or-expired")
		slot := l.slot(contract.BookingID)
		if !slot.Ended || slot.EndReason != "not_after" || upstreamCalls.Load() != 0 {
			t.Fatal("partial expiry invariants")
		}
		l.evidence["outcome"] = "PASS_PARTIAL"
		l.evidence["scenario"] = "expiry-bookkeeping"
		l.evidence["full_scenario"] = "NOT RUN: partial expiry bookkeeping/helper cleanup and closed model credential; no first model reply or Linux wipe claimed"
		l.evidence["stage"] = "partial expiry cleanup complete"
		l.evidence["upstream_calls"] = upstreamCalls.Load()
		l.evidence["partial_expiry"] = map[string]any{"journal_ended": slot.Ended, "journal_destroyed": slot.Destroyed, "reason": slot.EndReason, "helper_bootstrap_removed": true, "model_credential_refused": true}
		t.Log("PARTIAL PASS: expiry journal, owned helper cleanup and closed credential; no first model reply claim")
		return
	}

	conversation.send("first model request", false, tag)
	conversation.receive("model fixture reply", 10*time.Second)
	l.evidence["stage"] = "first model reply"
	t.Log("real payload/model reply received")
	conversation.send("second model request", false)
	conversation.receive("model fixture reply", 10*time.Second)
	conversation.send("request beyond cap", false)
	conversation.receive("MODEL_CAP", 10*time.Second)
	conversation.send("terminal client cannot retry", false)
	conversation.receive("MODEL_CAP", 10*time.Second)
	if upstreamCalls.Load() != 2 {
		t.Fatal("model cap or terminal latch leaked upstream call")
	}
	boot, ok := helper.bootstrap(contract.BookingID)
	if !ok {
		t.Fatal("native helper bootstrap missing")
	}
	l.secret([]byte(boot.ModelBearer))
	l.secret([]byte(boot.ChannelSecret))
	l.checkProxyRefusal(p, boot, "wrong-pin")
	before := len(l.slot(contract.BookingID).SeenRumorIDs)
	idleStart := time.Now()
	if scenario == "expiry" && time.Until(time.Unix(contract.NotAfter, 0)) <= 90*time.Second {
		t.Fatal("fixture cannot establish application idle beyond relay read deadline")
	}
	if scenario == "revoke" {
		l.revokeNative(signerConfig, contract, proof)
		conversation.send("must not reach revoked slot", false)
	}
	deadline := time.Unix(contract.NotAfter+25, 0)
	if scenario == "revoke" {
		deadline = time.Now().Add(30 * time.Second)
	}
	for !l.slot(contract.BookingID).Ended {
		if time.Now().After(deadline) {
			t.Fatal("slot closure deadline")
		}
		time.Sleep(100 * time.Millisecond)
	}
	ended := l.slot(contract.BookingID)
	idle := time.Since(idleStart)
	if ended.ChannelSecretHex != "" {
		t.Fatal("ended slot retained channel credential")
	}
	if scenario == "expiry" && (ended.EndReason != "not_after" || idle <= 90*time.Second || time.Now().Unix() < contract.NotAfter) {
		t.Fatal("expiry did not cross relay idle deadline and end at not_after")
	}
	l.await("owned helper cleanup", helper.destroyed)
	l.evidence["closure"] = map[string]any{"journal_ended": ended.Ended, "journal_destroyed": ended.Destroyed, "reason": ended.EndReason, "channel_cleared": true, "helper_bootstrap_removed": true, "application_idle_milliseconds": idle.Milliseconds(), "relay_read_deadline_milliseconds": 90000}
	l.checkProxyRefusal(p, boot, "revoked-or-expired")
	if upstreamCalls.Load() != 2 || len(l.slot(contract.BookingID).SeenRumorIDs) != before {
		t.Fatal("closed grant produced a new delivery")
	}
	l.stop(managerProcess)
	l.stop(gatewayProcess)
	var registry struct {
		Records map[string]struct {
			Phase    string       `json:"phase"`
			Exposure proxy.Counts `json:"exposure"`
			Observed proxy.Usage  `json:"observed"`
		} `json:"records"`
	}
	ledger, e := os.ReadFile(filepath.Join(modelState, "registry.json"))
	checked(t, e, "proxy accounting ledger")
	checked(t, json.Unmarshal(ledger, &registry), "proxy accounting shape")
	row, ok := registry.Records[contract.BookingID]
	if !ok || row.Exposure.Requests != 2 || row.Observed.Input != 14 || row.Observed.Output != 6 || row.Phase != "revoked" {
		t.Fatal("proxy accounting/revocation evidence")
	}
	l.evidence["model_accounting"] = row
	l.evidence["scenario"] = scenario
	l.evidence["outcome"] = "PASS"
	l.evidence["full_scenario"] = "native V2 exchange, SG1 CLI, S1, real manager, PL1 payload/model delivery and closure passed"
	l.evidence["fake_helper_limit"] = "actual payload PID and disposable bootstrap removed; Linux isolation and physical disk wipe NOT EXERCISED"
	l.evidence["upstream_calls"] = upstreamCalls.Load()
	l.evidence["relay"] = "actual relay CLI; compatibility AUTH off"
}

func (l *lab) checkProxyRefusal(p tlsPaths, b gatewaybind.PayloadBootstrap, kind string) {
	roots := x509.NewCertPool()
	raw, e := os.ReadFile(p.ca)
	checked(l.t, e, "probe CA")
	if !roots.AppendCertsFromPEM(raw) {
		l.t.Fatal("probe roots")
	}
	tr := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	if kind == "wrong-pin" {
		b.ModelCertSHA256 = strings.Repeat("0", 64)
		client, e := payload.New(encoded(b), payload.Options{Model: "fixture", MaxTokens: 16, Roots: roots})
		checked(l.t, e, "wrong-pin payload client")
		defer client.Close()
		_, e = client.Respond(context.Background(), "must fail pin")
		if e != payload.ErrTransport {
			l.t.Fatal("wrong-pin payload did not return MODEL_TRANSPORT")
		}
		return
	}

	req, e := http.NewRequest("POST", b.ModelEndpoint+"/slots/"+b.BookingID+"/v1/messages", strings.NewReader(`{"model":"fixture","max_tokens":16,"messages":[{"role":"user","content":"rejected probe"}]}`))
	checked(l.t, e, "proxy refusal request")
	req.Header.Set("Authorization", "Bearer "+string(b.ModelBearer))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("anthropic-version", "2023-06-01")
	res, e := (&http.Client{Transport: tr, Timeout: 3 * time.Second}).Do(req)

	checked(l.t, e, "proxy refusal HTTP")
	defer res.Body.Close()
	body, e := io.ReadAll(io.LimitReader(res.Body, 1024))
	checked(l.t, e, "proxy refusal body")
	if res.StatusCode != 401 || string(body) != `{"error":"AUTH"}` {
		l.t.Fatal("closed bearer not refused as AUTH")
	}
}
func (l *lab) revokeNative(config string, c booking.ContractV2, proof []byte) {
	var cfg signer.FileConfig
	raw, e := os.ReadFile(config)
	checked(l.t, e, "operator signer config")
	checked(l.t, json.Unmarshal(raw, &cfg), "operator config decode")
	cfg.OperatorOutbox = l.dir("operator-outbox")
	item := signer.Item{ID: rental.Hash([]byte("rehearsal operator revoke " + c.BookingID)), Kind: "revoke", Revoke: &signer.Revoke{Version: 2, BookingID: c.BookingID, ContractSHA256: c.Hash(), Reason: "operator"}}
	body := encoded(item)
	id := rental.Hash(body)
	l.write(filepath.Join(cfg.OperatorOutbox, id+".json"), body, 0600)
	l.write(filepath.Join(cfg.OperatorOutbox, "index.json"), encoded([]string{id}), 0600)
	updated := l.json("signer-revoke.json", cfg, 0600)
	presentation, e := rental.ParseGrantPresentation(proof)
	checked(l.t, e, "revoke presentation")
	point := presentation.SignedGrant.Grant.Seal
	node, e := su.NewRPC(l.read)
	checked(l.t, e, "seal observer")
	observe := func() json.RawMessage {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		raw, e := node.Call(ctx, "gettxout", point.TxID, point.Vout, true)
		checked(l.t, e, "fresh seal JSON-RPC")
		return bytes.TrimSpace(raw)
	}
	// JSON-RPC preserves null. namecoin-cli renders a null result as empty stdout,
	// so the generic CLI string adapter cannot establish spent-output semantics.
	if raw := observe(); len(raw) == 0 || raw[0] != '{' {
		l.t.Fatal("pre-revoke seal is not unspent")
	}
	l.signerCycle(updated)
	if string(observe()) != "null" {
		l.t.Fatal("SG1 revoke did not spend seal")
	}
	l.evidence["early_revoke"] = "native operator FileSource and SG1 CLI spent exact issued seal; no imported wallet key"
}
