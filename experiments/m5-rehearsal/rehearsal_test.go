package rehearsal

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/gorilla/websocket"
	store "relux.works/swarma-chain-lab/experiments/grant-store"
	"relux.works/swarma-chain-lab/experiments/rental"
	booking "relux.works/swarma-chain-lab/experiments/rental-booking"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/nostr"
	signer "relux.works/swarma-chain-lab/experiments/signer-service"
	su "relux.works/swarma-chain-lab/experiments/single-use"
)

func (l *lab) template(service string, v any) {
	l.t.Helper()
	b, e := os.ReadFile(filepath.Join(l.repo, "deploy/templates", service, "service.json"))
	checked(l.t, e, "deploy template")
	checked(l.t, json.Unmarshal(b, v), "template schema")
}
func (l *lab) http(method, url string, in, out any) int {
	l.t.Helper()
	var body io.Reader
	if in != nil {
		body = bytes.NewReader(encoded(in))
	}
	req, e := http.NewRequest(method, url, body)
	checked(l.t, e, "HTTP request")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "http://"+req.URL.Host)
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil}}
	defer client.CloseIdleConnections()
	r, e := client.Do(req)
	if e != nil {
		return 0
	}
	defer r.Body.Close()
	b, e := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	checked(l.t, e, "bounded HTTP body")
	if out != nil && r.StatusCode < 300 {
		checked(l.t, json.Unmarshal(b, out), "HTTP JSON")
	}
	return r.StatusCode
}

type tlsPaths struct{ ca, server, key, client, clientKey, serverPin, clientPin string }

func (l *lab) tlsFiles() tlsPaths {
	caKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	checked(l.t, e, "CA key")
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	checked(l.t, e, "CA cert")
	ca, e = x509.ParseCertificate(der)
	checked(l.t, e, "CA parse")
	p := tlsPaths{ca: filepath.Join(l.private, "ca.pem")}
	l.write(p.ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600)
	leaf := func(name string, serial int64, usage x509.ExtKeyUsage) (string, string, string) {
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		checked(l.t, e, "leaf key")
		c := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
		d, e := x509.CreateCertificate(rand.Reader, c, ca, &key.PublicKey, caKey)
		checked(l.t, e, "leaf cert")
		k, e := x509.MarshalPKCS8PrivateKey(key)
		checked(l.t, e, "leaf encoding")
		kp := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k})
		l.secret(kp)
		cp, path := filepath.Join(l.private, name+".pem"), filepath.Join(l.private, name+".key")
		l.write(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d}), 0600)
		mode := os.FileMode(0600)
		if name == "server" {
			mode = 0400
		}
		l.write(path, kp, mode)
		return cp, path, rental.Hash(d)
	}
	p.server, p.key, p.serverPin = leaf("server", 2, x509.ExtKeyUsageServerAuth)
	p.client, p.clientKey, p.clientPin = leaf("client", 3, x509.ExtKeyUsageClientAuth)
	return p
}

// This is an executable composition survey at one pinned landed base. Passing
// means the documented blockers were reproduced, NOT that M5 completed. No
// manual grant/outbox bridge masks the remaining signer intake break.
func TestLandedComposition(t *testing.T) {
	l := newLab(t)
	agent := l.key("agent.key", false)
	provider := l.key("provider.key", false)
	grant := l.key("grant.key", true)
	funding := l.key("funding.key", true)
	renter := l.key("renter.key", true)
	l.startCore(agent.PubKeyHex(), grant.PubKeyHex())
	relayAddr, bookingAddr, storeAddr := address(t), address(t), address(t)
	relayURL := "ws://" + relayAddr
	bookingURL := "http://" + bookingAddr
	storeURL := "http://" + storeAddr
	var rc map[string]any
	l.template("relay", &rc)
	rc["state_dir"], rc["public_url"], rc["trusted_proxy_ip"] = l.dir("relay"), relayURL, ""
	l.spawn("relay", "-listen", relayAddr, "-config", l.json("relay.json", rc, 0600))
	l.await("relay readiness", func() bool {
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
	scClient := &store.Client{Signer: grant}
	l.await("S1 readiness", func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, e := scClient.List(ctx, storeURL)
		return e != nil && e.Error() == "store status 403"
	})
	if l.http("OPTIONS", storeURL+"/", nil, nil) != 204 {
		t.Fatal("S1 HTTP positive control")
	}
	l.evidence["s1_empty_namespace_refusal"] = "signed empty namespace correctly returns403; OPTIONS positive returns204"
	var cfg booking.Config
	l.template("booking", &cfg)
	cfg.StateDir = l.dir("booking")
	seed := make([]byte, 32)
	_, e := rand.Read(seed)
	checked(t, e, "branch seed")
	l.secret(seed)
	master, e := hdkeychain.NewMaster(seed, &chaincfg.RegressionNetParams)
	checked(t, e, "booking branch")
	pub, e := master.Neuter()
	checked(t, e, "public branch")
	cfg.PublicBranch = pub.String()
	cfg.PublicBranchSHA256 = booking.Hash([]byte(pub.String()))
	cfg.AgentPubkey = agent.PubKeyHex()
	cfg.ProviderPubkey = provider.PubKeyHex()
	profile := []byte("local rehearsal profile\n")
	cfg.Template = booking.Template{Version: 1, ID: "demo", ProfileID: "rehearsal", ProfileVersion: "1", ProfileSHA256: booking.Hash(profile), Allowed: []string{"deliver"}, Forbidden: []string{"pay", "publish", "repository.push", "secret.release"}, BudgetSat: 1000000}
	cfg.TemplateSHA256 = booking.Hash(encoded(cfg.Template))
	cfg.USDMicrosPerNMC = 100000000
	cfg.RateAsOf = time.Now().Unix()
	cfg.MaxRateAge = 7200
	cfg.MinStartNowRemainingSeconds = 0
	cfg.Slots = []booking.Slot{{ID: "one", StationName: agentName, NotBefore: time.Now().Unix() + 90, NotAfter: time.Now().Unix() + 1800, PaymentPolicy: "advance"}}
	profilePath := filepath.Join(l.private, "profile.txt")
	l.write(profilePath, profile, 0600)
	// The booking operator adapter receives a distinct read-only credential file,
	// never the node's unrestricted fixture-cookie configuration.
	observerConf := filepath.Join(l.private, "booking-node.conf")
	l.write(observerConf, []byte(fmt.Sprintf("rpcuser=%s\nrpcpassword=%s\n[regtest]\nrpcconnect=127.0.0.1\nrpcport=%d\n", l.read.Username, l.read.Password, l.read.Port)), 0600)
	operator := su.OperatorRoute{Network: "regtest", Genesis: su.RegtestGenesis, NodeCLI: l.cli, NodeCLISHA256: cliPin, NodeConfig: observerConf, NodeDataDir: l.nodeDir}
	bookingProcess := l.spawn("booking", "-config", l.json("booking.json", cfg, 0600), "-profile", profilePath, "-provider-key", filepath.Join(l.private, "provider.key"), "-route", l.json("operator-route.json", operator, 0600), "-listen", bookingAddr, "-relay", relayURL, "-poll", "1s")
	l.await("booking readiness", func() bool { return l.http("GET", bookingURL+"/", nil, nil) == 200 })
	l.evidence["booking_profile"] = "legacy v1 first; explicit ServiceV2 CLI next, no contract conversion"
	p := l.tlsFiles()
	managerAddr, payloadAddr := address(t), address(t)
	seal, e := rental.GrantSealScript(grant.PubKeyHex())
	checked(t, e, "grant seal")
	var gc map[string]any
	l.template("gateway", &gc)
	gc["agent_key_file"] = filepath.Join(l.private, "agent.key")
	gc["agent_pubkey"] = agent.PubKeyHex()
	gc["relay_url"] = relayURL
	gc["journal_dir"] = filepath.Join(l.private, "journal")
	k := gc["kernel"].(map[string]any)
	k["agent_name"] = agentName
	k["landlord_name"] = landlordName
	k["issuer_pubkey"] = grant.PubKeyHex()
	k["seal_script"] = seal
	k["state_dir"] = filepath.Join(l.private, "kernel")
	k["rpc_port"] = l.read.Port
	k["rpc_route_file"] = l.json("observer.json", l.read, 0400)
	x := gc["exchange"].(map[string]any)
	x["state_dir"] = filepath.Join(l.private, "exchange")
	x["booking_url"] = bookingURL
	x["presentations_dir"] = l.dir("presentations")
	x["privacy_sha256"] = booking.Hash([]byte(booking.PrivacyNotice))
	x["template_sha256"] = cfg.TemplateSHA256
	x["profile_sha256"] = cfg.Template.ProfileSHA256
	x["pow_bits"] = 4
	m := gc["station"].(map[string]any)["manager"].(map[string]any)
	m["state_dir"] = filepath.Join(l.private, "broker")
	m["payload_id"] = "rehearsal-payload"
	m["payload_sha256"] = rental.Hash([]byte("scripted fixture payload"))
	m["listen"] = managerAddr
	m["payload_listen"] = payloadAddr
	mt := m["tls"].(map[string]any)
	mt["cert_file"] = p.server
	mt["key_file"] = p.key
	mt["cert_sha256"] = p.serverPin
	mt["manager_ca_file"] = p.ca
	mt["manager_cert_sha256"] = p.clientPin
	gp := l.json("gateway.json", gc, 0600)
	out, code := l.command("gateway config", l.bins["gateway"], "validate", "-config", gp)
	if code != 0 || strings.TrimSpace(string(out)) != "valid-public-config" {
		t.Fatal("gateway public configuration refused")
	}
	l.spawn("gateway", "serve", "-config", gp)
	l.await("real relay gateway", func() bool {
		b, _ := os.ReadFile(filepath.Join(l.private, "gateway.log"))
		return bytes.Contains(b, []byte("screening=off mode=regtest kernel=real station=manager"))
	})
	l.evidence["relay"] = "actual swarma-relay CLI for both gateway gift wraps and booking packages; no relay substitution"
	l.evidence["gateway_native_config_valid"] = true
	l.evidence["gateway_reached_real_manager_mode"] = true
	contract := l.converse(relayURL, bookingURL, agent, renter, false)
	l.bookingDiagnostic(cfg, contract, bookingURL, storeURL, grant, funding, provider)
	l.stop(bookingProcess)
	l.v2Diagnostic(cfg, profilePath, operator, bookingAddr, relayURL, agent)
	l.managerDiagnostic(p, managerAddr, m["payload_sha256"].(string))
	entries, e := os.ReadDir(filepath.Join(l.private, "presentations"))
	checked(t, e, "presentation directory")
	if len(entries) != 0 {
		t.Fatal("unexpected presentation")
	}
	l.evidence["signer_to_gateway_bridge"] = "not executed; signer ledger/S1 output is not the gateway booking-ID presentation directory"
	l.evidence["full_scenario"] = "BLOCKED G6: gateway v1 booking request lacks V2 coin; V2 returns COIN_UNAVAILABLE and gateway BookPending; legacy paid v1 has no signer index. Issued/ready, slot delivery, expiry wipe and early revoke NOT RUN"
	l.evidence["non_grantee_control"] = "actual relay scenario: terms/foreign consent/valid consent create no gateway slot; live-grantee positive control blocked by missing issuance bridge"
	l.evidence["outcome"] = "G6_booking_version_boundary_reproduced"
	l.evidence["model_in_full_scenario"] = "NOT RUN: G6 prevents issuance/slot creation; separate station-payload tests exercise real proxy/fake upstream accounting"
	l.evidence["registrar_substitution"] = "approved direct-Service replacement of Linux-only admin transport was not needed or exercised before G6"
}

func (l *lab) bookingDiagnostic(cfg booking.Config, c booking.Contract, url, storeURL string, grant, funding, provider *nostr.PrivKey) {
	t := l.t
	l.rpc("rehearsal", "sendtoaddress", c.PaymentAddress, su.Coins(c.PriceNMCSat))
	l.mine(1)
	var paid booking.Booking
	l.await("diagnostic confirmed payment", func() bool {
		return l.http("GET", url+"/booking?id="+c.BookingID, nil, &paid) == 200 && paid.Issuance != nil
	})
	if !paid.Published || paid.PackageEvent == nil || paid.PackageEvent.Verify() != nil {
		t.Fatal("package positive control")
	}
	_, e := os.Stat(filepath.Join(cfg.StateDir, "issue-"+c.BookingID+".json"))
	checked(t, e, "issuance export")
	if _, e = os.Stat(filepath.Join(cfg.StateDir, "index.json")); !os.IsNotExist(e) {
		t.Fatal("unexpected signer index")
	}
	src, e := signer.OpenFileSource(cfg.StateDir)
	checked(t, e, "signer source root")
	items, e := src.Pull(context.Background(), "", 1)
	if e == nil || e.Error() != "PRIVATE_FILE" || len(items) != 0 {
		t.Fatal("expected outbox mismatch not observed")
	}
	l.evidence["payment_and_intake"] = map[string]any{"payment_confirmed": true, "package_8182_published": true, "issuance_exported": true, "signer_pull": "PRIVATE_FILE: missing index.json"}
	// Both probes execute the actual signer CLI. A separately constructed empty
	// source is only a startup positive control; no paid package is adapted.
	seal, e := rental.GrantSealScript(grant.PubKeyHex())
	checked(t, e, "signer seal")
	fund, e := rental.GrantSealScript(funding.PubKeyHex())
	checked(t, e, "signer funding")
	fc := signer.FileConfig{Config: signer.Config{Profile: "v1-nmc", Policy: rental.IssuerPolicy{Policy: rental.Policy{Network: "regtest", Genesis: su.RegtestGenesis, IssuerPubkey: grant.PubKeyHex(), AgentPubkey: cfg.AgentPubkey, AgentName: agentName, StationName: agentName, LandlordName: landlordName, SealScript: seal, StationScript: seal, FundingScript: fund, StateDir: l.dir("issuer")}, ProviderPubkey: provider.PubKeyHex()}, StateDir: l.dir("signer"), GrantKeyPath: filepath.Join(l.private, "grant.key"), FundingKeyPath: filepath.Join(l.private, "funding.key"), Caps: signer.RegtestCaps()}, ReadRouteFile: l.json("signer-reader.json", l.read, 0600), BroadcastRouteFile: l.json("signer-broadcaster.json", l.broadcast, 0600), BookingOutbox: cfg.StateDir, StoreURL: storeURL, StoreLandlordReader: grant.PubKeyHex(), StoreAgentReader: cfg.AgentPubkey, IntervalSeconds: 1}
	out, code := l.command("signer booking outbox", l.bins["signer"], "-config", l.json("signer.json", fc, 0600), "-once")
	if code != 1 || strings.TrimSpace(string(out)) != "PRIVATE_FILE" {
		t.Fatal("signer CLI did not expose outbox mismatch")
	}
	fc.BookingOutbox = l.dir("empty-source-control")
	l.write(filepath.Join(fc.BookingOutbox, "index.json"), []byte("[]"), 0600)
	out, code = l.command("signer empty control", l.bins["signer"], "-config", l.json("signer-control.json", fc, 0600), "-once")
	if code != 0 {
		t.Fatal("signer startup positive control refused")
	}
	if leaked(out, l.secrets) {
		t.Fatal("signer diagnostic secret output")
	}
	l.evidence["signer_cli"] = map[string]any{"booking_source_exit": 1, "reason": "PRIVATE_FILE", "empty_source_control_exit": 0, "no_item_adapter_created": true, "inventory_enrolled": false}
	client := &store.Client{Signer: grant}
	list, e := client.List(context.Background(), storeURL)
	if e == nil || e.Error() != "store status 403" || len(list) != 0 {
		t.Fatal("S1 empty namespace invariant")
	}
	l.evidence["s1_grants_stored"] = 0
}

func (l *lab) managerDiagnostic(p tlsPaths, endpoint, hash string) {
	// Field order exactly matches the landed CLI's canonical config schema.
	c := struct {
		StateDir string `json:"state_dir"`
		Socket   string `json:"slotd_socket"`
		Min      uint16 `json:"slot_min"`
		Max      uint16 `json:"slot_max"`
		Payload  string `json:"payload_id"`
		Hash     string `json:"payload_sha256"`
		Endpoint string `json:"gateway_endpoint"`
		Pin      string `json:"gateway_cert_sha256"`
		Cert     string `json:"client_cert"`
		Key      string `json:"client_key"`
		CA       string `json:"server_ca"`
	}{filepath.Join(l.private, "manager"), filepath.Join(l.private, "fake-slotd.sock"), 1, 64, "rehearsal-payload", hash, "https://" + endpoint + "/v1/station-manager/poll", p.serverPin, p.client, p.clientKey, p.ca}
	path := l.json("manager.json", c, 0600)
	out, code := l.command("manager config", l.bins["manager"], "check-config", "--config", path)
	if code != 0 {
		l.t.Fatal("manager positive config control refused")
	}
	_ = out
	l.write(c.Socket+".clock", []byte(`{"boot_id":"0f8e1c3a-6b2d-4e7f-9a1b-2c3d4e5f6a7b","issued_boottime_ns":"10000000000"}`), 0600)
	listener, e := net.Listen("unix", c.Socket)
	checked(l.t, e, "fixture helper socket")
	defer listener.Close()
	checked(l.t, os.Chmod(c.Socket, 0600), "fixture socket mode")
	l.dir("manager")
	proc := l.spawn("manager", "run", "--config", path)
	l.await("tagged manager state", func() bool { _, e := os.Stat(filepath.Join(c.StateDir, "state.json")); return e == nil })
	l.stop(proc)
	b, e := os.ReadFile(filepath.Join(l.private, "manager.log"))
	checked(l.t, e, "manager log")
	if len(bytes.TrimSpace(b)) != 0 {
		l.t.Fatal("manager startup error")
	}
	l.evidence["manager_cli"] = map[string]any{"check_config_exit": 0, "tagged_darwin_run_started": true, "state_created": true, "fake_helper_reached": false, "reason": "no issuance, so no slot command; real fake lifecycle tested separately"}
}
