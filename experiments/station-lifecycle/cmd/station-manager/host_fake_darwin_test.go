//go:build darwin && slotdfake

package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	lifecycle "relux.works/swarma-chain-lab/experiments/station-lifecycle"
	"relux.works/swarma-chain-lab/experiments/station-lifecycle/slotd"
	"strings"
	"sync"
	"testing"
	"time"
)

func fixtureHash(b []byte) string { v := sha256.Sum256(b); return hex.EncodeToString(v[:]) }

// The actual manager run entry point polls a real mTLS broker and drives a Unix
// fake through the unchanged r4 codec. Early stop destroys the bound fake slot;
// this does not claim OS isolation, payload execution or physical data erasure.
func TestFakeManagerRun(t *testing.T) {
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	write := func(name string, b []byte) string {
		t.Helper()
		p := filepath.Join(root, name)
		if e := os.WriteFile(p, b, 0600); e != nil {
			t.Fatal(e)
		}
		return p
	}
	mk := func(name string) string {
		p := filepath.Join(root, name)
		if e := os.Mkdir(p, 0700); e != nil {
			t.Fatal(e)
		}
		return p
	}
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	pk, _ := x509.MarshalPKCS8PrivateKey(key)
	cp := write("cert", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	kp := write("key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}))
	roots := x509.NewCertPool()
	parsed, _ := x509.ParseCertificate(der)
	roots.AddCert(parsed)
	pair := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	payload := fixtureHash([]byte("fake payload"))
	b, e := lifecycle.NewBroker(lifecycle.BrokerConfig{StateDir: mk("broker"), Range: lifecycle.Range{First: 1, Last: 8}, Payload: lifecycle.Payload{ID: "fixture", SHA256: payload}, Now: time.Now})
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	server := httptest.NewUnstartedServer(b.Handler(fixtureHash(der)))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()
	socket := filepath.Join(root, "fake.sock")
	listener, e := net.Listen("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	if e = os.Chmod(socket, 0600); e != nil {
		t.Fatal(e)
	}
	fence := lifecycle.CreateFence{BootID: "0f8e1c3a-6b2d-4e7f-9a1b-2c3d4e5f6a7b", IssuedBoottimeNS: "10000000000"}
	clock, _ := json.Marshal(fence)
	write("fake.sock.clock", clock)
	var mu sync.Mutex
	records := map[string]slotd.Response{}
	ops := []string{}
	helperDone := make(chan struct{})
	go func() {
		defer close(helperDone)
		for {
			conn, e := listener.Accept()
			if e != nil {
				return
			}
			func() {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(time.Second))
				raw, e := bufio.NewReader(conn).ReadBytes('\n')
				if e != nil || len(raw) > slotd.MaxWire {
					return
				}
				var q slotd.Request
				if json.Unmarshal(raw, &q) != nil || !slotd.ValidRequest(q) {
					return
				}
				mu.Lock()
				defer mu.Unlock()
				ops = append(ops, q.Op)
				r, ok := records[q.Slot]
				if !ok {
					r = slotd.Response{V: 1, OK: true, Slot: q.Slot, State: "absent"}
				}
				switch q.Op {
				case "create":
					if *q.BootID != fence.BootID || *q.IssuedBoottimeNS != fence.IssuedBoottimeNS || r.State != "absent" {
						return
					}
					decoded, _ := base64.StdEncoding.DecodeString(*q.Bootstrap)
					r = slotd.Response{V: 1, OK: true, Slot: q.Slot, State: "created", NotAfter: *q.NotAfter, PayloadSHA256: payload, BootstrapSHA256: fixtureHash(decoded)}
				case "start":
					if r.State != "created" {
						return
					}
					r.State = "running"
				case "stop":
					if r.State != "running" {
						return
					}
					r.State = "stopped"
				case "destroy":
					if r.State != "stopped" {
						return
					}
					r.State = "destroyed"
				}
				records[q.Slot] = r
				out, _ := json.Marshal(r)
				conn.Write(append(out, '\n'))
			}()
		}
	}()
	defer func() { listener.Close(); <-helperDone }()
	c := config{StateDir: mk("manager"), Socket: socket, SlotMin: 1, SlotMax: 8, PayloadID: "fixture", PayloadSHA256: payload, Endpoint: server.URL + lifecycle.PollPath, GatewayCertSHA256: fixtureHash(der), ClientCert: cp, ClientKey: kp, ServerCA: cp}
	raw, _ := json.Marshal(c)
	path := write("config", raw)
	// Missing/invalid clock never constructs a fake host; no wall-clock fallback.
	write("fake.sock.clock", []byte(`{}`))
	if _, e = newHost(c); e == nil || e.Error() != "SLOTD_FAKE_CLOCK" {
		t.Fatal("invalid fake clock accepted")
	}
	write("fake.sock.clock", clock)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, []string{"run", "--config", path}) }()
	defer func() {
		cancel()
		select {
		case e := <-done:
			if e != nil {
				t.Error(e)
			}
		case <-time.After(5 * time.Second):
			t.Error("manager did not stop")
		}
	}()
	booking := fixtureHash([]byte("booking"))
	s, e := b.Allocate(booking, fixtureHash([]byte("grant")), time.Now().Unix()-1, time.Now().Unix()+300)
	if e != nil {
		t.Fatal(e)
	}
	if e = b.SetStart(booking); e != nil {
		t.Fatal(e)
	}
	wait := func(phase string) {
		t.Helper()
		call, stop := context.WithTimeout(ctx, 5*time.Second)
		defer stop()
		if _, e := b.Wait(call, booking, phase); e != nil {
			t.Fatal("broker phase "+phase, e)
		}
	}
	wait("running")
	if e = b.SetStop(booking); e != nil {
		t.Fatal(e)
	}
	wait("stopped")
	mu.Lock()
	state := records[s.ID].State
	trace := strings.Join(ops, ",")
	mu.Unlock()
	if state != "destroyed" || !strings.Contains(trace, "create") || !strings.Contains(trace, "start") || !strings.Contains(trace, "destroy") {
		t.Fatal("fake manager lifecycle incomplete", state, trace)
	}
}
