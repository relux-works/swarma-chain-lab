package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Private-input validation rejects aliases, permissive files and oversized
// material before parsing, and returns fixed codes without echoing input bytes.
func TestPrivateInput(t *testing.T) {
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	os.Chmod(root, 0750)
	p := filepath.Join(root, "config")
	secret := "fixture-private-input"
	if e = os.WriteFile(p, []byte(secret), 0640); e != nil {
		t.Fatal(e)
	}
	if raw, e := readPrivate(p); e != nil || string(raw) != secret {
		t.Fatal("valid private input", e)
	}
	if e = os.Chmod(p, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = readPrivate(p); e == nil || e.Error() != "DK5_FILE_MODE" {
		t.Fatal("public input accepted", e)
	}
	if e = os.Chmod(p, 0640); e != nil {
		t.Fatal(e)
	}
	alias := filepath.Join(root, "alias")
	if e = os.Symlink(p, alias); e != nil {
		t.Fatal(e)
	}
	if _, e = readPrivate(alias); e == nil || e.Error() != "DK5_FILE_OPEN" {
		t.Fatal("symlink input accepted", e)
	}
	if e = os.WriteFile(p, []byte(strings.Repeat("x", 65537)), 0640); e != nil {
		t.Fatal(e)
	}
	if _, e = readPrivate(p); e == nil || e.Error() != "DK5_FILE_SIZE" {
		t.Fatal("unbounded input accepted", e)
	}
	if e = os.WriteFile(p, []byte(`{"unknown":"`+secret+`"}`), 0640); e != nil {
		t.Fatal(e)
	}
	e = run(context.Background(), []string{"check-config", "--config", p})
	if e == nil || e.Error() != "CONFIG" || strings.Contains(e.Error(), secret) {
		t.Fatal("invalid config leaked or accepted", e)
	}
}

// A complete private configuration validates without contacting any helper,
// creating runtime state, or copying the manager key into a station bootstrap.
func TestCheckConfig(t *testing.T) {
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	os.Chmod(root, 0750)
	pub, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fixture"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
	if e != nil {
		t.Fatal(e)
	}
	pk, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	write := func(name string, b []byte) string {
		p := filepath.Join(root, name)
		if e := os.WriteFile(p, b, 0640); e != nil {
			t.Fatal(e)
		}
		return p
	}
	cp := write("cert.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	kp := write("key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}))
	c := config{StateDir: filepath.Join(root, "state"), Socket: filepath.Join(root, "helper.sock"), SlotMin: 1, SlotMax: 16, PayloadID: "fixture", PayloadSHA256: strings.Repeat("a", 64), Endpoint: "https://127.0.0.1:9443/v1/station-manager/poll", GatewayCertSHA256: strings.Repeat("b", 64), ClientCert: cp, ClientKey: kp, ServerCA: cp}
	raw, e := json.Marshal(c)
	if e != nil {
		t.Fatal(e)
	}
	path := write("config.json", raw)
	if e = run(context.Background(), []string{"check-config", "--config", path}); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(c.StateDir); !os.IsNotExist(e) {
		t.Fatal("check-config created runtime state")
	}
	if _, e = os.Stat(c.Socket); !os.IsNotExist(e) {
		t.Fatal("check-config touched helper")
	}
}
