package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "isolated-test-ca"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, e := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	cert, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	return &testCA{cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}
func (ca *testCA) leaf(t *testing.T, serial int64, client, expired bool) (tls.Certificate, []byte, []byte) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	usage := x509.ExtKeyUsageServerAuth
	if client {
		usage = x509.ExtKeyUsageClientAuth
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	if expired {
		tmpl.NotAfter = time.Now().Add(-time.Minute)
	}
	der, e := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw})
	pair, e := tls.X509KeyPair(certPEM, keyPEM)
	if e != nil {
		t.Fatal(e)
	}
	return pair, certPEM, keyPEM
}
func certPin(c tls.Certificate) string {
	h := sha256.Sum256(c.Certificate[0])
	return hex.EncodeToString(h[:])
}

// Real TLS handshakes require both trust and the manager leaf pin. A trusted
// sibling, an untrusted certificate, no client cert and an expired cert cannot
// invoke the manager handler. Payload TLS intentionally needs no client cert.
func TestGatewayTLSAuthority(t *testing.T) {
	ca := newTestCA(t)
	server, certPEM, keyPEM := ca.leaf(t, 2, false, false)
	manager, _, _ := ca.leaf(t, 3, true, false)
	root := testRoot(t)
	write := func(name string, b []byte, mode os.FileMode) string {
		t.Helper()
		p := filepath.Join(root, name)
		if e := os.WriteFile(p, b, mode); e != nil {
			t.Fatal(e)
		}
		return p
	}
	c := gatewayTLSConfig{CertFile: write("server.pem", certPEM, 0644), KeyFile: write("server.key", keyPEM, 0400), CertSHA256: certPin(server), ManagerCAFile: write("ca.pem", ca.pem, 0644), ManagerCertSHA256: certPin(manager)}
	mtls, payload, e := gatewayTLS(c)
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.pem)
	var calls atomic.Int64
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(204) })
	serveTLS := func(conf *tls.Config) *httptest.Server {
		t.Helper()
		s := httptest.NewUnstartedServer(h)
		s.Config = managerHTTP(h)
		s.Config.ErrorLog = log.New(io.Discard, "", 0)
		s.TLS = conf
		s.StartTLS()
		t.Cleanup(s.Close)
		return s
	}
	srv := serveTLS(mtls)
	try := func(s *httptest.Server, certs []tls.Certificate) bool {
		t.Helper()
		tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: certs, MinVersion: tls.VersionTLS13}, Proxy: nil}
		defer tr.CloseIdleConnections()
		client := &http.Client{Transport: tr, Timeout: time.Second}
		resp, e := client.Post(s.URL+"/v1/station-manager/poll", "application/json", nil)
		if e != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == 204
	}
	if !try(srv, []tls.Certificate{manager}) || calls.Load() != 1 {
		t.Fatal("valid manager refused")
	}
	sibling, _, _ := ca.leaf(t, 4, true, false)
	untrusted, _, _ := newTestCA(t).leaf(t, 5, true, false)
	expired, _, _ := ca.leaf(t, 6, true, true)
	for _, certs := range [][]tls.Certificate{nil, {sibling}, {untrusted}, {expired}} {
		if try(srv, certs) || calls.Load() != 1 {
			t.Fatal("manager authority bypass")
		}
	}
	if !try(srv, []tls.Certificate{manager}) || calls.Load() != 2 {
		t.Fatal("valid manager after refusals")
	}
	public := serveTLS(payload)
	if !try(public, nil) || payload.ClientAuth != tls.NoClientCert {
		t.Fatal("payload incorrectly requires manager credential")
	}
	// The own certificate pin is checked before listening, and the key file's
	// private permission requirement is not waived by a matching public pin.
	wrong := c
	wrong.CertSHA256 = c.ManagerCertSHA256
	if _, _, e = gatewayTLS(wrong); e != errTLS {
		t.Fatal("server pin accepted")
	}
	if e = os.Chmod(c.KeyFile, 0644); e != nil {
		t.Fatal(e)
	}
	if _, _, e = gatewayTLS(c); e != errTLS {
		t.Fatal("public TLS key accepted")
	}
}
