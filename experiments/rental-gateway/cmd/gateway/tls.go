package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net/http"
	"time"
)

var errTLS = errors.New("TLS_CONFIGURATION_REFUSED")

type gatewayTLSConfig struct {
	CertFile          string `json:"cert_file"`
	KeyFile           string `json:"key_file"`
	CertSHA256        string `json:"cert_sha256"`
	ManagerCAFile     string `json:"manager_ca_file"`
	ManagerCertSHA256 string `json:"manager_cert_sha256"`
}

// The manager has separate transport authority: a verified client certificate
// AND its exact leaf pin. Payloads use server TLS followed by stationlink HMAC;
// they never receive the manager certificate or key.
func gatewayTLS(c gatewayTLSConfig) (manager, payload *tls.Config, err error) {
	if !digest(c.CertSHA256) || !digest(c.ManagerCertSHA256) {
		return nil, nil, errTLS
	}
	certPEM, e := readFile(c.CertFile, 64<<10, 0)
	if e != nil {
		return nil, nil, errTLS
	}
	keyPEM, e := readFile(c.KeyFile, 16<<10, 0400)
	if e != nil {
		return nil, nil, errTLS
	}
	defer clear(keyPEM)
	cert, e := tls.X509KeyPair(certPEM, keyPEM)
	if e != nil || len(cert.Certificate) == 0 {
		return nil, nil, errTLS
	}
	leaf, e := x509.ParseCertificate(cert.Certificate[0])
	if e != nil {
		return nil, nil, errTLS
	}
	now := time.Now()
	hash := sha256.Sum256(leaf.Raw)
	if hex.EncodeToString(hash[:]) != c.CertSHA256 || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, nil, errTLS
	}
	ca, e := readFile(c.ManagerCAFile, 64<<10, 0)
	if e != nil {
		return nil, nil, errTLS
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, nil, errTLS
	}
	payload = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
	manager = payload.Clone()
	manager.ClientAuth = tls.RequireAndVerifyClientCert
	manager.ClientCAs = roots
	manager.VerifyConnection = func(s tls.ConnectionState) error {
		if len(s.VerifiedChains) == 0 || len(s.PeerCertificates) == 0 {
			return errTLS
		}
		pin := sha256.Sum256(s.PeerCertificates[0].Raw)
		if hex.EncodeToString(pin[:]) != c.ManagerCertSHA256 {
			return errTLS
		}
		return nil
	}
	return manager, payload, nil
}

func managerHTTP(handler http.Handler) *http.Server {
	return &http.Server{Handler: handler, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 4096}
}
