package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/configguard"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	proxy "github.com/relux-works/swarma-chain-lab/experiments/model-proxy"
)

func main() {
	configguard.CheckMain("model")
	if e := run(); e != nil {
		var reason configguard.Reason
		if errors.As(e, &reason) {
			fmt.Fprintln(os.Stderr, reason.Error())
		} else {
			fmt.Fprintln(os.Stderr, "MODEL_PROXY_FAILED")
		}
		os.Exit(1)
	}
}
func run() error {
	path := flag.String("config", "", "private configuration file")
	flag.Parse()
	if *path == "" || flag.NArg() != 0 || runtime.GOOS != "linux" {
		return fmt.Errorf("CONFIG")
	}
	c, e := proxy.LoadConfig(*path)
	if e != nil {
		return e
	}
	key, e := proxy.ReadInstalledFile(c.APIKeyFile, 4096)
	if e != nil {
		return e
	}
	certPEM, e := proxy.ReadInstalledFile(c.TLSCert, 65536)
	if e != nil {
		return e
	}
	keyPEM, e := proxy.ReadInstalledFile(c.TLSKey, 65536)
	if e != nil {
		return e
	}
	cert, e := tls.X509KeyPair(certPEM, keyPEM)
	if e != nil || len(cert.Certificate) == 0 {
		return fmt.Errorf("TLS")
	}
	h := sha256.Sum256(cert.Certificate[0])
	if hex.EncodeToString(h[:]) != c.Endpoint.CertSHA256 {
		return fmt.Errorf("TLS_PIN")
	}
	origin, e := url.Parse(c.Endpoint.URL)
	if e != nil {
		return fmt.Errorf("ORIGIN")
	}
	host, port, e := net.SplitHostPort(c.Listen)
	if e != nil || net.ParseIP(host) == nil || port == "0" {
		return fmt.Errorf("LISTEN")
	}
	expected := origin.Port()
	if expected == "" {
		expected = "443"
	}
	if port != expected {
		return fmt.Errorf("LISTEN")
	}
	var mu sync.Mutex
	s, e := proxy.New(proxy.Config{StateDir: c.StateDir, Endpoint: c.Endpoint, Upstream: c.Upstream, APIKey: proxy.Secret(key), Models: c.Models, ModelProfiles: c.ModelProfiles, Now: time.Now, Audit: func(a proxy.Audit) { mu.Lock(); defer mu.Unlock(); _ = json.NewEncoder(os.Stdout).Encode(a) }})
	if e != nil {
		return e
	}
	defer s.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	ln, e := net.Listen("tcp", c.Listen)
	if e != nil {
		return fmt.Errorf("LISTEN")
	}
	defer ln.Close()
	server := &http.Server{Handler: s, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 65 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 8192, ErrorLog: log.New(io.Discard, "", 0)}
	tlsLn := tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	errs := make(chan error, 2)
	go func() { errs <- s.ServeAdmin(ctx, c.AdminSocket, c.CallerUID) }()
	go func() { errs <- server.Serve(tlsLn) }()
	select {
	case e = <-errs:
	case <-ctx.Done():
	}
	cancel()
	server.Close()
	return e
}
