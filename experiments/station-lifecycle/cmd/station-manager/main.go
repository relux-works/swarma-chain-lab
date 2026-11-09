// station-manager is the demo station-lifecycle adapter, not a platform user
// manager replacement. It invokes only the separately installed slotd protocol.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	lifecycle "github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle"
)

type config struct {
	StateDir          string `json:"state_dir"`
	Socket            string `json:"slotd_socket"`
	SlotMin           uint16 `json:"slot_min"`
	SlotMax           uint16 `json:"slot_max"`
	PayloadID         string `json:"payload_id"`
	PayloadSHA256     string `json:"payload_sha256"`
	Endpoint          string `json:"gateway_endpoint"`
	GatewayCertSHA256 string `json:"gateway_cert_sha256"`
	ClientCert        string `json:"client_cert"`
	ClientKey         string `json:"client_key"`
	ServerCA          string `json:"server_ca"`
}

func fail(code string) error { return errors.New(code) }

// Inputs are private, bounded, regular files with no symlink path components.
// Check the opened descriptor against lstat before reading; never echo paths or
// parse errors, which could contain credentials supplied by a malformed input.
func readPrivate(path string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fail("INPUT_PATH")
	}
	resolved, e := filepath.EvalSymlinks(path)
	if e != nil || resolved != path {
		return nil, fail("INPUT_PATH")
	}
	before, e := os.Lstat(path)
	if e != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0077 != 0 {
		return nil, fail("INPUT_MODE")
	}
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, fail("INPUT_OPEN")
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !os.SameFile(before, st) || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return nil, fail("INPUT_MODE")
	}
	owner, ok := st.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) || owner.Nlink != 1 {
		return nil, fail("INPUT_OWNER")
	}
	raw, e := io.ReadAll(io.LimitReader(f, 65537))
	if e != nil || len(raw) == 0 || len(raw) > 65536 {
		return nil, fail("INPUT_SIZE")
	}
	return raw, nil
}
func load(path string) (config, *lifecycle.PollClient, error) {
	c := config{}
	raw, e := readPrivate(path)
	if e != nil {
		return c, nil, e
	}
	raw = bytes.TrimSpace(raw)
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&c) != nil {
		return c, nil, fail("CONFIG")
	}
	encoded, _ := json.Marshal(c)
	if !bytes.Equal(raw, encoded) {
		return c, nil, fail("CONFIG_CANONICAL")
	}
	if c.SlotMin > c.SlotMax || c.SlotMax > 9999 || !filepath.IsAbs(c.StateDir) || filepath.Clean(c.StateDir) != c.StateDir || !filepath.IsAbs(c.Socket) || filepath.Clean(c.Socket) != c.Socket {
		return c, nil, fail("CONFIG")
	}
	// Validate core policy without creating a state directory or acquiring a lock.
	if !validPayload(c.PayloadID, c.PayloadSHA256) {
		return c, nil, fail("CONFIG")
	}
	cert, e := readPrivate(c.ClientCert)
	if e != nil {
		return c, nil, e
	}
	key, e := readPrivate(c.ClientKey)
	if e != nil {
		return c, nil, e
	}
	pair, e := tls.X509KeyPair(cert, key)
	if e != nil {
		return c, nil, fail("CLIENT_CERT")
	}
	ca, e := readPrivate(c.ServerCA)
	if e != nil {
		return c, nil, e
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return c, nil, fail("SERVER_CA")
	}
	client, e := lifecycle.NewPollClient(c.Endpoint, pair, roots, c.GatewayCertSHA256)
	if e != nil {
		return c, nil, fail("LINK_CONFIG")
	}
	return c, client, nil
}
func validPayload(id, hash string) bool {
	if len(id) == 0 || len(id) > 64 || len(hash) != 64 {
		return false
	}
	for _, v := range id {
		if !(v >= 'a' && v <= 'z' || v >= '0' && v <= '9' || v == '-' || v == '_') {
			return false
		}
	}
	for _, v := range hash {
		if !(v >= 'a' && v <= 'f' || v >= '0' && v <= '9') {
			return false
		}
	}
	return true
}
func run(ctx context.Context, args []string) error {
	if len(args) != 3 || (args[0] != "run" && args[0] != "check-config") || args[1] != "--config" {
		return fail("USAGE: station-manager run|check-config --config ABSOLUTE_PRIVATE_JSON")
	}
	c, client, e := load(args[2])
	if e != nil {
		return e
	}
	defer client.Close()
	if args[0] == "check-config" {
		return nil
	}
	host, e := newHost(c)
	if e != nil {
		return e
	}
	m, e := lifecycle.New(lifecycle.Config{StateDir: c.StateDir, Range: lifecycle.Range{First: c.SlotMin, Last: c.SlotMax}, Payload: lifecycle.Payload{ID: c.PayloadID, SHA256: c.PayloadSHA256}, Host: host, Now: time.Now})
	if e != nil {
		return e
	}
	defer m.Close()
	e = client.Run(ctx, m)
	if errors.Is(e, context.Canceled) {
		return nil
	}
	return e
}
func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if e := run(ctx, os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, "station-manager:", e)
		os.Exit(1)
	}
}
