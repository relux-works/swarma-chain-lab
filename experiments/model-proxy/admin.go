package modelproxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type adminRequest struct {
	V       int     `json:"v"`
	Op      string  `json:"op"`
	Binding Binding `json:"binding"`
}
type adminResponse struct {
	V          int         `json:"v"`
	OK         bool        `json:"ok"`
	Binding    Binding     `json:"binding"`
	Credential *Credential `json:"credential,omitempty"`
	Error      string      `json:"error,omitempty"`
}
type peerKey struct{}

func (s *Service) adminHandler(w http.ResponseWriter, r *http.Request) {
	if valid, ok := r.Context().Value(peerKey{}).(bool); !ok || !valid {
		refusal(w, 403, "PEER")
		return
	}
	if r.Method != "POST" || r.URL.Path != "/v1/registry" || r.URL.RawQuery != "" {
		refusal(w, 400, "ADMIN")
		return
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, 4097))
	var q adminRequest
	if e != nil || len(raw) > 4096 || unique(raw) != nil || json.Unmarshal(raw, &q) != nil || !bytes.Equal(raw, canonical(q)) || q.V != 1 || !q.Binding.Valid() {
		refusal(w, 400, "ADMIN")
		return
	}
	out := adminResponse{V: 1, Binding: q.Binding}
	switch q.Op {
	case "prepare":
		c, err := s.Prepare(q.Binding)
		e = err
		if e == nil {
			out.Credential = &c
		}
	case "activate":
		e = s.Activate(q.Binding)
	case "revoke":
		e = s.Revoke(q.Binding)
	default:
		refusal(w, 400, "ADMIN")
		return
	}
	if e != nil {
		out.Error = "ADMIN_REFUSED"
	} else {
		out.OK = true
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(canonical(out))
}

// ServeAdmin owns only the newly created socket. Parent ownership/mode and caller
// UID are operator inputs; it installs no user, group, service or privilege rule.
func (s *Service) ServeAdmin(ctx context.Context, path string, callerUID uint32) error {
	if !supportsPeers() {
		return fail("LINUX_ONLY")
	}
	if !privateParent(path, os.Getuid()) {
		return fail("ADMIN_PATH")
	}
	if _, e := os.Lstat(path); !os.IsNotExist(e) {
		return fail("ADMIN_EXISTS")
	}
	ln, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		return fail("ADMIN_LISTEN")
	}
	defer ln.Close()
	if os.Chmod(path, 0660) != nil {
		return fail("ADMIN_MODE")
	}
	server := &http.Server{Handler: http.HandlerFunc(s.adminHandler), ReadHeaderTimeout: time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second, MaxHeaderBytes: 4096, ErrorLog: log.New(io.Discard, "", 0), ConnContext: func(ctx context.Context, c net.Conn) context.Context { return context.WithValue(ctx, peerKey{}, true) }}
	accepted := &peerListener{Listener: ln, uid: callerUID}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			server.Close()
		case <-done:
		}
	}()
	e = server.Serve(accepted)
	if e != nil && e != http.ErrServerClosed {
		return fail("ADMIN_SERVE")
	}
	return nil
}

type peerListener struct {
	net.Listener
	uid uint32
}

func (p *peerListener) Accept() (net.Conn, error) {
	for {
		c, e := p.Listener.Accept()
		if e != nil {
			return nil, e
		}
		uid, e := peerUID(c)
		if e == nil && uid == p.uid {
			return c, nil
		}
		c.Close()
	}
}
func noLinks(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	for p := path; ; p = filepath.Dir(p) {
		i, e := os.Lstat(p)
		if e != nil || i.Mode()&os.ModeSymlink != 0 {
			return false
		}
		if p == "/" {
			break
		}
	}
	return true
}
func privateParent(path string, uid int) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !noLinks(filepath.Dir(path)) {
		return false
	}
	i, e := os.Lstat(filepath.Dir(path))
	return e == nil && i.IsDir() && i.Mode().Perm() == 0750 && fileUID(i) == uid
}

// Client is the local registrar boundary. Production checks the proxy's socket
// and connected peer UID; there is no TCP or non-Linux fallback.
type Client struct {
	SocketPath string
	ServerUID  uint32
}

func (c Client) call(ctx context.Context, q adminRequest) (adminResponse, error) {
	var out adminResponse
	if !supportsPeers() {
		return out, fail("LINUX_ONLY")
	}
	if !privateParent(c.SocketPath, int(c.ServerUID)) {
		return out, fail("ADMIN_PATH")
	}
	i, e := os.Lstat(c.SocketPath)
	if e != nil || i.Mode()&os.ModeSocket == 0 || i.Mode().Perm() != 0660 || fileUID(i) != int(c.ServerUID) {
		return out, fail("ADMIN_PATH")
	}
	transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		d := net.Dialer{Timeout: time.Second}
		conn, e := d.DialContext(ctx, "unix", c.SocketPath)
		if e != nil {
			return nil, fail("ADMIN_CONNECT")
		}
		uid, e := peerUID(conn)
		if e != nil || uid != c.ServerUID {
			conn.Close()
			return nil, fail("PEER")
		}
		return conn, nil
	}}
	defer transport.CloseIdleConnections()
	call, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	req, e := http.NewRequestWithContext(call, "POST", "http://local/v1/registry", bytes.NewReader(canonical(q)))
	if e != nil {
		return out, fail("ADMIN")
	}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return fail("REDIRECT") }}
	resp, e := client.Do(req)
	if e != nil {
		return out, fail("ADMIN_TRANSPORT")
	}
	defer resp.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(resp.Body, 4097))
	if e != nil || len(raw) > 4096 || resp.StatusCode != 200 || unique(raw) != nil || json.Unmarshal(raw, &out) != nil || !bytes.Equal(raw, canonical(out)) || out.V != 1 || out.Binding != q.Binding {
		return adminResponse{}, fail("ADMIN_RESPONSE")
	}
	if !out.OK || out.Error != "" {
		return adminResponse{}, fail("ADMIN_REFUSED")
	}
	if q.Op == "prepare" {
		if out.Credential == nil || !out.Credential.Valid() {
			return adminResponse{}, fail("ADMIN_RESPONSE")
		}
	} else if out.Credential != nil {
		return adminResponse{}, fail("ADMIN_RESPONSE")
	}
	return out, nil
}
func (c Credential) Valid() bool {
	b, e := base64.RawURLEncoding.DecodeString(string(c.Bearer))
	return e == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == string(c.Bearer) && validOrigin(c.Endpoint.URL) && digest(c.Endpoint.CertSHA256)
}
func (c Client) Prepare(ctx context.Context, b Binding) (Credential, error) {
	r, e := c.call(ctx, adminRequest{1, "prepare", b})
	if e != nil {
		return Credential{}, e
	}
	return *r.Credential, nil
}
func (c Client) Activate(ctx context.Context, b Binding) error {
	_, e := c.call(ctx, adminRequest{1, "activate", b})
	return e
}
func (c Client) Revoke(ctx context.Context, b Binding) error {
	_, e := c.call(ctx, adminRequest{1, "revoke", b})
	return e
}
