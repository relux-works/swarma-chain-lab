package chaingateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	ExitConfig   = 10
	ExitNode     = 11
	ExitTipMoved = 12
	ExitLocked   = 13
	ExitPublish  = 14
)

// Configuration contains operator-selected paths and watch bindings, never secrets.
// Its JSON is closed; all fields are required (including an explicit credential mode).
type Configuration struct {
	RPCURL          string     `json:"rpc_url"`
	Network         string     `json:"network"`
	Genesis         string     `json:"genesis"`
	CredentialMode  string     `json:"credential_mode"`
	CredentialFile  string     `json:"credential_file"`
	CredentialGroup uint32     `json:"credential_group"`
	Output          string     `json:"output"`
	Lock            string     `json:"lock"`
	Names           []string   `json:"names"`
	Seals           []Outpoint `json:"seals"`
}
type Outpoint struct {
	Txid string `json:"txid"`
	Vout uint32 `json:"vout"`
}

type custody struct {
	uid    uint32
	anchor string
}

// Main is a root-only oneshot. Only fixed diagnostics cross this boundary.
// Scheduling, ownership provisioning and installed qualification belong to Infra.
func Main(args []string, output io.Writer) int {
	if len(args) != 2 || args[0] != "-config" || os.Geteuid() != 0 {
		return report(ExitConfig, output)
	}
	return runReport(args[1], custody{uid: 0, anchor: "/"}, output)
}
func runReport(path string, p custody, output io.Writer) int { return report(run(path, p), output) }
func report(code int, output io.Writer) int {
	messages := map[int]string{0: "snapshot refreshed (observe only)", 10: "invalid configuration or custody", 11: "node or credential unavailable", 12: "tip moved; previous snapshot retained", 13: "writer already active", 14: "publication failed"}
	fmt.Fprintln(output, messages[code])
	return code
}

func cleanPath(s string) bool { return filepath.IsAbs(s) && filepath.Clean(s) == s && s != "/" }

// openProtected walks from / with descriptor-relative O_NOFOLLOW. Extended ACLs
// are rejected rather than guessing their effective write permissions.
func (p custody) openProtected(path string, flags int, mode uint32) (*os.File, error) {
	if !cleanPath(path) {
		return nil, bad("path")
	}
	anchor := p.anchor
	if anchor == "" {
		anchor = "/"
	}
	rel, e := filepath.Rel(anchor, path)
	if e != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		return nil, bad("anchor")
	}
	fd, e := syscall.Open(anchor, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	parts := strings.Split(rel, "/")
	for i, part := range parts {
		nextFlags := syscall.O_RDONLY | syscall.O_DIRECTORY
		if i == len(parts)-1 {
			nextFlags = flags
		}
		next, e := syscall.Openat(fd, part, nextFlags|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, mode)
		syscall.Close(fd)
		if e != nil {
			return nil, e
		}
		fd = next
		var st syscall.Stat_t
		if e = syscall.Fstat(fd, &st); e != nil {
			syscall.Close(fd)
			return nil, e
		}
		// Fixture custody uses the current uid; root-owned higher ancestors remain trusted.
		if (st.Uid != p.uid && st.Uid != 0) || st.Mode&0022 != 0 {
			syscall.Close(fd)
			return nil, bad("custody")
		}
		_, e = syscall.Getxattr("/proc/self/fd/"+strconv.Itoa(fd), "system.posix_acl_access", nil)
		if e != syscall.ENODATA && e != syscall.ENOTSUP {
			syscall.Close(fd)
			return nil, bad("acl")
		}
	}
	return os.NewFile(uintptr(fd), path), nil
}
func regular(f *os.File, uid uint32, modes ...uint32) (*syscall.Stat_t, error) {
	var st syscall.Stat_t
	if syscall.Fstat(int(f.Fd()), &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Nlink != 1 || st.Uid != uid || !slices.Contains(modes, st.Mode&07777) {
		return nil, bad("file custody")
	}
	return &st, nil
}
func (p custody) read(path string, limit int, modes ...uint32) ([]byte, *syscall.Stat_t, error) {
	f, e := p.openProtected(path, syscall.O_RDONLY, 0)
	if e != nil {
		return nil, nil, e
	}
	defer f.Close()
	st, e := regular(f, p.uid, modes...)
	if e != nil {
		return nil, nil, e
	}
	b, e := io.ReadAll(io.LimitReader(f, int64(limit+1)))
	if e != nil || len(b) > limit {
		return nil, nil, bad("size")
	}
	return b, st, nil
}
func loadConfig(path string, p custody) (Configuration, error) {
	var c Configuration
	b, _, e := p.read(path, 65536, 0600, 0644)
	if e != nil {
		return c, e
	}
	m, e := parseJSON(b, 65536, false, false)
	if e != nil {
		return c, e
	}
	if _, e = fields(m, "rpc_url", "network", "genesis", "credential_mode", "credential_file", "credential_group", "output", "lock", "names", "seals"); e != nil {
		return c, e
	}
	// Re-encode parsed maps to preserve duplicate/alias protection before typed decoding.
	b, _ = json.Marshal(m)
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e = d.Decode(&c); e != nil {
		return c, e
	}
	u, e := url.Parse(c.RPCURL)
	if e != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || u.RawPath != "" || u.Port() == "" {
		return c, bad("endpoint")
	}
	ip := net.ParseIP(u.Hostname())
	if ip == nil || !ip.IsLoopback() {
		return c, bad("local endpoint")
	}
	port, e := strconv.Atoi(u.Port())
	if e != nil || port < 1 || port > 65535 {
		return c, bad("port")
	}
	if !network(c.Network) || !hash(c.Genesis) || (c.CredentialMode != "cookie" && c.CredentialMode != "rpcauth-user") {
		return c, bad("bindings")
	}
	paths := []string{path, c.CredentialFile, c.Output, c.Lock}
	for i, s := range paths {
		if !cleanPath(s) {
			return c, bad("path")
		}
		for _, other := range paths[:i] {
			if s == other {
				return c, bad("overlap")
			}
		}
	}
	if len(c.Names) < 1 || len(c.Names) > 16 || len(c.Seals) < 1 || len(c.Seals) > 256 {
		return c, bad("watch capacity")
	}
	for i, n := range c.Names {
		if !name(n) || (i > 0 && n <= c.Names[i-1]) {
			return c, bad("name set")
		}
	}
	for i, s := range c.Seals {
		if !hash(s.Txid) {
			return c, bad("outpoint")
		}
		if i > 0 {
			prev := c.Seals[i-1]
			if s.Txid < prev.Txid || (s.Txid == prev.Txid && s.Vout <= prev.Vout) {
				return c, bad("seal set")
			}
		}
	}
	return c, nil
}

type rpcClient struct {
	endpoint string
	auth     string
	secrets  []string
	client   *http.Client
}

func newRPC(c Configuration, p custody) (*rpcClient, error) {
	b, st, e := p.read(c.CredentialFile, 4096, 0600, 0640)
	if e != nil || st == nil || st.Gid != c.CredentialGroup {
		return nil, bad("credential")
	}
	s := strings.TrimSuffix(string(b), "\n")
	user, pass, ok := strings.Cut(s, ":")
	if !ok || user == "" || pass == "" || strings.ContainsAny(s, "\r\n\x00") || strings.Contains(user, ":") || strings.HasPrefix(s, "rpcauth=") || regexp.MustCompile(`^[0-9a-fA-F]+\$[0-9a-fA-F]{64}$`).MatchString(pass) || (c.CredentialMode == "cookie" && user != "__cookie__") || (c.CredentialMode == "rpcauth-user" && user == "__cookie__") {
		return nil, bad("credential")
	}
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(s))
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext}
	return &rpcClient{c.RPCURL, auth, []string{s, user, pass, base64.StdEncoding.EncodeToString([]byte(s))}, &http.Client{Timeout: time.Second, Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return bad("redirect") }}}, nil
}
func (r *rpcClient) call(ctx context.Context, method string, params []any) (any, error) {
	b, _ := json.Marshal(map[string]any{"jsonrpc": "1.0", "id": 1, "method": method, "params": params})
	req, e := http.NewRequestWithContext(ctx, "POST", r.endpoint, bytes.NewReader(b))
	if e != nil {
		return nil, bad("rpc")
	}
	req.Header.Set("Authorization", r.auth)
	req.Header.Set("Content-Type", "application/json")
	resp, e := r.client.Do(req)
	if e != nil {
		return nil, bad("rpc")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, bad("rpc status")
	}
	b, e = io.ReadAll(io.LimitReader(resp.Body, 65537))
	if e != nil {
		return nil, bad("rpc read")
	}
	m, e := parseJSON(b, 65536, false, true)
	if e != nil {
		return nil, bad("rpc json")
	}
	if _, e = fields(m, "result", "error", "id"); e != nil || m["id"] != json.Number("1") || m["error"] != nil {
		return nil, bad("rpc envelope")
	}
	return m["result"], nil
}
func object(v any) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, bad("rpc object")
	}
	return m, nil
}
func (r *rpcClient) tip(ctx context.Context, network string) (map[string]any, error) {
	v, e := r.call(ctx, "getblockchaininfo", []any{})
	if e != nil {
		return nil, e
	}
	m, e := object(v)
	if e != nil || m["chain"] != network || m["initialblockdownload"] != false || !hash(m["bestblockhash"]) || !integer(m["blocks"], maxInteger) {
		return nil, bad("chain")
	}
	v, e = r.call(ctx, "getblockheader", []any{m["bestblockhash"], true})
	if e != nil {
		return nil, e
	}
	h, e := object(v)
	if e != nil || h["hash"] != m["bestblockhash"] || h["height"] != m["blocks"] || !integer(h["time"], maxInteger) {
		return nil, bad("header")
	}
	return map[string]any{"hash": h["hash"], "height": h["height"], "time": h["time"]}, nil
}
func (r *rpcClient) collect(ctx context.Context, c Configuration) ([]any, []any, error) {
	ns := []any{}
	ss := []any{}
	for _, n := range c.Names {
		v, e := r.call(ctx, "name_show", []any{n, map[string]any{"allowExpired": true, "nameEncoding": "ascii", "valueEncoding": "hex"}})
		if e != nil {
			return nil, nil, e
		}
		m, e := object(v)
		if e != nil || m["name"] != n || m["name_encoding"] != "ascii" || m["value_encoding"] != "hex" || !boolean(m["expired"]) || !integer(m["height"], maxInteger) || !outpoint(m) {
			return nil, nil, bad("name")
		}
		val, ok := m["value"].(string)
		if !ok || len(val) > 1040 {
			return nil, nil, bad("name value")
		}
		raw, e := hex.DecodeString(val)
		if e != nil {
			return nil, nil, bad("name hex")
		}
		v, e = r.call(ctx, "getblockhash", []any{m["height"]})
		if e != nil || !hash(v) {
			return nil, nil, bad("name block")
		}
		nr := map[string]any{"expired": m["expired"], "height": m["height"], "name": n, "name_block_hash": v, "txid": m["txid"], "value_b64": base64.StdEncoding.EncodeToString(raw), "vout": m["vout"]}
		ns = append(ns, nr)
	}
	for _, s := range c.Seals {
		v, e := r.call(ctx, "gettxout", []any{s.Txid, s.Vout, true})
		if e != nil {
			return nil, nil, e
		}
		state := "not_in_utxo_set"
		if v != nil {
			m, e := object(v)
			if e != nil || !hash(m["bestblock"]) || !integer(m["confirmations"], maxInteger) {
				return nil, nil, bad("utxo")
			}
			state = "unspent"
		}
		ss = append(ss, map[string]any{"state": state, "txid": s.Txid, "vout": s.Vout})
	}
	return ns, ss, nil
}
func (r *rpcClient) leaks(b []byte, ns []any) bool {
	for _, s := range r.secrets {
		if bytes.Contains(b, []byte(s)) {
			return true
		}
		for _, v := range ns {
			raw, _ := base64.StdEncoding.DecodeString(v.(map[string]any)["value_b64"].(string))
			if bytes.Contains(raw, []byte(s)) {
				return true
			}
		}
	}
	return false
}

func run(path string, p custody) int {
	c, e := loadConfig(path, p)
	if e != nil {
		return ExitConfig
	}
	lock, e := p.openProtected(c.Lock, syscall.O_RDWR|syscall.O_CREAT, 0600)
	if e != nil {
		return ExitConfig
	}
	defer lock.Close()
	if _, e = regular(lock, p.uid, 0600); e != nil {
		return ExitConfig
	}
	if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		if e == syscall.EWOULDBLOCK {
			return ExitLocked
		}
		return ExitConfig
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	r, e := newRPC(c, p)
	if e != nil {
		return ExitNode
	}
	defer r.client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	genesis, e := r.call(ctx, "getblockhash", []any{0})
	if e != nil || genesis != c.Genesis {
		return ExitNode
	}
	for attempt := 0; attempt < 3; attempt++ {
		before, e := r.tip(ctx, c.Network)
		if e != nil {
			return ExitNode
		}
		ns, ss, e := r.collect(ctx, c)
		if e != nil {
			return ExitNode
		}
		after, e := r.tip(ctx, c.Network)
		if e != nil {
			return ExitNode
		}
		if !equalTip(before, after) {
			if attempt < 2 {
				select {
				case <-time.After(time.Duration(attempt+1) * 100 * time.Millisecond):
				case <-ctx.Done():
					return ExitNode
				}
			}
			continue
		}
		now := time.Now().Unix()
		if now < 0 {
			return ExitNode
		}
		b, _ := json.Marshal(map[string]any{"consistency": "bracketed", "mode": "observe_only", "names": ns, "network": c.Network, "seals": ss, "tip": before, "v": 1, "written_at": now})
		// encoding/json HTML escapes are not CG1 canonical; use the canonical encoder.
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		m, _ := parseJSON(b, 65536, false, false)
		if m == nil {
			return ExitNode
		}
		if enc.Encode(m) != nil {
			return ExitNode
		}
		b = bytes.TrimSuffix(buf.Bytes(), []byte{'\n'})
		if validate("snapshot", b) != nil || r.leaks(b, ns) {
			return ExitNode
		}
		if e = publish(c.Output, b, p); e != nil {
			return ExitPublish
		}
		return 0
	}
	return ExitTipMoved
}
func equalTip(a, b map[string]any) bool {
	return a["hash"] == b["hash"] && a["height"] == b["height"] && a["time"] == b["time"]
}

func publish(path string, b []byte, p custody) error {
	dir, e := p.openProtected(filepath.Dir(path), syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if e != nil {
		return e
	}
	defer dir.Close()
	var ds syscall.Stat_t
	if syscall.Fstat(int(dir.Fd()), &ds) != nil || ds.Mode&07777 != 0755 || ds.Uid != p.uid {
		return bad("output directory")
	}
	name := filepath.Base(path)
	old, e := syscall.Openat(int(dir.Fd()), name, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if e == nil {
		f := os.NewFile(uintptr(old), name)
		_, e = regular(f, p.uid, 0644)
		f.Close()
		if e != nil {
			return e
		}
	} else if e != syscall.ENOENT {
		return e
	}
	nonce := make([]byte, 12)
	if _, e = rand.Read(nonce); e != nil {
		return e
	}
	tmp := ".snapshot-" + hex.EncodeToString(nonce)
	fd, e := syscall.Openat(int(dir.Fd()), tmp, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if e != nil {
		return e
	}
	f := os.NewFile(uintptr(fd), tmp)
	defer f.Close()
	defer syscall.Unlinkat(int(dir.Fd()), tmp)
	if _, e = f.Write(b); e != nil {
		return e
	}
	if e = f.Chmod(0644); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = syscall.Renameat(int(dir.Fd()), tmp, int(dir.Fd()), name); e != nil {
		return e
	}
	return dir.Sync()
}
