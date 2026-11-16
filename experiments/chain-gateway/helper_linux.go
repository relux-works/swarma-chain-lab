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
	"sync"
	"syscall"
	"time"
)

const (
	ExitConfig     = 11
	ExitNode       = 11
	ExitTipMoved   = 12
	ExitLocked     = 14
	ExitPublish    = 11
	ExitDurability = 13
)

// Configuration contains operator-selected paths and watch bindings, never secrets.
// Its JSON is closed; all fields are required (including an explicit credential mode).
type Configuration struct {
	ServerUID           uint32     `json:"server_uid"`
	AllowedUIDs         []uint32   `json:"allowed_uids"`
	WorkloadUIDs        []uint32   `json:"workload_uids"`
	NodeDedicated       bool       `json:"node_dedicated"`
	NodeUID             uint32     `json:"node_uid"`
	Profile             string     `json:"profile"`
	NodeConfig          string     `json:"node_config"`
	GatewayVerifierUser string     `json:"gateway_verifier_user"`
	VerifierUser        string     `json:"verifier_user"`
	CookieSource        string     `json:"cookie_source"`
	RPCURL              string     `json:"rpc_url"`
	Network             string     `json:"network"`
	Genesis             string     `json:"genesis"`
	CredentialMode      string     `json:"credential_mode"`
	CredentialFile      string     `json:"credential_file"`
	CredentialGroup     uint32     `json:"credential_group"`
	Output              string     `json:"output"`
	Lock                string     `json:"lock"`
	Names               []string   `json:"names"`
	Seals               []Outpoint `json:"seals"`
}
type Outpoint struct {
	Txid string `json:"txid"`
	Vout uint32 `json:"vout"`
}

type custody struct {
	uid          uint32
	anchor       string
	namespacePID int
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
	messages := map[int]string{0: "snapshot refreshed (observe only)", 11: "snapshot unavailable; previous file retained", 12: "tip moved; previous snapshot retained", 13: "snapshot renamed; durability unconfirmed", 14: "writer already active; skipped"}
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
	if _, e = fields(m, "server_uid", "allowed_uids", "workload_uids", "node_dedicated", "gateway_verifier_user", "node_uid", "profile", "node_config", "verifier_user", "cookie_source", "rpc_url", "network", "genesis", "credential_mode", "credential_file", "credential_group", "output", "lock", "names", "seals"); e != nil {
		return c, e
	}
	points, ok := m["seals"].([]any)
	if !ok {
		return c, bad("seal array")
	}
	for _, point := range points {
		selected, e := fields(point, "txid", "vout")
		if e != nil || !outpoint(selected) {
			return c, bad("exact outpoint fields")
		}
	}
	// Re-encode parsed maps to preserve duplicate/alias protection before typed decoding.
	b, _ = json.Marshal(m)
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e = d.Decode(&c); e != nil {
		return c, e
	}
	if !exclusiveNode(c) {
		return c, bad("exclusive node identity")
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
	if c.GatewayVerifierUser == c.VerifierUser || !regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`).MatchString(c.GatewayVerifierUser) {
		return c, bad("separate verifier users")
	}
	if c.Profile != "cg1-v1" || !cleanPath(c.NodeConfig) || (c.CredentialMode == "rpcauth-user" && (!regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`).MatchString(c.VerifierUser) || c.CookieSource != "none")) || (c.CredentialMode == "cookie" && c.CookieSource != "live" && c.CookieSource != "admitted-root-copy") {
		return c, bad("profile")
	}
	if !network(c.Network) || !hash(c.Genesis) || (c.CredentialMode != "cookie" && c.CredentialMode != "rpcauth-user") {
		return c, bad("bindings")
	}
	paths := []string{path, c.CredentialFile, c.Output, c.Lock, c.NodeConfig}
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
	if snapshotTempName.MatchString(filepath.Base(c.Output)) || snapshotTempName.MatchString(filepath.Base(c.Lock)) {
		return c, bad("reserved snapshot temp name")
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
	pacer    *rpcPacer
}

func newRPC(c Configuration, p custody) (*rpcClient, error) {
	if e := p.verifyNamespaces(); e != nil {
		return nil, e
	}
	if e := hardenDumps(); e != nil {
		return nil, e
	}
	if e := verifyNodeLoopback(c, p); e != nil {
		return nil, e
	}
	u, _ := url.Parse(c.RPCURL)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, e := authenticatedDial(ctx, "tcp", u.Host, c.NodeUID)
	if e != nil {
		return nil, e
	}
	conn.Close()
	owner := p
	modes := []uint32{0600, 0640}
	if c.CredentialMode == "cookie" {
		modes = []uint32{0600}
		if c.CookieSource == "live" {
			owner.uid = c.NodeUID
		}
	}
	b, st, e := owner.read(c.CredentialFile, 4096, modes...)
	if e != nil || st == nil || st.Gid != c.CredentialGroup {
		return nil, bad("credential")
	}
	s := strings.TrimSuffix(string(b), "\n")
	user, pass, ok := strings.Cut(s, ":")
	if !ok || user == "" || pass == "" || strings.ContainsAny(s, "\r\n\x00") || strings.Contains(user, ":") || strings.HasPrefix(s, "rpcauth=") || regexp.MustCompile(`^[0-9a-fA-F]+\$[0-9a-fA-F]{64}$`).MatchString(pass) || (c.CredentialMode == "cookie" && user != "__cookie__") || (c.CredentialMode == "rpcauth-user" && user == "__cookie__") {
		return nil, bad("credential")
	}
	if c.CredentialMode == "rpcauth-user" {
		if user != c.VerifierUser || verifyWhitelist(c, p) != nil {
			return nil, bad("verifier whitelist")
		}
	}
	auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(s))
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true, DisableCompression: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return authenticatedDial(ctx, network, address, c.NodeUID)
	}}
	return &rpcClient{endpoint: c.RPCURL, auth: auth, secrets: []string{s, base64.StdEncoding.EncodeToString([]byte(s)), auth, pass}, client: &http.Client{Timeout: time.Second, Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return bad("redirect") }}, pacer: newPacer()}, nil
}
func (r *rpcClient) call(ctx context.Context, method string, params []any) (any, error) {
	return r.callWithID(ctx, method, params, "snapshot")
}
func (r *rpcClient) callWithID(ctx context.Context, method string, params []any, id string) (any, error) {
	if !slices.Contains(strings.Split(verifierMethods, ","), method) {
		return nil, bad("forbidden method")
	}
	if e := r.pacer.take(ctx); e != nil {
		return nil, e
	}
	b, _ := json.Marshal(map[string]any{"jsonrpc": "1.0", "id": id, "method": method, "params": params})
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
	bound := upstreamBounds[method]
	b, e = upstreamRead(resp.Body, bound.bytes)
	if e != nil || resp.Header.Get("Content-Encoding") != "" {
		return nil, bad("rpc read")
	}
	class := upstreamClass(upstreamInput{Method: method, Status: resp.StatusCode, ID: id, Body: string(b)})
	if class != "ok" && class != "absent" {
		return nil, readFailure(class)
	}
	m, e := upstreamParse(b, bound.depth)
	if e != nil {
		return nil, bad("rpc json")
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

// Sixteen workers bound upstream load; result slots retain configured ordering.
func (r *rpcClient) collect(ctx context.Context, c Configuration, at map[string]any) ([]any, []any, error) {
	ns := make([]any, len(c.Names))
	ss := make([]any, len(c.Seals))
	jobs := make(chan int)
	var wg sync.WaitGroup
	var failure error
	var failureMu sync.Mutex
	for worker := 0; worker < 16; worker++ {
		wg.Go(func() {
			for i := range jobs {
				var value any
				var e error
				if i < len(ns) {
					value, e = r.readName(ctx, c.Names[i])
				} else {
					value, e = r.readSeal(ctx, c.Seals[i-len(ns)], at)
				}
				if e != nil {
					failureMu.Lock()
					failure = strongerFailure(failure, e)
					failureMu.Unlock()
				} else if i < len(ns) {
					ns[i] = value
				} else {
					ss[i-len(ns)] = value
				}
			}
		})
	}
	for i := 0; i < len(ns)+len(ss); i++ {
		select {
		case jobs <- i:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return nil, nil, ctx.Err()
		}
	}
	close(jobs)
	wg.Wait()
	return ns, ss, failure
}
func (r *rpcClient) readName(ctx context.Context, n string) (any, error) {
	encoded := hex.EncodeToString([]byte(n))
	v, e := r.call(ctx, "name_show", []any{encoded, map[string]any{"allowExpired": true, "nameEncoding": "hex", "valueEncoding": "hex"}})
	if e != nil {
		return nil, e
	}
	m, e := object(v)
	if e != nil || m["name"] != encoded || m["name_encoding"] != "hex" || m["value_encoding"] != "hex" || !boolean(m["expired"]) || !integer(m["height"], maxInteger) || !outpoint(m) {
		return nil, bad("name")
	}
	val, ok := m["value"].(string)
	if !ok || len(val) > 1040 {
		return nil, bad("name value")
	}
	raw, e := hex.DecodeString(val)
	if e != nil {
		return nil, bad("name hex")
	}
	v, e = r.call(ctx, "getblockhash", []any{m["height"]})
	if e != nil || !hash(v) {
		return nil, bad("name block")
	}
	return map[string]any{"expired": m["expired"], "height": m["height"], "name": n, "name_block_hash": v, "txid": m["txid"], "value_b64": base64.StdEncoding.EncodeToString(raw), "vout": m["vout"]}, nil
}
func (r *rpcClient) readSeal(ctx context.Context, s Outpoint, at map[string]any) (any, error) {
	// No signed-index qualification is claimed for this implementation profile.
	if s.Vout > 2147483647 {
		return nil, bad("unqualified vout")
	}
	cv, e := r.call(ctx, "gettxout", []any{s.Txid, s.Vout, false})
	if e != nil {
		return nil, e
	}
	mv, e := r.call(ctx, "gettxout", []any{s.Txid, s.Vout, true})
	if e != nil {
		return nil, e
	}
	var evidence error
	var c, m map[string]any
	for i, v := range []any{cv, mv} {
		if v == nil {
			continue
		}
		view, e := object(v)
		if e != nil {
			return nil, e
		}
		script, ok := view["scriptPubKey"].(map[string]any)
		if !ok || !hash(view["bestblock"]) || !integer(view["confirmations"], maxInteger) {
			return nil, bad("utxo")
		}
		if view["bestblock"] != at["hash"] {
			evidence = readFailure("tip_moved")
		}
		if _, ok = script["hex"].(string); !ok {
			return nil, bad("script")
		}
		if i == 0 {
			c = view
		} else {
			m = view
		}
	}
	record := map[string]any{"state": "not_in_utxo_set", "txid": s.Txid, "vout": json.Number(strconv.FormatUint(uint64(s.Vout), 10))}
	source := c
	if c != nil {
		if uintValue(c["confirmations"]) < 1 {
			return nil, bad("confirmed view")
		}
		record["state"] = "spend_pending"
		if m != nil {
			if c["confirmations"] != m["confirmations"] || c["scriptPubKey"].(map[string]any)["hex"] != m["scriptPubKey"].(map[string]any)["hex"] {
				return nil, bad("views disagree")
			}
			record["state"] = "unspent"
		}
	} else if m != nil {
		if uintValue(m["confirmations"]) != 0 {
			return nil, bad("mempool view")
		}
		source = m
		record["state"] = "unconfirmed"
	}
	if source != nil {
		record["confirmations"] = source["confirmations"]
		record["script_pubkey"] = source["scriptPubKey"].(map[string]any)["hex"]
	}
	if sealRecord(record, at) != nil {
		return nil, bad("seal schema")
	}
	return record, evidence
}

func (r *rpcClient) leaks(b []byte, ns []any) bool {
	m, e := parseJSON(b, 65536, false, false)
	if e != nil {
		return true
	}
	var match func(any) bool
	match = func(v any) bool {
		switch x := v.(type) {
		case string:
			return slices.Contains(r.secrets, x)
		case map[string]any:
			for _, v := range x {
				if match(v) {
					return true
				}
			}
		case []any:
			for _, v := range x {
				if match(v) {
					return true
				}
			}
		}
		return false
	}
	if match(m) {
		return true
	}
	for _, v := range ns {
		record, ok := v.(map[string]any)
		if !ok {
			return true
		}
		raw, e := base64.StdEncoding.DecodeString(str(record["value_b64"]))
		if e != nil || slices.Contains(r.secrets, string(raw)) {
			return true
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
	if e = cleanupTemps(c.Output, p); e != nil {
		return ExitPublish
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	r, e := newRPC(c, p)
	if e != nil {
		return ExitNode
	}
	defer r.client.CloseIdleConnections()
	if c.CredentialMode == "rpcauth-user" && !r.denied(ctx) {
		return ExitNode
	}
	genesis, e := r.call(ctx, "getblockhash", []any{0})
	if e != nil || genesis != c.Genesis {
		return ExitNode
	}
	headers := map[string]map[string]any{}
	for attempt := 0; attempt < 3; attempt++ {
		before, e := r.tip(ctx, c.Network)
		var ns, ss []any
		var after map[string]any
		if e == nil {
			ns, ss, e = r.collect(ctx, c, before)
			var closing error
			after, closing = r.tip(ctx, c.Network)
			e = strongerFailure(e, closing)
		}
		a := collectionAttempt{Before: before, After: after, Failure: e}
		if before != nil && after != nil && e == nil {
			a.Requests = configuredReads(c)
			for _, v := range ns {
				a.Replies = append(a.Replies, projectedReply(c, "name_show", v, before))
			}
			for _, v := range ss {
				a.Replies = append(a.Replies, projectedReply(c, "gettxout", v, before))
			}
			e = assessCollection(c, a, headers)
		} else {
			// Refused reads carry no record data. Retain successful bracket headers.
			for _, at := range []map[string]any{before, after} {
				if at != nil {
					h := str(at["hash"])
					if old := headers[h]; old != nil && !equalTip(old, at) {
						e = bad("inconsistent header")
					}
					headers[h] = at
				}
			}
		}
		code, wait := retryOutcome(e, attempt+1)
		if ctx.Err() != nil {
			return ExitNode
		}
		if code > 0 {
			return code
		}
		if code < 0 {
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return ExitNode
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
		return publicationExit(publish(c.Output, b, p))
	}
	return ExitTipMoved
}
func equalTip(a, b map[string]any) bool {
	return a["hash"] == b["hash"] && a["height"] == b["height"] && a["time"] == b["time"]
}

// publicationStep permits bounded syscall-failure controls without changing the CLI.
type publicationStep func(string, func() error) error

func publicationAction(_ string, action func() error) error { return action() }
func publish(path string, b []byte, p custody) error {
	return publishWith(path, b, p, publicationAction)
}
func publishWith(path string, b []byte, p custody, step publicationStep) (result error) {
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
	var f *os.File
	if e = step("temp_create", func() error {
		fd, err := syscall.Openat(int(dir.Fd()), tmp, syscall.O_RDWR|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
		if err == nil {
			f = os.NewFile(uintptr(fd), tmp)
		}
		return err
	}); e != nil {
		return e
	}
	renamed := false
	defer func() {
		f.Close()
		if !renamed {
			cleanup := step("own_temp_cleanup", func() error {
				fd, err := syscall.Openat(int(dir.Fd()), tmp, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
				if err != nil {
					return err
				}
				own := os.NewFile(uintptr(fd), tmp)
				defer own.Close()
				if _, err = regular(own, p.uid, 0600, 0644); err != nil {
					return err
				}
				return syscall.Unlinkat(int(dir.Fd()), tmp)
			})
			if cleanup != nil {
				result = bad("own temp cleanup")
			}
		}
	}()
	if e = step("temp_write", func() error { return writeSnapshot(f, b) }); e != nil {
		return e
	}
	if e = step("temp_validate", func() error {
		if _, err := f.Seek(0, 0); err != nil {
			return err
		}
		raw, err := io.ReadAll(io.LimitReader(f, 65537))
		if err != nil || !bytes.Equal(raw, b) {
			return bad("temp content")
		}
		return validate("snapshot", raw)
	}); e != nil {
		return e
	}
	if e = step("temp_metadata", func() error {
		if err := f.Chmod(0644); err != nil {
			return err
		}
		_, err := regular(f, p.uid, 0644)
		return err
	}); e != nil {
		return e
	}
	if e = step("file_sync", f.Sync); e != nil {
		return e
	}
	if e = step("file_close", f.Close); e != nil {
		return e
	}
	if e = step("rename", func() error { return syscall.Renameat(int(dir.Fd()), tmp, int(dir.Fd()), name) }); e != nil {
		return e
	}
	renamed = true
	// Open/sync/close failures here describe an actual successful rename.
	var durable *os.File
	if e = step("directory_open", func() error {
		var err error
		durable, err = p.openProtected(filepath.Dir(path), syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
		return err
	}); e != nil {
		return renamedError{e}
	}
	defer durable.Close()
	if e = step("directory_sync", durable.Sync); e != nil {
		return renamedError{e}
	}
	if e = step("directory_close", durable.Close); e != nil {
		return renamedError{e}
	}
	return nil
}

func writeSnapshot(w io.Writer, b []byte) error {
	n, e := w.Write(b)
	if e != nil {
		return e
	}
	if n != len(b) {
		return io.ErrShortWrite
	}
	return nil
}

func publicationExit(e error) int {
	if e == nil {
		return 0
	}
	if publicationRenamed(e) {
		return ExitDurability
	}
	return ExitPublish
}
