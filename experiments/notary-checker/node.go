package notarycheck

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

// NewNodeNameReader accepts only explicit loopback HTTP RPC and a credential
// file containing user:password (including Core cookie files). It has no fixture
// option. Node views also verify chain=regtest before any certification.
func NewNodeNameReader(endpoint, credentialFile string) (*NodeNameReader, error) {
	u, e := url.Parse(endpoint)
	if e != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || !loopback(u.Hostname()) || u.Port() == "" {
		return nil, refuse("NODE_CONFIG")
	}
	f, e := os.OpenFile(credentialFile, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, refuse("NODE_CREDENTIALS")
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {
		return nil, refuse("NODE_CREDENTIALS")
	}
	if stat, ok := st.Sys().(*syscall.Stat_t); !ok || stat.Uid != uint32(os.Getuid()) {
		return nil, refuse("NODE_CREDENTIALS")
	}
	raw, e := io.ReadAll(io.LimitReader(f, 4097))
	if e != nil || len(raw) > 4096 {
		return nil, refuse("NODE_CREDENTIALS")
	}
	defer clear(raw)
	cred := strings.TrimSpace(string(raw))
	user, password, ok := strings.Cut(cred, ":")
	if !ok || user == "" || password == "" || strings.ContainsAny(cred, "\r\n") {
		return nil, refuse("NODE_CREDENTIALS")
	}
	return &NodeNameReader{endpoint: endpoint, user: user, password: password, ctx: context.Background(), client: &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil, MaxConnsPerHost: 32, MaxIdleConnsPerHost: 4}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func loopback(s string) bool { ip := net.ParseIP(s); return ip != nil && ip.IsLoopback() }

// WithContext bounds every call in this per-request reader to the same deadline.
func (n *NodeNameReader) WithContext(ctx context.Context) *NodeNameReader {
	c := *n
	c.ctx = ctx
	return &c
}
func (n *NodeNameReader) rpc(method string, params any, out any) error {
	if n == nil || n.client == nil {
		return refuse("MVP_CHAIN_READ_REQUIRED")
	}
	raw, _ := json.Marshal(struct {
		Version string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Method  string `json:"method"`
		Params  any    `json:"params"`
	}{"1.0", 1, method, params})
	req, e := http.NewRequestWithContext(n.ctx, "POST", n.endpoint, bytes.NewReader(raw))
	if e != nil {
		return refuse("NODE_RPC_FAILURE")
	}
	req.SetBasicAuth(n.user, n.password)
	req.Header.Set("Content-Type", "application/json")
	resp, e := n.client.Do(req)
	if e != nil {
		return refuse("NODE_RPC_FAILURE")
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(io.LimitReader(resp.Body, 1048577))
	if e != nil || len(b) > 1048576 {
		return refuse("NODE_RPC_FAILURE")
	}
	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code int `json:"code"`
		} `json:"error"`
		ID int `json:"id"`
	}
	if json.Unmarshal(b, &envelope) != nil || envelope.ID != 1 {
		return refuse("NODE_RPC_FAILURE")
	}
	if envelope.Error != nil {
		// Core uses -4 for both never-registered and expired names.
		if method == "name_show" && envelope.Error.Code == -4 {
			return refuse("NODE_NAME_UNREGISTERED")
		}
		return refuse("NODE_RPC_FAILURE")
	}
	if resp.StatusCode != 200 || len(envelope.Result) == 0 || string(envelope.Result) == "null" || json.Unmarshal(envelope.Result, out) != nil {
		return refuse("NODE_RPC_FAILURE")
	}
	return nil
}
func (n *NodeNameReader) View(height int64, hash string) error {
	if height < 0 || !ishex(hash, 64) {
		return refuse("STATEMENT_FIELD")
	}
	var info struct {
		Chain  string `json:"chain"`
		Blocks int64  `json:"blocks"`
		Best   string `json:"bestblockhash"`
	}
	if e := n.rpc("getblockchaininfo", []any{}, &info); e != nil {
		return e
	}
	if info.Chain != "regtest" {
		return refuse("NODE_NETWORK")
	}
	if info.Blocks != height || info.Best != hash {
		return refuse("NODE_TIP_MISMATCH")
	}
	var got string
	if e := n.rpc("getblockhash", []any{height}, &got); e != nil {
		return e
	}
	if got != hash {
		return refuse("NODE_TIP_MISMATCH")
	}
	return nil
}

type nodeName struct {
	Name          string `json:"name"`
	Value         string `json:"value"`
	TxID          string `json:"txid"`
	Vout          uint32 `json:"vout"`
	Height        int64  `json:"height"`
	ExpiresIn     int64  `json:"expires_in"`
	Expired       bool   `json:"expired"`
	NameEncoding  string `json:"name_encoding"`
	ValueEncoding string `json:"value_encoding"`
}

func (n *NodeNameReader) Lookup(name string, height int64, hash string) (NameObservation, error) {
	if n == nil || n.client == nil {
		return NameObservation{}, refuse("MVP_CHAIN_READ_REQUIRED")
	}
	if !nameRE.MatchString(name) {
		return NameObservation{}, refuse("NODE_NAME_VALUE")
	}
	if e := n.View(height, hash); e != nil {
		return NameObservation{}, e
	}
	opts := map[string]any{"nameEncoding": "utf8", "valueEncoding": "utf8"}
	var current nodeName
	if e := n.rpc("name_show", []any{name, opts}, &current); e != nil {
		return NameObservation{}, e
	}
	if current.Expired || current.ExpiresIn <= 0 {
		return NameObservation{}, refuse("NODE_NAME_UNREGISTERED")
	}
	if current.Name != name || current.NameEncoding != "utf8" || current.ValueEncoding != "utf8" || current.Height < 0 || current.Height > height || !ishex(current.TxID, 64) || len(current.Value) > 520 || !utf8.ValidString(current.Value) || !json.Valid([]byte(current.Value)) {
		return NameObservation{}, refuse("NODE_NAME_VALUE")
	}
	var history []nodeName
	if e := n.rpc("name_history", []any{name, opts}, &history); e != nil {
		return NameObservation{}, e
	}
	if len(history) == 0 || history[len(history)-1] != current {
		return NameObservation{}, refuse("NODE_NAME_HISTORY")
	}
	registration := history[0]
	for i, h := range history {
		if h.Name != name || h.Height < 0 || h.Height > height || !ishex(h.TxID, 64) {
			return NameObservation{}, refuse("NODE_NAME_HISTORY")
		}
		if i > 0 {
			prev := history[i-1]
			if h.Height <= prev.Height {
				return NameObservation{}, refuse("NODE_NAME_HISTORY")
			}
			// expires_in is relative to the current node tip; an expired stretch
			// followed by a fresh registration must never reuse the old outpoint.
			if h.Height >= height+prev.ExpiresIn {
				registration = h
			}
		}
	}
	if e := n.View(height, hash); e != nil {
		return NameObservation{}, e
	}
	return NameObservation{Point{registration.TxID, registration.Vout}, []byte(current.Value), height, hash}, nil
}

// CheckRunningWithNode accepts only the concrete RPC reader. The existing
// running path without it still refuses MVP_CHAIN_READ_REQUIRED.
func CheckRunningWithNode(in Input, node *NodeNameReader) (Result, error) {
	if in.Names != nil {
		return Result{}, refuse("MVP_CHAIN_READ_REQUIRED")
	}
	in.Names = node
	return Check(in)
}
