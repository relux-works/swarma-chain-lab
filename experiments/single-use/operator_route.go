package singleuse

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// OperatorRoute is a separately installed public capability. Config/datadir
// are references only: this adapter never opens their contents. No credentials,
// wallet option, URL, shell command, arbitrary executable argv or default network.
type OperatorRoute struct {
	Network       string `json:"Network"`
	Genesis       string `json:"Genesis"`
	NodeCLI       string `json:"NodeCLI"`
	NodeCLISHA256 string `json:"NodeCLISHA256"`
	NodeConfig    string `json:"NodeConfig"`
	NodeDataDir   string `json:"NodeDataDir"`
}
type OperatorRPC struct {
	route OperatorRoute
	root  string
}

func mainnetRouteBound(node Node, p Policy) bool {
	n, ok := node.(*OperatorRPC)
	return ok && n != nil && n.route.Network == p.Network && n.route.Genesis == p.Genesis && n.root == p.StateDir
}

func absoluteReference(path string) bool { return filepath.IsAbs(path) && filepath.Clean(path) == path }
func (r OperatorRoute) binaryOK() bool {
	b, e := PublicFile(r.NodeCLI, 64<<20)
	if e != nil || Hash(b) != r.NodeCLISHA256 {
		return false
	}
	s, e := os.Stat(r.NodeCLI)
	return e == nil && s.Mode().Perm()&0111 != 0
}
func NewOperatorRPC(r OperatorRoute, network, genesis, root string) (*OperatorRPC, error) {
	if !NetworkPinned(network, genesis) || r.Network != network || r.Genesis != genesis || !digestHex(r.NodeCLISHA256) || !absoluteReference(r.NodeCLI) || !absoluteReference(r.NodeConfig) || !absoluteReference(r.NodeDataDir) || !absoluteReference(root) || !r.binaryOK() {
		return nil, fail("OPERATOR_ROUTE")
	}
	return &OperatorRPC{r, root}, nil
}
func (n *OperatorRPC) Call(parent context.Context, method string, params ...any) (json.RawMessage, error) {
	if !readMethods[method] || len(params) > 3 {
		return nil, fail("READ_ONLY_METHOD")
	}
	args := []string{"-conf=" + n.route.NodeConfig, "-datadir=" + n.route.NodeDataDir, "-chain=" + n.route.Network, "-rpcclienttimeout=2", method}
	for _, p := range params {
		b, e := json.Marshal(p)
		if e != nil || len(b) > 4096 {
			return nil, fail("RPC_INPUT")
		}
		if s, ok := p.(string); ok {
			if s == "" || strings.HasPrefix(s, "-") {
				return nil, fail("RPC_INPUT")
			}
			args = append(args, s)
		} else {
			args = append(args, string(b))
		}
	}
	if !n.route.binaryOK() {
		return nil, fail("NODE_CLI_PIN")
	}
	dir, e := os.MkdirTemp(n.root, "node-read-")
	if e != nil {
		return nil, fail("RPC_WORKDIR")
	}
	defer os.RemoveAll(dir)
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, n.route.NodeCLI, args...)
	cmd.WaitDelay = time.Second
	cmd.Dir = dir
	cmd.Env = []string{"HOME=" + dir, "TMPDIR=" + dir, "XDG_CACHE_HOME=" + dir, "PATH=/nonexistent", "LC_ALL=C"}
	out, diag := &limitedBuffer{max: 8 << 20}, &limitedBuffer{max: 8192}
	cmd.Stdout = out
	cmd.Stderr = diag
	if cmd.Run() != nil || ctx.Err() != nil {
		return nil, fail("RPC_UNAVAILABLE")
	}
	if method == "getblockhash" {
		s := strings.TrimSuffix(out.String(), "\n")
		if !digestHex(s) {
			return nil, fail("RPC_RESPONSE")
		}
		return json.Marshal(s)
	}
	if method == "gettxout" && out.Len() == 0 {
		return json.RawMessage("null"), nil
	}
	if !json.Valid(out.Bytes()) {
		return nil, fail("RPC_RESPONSE")
	}
	return bytes.Clone(out.Bytes()), nil
}
