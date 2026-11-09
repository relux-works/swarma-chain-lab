package deploy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
)

var (
	ErrPolicy      = errors.New("deploy: invalid policy")
	ErrNetwork     = errors.New("deploy: regtest required")
	ErrPlaceholder = errors.New("deploy: unresolved placeholder")
)

// Policy is a public installation descriptor, separate from native service JSON.
// Validation checks deployment pins/references only; it never opens credentials,
// probes nodes, creates state, or replaces the service's native startup checks.
type Policy struct {
	Version          int    `json:"version"`
	Network          string `json:"network"`
	Service          string `json:"service"`
	ReleaseVersion   string `json:"release_version"`
	Commit           string `json:"commit"`
	BinarySHA256     string `json:"binary_sha256"`
	StateDir         string `json:"state_dir"`
	Listen           string `json:"listen"`
	Config           string `json:"config"`
	Profile          string `json:"profile,omitempty"`
	ProviderKey      string `json:"provider_key,omitempty"`
	Route            string `json:"route,omitempty"`
	NodeCLI          string `json:"node_cli,omitempty"`
	NodeCLISHA256    string `json:"node_cli_sha256,omitempty"`
	RPCConfig        string `json:"rpc_config,omitempty"`
	RPCClientDataDir string `json:"rpc_client_datadir,omitempty"`
	RPCEndpoint      string `json:"rpc_endpoint,omitempty"`
	Relay            string `json:"relay,omitempty"`
	ManagerListen    string `json:"manager_listen,omitempty"`
	Screening        string `json:"screening,omitempty"`
	StationDriver    string `json:"station_driver,omitempty"`
}

func label(s string) bool {
	if len(s) == 0 || len(s) > 64 || s == "." || s == ".." {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}
func localEndpoint(s string) bool {
	h, p, e := net.SplitHostPort(s)
	n, ne := strconv.Atoi(p)
	return e == nil && ne == nil && n > 0 && n <= 65535 && strconv.Itoa(n) == p && h == "127.0.0.1"
}
func stationEndpoint(s string) bool {
	h, p, e := net.SplitHostPort(s)
	n, ne := strconv.Atoi(p)
	ip := net.ParseIP(h)
	return e == nil && ne == nil && n > 0 && n <= 65535 && strconv.Itoa(n) == p && ip != nil && ip.String() == h && !ip.IsUnspecified() && !ip.IsMulticast()
}
func pathUnder(path, parent string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	rel, e := filepath.Rel(parent, path)
	return e == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func Validate(raw []byte) (Policy, error) {
	var p Policy
	if len(raw) == 0 || len(raw) > 16384 || uniqueJSON(raw) != nil {
		return p, ErrPolicy
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil {
		return Policy{}, ErrPolicy
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return Policy{}, ErrPolicy
	}
	if p.Network != "regtest" {
		return Policy{}, ErrNetwork
	}
	for _, marker := range []string{"PLACEHOLDER", "CHANGE_ME", "<", ">", "@VERSION@", "${"} {
		if bytes.Contains(raw, []byte(marker)) {
			return Policy{}, ErrPlaceholder
		}
	}
	if p.Version != 1 || !label(p.ReleaseVersion) || !exactHex(p.Commit, 20) || !exactHex(p.BinarySHA256, 32) || (p.Service != "gateway" && !localEndpoint(p.Listen)) {
		return Policy{}, ErrPolicy
	}
	root := "/var/lib/swarma-" + p.Service
	configRoot := "/etc/swarma/" + p.Service
	if p.StateDir != root || p.Config != configRoot+"/service.json" {
		return Policy{}, ErrPolicy
	}
	switch p.Service {
	case "booking":
		if p.Profile != configRoot+"/profile.bin" || p.ProviderKey != root+"/provider.hex" || p.Route != configRoot+"/operator-route.json" ||
			!pathUnder(p.NodeCLI, "/opt/namecoin") || !strings.HasSuffix(p.NodeCLI, "/bin/namecoin-cli") || !exactHex(p.NodeCLISHA256, 32) ||
			p.RPCConfig != root+"/rpc/namecoin.conf" || p.RPCClientDataDir != root+"/rpc/client" || p.RPCEndpoint != "127.0.0.1:18443" || p.Listen != "127.0.0.1:18819" {
			return Policy{}, ErrPolicy
		}
		u, e := url.Parse(p.Relay)
		if e != nil || u.Scheme != "ws" || !localEndpoint(u.Host) || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return Policy{}, ErrPolicy
		}
	case "store", "relay":
		port := "127.0.0.1:8091"
		if p.Service == "relay" {
			port = "127.0.0.1:18818"
		}
		if p.Listen != port || p.Profile != "" || p.ProviderKey != "" || p.Route != "" || p.NodeCLI != "" || p.NodeCLISHA256 != "" || p.RPCConfig != "" || p.RPCClientDataDir != "" || p.RPCEndpoint != "" || p.Relay != "" {
			return Policy{}, ErrPolicy
		}
	case "gateway":
		if !stationEndpoint(p.Listen) || !stationEndpoint(p.ManagerListen) || p.Listen == p.ManagerListen || p.Screening != "off" || p.StationDriver != "manager" || p.Profile != "" || p.ProviderKey != "" || p.Route != "" || p.NodeCLI != "" || p.NodeCLISHA256 != "" || p.RPCConfig != "" || p.RPCClientDataDir != "" || p.RPCEndpoint != "" || p.Relay != "" {
			return Policy{}, ErrPolicy
		}
	default:
		return Policy{}, ErrPolicy
	}
	if p.Service != "gateway" && (p.ManagerListen != "" || p.Screening != "" || p.StationDriver != "") {
		return Policy{}, ErrPolicy
	}
	return p, nil
}

// ValidatePublicJSON checks additional native public config files for unresolved
// values, credential material and conflicting network markers. It is deliberately
// not a replacement for each product's complete native schema/startup validator.
func ValidatePublicJSON(raw []byte) error {
	if len(raw) == 0 || len(raw) > 1<<20 || uniqueJSON(raw) != nil {
		return ErrPolicy
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return ErrPolicy
	}
	var check func(any) error
	check = func(v any) error {
		switch x := v.(type) {
		case map[string]any:
			for k, v := range x {
				switch strings.ToLower(k) {
				case "network":
					if v != "regtest" {
						return ErrNetwork
					}
				case "password", "rpcpassword", "rpcauth", "private_key", "secret":
					return ErrPolicy
				}
				if e := check(v); e != nil {
					return e
				}
			}
		case []any:
			for _, v := range x {
				if e := check(v); e != nil {
					return e
				}
			}
		case string:
			for _, marker := range []string{"PLACEHOLDER", "CHANGE_ME", "<", ">", "@VERSION@", "${"} {
				if strings.Contains(x, marker) {
					return ErrPlaceholder
				}
			}
		}
		return nil
	}
	if _, ok := v.(map[string]any); !ok {
		return ErrPolicy
	}
	return check(v)
}

// Reject duplicate keys, trailing values and excess depth before typed decoding.
// A last-key-wins network or file-reference parser is not this contract.
func uniqueJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 16 {
			return ErrPolicy
		}
		t, e := d.Token()
		if e != nil {
			return ErrPolicy
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				s, ok := k.(string)
				if e != nil || !ok || seen[s] {
					return ErrPolicy
				}
				seen[s] = true
				if e = walk(depth + 1); e != nil {
					return e
				}
			}
			t, e = d.Token()
			if e != nil || t != json.Delim('}') {
				return ErrPolicy
			}
		case '[':
			for d.More() {
				if e = walk(depth + 1); e != nil {
					return e
				}
			}
			t, e = d.Token()
			if e != nil || t != json.Delim(']') {
				return ErrPolicy
			}
		default:
			return ErrPolicy
		}
		return nil
	}
	if e := walk(0); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrPolicy
	}
	return nil
}
