package chaingateway

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
)

const verifierMethods = "getblockchaininfo,getblockhash,getblockheader,name_show,gettxout"

// This protected profile excludes whitelist unions; the denial probe supplements
// configuration inspection, and cannot prove the node loaded that configuration.
func verifyWhitelist(c Configuration, p custody) error {
	p.uid = c.NodeUID
	b, _, e := p.read(c.NodeConfig, 65536, 0600, 0644)
	if e != nil {
		p.uid = 0
		b, _, e = p.read(c.NodeConfig, 65536, 0600, 0644)
		if e != nil {
			return e
		}
	}
	options, e := nodeOptions(b)
	if e != nil {
		return e
	}
	entries, defaults := 0, 0
	for _, option := range options {
		if option.key == "includeconf" {
			return bad("uninspected included config")
		}
		if option.section != "" && option.section != c.Network {
			continue
		}
		key, val := option.key, option.value
		if key == "rpcwhitelistdefault" {
			if val != "1" {
				return bad("whitelist default")
			}
			defaults++
		}
		if key == "rpcwhitelist" {
			user, methods, ok := strings.Cut(val, ":")
			if user == c.VerifierUser {
				actual := strings.Split(methods, ",")
				expected := strings.Split(verifierMethods, ",")
				slices.Sort(actual)
				slices.Sort(expected)
				if !ok || !slices.Equal(actual, expected) {
					return bad("whitelist methods")
				}
				entries++
			}
		}
	}
	if entries != 1 || defaults != 1 {
		return bad("whitelist union or missing")
	}
	return nil
}
func (r *rpcClient) denied(ctx context.Context) bool {
	if e := r.pacer.take(ctx); e != nil {
		return false
	}
	req, e := http.NewRequestWithContext(ctx, "POST", r.endpoint, bytes.NewBufferString(`{"jsonrpc":"1.0","id":"probe","method":"getrpcinfo","params":[]}`))
	if e != nil {
		return false
	}
	req.Header.Set("Authorization", r.auth)
	req.Header.Set("Content-Type", "application/json")
	resp, e := r.client.Do(req)
	if e != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusForbidden
}

// Only exact helper crash names under the held writer lock are eligible. A
// recognized file with invalid custody causes refusal, never broader deletion.
func cleanupTemps(path string, p custody) error {
	dir, e := p.openProtected(filepath.Dir(path), syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if e != nil {
		return e
	}
	defer dir.Close()
	var st syscall.Stat_t
	if syscall.Fstat(int(dir.Fd()), &st) != nil || st.Uid != p.uid || st.Mode&07777 != 0755 {
		return bad("output directory")
	}
	entries, e := dir.ReadDir(-1)
	if e != nil {
		return e
	}
	pattern := snapshotTempName
	for _, entry := range entries {
		if !pattern.MatchString(entry.Name()) {
			continue
		}
		fd, e := syscall.Openat(int(dir.Fd()), entry.Name(), syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if e != nil {
			return e
		}
		f := os.NewFile(uintptr(fd), entry.Name())
		_, e = regular(f, p.uid, 0600, 0644)
		f.Close()
		if e != nil {
			return e
		}
		if e = syscall.Unlinkat(int(dir.Fd()), entry.Name()); e != nil {
			return e
		}
	}
	return dir.Sync()
}

// Installed node inputs must explicitly bind and allow only numeric loopback.
// Effective argv, service identity exclusivity and namespaces remain Q6 qualification.
func verifyNodeLoopback(c Configuration, p custody) error {
	owner := p
	owner.uid = c.NodeUID
	b, _, e := owner.read(c.NodeConfig, 65536, 0600, 0644)
	if e != nil {
		b, _, e = p.read(c.NodeConfig, 65536, 0600, 0644)
		if e != nil {
			return e
		}
	}
	options, e := nodeOptions(b)
	if e != nil {
		return e
	}
	binds, allows := 0, 0
	for _, option := range options {
		if option.key == "includeconf" {
			return bad("included node config")
		}
		key, val := option.key, option.value
		active := option.section == "" || option.section == c.Network
		switch key {
		case "rpcbind":
			host := val
			if h, _, err := net.SplitHostPort(val); err == nil {
				host = h
			}
			ip := net.ParseIP(host)
			if ip == nil || !ip.IsLoopback() {
				return bad("node bind")
			}
			if active {
				binds++
			}
		case "rpcallowip":
			ip := net.ParseIP(val)
			if strings.Contains(val, "/") {
				base, network, err := net.ParseCIDR(val)
				if err != nil {
					return bad("node allow")
				}
				ones, bits := network.Mask.Size()
				if !base.IsLoopback() || (bits == 32 && ones < 8) || (bits == 128 && ones != 128) {
					return bad("node allow")
				}
				ip = base
			}
			if ip == nil || !ip.IsLoopback() {
				return bad("node allow")
			}
			if active {
				allows++
			}
		}
	}
	if binds == 0 || allows == 0 {
		return bad("explicit node loopback policy")
	}
	return nil
}

var snapshotTempName = regexp.MustCompile(`^\.snapshot-[0-9a-f]{24}$`)

type nodeOption struct{ section, key, value string }

// Core combines [section] and dotted keys. Inspect every bind/allow and include,
// even in inactive networks; only active settings satisfy the required policy.
func nodeOptions(raw []byte) ([]nodeOption, error) {
	options := []nodeOption{}
	section := ""
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") || strings.Count(line, "[") != 1 || strings.Count(line, "]") != 1 {
				return nil, bad("config section")
			}
			section = strings.TrimSpace(line[1 : len(line)-1])
			if section == "" {
				return nil, bad("config section")
			}
			continue
		}
		key, val, _ := strings.Cut(line, "=")
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		scope := section
		if dot := strings.LastIndexByte(key, '.'); dot >= 0 {
			if scope != "" {
				scope += "."
			}
			scope += key[:dot]
			key = key[dot+1:]
		}
		options = append(options, nodeOption{scope, key, val})
	}
	return options, nil
}
