package chaingateway

import (
	"bytes"
	"context"
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
	entries, defaults := 0, 0
	section := ""
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if strings.HasPrefix(line, "includeconf") {
			return bad("uninspected included config")
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") || strings.Count(line, "[") != 1 || strings.Count(line, "]") != 1 {
				return bad("config section")
			}
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		if section != "" && section != c.Network {
			continue
		}
		if line == "" {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
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
	req, e := http.NewRequestWithContext(ctx, "POST", r.endpoint, bytes.NewBufferString(`{"jsonrpc":"1.0","id":1,"method":"getrpcinfo","params":[]}`))
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
	pattern := regexp.MustCompile(`^\.snapshot-[0-9a-f]{24}$`)
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
