//go:build linux

package g2run

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// InstallManifestSpec replaces the source script's fixed gid, service and wallet
// directory with instance parameters. Files retain the required order.
type InstallManifestSpec struct {
	ReleaseSHA, Service, WalletDir string
	GID                            uint32
}
type installFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}
type installManifest struct {
	Version int           `json:"v"`
	Release string        `json:"release_sha256"`
	Service string        `json:"service"`
	GID     uint32        `json:"gid"`
	Files   []installFile `json:"files"`
}

func (s InstallManifestSpec) validate() error {
	if !portHex(s.ReleaseSHA, 64) || !portAccount(s.Service) || !portAbs(s.WalletDir) || s.WalletDir == "/" || s.GID == ^uint32(0) {
		return errors.New("MANIFEST_SPEC")
	}
	return nil
}

// pythonCompact canonicalizes strings as Python's default ensure_ascii JSON does,
// preserving object member order; numbers here have already passed typed decode.
func pythonCompact(raw []byte) ([]byte, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var b bytes.Buffer
	quote := func(s string) {
		b.WriteByte('"')
		for _, r := range s {
			switch r {
			case '"', '\\':
				b.WriteByte('\\')
				b.WriteRune(r)
			case '\b':
				b.WriteString(`\b`)
			case '\f':
				b.WriteString(`\f`)
			case '\n':
				b.WriteString(`\n`)
			case '\r':
				b.WriteString(`\r`)
			case '\t':
				b.WriteString(`\t`)
			default:
				if r < 0x20 || r >= 0x7f {
					if r > 0xffff {
						v := r - 0x10000
						fmt.Fprintf(&b, `\u%04x\u%04x`, 0xd800+(v>>10), 0xdc00+(v&1023))
					} else {
						fmt.Fprintf(&b, `\u%04x`, r)
					}
				} else {
					b.WriteRune(r)
				}
			}
		}
		b.WriteByte('"')
	}
	var walk func() error
	walk = func() error {
		tok, e := d.Token()
		if e != nil {
			return e
		}
		switch v := tok.(type) {
		case json.Delim:
			b.WriteByte(byte(v))
			first := true
			for d.More() {
				if !first {
					b.WriteByte(',')
				}
				first = false
				if v == '{' {
					k, e := d.Token()
					if e != nil {
						return e
					}
					quote(k.(string))
					b.WriteByte(':')
				}
				if e = walk(); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil {
				return e
			}
			b.WriteByte(byte(end.(json.Delim)))
		case string:
			quote(v)
		case json.Number:
			b.WriteString(v.String())
		case bool:
			if v {
				b.WriteString("true")
			} else {
				b.WriteString("false")
			}
		case nil:
			b.WriteString("null")
		default:
			return errors.New("MANIFEST_JSON")
		}
		return nil
	}
	if e := walk(); e != nil {
		return nil, e
	}
	return b.Bytes(), nil
}

// CheckInstallManifest ports g2-manifest-check: exact keys/types/order, compact
// bytes, approved digests and the live bytes must all agree before signing.
func CheckInstallManifest(fs PortFS, raw, approved []byte, s InstallManifestSpec) error {
	fail := func(s string) error { return errors.New("MANIFEST_" + s) }
	if e := s.validate(); e != nil {
		return e
	}
	var obj map[string]any
	if decodePortJSON(raw, &obj) != nil {
		return fail("JSON")
	}
	if len(obj) != 5 {
		return fail("KEYS")
	}
	for _, k := range []string{"v", "release_sha256", "service", "gid", "files"} {
		if _, ok := obj[k]; !ok {
			return fail("KEYS")
		}
	}
	n, ok := portUint(obj["v"], 1)
	if !ok || n != 1 {
		return fail("VERSION")
	}
	gid, ok := portUint(obj["gid"], 1<<32-2)
	if !ok || uint32(gid) != s.GID {
		return fail("GID")
	}
	if obj["service"] != s.Service {
		return fail("SERVICE")
	}
	if obj["release_sha256"] != s.ReleaseSHA {
		return fail("RELEASE")
	}
	entries, ok := obj["files"].([]any)
	if !ok || len(entries) != 3 {
		return fail("FILES")
	}
	got := map[string]string{}
	for i, name := range []string{"receipt.key", "service.json", "wallet.json"} {
		m, ok := portObject(entries[i])
		if !ok || len(m) != 2 || m["path"] != s.WalletDir+"/"+name {
			return fail("FILE_ENTRY")
		}
		sha, ok := m["sha256"].(string)
		if !ok || !portHex(sha, 64) {
			return fail("FILE_DIGEST")
		}
		got[s.WalletDir+"/"+name] = sha
	}
	canonical, e := pythonCompact(raw)
	if e != nil || !bytes.Equal(raw, canonical) {
		return fail("NONCANONICAL")
	}
	var want map[string]string
	if decodePortJSON(approved, &want) != nil || len(want) != len(got) {
		return fail("APPROVED_HASHES")
	}
	for path, sha := range got {
		if want[path] != sha {
			return fail("APPROVED_HASHES")
		}
	}
	for path, sha := range got {
		live, e := fs.hash(path)
		if e != nil {
			return fail("LIVE_READ")
		}
		if live != sha {
			return fail("LIVE_DIGEST")
		}
	}
	return nil
}

// BuildInstallManifest produces the three-file candidate. It remains untrusted
// until CheckInstallManifest compares it to the independently approved hashes.
func BuildInstallManifest(fs PortFS, s InstallManifestSpec) ([]byte, error) {
	if e := s.validate(); e != nil {
		return nil, e
	}
	m := installManifest{Version: 1, Release: s.ReleaseSHA, Service: s.Service, GID: s.GID, Files: []installFile{}}
	for _, n := range []string{"receipt.key", "service.json", "wallet.json"} {
		path := s.WalletDir + "/" + n
		sha, e := fs.hash(path)
		if e != nil {
			return nil, errors.New("MANIFEST_LIVE_READ")
		}
		m.Files = append(m.Files, installFile{path, sha})
	}
	raw, e := json.Marshal(m)
	if e != nil {
		return nil, e
	}
	raw, e = pythonCompact(raw)
	return raw, e
}
