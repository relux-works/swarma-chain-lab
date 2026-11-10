package configguard

import (
	"crypto/sha256"
	"encoding/hex"

	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

type Entry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Manifest is private resolved-input metadata, distinct from the public binary
// release manifest. Anchor custody/wiring is external to this checker.
type Manifest struct {
	Version       int     `json:"v"`
	ReleaseSHA256 string  `json:"release_sha256"`
	Service       string  `json:"service"`
	GID           int     `json:"gid"`
	Files         []Entry `json:"files"`
}
type Set struct {
	reader Reader
	files  map[string]string
}

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func digestOK(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}

func openManifest(raw []byte, path, release, service string, r Reader) (*Set, error) {
	var m Manifest
	if su.StrictInput(raw, &m) != nil || m.Version != 1 || len(m.Files) < 1 || len(m.Files) > 256 {
		return nil, fail("DK5_MANIFEST_SCHEMA")
	}
	if m.ReleaseSHA256 != release || m.Service != service || m.GID != r.GID {
		return nil, fail("DK5_MANIFEST_BINDING")
	}
	set := &Set{reader: r, files: make(map[string]string)}
	previous := ""
	for _, entry := range m.Files {
		if !validPath(entry.Path) || entry.Path == path || entry.Path <= previous || !digestOK(entry.SHA256) {
			return nil, fail("DK5_MANIFEST_PATH")
		}
		previous = entry.Path
		set.files[entry.Path] = entry.SHA256
	}
	for _, entry := range m.Files {
		b, e := set.Read(entry.Path, 16<<20)
		clear(b)
		if e != nil {
			return nil, e
		}
	}
	return set, nil
}

// Read checks membership before opening a path and rechecks metadata and hash
// for each load. A prior successful startup check does not waive later drift.
func (s *Set) Read(path string, limit int64) ([]byte, error) {
	if s == nil {
		return nil, fail("DK5_MANIFEST_REQUIRED")
	}
	want, ok := s.files[path]
	if !ok {
		return nil, fail("DK5_UNLISTED_PATH")
	}
	raw, e := s.reader.Read(path, limit)
	if e != nil {
		return nil, e
	}
	if digest(raw) != want {
		clear(raw)
		return nil, fail("DK5_CONTENT_HASH")
	}
	return raw, nil
}
