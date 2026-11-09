package modelproxy

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"syscall"
)

// ReadPrivateFile checks every path component, owner, exact mode and inode before
// and after reading. Only synthetic key files are used in tests.
func ReadPrivateFile(path string, mode os.FileMode, limit int64) ([]byte, error) {
	if !noLinks(path) {
		return nil, fail("PRIVATE_FILE")
	}
	i, e := os.Lstat(path)
	if e != nil || !i.Mode().IsRegular() || i.Mode().Perm() != mode || fileUID(i) != os.Getuid() || i.Size() < 1 || i.Size() > limit {
		return nil, fail("PRIVATE_FILE")
	}
	stat, ok := i.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return nil, fail("PRIVATE_FILE")
	}
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, fail("PRIVATE_FILE")
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(i, opened) || opened.Mode() != i.Mode() {
		return nil, fail("PRIVATE_FILE")
	}
	raw, e := io.ReadAll(io.LimitReader(f, limit+1))
	after, ae := f.Stat()
	if e != nil || ae != nil || int64(len(raw)) != i.Size() || after.Size() != i.Size() || after.Mode() != i.Mode() {
		return nil, fail("PRIVATE_FILE")
	}
	return raw, nil
}

type FileConfig struct {
	StateDir      string                  `json:"state_dir"`
	Listen        string                  `json:"listen"`
	Endpoint      Endpoint                `json:"endpoint"`
	TLSCert       string                  `json:"tls_cert"`
	TLSKey        string                  `json:"tls_key"`
	AdminSocket   string                  `json:"admin_socket"`
	CallerUID     uint32                  `json:"caller_uid"`
	Upstream      string                  `json:"upstream"`
	APIKeyFile    string                  `json:"api_key_file"`
	Models        map[string]Model        `json:"models"`
	ModelProfiles map[string]ModelProfile `json:"model_profiles,omitempty"`
}

func LoadConfig(path string) (FileConfig, error) {
	var c FileConfig
	raw, e := ReadPrivateFile(path, 0600, MaxBody)
	if e != nil {
		return c, fail("CONFIG_FILE")
	}
	raw = bytes.TrimSpace(raw)
	if unique(raw) != nil || json.Unmarshal(raw, &c) != nil || !bytes.Equal(raw, canonical(c)) {
		return FileConfig{}, fail("CONFIG_FILE")
	}
	return c, nil
}
