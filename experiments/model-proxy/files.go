package modelproxy

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"syscall"

	"github.com/relux-works/swarma-chain-lab/experiments/single-use/modelprofile"
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

type FileConfig = modelprofile.FileConfig

func LoadConfig(path string) (FileConfig, error) {
	var c FileConfig
	raw, e := ReadInstalledFile(path, MaxBody)
	if e != nil {
		return c, e
	}
	return ParseConfig(raw)
}

// ParseConfig validates bytes already admitted by the caller's static-file boundary.
func ParseConfig(raw []byte) (FileConfig, error) {
	return modelprofile.DecodeFileConfig(raw)
}

// GatewayFileConfig is the sealed file with the gateway tail: `mode` and
// `run_max_window_seconds` follow the published fields in this order, each
// optional. The tail is admitted through the same installed static boundary
// and manifest hash as the rest of the file; omitted mode is development and
// an omitted run maximum admits no run binding.
type GatewayFileConfig struct {
	FileConfig
	Mode                string `json:"mode,omitempty"`
	RunMaxWindowSeconds uint64 `json:"run_max_window_seconds,omitempty"`
}

func LoadGatewayConfig(path string) (GatewayFileConfig, error) {
	raw, e := ReadInstalledFile(path, MaxBody)
	if e != nil {
		return GatewayFileConfig{}, e
	}
	return ParseGatewayConfig(raw)
}

// ParseGatewayConfig applies the published canonical rules to the whole file,
// then the published decoder to the published part. A run maximum above
// MaxRunWindow or an unknown mode is refused at decode, before any startup.
func ParseGatewayConfig(raw []byte) (GatewayFileConfig, error) {
	var g GatewayFileConfig
	if len(raw) == 0 || len(raw) > MaxBody {
		return g, modelprofile.ErrFile
	}
	raw = bytes.TrimSpace(raw)
	if unique(raw) != nil || json.Unmarshal(raw, &g) != nil {
		return GatewayFileConfig{}, modelprofile.ErrFile
	}
	if canonical, e := json.Marshal(g); e != nil || !bytes.Equal(raw, canonical) {
		return GatewayFileConfig{}, modelprofile.ErrFile
	}
	if _, e := modelprofile.DecodeFileConfig(privateCanonical(g.FileConfig)); e != nil {
		return GatewayFileConfig{}, e
	}
	switch g.Mode {
	case "", ModeDevelopment, ModeManaged:
	default:
		return GatewayFileConfig{}, fail("CONFIG_MODE")
	}
	if g.RunMaxWindowSeconds > MaxRunWindow {
		return GatewayFileConfig{}, fail("CONFIG_RUN_WINDOW")
	}
	return g, nil
}
