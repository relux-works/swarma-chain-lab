package wallet

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"

	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/durable"
)

const DefaultWalletDir = ".local/share/swarma/agent-wallet/node"
const DefaultMemoryZone = ".local/share/swarma/memory"

// LoadConfig reads only the explicitly supplied private tool configuration.
// WalletDir and MemoryZone are forbidden-path metadata, never opened by this tool.
func LoadConfig(path string) (Config, error) {
	var c Config
	info, e := os.Lstat(path)
	if e != nil || !durable.PrivateRegular(info) || info.Size() > 65536 {
		return c, fail("CONFIG_PRIVATE_FILE")
	}
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return c, fail("CONFIG_PRIVATE_FILE")
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(info, opened) || !durable.PrivateRegular(opened) {
		return c, fail("CONFIG_PRIVATE_FILE")
	}
	b := make([]byte, info.Size())
	if n, e := f.ReadAt(b, 0); e != nil || n != len(b) {
		return c, fail("CONFIG_READ")
	}
	if su.StrictInput(b, &c) != nil {
		return c, fail("CONFIG_SCHEMA")
	}
	home, e := os.UserHomeDir()
	if e != nil || !filepath.IsAbs(home) {
		return c, fail("CONFIG_HOME")
	}
	for field, def := range map[*string]string{&c.WalletDir: DefaultWalletDir, &c.MemoryZone: DefaultMemoryZone} {
		if *field == "" {
			*field = def
		}
		if !filepath.IsAbs(*field) {
			clean := filepath.Clean(*field)
			if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || clean != *field {
				return c, fail("CONFIG_PATH")
			}
			*field = filepath.Join(home, clean)
		}
	}
	return c, nil
}
func PublicObject(path string) ([]byte, error) { return su.PublicFile(path, 65536) }
func LoadGrant(c Config, reference string) ([]byte, error) {
	if hexN(reference, 32) {
		b, e := PublicObject(filepath.Join(c.ObjectsDir, reference+".json"))
		if e != nil {
			return nil, e
		}
		a := CombinedAuthority{Kernel: KernelAuthority{Policy: c.Policy}, Agent: c.Policy.AgentName, Landlord: c.Policy.LandlordName}
		g, parseErr := a.Parse(b)
		if parseErr != nil || g.ID != reference {
			return nil, fail("OBJECT_HASH")
		}
		return b, nil
	}
	return PublicObject(reference)
}
func LoadTerms(c Config, g Grant) ([]byte, error) {
	if g.Kind == "single-use" {
		return nil, nil
	}
	b, e := PublicObject(filepath.Join(c.ObjectsDir, g.Contract+".json"))
	if e != nil {
		return nil, e
	}
	if Hash(b) != g.Contract {
		return nil, fail("CONTRACT_HASH")
	}
	return b, nil
}
func (w *Wallet) Grant(raw []byte) (Grant, error) { return w.authority.Parse(raw) }
