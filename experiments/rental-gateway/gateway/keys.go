package gateway

import (
	"fmt"
	"os"
	"strings"

	"relux.works/swarma-chain-lab/experiments/rental-gateway/nostr"
)

// LoadAgentKey loads the stable agent private key from a file that
// must be a regular file with no group/other permissions (0600 or
// stricter). The key is held only in memory by the gateway and is
// never logged. Stations never receive it in any form.
func LoadAgentKey(path string) (*nostr.PrivKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("agent key: %s is not a regular file", path)
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("agent key: %s has mode %04o, want 0600 or stricter", path, info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := nostr.PrivKeyFromHex(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("agent key: %w", err)
	}
	return key, nil
}

// SaveAgentKey writes a new agent key file (0600), refusing to
// overwrite an existing file.
func SaveAgentKey(path string, key *nostr.PrivKey) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(key.Hex() + "\n"); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
