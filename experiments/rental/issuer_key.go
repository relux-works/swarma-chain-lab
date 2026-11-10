package rental

import (
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	secp "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/durable"
)

// readGrantKey reads exactly 32 binary scalar bytes from an owner-only file.
// No symlink components, hardlinks, alternate encodings or scalar reduction.
// Callers Zero the key; runtime/compiler copies remain an OS custody limit.
func readGrantKey(path, expected string) (*secp.PrivateKey, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, bad("KEY_PATH")
	}
	real, e := filepath.EvalSymlinks(path)
	if e != nil || real != path {
		return nil, bad("KEY_PATH")
	}
	before, e := os.Lstat(path)
	if e != nil || !durable.PrivateRegular(before) || before.Size() != 32 {
		return nil, bad("KEY_FILE")
	}
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, bad("KEY_FILE")
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !os.SameFile(before, info) || !durable.PrivateRegular(info) || info.Size() != 32 {
		return nil, bad("KEY_FILE")
	}
	raw, e := io.ReadAll(io.LimitReader(f, 33))
	defer clear(raw)
	if e != nil || len(raw) != 32 {
		return nil, bad("KEY_FILE")
	}
	info, e = f.Stat()
	if e != nil || !durable.PrivateRegular(info) || info.Size() != 32 {
		return nil, bad("KEY_FILE")
	}
	return parseGrantKey(raw, expected)
}

func parseGrantKey(raw []byte, expected string) (*secp.PrivateKey, error) {
	if len(raw) != 32 {
		return nil, bad("KEY_FILE")
	}
	var scalar secp.ModNScalar
	defer scalar.Zero()
	if scalar.SetByteSlice(raw) || scalar.IsZero() {
		return nil, bad("KEY_SCALAR")
	}
	key := secp.NewPrivateKey(&scalar)
	if hex.EncodeToString(schnorr.SerializePubKey(key.PubKey())) != expected {
		key.Zero()
		return nil, bad("KEY_PIN")
	}
	return key, nil
}
