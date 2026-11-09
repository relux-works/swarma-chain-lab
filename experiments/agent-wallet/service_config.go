package wallet

import (
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/durable"
)

type ServiceConfig struct {
	Network        string `json:"network,omitempty"`
	Genesis        string `json:"genesis,omitempty"`
	Version        int    `json:"version"`
	Service        string `json:"service"`
	Socket         string `json:"socket"`
	SocketGID      uint32 `json:"socket_gid"`
	PeerUID        uint32 `json:"peer_uid"`
	Grantee        string `json:"grantee"`
	SkewSeconds    int64  `json:"skew_seconds"`
	TimeoutSeconds int    `json:"timeout_seconds"`
	StateDir       string `json:"state_dir"`
	WalletConfig   string `json:"wallet_config"`
	ReceiptKeyFile string `json:"receipt_key_file"`
}

func privateBytes(path string, limit int64) ([]byte, error) {
	i, e := os.Lstat(path)
	if e != nil || !durable.PrivateRegular(i) || i.Size() < 1 || i.Size() > limit {
		return nil, fail("SERVICE_PRIVATE_FILE")
	}
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, fail("SERVICE_PRIVATE_FILE")
	}
	defer f.Close()
	j, e := f.Stat()
	if e != nil || !os.SameFile(i, j) || !durable.PrivateRegular(j) {
		return nil, fail("SERVICE_PRIVATE_FILE")
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(b)) != i.Size() {
		return nil, fail("SERVICE_PRIVATE_FILE")
	}
	return b, nil
}

// LoadActionKey reads exactly one private scalar file; no wallet/RPC config.
func LoadActionKey(path string) (*btcec.PrivateKey, error) {
	b, e := privateBytes(path, 64)
	if e != nil {
		return nil, e
	}
	if !hexN(string(b), 32) {
		return nil, fail("ACTION_KEY")
	}
	decoded, _ := hex.DecodeString(string(b))
	var s btcec.ModNScalar
	if s.SetByteSlice(decoded) || s.IsZero() {
		return nil, fail("ACTION_KEY")
	}
	return btcec.PrivKeyFromScalar(&s), nil
}
func LoadServiceConfig(path string) (ServiceConfig, error) {
	var c ServiceConfig
	b, e := privateBytes(path, 65536)
	if e != nil {
		return c, e
	}
	if su.StrictInput(b, &c) != nil {
		return c, fail("SERVICE_CONFIG")
	}
	return c, nil
}
func validServiceConfig(c ServiceConfig) error {
	network, genesis := serviceNetworkPins(c.Network, c.Genesis)
	if !su.NetworkPinned(network, genesis) {
		return fail("SERVICE_NETWORK_PIN")
	}
	if c.Version != 1 || c.Service != WalletServiceID || c.PeerUID == 0 || int(c.PeerUID) == os.Getuid() || os.Getuid() == 0 || c.SocketGID == 0 || c.SkewSeconds < 1 || c.SkewSeconds > 300 || c.TimeoutSeconds < 1 || c.TimeoutSeconds > 60 || !hexN(c.Grantee, 32) {
		return fail("SERVICE_CONFIG")
	}
	key, _ := hex.DecodeString(c.Grantee)
	if _, e := schnorr.ParsePubKey(key); e != nil {
		return fail("SERVICE_CONFIG")
	}
	for _, p := range []string{c.Socket, c.StateDir, c.WalletConfig, c.ReceiptKeyFile} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return fail("SERVICE_PATH")
		}
	}
	parent := filepath.Dir(c.Socket)
	resolved, e := filepath.EvalSymlinks(parent)
	if e != nil || resolved != parent {
		return fail("SERVICE_SOCKET_DIR")
	}
	i, e := os.Lstat(parent)
	if e != nil || !i.IsDir() || i.Mode().Perm() != 0750 {
		return fail("SERVICE_SOCKET_DIR")
	}
	st, ok := i.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Getuid() || st.Gid != c.SocketGID {
		return fail("SERVICE_SOCKET_DIR")
	}
	if c.StateDir == parent || c.WalletConfig == c.ReceiptKeyFile {
		return fail("SERVICE_PATH")
	}
	return nil
}

func serviceNetworkPins(network, genesis string) (string, string) {
	if network == "" && genesis == "" {
		return "regtest", su.RegtestGenesis
	}
	return network, genesis
}
