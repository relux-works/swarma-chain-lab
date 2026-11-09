package deploy

// This structural mirror contains public pins and private file references only.
// It never reads the private W1 wallet configuration or a scalar file.
type walletServiceConfig struct {
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

func validateWallet(raw []byte) error {
	var c walletServiceConfig
	if e := serviceDecode(raw, &c, false); e != nil {
		return e
	}
	if (c.Network != "" || c.Genesis != "") && !deploymentNetwork(c.Network, c.Genesis) {
		return ErrNetwork
	}
	if c.Version != 1 || c.Service != "wallet.nmc" || c.Socket != "/run/swarma-wallet/wallet.sock" || c.SocketGID == 0 || c.PeerUID == 0 || !digestPin(c.Grantee) || c.SkewSeconds < 1 || c.SkewSeconds > 300 || c.TimeoutSeconds < 1 || c.TimeoutSeconds > 60 || c.StateDir != "/var/lib/swarma-wallet/service" || c.WalletConfig != "/etc/swarma/wallet/wallet.json" || c.ReceiptKeyFile != "/etc/swarma/wallet/receipt.key" {
		return ErrPolicy
	}
	return nil
}
