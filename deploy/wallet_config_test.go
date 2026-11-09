package deploy

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func walletFixture() walletServiceConfig {
	return walletServiceConfig{Version: 1, Service: "wallet.nmc", Socket: "/run/swarma-wallet/wallet.sock", SocketGID: 1002, PeerUID: 1001, Grantee: strings.Repeat("a", 64), SkewSeconds: 60, TimeoutSeconds: 30, StateDir: "/var/lib/swarma-wallet/service", WalletConfig: "/etc/swarma/wallet/wallet.json", ReceiptKeyFile: "/etc/swarma/wallet/receipt.key"}
}

// Public references/pins are checked without opening credentials or assuming
// actual UID/group membership; native startup adds curve, mode and owner checks.
func TestWalletDeployment(t *testing.T) {
	p := newPolicy("wallet")
	c := walletFixture()
	if _, e := Validate(encoded(t, p)); e != nil {
		t.Fatal("wallet descriptor neighbor", e)
	}
	if e := ValidateServiceInputs(p, [][]byte{encoded(t, c)}); e != nil {
		t.Fatal("wallet config neighbor", e)
	}
	for name, mut := range map[string]func(*walletServiceConfig){
		"service": func(c *walletServiceConfig) { c.Service = "shell" }, "peer_root": func(c *walletServiceConfig) { c.PeerUID = 0 }, "group": func(c *walletServiceConfig) { c.SocketGID = 0 }, "socket": func(c *walletServiceConfig) { c.Socket = "/run/foreign/socket" }, "wallet_config": func(c *walletServiceConfig) { c.WalletConfig = "/etc/swarma/issuer/service.json" }, "key": func(c *walletServiceConfig) { c.ReceiptKeyFile = c.WalletConfig }, "state": func(c *walletServiceConfig) { c.StateDir = "/var/lib/swarma-wallet" }, "skew": func(c *walletServiceConfig) { c.SkewSeconds = 301 }, "timeout": func(c *walletServiceConfig) { c.TimeoutSeconds = 0 }, "grantee": func(c *walletServiceConfig) { c.Grantee = "" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := c
			mut(&bad)
			if e := ValidateServiceInputs(p, [][]byte{encoded(t, bad)}); e != ErrPolicy {
				t.Fatal("wallet deploy guard", e)
			}
			if e := ValidateServiceInputs(p, [][]byte{encoded(t, c)}); e != nil {
				t.Fatal("wallet deploy positive", e)
			}
		})
	}
	for _, inputs := range [][][]byte{nil, {encoded(t, c), encoded(t, c)}, {[]byte(`{"password":"fixture-not-a-secret"}`)}} {
		if e := ValidateServiceInputs(p, inputs); e == nil {
			t.Fatal("wallet deployment input guard")
		}
	}
	raw, _ := os.ReadFile("templates/wallet/service.json")
	if e := ValidateServiceInputs(p, [][]byte{raw}); e != ErrPlaceholder {
		t.Fatal("wallet placeholder activation", e)
	}
	unit, e := os.ReadFile("templates/systemd/swarma-wallet.service.in")
	if e != nil {
		t.Fatal(e)
	}
	for _, required := range []string{"User=swarma-wallet\n", "Group=swarma-wallet-peer\n", "RuntimeDirectoryMode=0750", "StateDirectoryMode=0700", "UMask=0077", "CapabilityBoundingSet=\n", "NoNewPrivileges=true", "ReadOnlyPaths=/etc/swarma/wallet", "ReadWritePaths=/var/lib/swarma-wallet /run/swarma-wallet", "IPAddressDeny=any", "IPAddressAllow=127.0.0.1/32", "agent-walletd --config /etc/swarma/wallet/service.json"} {
		if !bytes.Contains(unit, []byte(required)) {
			t.Fatal("wallet unit boundary", required)
		}
	}
	for _, forbidden := range []string{"Environment=", "ExecStartPre=", "rpcpassword", "/home/", "/Users/", "rm -", "agent-wallet-legacy"} {
		if bytes.Contains(unit, []byte(forbidden)) {
			t.Fatal("wallet unit unsafe directive")
		}
	}
}
