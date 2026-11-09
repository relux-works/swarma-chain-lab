package wallet

import (
	"os"
	"path/filepath"
	"testing"
)

// Temporary directory permissions and configuration guards are real, but this
// test does not impersonate another UID or prove a deployed agent's denied read.
func TestActionServiceConfig(t *testing.T) {
	root, e := filepath.EvalSymlinks(privateDir(t))
	if e != nil {
		t.Fatal(e)
	}
	run := filepath.Join(root, "run")
	if e = os.Mkdir(run, 0750); e != nil {
		t.Fatal(e)
	}
	os.Chmod(run, 0750)
	if e = os.Chown(run, os.Getuid(), os.Getgid()); e != nil {
		t.Fatal(e)
	}
	_, pub := testKey(2)
	c := ServiceConfig{1, WalletServiceID, filepath.Join(run, "wallet.sock"), uint32(os.Getgid()), uint32(os.Getuid() + 1), pub, 60, 2, filepath.Join(root, "state"), filepath.Join(root, "wallet.json"), filepath.Join(root, "receipt.key")}
	if e = validServiceConfig(c); e != nil {
		t.Fatal("service config neighbor", e)
	}
	for name, change := range map[string]func(*ServiceConfig){
		"same-uid":             func(c *ServiceConfig) { c.PeerUID = uint32(os.Getuid()) },
		"root-peer":            func(c *ServiceConfig) { c.PeerUID = 0 },
		"root-group":           func(c *ServiceConfig) { c.SocketGID = 0 },
		"wrong-group":          func(c *ServiceConfig) { c.SocketGID++ },
		"zero-skew":            func(c *ServiceConfig) { c.SkewSeconds = 0 },
		"long-skew":            func(c *ServiceConfig) { c.SkewSeconds = 301 },
		"zero-timeout":         func(c *ServiceConfig) { c.TimeoutSeconds = 0 },
		"long-timeout":         func(c *ServiceConfig) { c.TimeoutSeconds = 61 },
		"relative-path":        func(c *ServiceConfig) { c.StateDir = "state" },
		"shared-runtime-state": func(c *ServiceConfig) { c.StateDir = run },
		"shared-key-config":    func(c *ServiceConfig) { c.WalletConfig = c.ReceiptKeyFile },
	} {
		t.Run(name, func(t *testing.T) {
			x := c
			change(&x)
			if e := validServiceConfig(x); e == nil {
				t.Fatal("service config guard", name)
			}
		})
	}
	for _, mode := range []os.FileMode{0700, 0770, 0755} {
		os.Chmod(run, mode)
		if e = validServiceConfig(c); e == nil {
			t.Fatal("socket directory mode guard")
		}
	}
	os.Chmod(run, 0750)
	alias := filepath.Join(root, "alias")
	if e = os.Symlink(run, alias); e != nil {
		t.Fatal(e)
	}
	x := c
	x.Socket = filepath.Join(alias, "wallet.sock")
	if e = validServiceConfig(x); e == nil {
		t.Fatal("socket parent alias guard")
	}
	path := filepath.Join(root, "service.json")
	os.WriteFile(path, canonical(c), 0600)
	if _, e = LoadServiceConfig(path); e != nil {
		t.Fatal("private config neighbor", e)
	}
	os.Chmod(path, 0640)
	if _, e = LoadServiceConfig(path); e == nil {
		t.Fatal("config mode guard")
	}
	os.Chmod(path, 0600)
	os.WriteFile(path, []byte(`{"version":1,"rpc_password":"do-not-echo"}`), 0600)
	if _, e = LoadServiceConfig(path); e == nil || e.Error() != "SERVICE_CONFIG" {
		t.Fatal("config closed schema guard", e)
	}
	if e = validServiceConfig(c); e != nil {
		t.Fatal("config restored neighbor", e)
	}
}
