package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-chain-lab/deploy"
)

// The real CLI dispatch requires the new model native file, accepts a complete
// synthetic one, and refuses a missing key/duplicate file before any service runs.
func TestValidateModelInputs(t *testing.T) {
	root := t.TempDir()
	policy := `{"version":1,"network":"regtest","service":"model","release_version":"test","commit":"` + strings.Repeat("a", 40) + `","binary_sha256":"` + strings.Repeat("b", 64) + `","state_dir":"/var/lib/swarma-model","listen":"127.0.0.1:8443","config":"/etc/swarma/model/service.json"}`
	native := `{"state_dir":"/var/lib/swarma-model","listen":"127.0.0.1:8443","endpoint":{"url":"https://model.invalid:8443","cert_sha256":"` + strings.Repeat("a", 64) + `"},"tls_cert":"/etc/swarma/model/tls.pem","tls_key":"/etc/swarma/model/tls.key","admin_socket":"/run/swarma-model/admin.sock","caller_uid":1001,"upstream":"https://upstream.invalid/v1/messages","api_key_file":"/etc/swarma/model/api.key","models":{"fixture":{"context_tokens":100,"input_nano_usd":1,"output_nano_usd":2,"source":"synthetic"}}}`
	write := func(name, s string) string {
		p := filepath.Join(root, name)
		if e := os.WriteFile(p, []byte(s), 0600); e != nil {
			t.Fatal(e)
		}
		return p
	}
	p, n := write("policy.json", policy), write("native.json", native)
	args := []string{"validate", "-config", p}
	if e := run(args); e != deploy.ErrPolicy {
		t.Fatal("missing new native config accepted", e)
	}
	valid := append(append([]string{}, args...), "-public", n)
	if e := run(valid); e != nil {
		t.Fatal("complete model CLI input refused", e)
	}
	if e := run(append(valid, "-public", n)); e != deploy.ErrPolicy {
		t.Fatal("ambiguous native input accepted", e)
	}
	write("native.json", strings.Replace(native, `"tls_key":"/etc/swarma/model/tls.key"`, `"tls_key":""`, 1))
	if e := run(valid); e != deploy.ErrPolicy {
		t.Fatal("missing key path accepted", e)
	}
}

// The real CLI coin-check route reaches the equality guard and uses fixed output;
// it does not infer a missing set from the other file or accept duplicate coins.
func TestCheckCoinsCommand(t *testing.T) {
	root := t.TempDir()
	g, b := filepath.Join(root, "gateway.json"), filepath.Join(root, "booking.json")
	write := func(p, s string) {
		if e := os.WriteFile(p, []byte(s), 0600); e != nil {
			t.Fatal(e)
		}
	}
	write(g, `{"exchange":{"booking_version":2,"payment_coins":["nmc"]}}`)
	write(b, `{"service_version":2,"config":{"coins":{"nmc":{"public_branch":"fixture"}}}}`)
	args := []string{"check-coins", "-gateway", g, "-booking", b}
	if e := run(args); e != nil {
		t.Fatal("coin command refused equal sets", e)
	}
	write(g, `{"exchange":{"booking_version":2,"payment_coins":["btc"]}}`)
	if e := run(args); e != deploy.ErrPolicy {
		t.Fatal("coin command accepted unequal sets", e)
	}
}
