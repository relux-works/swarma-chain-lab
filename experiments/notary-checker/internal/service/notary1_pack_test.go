package service

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	check "github.com/relux-works/swarma-chain-lab/experiments/notary-checker"
)

func notary1Pack(t *testing.T) (Config, []byte) {
	t.Helper()
	root := filepath.Join("..", "..", "deploy", "notary1")
	raw, err := os.ReadFile(filepath.Join(root, "service.json"))
	if err != nil {
		t.Fatal(err)
	}
	var c Config
	if err := Strict(raw, &c); err != nil || !validConfig(c) {
		t.Fatalf("shipped config rejected: %v", err)
	}
	policy, err := os.ReadFile(filepath.Join(root, "deployment-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	return c, policy
}

// Claim: the shipped host config passes the service's exact parser/validator,
// and its strict D8 fixture policy loads through Load with no RPC or node.
// Only filesystem paths move into scratch; endpoints and limits stay unchanged.
// This proves loading, not deployed permissions, policy provisioning or ATTEST.
func TestNotary1PackLoads(t *testing.T) {
	c, policy := notary1Pack(t)
	want := Config{
		Listen: "127.0.0.1:8080", KeyFile: "/var/lib/notary-service/private/attestation.key",
		RPCEndpoint: "http://127.0.0.1:18443", RPCCredentialFile: "/run/notary-service/rpc.cookie",
		DeploymentPolicyFile: "/etc/notary-service/deployment-policy.json",
		Limits:               Limits{RequestBytes: 65536, RequestsPerSecond: 10, Burst: 10, TimeoutMS: 3000, Concurrent: 2},
	}
	if !reflect.DeepEqual(c, want) {
		t.Fatal("host paths, loopback endpoints or limits drifted")
	}
	var p check.Policy
	if err := Strict(policy, &p); err != nil || p.Mode != "" || len(p.ModeApprovals) != 0 {
		t.Fatal("policy must retain zero-valued strict D8 mode")
	}
	fixturePolicy, err := os.ReadFile("../../testdata/positive/policy.json")
	if err != nil || !bytes.Equal(policy, fixturePolicy) {
		t.Fatal("commissioning policy must match the documented positive fixture exactly")
	}
	path, _ := notary1Scratch(t, c, policy)
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.policyObject.Mode != "" || !bytes.Equal(s.policy, policy) {
		t.Fatal("Load changed strict policy bytes or mode")
	}
}

func notary1Scratch(t *testing.T, c Config, policy []byte) (string, Config) {
	t.Helper()
	dir := t.TempDir()
	c.KeyFile = filepath.Join(dir, "attestation.key")
	c.RPCCredentialFile = filepath.Join(dir, "rpc.cookie")
	c.DeploymentPolicyFile = filepath.Join(dir, "deployment-policy.json")
	if _, err := Keygen(c.KeyFile); err != nil {
		t.Fatal(err)
	}
	// Synthetic, nonfunctional credentials; never a host cookie or network call.
	put(t, c.RPCCredentialFile, []byte("fixture:unused"))
	put(t, c.DeploymentPolicyFile, policy)
	path := filepath.Join(dir, "service.json")
	put(t, path, encode(t, c))
	return path, c
}

// Claim: each required top-level/limit field and a non-loopback listen refuse
// as CONFIG through Load. The valid pack above prevents an always-reject gate.
func TestNotary1PackConfigRefusals(t *testing.T) {
	c, policy := notary1Pack(t)
	path, relocated := notary1Scratch(t, c, policy)
	for _, field := range []string{"listen", "key_file", "rpc_endpoint", "rpc_credential_file", "deployment_policy_file", "limits",
		"request_bytes", "requests_per_second", "burst", "timeout_ms", "concurrent"} {
		t.Run("missing-"+field, func(t *testing.T) {
			var fields map[string]any
			// Maps are only used to remove one member; Load owns validation.
			if err := json.Unmarshal(encode(t, relocated), &fields); err != nil {
				t.Fatal(err)
			}
			if limits, ok := fields["limits"].(map[string]any); ok {
				delete(limits, field)
			}
			delete(fields, field)
			put(t, path, encode(t, fields))
			if s, err := Load(path); err == nil || err.Error() != "CONFIG" || s != nil {
				if s != nil {
					s.Close()
				}
				t.Fatalf("missing %s must refuse CONFIG: %v", field, err)
			}
		})
	}
	relocated.Listen = "0.0.0.0:8080"
	put(t, path, encode(t, relocated))
	if s, err := Load(path); err == nil || err.Error() != "CONFIG" || s != nil {
		if s != nil {
			s.Close()
		}
		t.Fatalf("non-loopback listen must refuse CONFIG: %v", err)
	}
}

// Claim: unknown policy members refuse POLICY_FILE, and a group-readable staged
// credential refuses NODE_CREDENTIALS, without constructing a usable signer.
func TestNotary1PackPolicyAndCookieRefusals(t *testing.T) {
	c, policy := notary1Pack(t)
	for _, tc := range []struct{ name, want string }{
		{"unknown-policy-member", "POLICY_FILE"},
		{"group-readable-service-cookie", "NODE_CREDENTIALS"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, relocated := notary1Scratch(t, c, policy)
			if tc.name == "unknown-policy-member" {
				put(t, relocated.DeploymentPolicyFile, []byte(`{"unexpected":true}`))
			} else if err := os.Chmod(relocated.RPCCredentialFile, 0640); err != nil {
				t.Fatal(err)
			}
			if s, err := Load(path); err == nil || err.Error() != tc.want || s != nil {
				if s != nil {
					s.Close()
				}
				t.Fatalf("want %s, got %v", tc.want, err)
			}
		})
	}
}
