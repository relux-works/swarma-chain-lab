package notary1_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	check "github.com/relux-works/swarma-chain-lab/experiments/notary-checker"
	"github.com/relux-works/swarma-chain-lab/experiments/notary-checker/internal/service"
)

func read(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Claim: the smoke's policy name and canonical value pass the service's own checker/name parser; adjacent absent/wrong shapes refuse exactly NOTARY_KEY.
func TestNotary1SmokeResolverContract(t *testing.T) {
	var spec struct {
		Name        string          `json:"name"`
		Value       json.RawMessage `json:"value"`
		AbsentValue json.RawMessage `json:"absent_value"`
	}
	if err := service.Strict(read(t, "smoke-binding.json"), &spec); err != nil {
		t.Fatal(err)
	}
	fixture := func(name string) []byte { return read(t, "../../testdata/positive/"+name+".json") }
	var policy check.Policy
	if err := service.Strict(read(t, "deployment-policy.json"), &policy); err != nil || spec.Name != policy.NotaryName || spec.Name != "id/certifier" {
		t.Fatal("smoke name must be the exact shipped policy lookup name")
	}
	var binding struct {
		Swarma struct {
			Notary struct {
				Attest string `json:"attest"`
			} `json:"notary"`
		} `json:"swarma"`
	}
	if err := json.Unmarshal(fixture("notary-value"), &binding); err != nil {
		t.Fatal(err)
	}
	value := bytes.ReplaceAll(spec.Value, []byte("RECEIPT_PUBLIC_KEY"), []byte(binding.Swarma.Notary.Attest))
	if !bytes.Equal(value, fixture("notary-value")) {
		t.Fatal("smoke authority shape differs from the known accepted canonical value")
	}
	in := check.Input{Parent: fixture("parent"), Child: fixture("child"), ParentContract: fixture("parent-contract"),
		ChildContract: fixture("child-contract"), Request: fixture("request"), Policy: read(t, "deployment-policy.json"),
		Statement: fixture("statement"), NotaryValue: value, At: 1700000100}
	result, err := check.Check(in) // Same authority parser reached by service.attest, without RPC or a signer.
	if err != nil || len(result.Attestation) == 0 {
		t.Fatalf("positive smoke shape refused: %v", err)
	}
	var a check.Attestation
	if err := json.Unmarshal(result.Attestation, &a); err != nil || a.NotaryName != spec.Name || a.NotaryKey != binding.Swarma.Notary.Attest {
		t.Fatal("candidate must bind the smoke name and resolved key")
	}
	for _, invalid := range [][]byte{spec.AbsentValue, []byte(`{"swarma":{"landlord":{"grant":"` + binding.Swarma.Notary.Attest + `"}}}`), bytes.Replace(value, []byte(`{"notary"`), []byte(`{ "notary"`), 1)} {
		in.NotaryValue = invalid
		if got, err := check.Check(in); err == nil || err.Error() != "NOTARY_KEY" || len(got.Attestation) != 0 || got.Digest != "" {
			t.Fatalf("absent/wrong authority must refuse NOTARY_KEY without candidate: %v", err)
		}
	}
	in.NotaryValue = value
	in.Policy = bytes.ReplaceAll(in.Policy, []byte(spec.Name), []byte("id/unregistered"))
	if got, err := check.Check(in); err == nil || err.Error() != "NOTARY_NOT_DESIGNATED" || len(got.Attestation) != 0 {
		t.Fatalf("an unrelated smoke name must not certify the policy bundle: %v", err)
	}
}

// Claim: the helper's fresh time/registration-bound bundle passes the service's strict request parser and checker; removing the authority binding refuses NOTARY_KEY.
func TestNotary1FreshSmokeBundle(t *testing.T) {
	code := `import importlib.util,json,time
from pathlib import Path
p=Path('smoke.py').resolve()
s=importlib.util.spec_from_file_location('smoke',p)
m=importlib.util.module_from_spec(s)
s.loader.exec_module(m)
public=json.loads((m.MODULE/'testdata/positive/notary-value.json').read_bytes())['swarma']['notary']['attest']
policy,request=m.fresh_bundle(dict(txid='ab'*32,vout=2),dict(blocks=123,bestblockhash='cd'*32),public)
print(json.dumps(dict(request=request,policy=policy,notary_value=m.binding(public)[1],at=int(time.time())),separators=(',',':')))
`
	cmd := exec.Command("python3", "-I", "-B", "-c", code)
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("offline fresh encoder: %v", err)
	}
	var generated struct {
		Request     service.Request `json:"request"`
		Policy      json.RawMessage `json:"policy"`
		NotaryValue json.RawMessage `json:"notary_value"`
		At          int64           `json:"at"`
	}
	if err := service.Strict(raw, &generated); err != nil {
		t.Fatal("fresh request must pass the service's strict parser")
	}
	r := generated.Request
	in := check.Input{Parent: r.Parent, Child: r.Child, ParentContract: r.ParentContract, ChildContract: r.ChildContract,
		Request: r.Request, Statement: r.Statement, Policy: generated.Policy, NotaryValue: generated.NotaryValue, At: generated.At}
	if got, err := check.Check(in); err != nil || len(got.Attestation) == 0 {
		t.Fatalf("fresh smoke bundle must pass the actual checker: %v", err)
	}
	in.NotaryValue = []byte(`{}`)
	if got, err := check.Check(in); err == nil || err.Error() != "NOTARY_KEY" || len(got.Attestation) != 0 {
		t.Fatalf("fresh absent-binding neighbor must refuse NOTARY_KEY: %v", err)
	}
}

// Claim: the helper's encoding, positive/refusal verification and one-shot sequencing pass offline controls without node, HTTP or process execution.
func TestNotary1SmokeHelperOffline(t *testing.T) {
	cmd := exec.Command("python3", "-I", "test-smoke.py")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("offline smoke controls: %v\n%s", err, output)
	}
}

// Claim: the commissioning override preserves the production command except wallet/fee options, and both unit forms verify offline with a missing-ExecStart control.
func TestNotary1CommissioningUnitsVerify(t *testing.T) {
	node := string(read(t, "namecoind-regtest.service"))
	override := string(read(t, "commissioning.conf"))
	var production, commissioning string
	for _, line := range strings.Split(node, "\n") {
		if strings.HasPrefix(line, "ExecStart=") {
			production = line
		}
	}
	for _, line := range strings.Split(override, "\n") {
		if strings.HasPrefix(line, "ExecStart=") && line != "ExecStart=" {
			commissioning = line
		}
	}
	want := strings.Replace(production, "-disablewallet=1", "-disablewallet=0 -fallbackfee=0.001", 1)
	if production == "" || commissioning != want || strings.Count(override, "ExecStart=") != 2 {
		t.Fatal("commissioning must retain every production isolation option")
	}
	analyze, err := exec.LookPath("systemd-analyze")
	if err != nil {
		t.Skip("systemd-analyze unavailable; target verification required")
	}
	root := t.TempDir()
	write := func(path, value string, mode os.FileMode) {
		t.Helper()
		path = filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(value), mode); err != nil {
			t.Fatal(err)
		}
	}
	for _, target := range []string{"sysinit.target", "basic.target", "local-fs.target", "shutdown.target", "multi-user.target", "sockets.target", "timers.target", "paths.target", "slices.target", "system.slice", "-.slice"} {
		write("etc/systemd/system/"+target, "[Unit]\nDescription=Offline fixture\n", 0644)
	}
	for _, binary := range []string{"opt/namecoin/28.0/bin/namecoind", "opt/namecoin/28.0/bin/namecoin-cli", "opt/notary-service/v0.1.1/notary-service", "usr/bin/install"} {
		write(binary, "#!/bin/sh\nexit 0\n", 0755)
	}
	write("etc/systemd/system/namecoind-regtest.service", node, 0644)
	write("etc/systemd/system/notary-service.service", string(read(t, "notary-service.service")), 0644)
	verify := func() ([]byte, error) {
		cmd := exec.Command(analyze, "verify", "--man=no", "--generators=no", "--recursive-errors=yes", "--root="+root, "namecoind-regtest.service", "notary-service.service")
		cmd.Env = append(os.Environ(), "LC_ALL=C", "SYSTEMD_LOG_LEVEL=warning")
		return cmd.CombinedOutput()
	}
	if output, err := verify(); err != nil || len(output) != 0 {
		t.Fatalf("production offline verify: %v\n%s", err, output)
	}
	write("etc/systemd/system/namecoind-regtest.service.d/commissioning.conf", override, 0644)
	if output, err := verify(); err != nil || len(output) != 0 {
		t.Fatalf("commissioning offline verify: %v\n%s", err, output)
	}
	write("etc/systemd/system/namecoind-regtest.service.d/commissioning.conf", "[Service]\nExecStart=\n", 0644)
	if output, err := verify(); err == nil || !strings.Contains(string(output), "no ExecStart=") {
		t.Fatalf("missing-ExecStart control did not fail as intended: %v\n%s", err, output)
	}
}
