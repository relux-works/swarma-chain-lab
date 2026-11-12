package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-chain-lab/deploy"
)

const (
	cliKeyG  = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	cliKey2G = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
)

func cliParams() deploy.G2PayParameters {
	return deploy.G2PayParameters{Network: "main", Genesis: "000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770", AgentUID: 1201, AgentSocketGID: 1301, OperatorGID: 1401, Grantee: cliKeyG, ReceiptPubkey: cliKey2G, FeeRateSatVB: 110, HotWalletName: "swarma-g2-hot", NodeRPCPort: 8336, G2: deploy.G2OperatorParameters{RequireTermsVersion: 2, MaxTransferSat: 100000, MaxDaySat: 300000, MaxDayCount: 10, MaxFeeSat: 100000, MaxFloatSat: 2000000, LowFloatSat: 500000, Canary: deploy.G2CanaryParameters{Outpoint: deploy.G2Outpoint{TxID: strings.Repeat("c", 64)}, ValueSat: 10000}, ConfirmationsK: 2, ConflictBlocksN: 6, ReadRatePerHour: 60, JournalSpendCapacity: 2048}}
}

// Claim: g2-render writes exactly the six G2 files (0600) into a new
// directory and prints their names; it refuses an existing directory (no
// overwrite), a relative output path and invalid parameters, creating
// nothing for the invalid input.
func TestG2RenderCommand(t *testing.T) {
	root := t.TempDir()
	params := filepath.Join(root, "params.json")
	raw, _ := json.Marshal(cliParams())
	os.WriteFile(params, append(raw, '\n'), 0600)
	out := filepath.Join(root, "rendered")
	var stdout bytes.Buffer
	if e := g2Render([]string{"-params", params, "-out", out}, &stdout); e != nil {
		t.Fatal("G2_CLI_RENDER positive", e)
	}
	entries, _ := os.ReadDir(out)
	if len(entries) != 6 || !strings.Contains(stdout.String(), `"status":"G2_RENDERED"`) {
		t.Fatal("G2_CLI_RENDER files", entries, stdout.String())
	}
	for _, entry := range entries {
		info, _ := entry.Info()
		if info.Mode().Perm() != 0600 {
			t.Fatal("rendered file mode", entry.Name(), info.Mode())
		}
	}
	if e := g2Render([]string{"-params", params, "-out", out}, io.Discard); e != deploy.ErrInput {
		t.Fatal("G2_CLI_RENDER overwrote an existing directory", e)
	}
	if e := g2Render([]string{"-params", params, "-out", "rendered"}, io.Discard); e != deploy.ErrInput {
		t.Fatal("relative output accepted", e)
	}
	bad := cliParams()
	bad.G2.AllowSingleUse = true
	raw, _ = json.Marshal(bad)
	os.WriteFile(params, raw, 0600)
	other := filepath.Join(root, "other")
	if e := g2Render([]string{"-params", params, "-out", other}, io.Discard); e != deploy.ErrPolicy {
		t.Fatal("G2_CLI_RENDER invalid parameters accepted", e)
	}
	if _, e := os.Stat(other); !os.IsNotExist(e) {
		t.Fatal("output created for invalid parameters")
	}
}

// Claim: g2-custody-probe prints a report and succeeds only when every probe
// passes; a missing denied path makes it fail with ErrCustody after printing
// the evidence. g2-custody-verify accepts that genuine report with -launch=false,
// refuses it under the default launch layout and refuses a tampered report.
// Limit: runs as the test UID; skipped as root.
func TestG2CustodyCommands(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root bypasses file modes")
	}
	root, _ := os.MkdirTemp("", "t18cli")
	denied := filepath.Join(root, "receipt.key")
	os.WriteFile(denied, []byte("x"), 0)
	t.Cleanup(func() { os.Chmod(denied, 0600); os.RemoveAll(root) })
	sock := filepath.Join(root, "w.sock")
	l, e := net.Listen("unix", sock)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			c.Close()
		}
	}()
	tcp, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := tcp.Addr().String()
	tcp.Close()
	uid := uint32(os.Getuid())
	spec := deploy.CustodySpecV1{Version: 1, AgentUID: uid, ServiceUID: uid + 1, DeniedReads: []string{denied}, DeniedRPC: []string{closed}, AllowedSocket: sock}
	specPath := filepath.Join(root, "spec.json")
	raw, _ := json.Marshal(spec)
	os.WriteFile(specPath, append(raw, '\n'), 0600)
	var stdout bytes.Buffer
	if e := g2CustodyProbe([]string{"-spec", specPath}, &stdout); e != nil {
		t.Fatal("G2_CLI_PROBE positive", e, stdout.String())
	}
	reportPath := filepath.Join(root, "report.json")
	os.WriteFile(reportPath, stdout.Bytes(), 0600)
	if e := g2CustodyVerify([]string{"-spec", specPath, "-report", reportPath, "-launch=false"}, io.Discard); e != nil {
		t.Fatal("G2_CLI_VERIFY genuine report", e)
	}
	if e := g2CustodyVerify([]string{"-spec", specPath, "-report", reportPath}, io.Discard); e != deploy.ErrPolicy {
		t.Fatal("G2_CLI_VERIFY accepted a non-launch spec", e)
	}
	tampered := bytes.Replace(stdout.Bytes(), []byte(`"uid":`), []byte(`"uid":1`), 1)
	os.WriteFile(reportPath, tampered, 0600)
	if e := g2CustodyVerify([]string{"-spec", specPath, "-report", reportPath, "-launch=false"}, io.Discard); e != deploy.ErrCustody {
		t.Fatal("G2_CLI_VERIFY accepted a tampered report", e)
	}
	spec.DeniedReads = append(spec.DeniedReads, filepath.Join(root, "missing"))
	raw, _ = json.Marshal(spec)
	os.WriteFile(specPath, raw, 0600)
	stdout.Reset()
	if e := g2CustodyProbe([]string{"-spec", specPath}, &stdout); e != deploy.ErrCustody || !strings.Contains(stdout.String(), `"observed":"ENOENT","pass":false`) {
		t.Fatal("G2_CLI_PROBE passed a missing denied path", e, stdout.String())
	}
	if r, e := deploy.RunCustodyProbe(context.Background(), spec); e != nil || r.Pass {
		t.Fatal("library disagrees with the command", e)
	}
}
