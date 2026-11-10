// Run from station-payload. Each bounded plant edits copied source only and must fail its
// exact product assertion; compilation failures, timeouts and crashes refuse.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type plant struct{ Name, Module, File, Old, New, Test, Witness string }

var plants = []plant{
	{"turn_writable_ancestor", "station-payload", "turn.go", " || info.Mode().Perm()&0022 != 0", "", "TestTurnJournalWritableAncestor", "writable ancestor accepted"},
	{"turn_relay_cap", "station-payload", "session.go", " || !nostr.ValidDeliveryEventLimit(f.RelayMaxEventBytes)", "", "TestSessionRelayCap", "invalid cap allowed Pull"},
	{"turn_size_bound", "station-payload", "session.go", "reply = nostr.BoundDeliveryReply(reply, relayMaxEventBytes)", "_ = relayMaxEventBytes; _ = nostr.DeliverySizeNotice", "TestTurnWrappedSizeRecovery", "station saved unwrappable ready reply"},
	{"turn_file_sync", "station-payload", "turn.go", "e = da1FileSync(f)", "e = nil", "TestDA1SyncProbe", "turn sync sequence"},
	{"turn_directory_sync", "station-payload", "turn.go", "da1DirectorySync(j.root)", "error(nil)", "TestDA1SyncProbe", "turn sync sequence"},
	{"turn_input_match", "station-payload", "turn.go", "if t.Input != input {", "if false && t.Input != input {", "TestTurnJournalRecovery", "changed input accepted"},
	{"turn_uncertain", "station-payload", "turn.go", "if t.Phase == \"in-flight\" {", "if false && t.Phase == \"in-flight\" {", "TestTurnJournalRecovery", "generation uncertainty not terminal"},
	{"turn_checksum", "station-payload", "turn.go", "v.Checksum != turnChecksum(v) || ", "", "TestTurnJournalRefusals", "corrupt record accepted"},
	{"turn_no_regenerate", "station-payload", "session.go", "if t.Phase == \"received\" {\n\t\t\t\tt.Phase = \"in-flight\"", "if t.Phase == \"received\" || t.Phase == \"ready\" || t.Phase == \"accepted\" {\n\t\t\t\tt.Reply = \"\"\n\t\t\t\tt.Phase = \"in-flight\"", "TestTurnSessionRecovery", "recovery regenerated or lost positive control"},
	{"turn_inflight", "station-payload", "session.go", "t.Phase = \"in-flight\"", "t.Phase = \"received\"", "TestTurnSessionRecovery", "recovery <nil> reply"},
	{"turn_receive_before_ack", "station-payload", "turn.go", "if e := j.save(t); e != nil {\n\t\treturn turn{}, e\n\t}\n\treturn j.turns[t.ID], nil", "t.Checksum = turnChecksum(t)\n\tj.turns[id] = t\n\treturn t, nil", "TestTurnSessionRecovery", "ACK preceded durable input"},

	{"responses_empty", "station-payload", "responses.go", "len(response.Output) == 0", "false && len(response.Output) == 0", "TestResponsesEmptyOutput", "Responses empty output accepted"},
	{"responses_validation", "station-payload", "responses.go", "err != nil {\n\t\treturn \"\", ErrResponse\n\t}\n\tvar response", "false && err != nil {\n\t\treturn \"\", ErrResponse\n\t}\n\tvar response", "TestResponsesBodyRefusals", "Responses invalid output escaped"},
	{"responses_refusal", "station-payload", "responses.go", "if part.Type == \"refusal\" {", "if false && part.Type == \"refusal\" {", "TestResponsesBodyRefusals", "Responses invalid output escaped"},
	{"responses_output", "station-payload", "responses.go", "out.Len()+len(part.Text) > MaxText", "false && out.Len()+len(part.Text) > MaxText", "TestResponsesBodyRefusals", "Responses invalid output escaped"},
	{"responses_body", "station-payload", "responses.go", "int64(len(body)) > limit", "false && int64(len(body)) > limit", "TestResponsesBodyLimit", "Responses oversized body released"},
	{"responses_route", "station-payload", "responses.go", "c.bootstrap.BookingID + \"/v1/responses\"", "c.bootstrap.BookingID + \"/v1/messages\"", "TestResponsesRequest", "Responses route/auth boundary"},
	{"responses_terminal", "station-payload", "client.go", "if c.terminal != nil {", "if false && c.terminal != nil {", "TestResponsesRefusalMapping", "Responses terminal refusal retried"},
	{"responses_pin", "station-payload", "client.go", "hex.EncodeToString(sum[:]) != b.ModelCertSHA256", "false && hex.EncodeToString(sum[:]) != b.ModelCertSHA256", "TestResponsesTransportPin", "Responses TLS pin bypass"},
	{"pinned_dialect", "station-payload", "../single-use/modelprofile/profile.go", "p.Dialect != want", "false && p.Dialect != want", "TestPinnedStartup", "pinned startup mismatch accepted"},
	{"pinned_model", "station-payload", "../single-use/modelprofile/profile.go", "m, ok := c.Models[p.Model]", "m, ok := c.Models[p.Model]; if !ok { m = Model{ContextTokens: 100}; ok = true }", "TestPinnedStartup", "pinned startup mismatch accepted"},
	{"pinned_endpoint", "station-payload", "../single-use/modelprofile/profile.go", "p.Endpoint != c.Endpoint.URL", "false && p.Endpoint != c.Endpoint.URL", "TestPinnedStartup", "pinned startup mismatch accepted"},
	{"pinned_pin", "station-payload", "../single-use/modelprofile/profile.go", "p.CertSHA256 != c.Endpoint.CertSHA256", "false && p.CertSHA256 != c.Endpoint.CertSHA256", "TestPinnedStartup", "pinned startup mismatch accepted"},
	{"pinned_cli", "station-payload", "cmd/station-payload/main.go", "c, e = payload.NewPinned(raw, options, *dialect, config)", "_ = config; c, e = payload.New(raw, options)", "TestPinnedCLI", "pinned CLI startup guard missing"},
	{"local_failure_latch", "station-payload", "client.go", "if err == Code(\"MODEL_CAP\") || err == Code(\"MODEL_AUTH\") {", "if err != nil {", "TestLocalFailureRecovery", "local failure latched"},
	{"response_failure_latch", "station-payload", "client.go", "if err == Code(\"MODEL_CAP\") || err == Code(\"MODEL_AUTH\") {", "if err != nil {", "TestResponseLossAccounting", "nonterminal response failure latched"},
	{"environment_proxy", "station-payload", "client.go", "Proxy: nil, DisableKeepAlives", "Proxy: http.ProxyFromEnvironment, DisableKeepAlives", "TestEnvironmentProxy", "environment proxy contacted or failure escaped"},
	{"trust", "station-payload", "client.go", "tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, VerifyConnection: func(s tls.ConnectionState) error {\n\t\tif len(s.VerifiedChains) == 0 || len(s.PeerCertificates) == 0 {", "tlsConfig := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, RootCAs: roots, VerifyConnection: func(s tls.ConnectionState) error {\n\t\tif len(s.PeerCertificates) == 0 {", "TestTLSBoundaries", "TLS boundary accepted"},
	{"codec", "station-payload", "client.go", "if err != nil {\n\t\treturn nil, ErrBootstrap", "if false && err != nil {\n\t\treturn nil, ErrBootstrap", "TestBootstrapAndV1", "invalid bootstrap accepted"},
	{"leaf_pin", "station-payload", "client.go", "hex.EncodeToString(sum[:]) != b.ModelCertSHA256", "false && hex.EncodeToString(sum[:]) != b.ModelCertSHA256", "TestTLSBoundaries", "TLS boundary accepted"},
	{"terminal", "station-payload", "client.go", "if c.terminal != nil {", "if false && c.terminal != nil {", "TestModelAccountingAndCap", "refusal retried or changed accounting"},
	{"v1", "station-payload", "client.go", "return \"echo: \" + text, nil", "return text, nil", "TestBootstrapAndV1", "v1 echo changed"},
	{"input", "station-payload", "client.go", "len(text) > MaxText || !utf8.ValidString(text)", "false && len(text) > MaxText || !utf8.ValidString(text)", "TestRequestBounds", "invalid text accepted"},
	{"output", "station-payload", "client.go", "out.Len()+len(b.Text) > MaxText", "false && out.Len()+len(b.Text) > MaxText", "TestResponseBounds", "invalid model response escaped"},
	{"response", "station-payload", "client.go", "err != nil {\n\t\treturn \"\", ErrResponse\n\t}\n\tvar response", "false && err != nil {\n\t\treturn \"\", ErrResponse\n\t}\n\tvar response", "TestResponseBounds", "invalid model response escaped"},
	{"route", "station-payload", "client.go", "c.bootstrap.BookingID + \"/v1/messages\"", "c.bootstrap.BookingID + \"/v1/wrong\"", "TestModelAccountingAndCap", "valid model neighbor refused"},
	{"bearer", "station-payload", "client.go", "req.Header.Set(\"Authorization\", \"Bearer \"+string(c.bootstrap.ModelBearer))", "req.Header.Set(\"Authorization\", \"Bearer wrong\")", "TestModelAccountingAndCap", "valid model neighbor refused"},
	{"redirect", "station-payload", "client.go", "CheckRedirect: func(*http.Request, []*http.Request) error { return ErrTransport }", "CheckRedirect: func(*http.Request, []*http.Request) error { return nil }", "TestHTTPFailures", "HTTP failure not fixed/terminal"},
	{"refusal", "station-payload", "client.go", "return Code(\"MODEL_\" + code)", "return Code(string(raw))", "TestHTTPFailures", "HTTP failure not fixed/terminal"},
	{"private_file", "station-payload", "cmd/station-payload/main.go", "proxy.ReadPrivateFile(*bootstrap, 0600, 4096)", "os.ReadFile(*bootstrap)", "TestCLI", "CLI refusal leaked or changed code"},
}

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	out := flag.String("out", ".temp/guards", "public evidence")
	flag.Parse()
	root, e := os.Getwd()
	if e != nil {
		return e
	}
	mod, e := os.ReadFile("go.mod")
	if e != nil || !bytes.HasPrefix(mod, []byte("module github.com/relux-works/swarma-chain-lab/experiments/station-payload\n")) {
		return errors.New("run from station-payload")
	}
	evidence, e := filepath.Abs(*out)
	if e != nil {
		return e
	}
	if e = os.MkdirAll(evidence, 0700); e != nil {
		return e
	}
	logs, e := os.MkdirTemp(evidence, "run-")
	if e != nil {
		return e
	}
	fmt.Println("evidence:", logs)
	if e = os.MkdirAll(filepath.Join(root, ".temp"), 0700); e != nil {
		return e
	}
	work, e := os.MkdirTemp(filepath.Join(root, ".temp"), "guards-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(work)
	for _, name := range []string{"station-payload", "single-use"} {
		if e = copyTree(filepath.Join(filepath.Dir(root), name), filepath.Join(work, name)); e != nil {
			return e
		}
	}
	for _, name := range []string{"station-lifecycle", "rental-gateway", "rental", "rental-booking", "sealwatch", "payment-chain", "model-proxy"} {
		if e = os.Symlink(filepath.Join(filepath.Dir(root), name), filepath.Join(work, name)); e != nil {
			return e
		}
	}

	// Observe real fsync calls in the copied fixture only; both wrappers delegate.
	turnFile := filepath.Join(work, "station-payload", "turn.go")
	original, e := os.ReadFile(turnFile)
	if e != nil {
		return e
	}
	if strings.Count(string(original), "f.Sync()") != 1 || strings.Count(string(original), "durable.SyncDir(j.root)") != 1 {
		return errors.New("sync instrumentation drift")
	}
	instrumented := strings.Replace(string(original), "f.Sync()", "da1FileSync(f)", 1)
	instrumented = strings.Replace(instrumented, "durable.SyncDir(j.root)", "da1DirectorySync(j.root)", 1)
	if e = os.WriteFile(turnFile, []byte(instrumented), 0600); e != nil {
		return e
	}
	provenance, _ := json.Marshal(map[string]string{"source_sha256": fmt.Sprintf("%x", sha256.Sum256(original)), "instrumented_sha256": fmt.Sprintf("%x", sha256.Sum256([]byte(instrumented)))})
	if e = os.WriteFile(filepath.Join(logs, "sync-instrumentation.json"), provenance, 0600); e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(work, "station-payload", "da1_sync_probe.go"), []byte(syncProbe), 0600); e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(work, "station-payload", "da1_sync_probe_test.go"), []byte(syncProbeTest), 0600); e != nil {
		return e
	}
	runTest := func(p plant, label string) ([]byte, int, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		pkg := "."
		if strings.HasPrefix(p.File, "cmd/") {
			pkg = "./cmd/station-payload"
		}
		cmd := exec.CommandContext(ctx, "go", "test", "-count=1", "-v", "-run", "^"+p.Test+"$", pkg)
		cmd.Dir = filepath.Join(work, p.Module)
		cmd.Env = append(os.Environ(), "GOWORK=off", "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOFLAGS=-mod=readonly")
		var b bytes.Buffer
		cmd.Stdout = &b
		cmd.Stderr = &b
		if e := cmd.Start(); e != nil {
			return nil, -1, e
		}
		pid := cmd.Process.Pid
		err := cmd.Wait()
		code := 0
		if err != nil {
			var x *exec.ExitError
			if !errors.As(err, &x) {
				return nil, -1, err
			}
			code = x.ExitCode()
		}
		raw := append([]byte(fmt.Sprintf("owned test-command PID %d\n", pid)), b.Bytes()...)
		if e := os.WriteFile(filepath.Join(logs, label+".log"), raw, 0600); e != nil {
			return nil, code, e
		}
		return raw, code, ctx.Err()
	}
	type result struct {
		Name          string
		Exit          int
		Detected      bool
		Before, After string
	}
	results := []result{}
	for _, p := range plants {
		raw, code, e := runTest(p, "baseline-"+p.Name)
		if e != nil || code != 0 || !bytes.Contains(raw, []byte("--- PASS: "+p.Test)) {
			return fmt.Errorf("baseline %s failed exit=%d", p.Name, code)
		}
		path := filepath.Join(work, p.Module, p.File)
		before, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		if n := strings.Count(string(before), p.Old); n != 1 {
			return fmt.Errorf("plant %s matched %d", p.Name, n)
		}
		after := []byte(strings.Replace(string(before), p.Old, p.New, 1))
		if e = os.WriteFile(path, after, 0600); e != nil {
			return e
		}
		raw, code, e = runTest(p, p.Name)
		restore := os.WriteFile(path, before, 0600)
		if e != nil {
			return e
		}
		if restore != nil {
			return restore
		}
		detected := code == 1 && bytes.Contains(raw, []byte("--- FAIL: "+p.Test)) && bytes.Contains(raw, []byte(p.Witness)) && !bytes.Contains(raw, []byte("[build failed]")) && !bytes.Contains(raw, []byte("panic:"))
		results = append(results, result{p.Name, code, detected, fmt.Sprintf("%x", sha256.Sum256(before)), fmt.Sprintf("%x", sha256.Sum256(after))})
		data, _ := json.MarshalIndent(results, "", "  ")
		if e = os.WriteFile(filepath.Join(logs, "results.json"), data, 0600); e != nil {
			return e
		}
		fmt.Printf("%s detected=%v\n", p.Name, detected)
		if !detected {
			return fmt.Errorf("plant %s missed intended assertion", p.Name)
		}
	}
	fmt.Printf("%d intended failures\n", len(results))
	return nil
}
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		rel, e := filepath.Rel(src, path)
		if e != nil {
			return e
		}
		if d.IsDir() {
			if d.Name() == ".temp" || d.Name() == ".git" {
				return filepath.SkipDir
			}
			return os.MkdirAll(filepath.Join(dst, rel), 0700)
		}
		if !d.Type().IsRegular() {
			return errors.New("unexpected source type")
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0600)
	})
}

const syncProbe = `package payload
import (
 "os"
 "sync"
 "github.com/relux-works/swarma-chain-lab/experiments/single-use/durable"
)
var da1SyncMu sync.Mutex
var da1SyncEvents []string
func da1FileSync(f *os.File) error { da1SyncMu.Lock(); da1SyncEvents=append(da1SyncEvents,"file"); da1SyncMu.Unlock(); return f.Sync() }
func da1DirectorySync(path string) error { da1SyncMu.Lock(); da1SyncEvents=append(da1SyncEvents,"dir"); da1SyncMu.Unlock(); return durable.SyncDir(path) }
`
const syncProbeTest = `package payload
import ("testing"; "strings")
// Actual turn save invokes file then directory sync; wrappers call the real OS.
func TestDA1SyncProbe(t *testing.T) {
 j,e:=openTurns(root(t),"binding"); if e!=nil {t.Fatal(e)};defer j.close()
 da1SyncMu.Lock();da1SyncEvents=nil;da1SyncMu.Unlock()
 if _,e=j.receive(strings.Repeat("a",64),"input");e!=nil{t.Fatal(e)}
 da1SyncMu.Lock();got:=strings.Join(da1SyncEvents,",");da1SyncMu.Unlock()
 if got!="file,dir"{t.Fatalf("turn sync sequence %q",got)}
}
`
