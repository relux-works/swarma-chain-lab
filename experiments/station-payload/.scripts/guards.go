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
	for _, name := range []string{"station-payload"} {
		if e = copyTree(filepath.Join(filepath.Dir(root), name), filepath.Join(work, name)); e != nil {
			return e
		}
	}
	for _, name := range []string{"station-lifecycle", "rental-gateway", "rental", "rental-booking", "single-use", "sealwatch", "payment-chain", "model-proxy"} {
		if e = os.Symlink(filepath.Join(filepath.Dir(root), name), filepath.Join(work, name)); e != nil {
			return e
		}
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
