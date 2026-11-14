// Run from grantcheck: go run .scripts/sender-guards.go -out .temp/sender-guards
// Each mutant uses a Go overlay; the checked-out source is never modified.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type plant struct {
	name, file, old, replacement, test, witness string
	occurrences                                 int
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	out := flag.String("out", ".temp/sender-guards", "fresh overlay evidence directory")
	flag.Parse()
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	evidence, err := filepath.Abs(*out)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(evidence, 0700); err != nil {
		return err
	}
	runDir, err := os.MkdirTemp(evidence, "run-")
	if err != nil {
		return err
	}
	plants := []plant{
		{"envelope_lifecycle_nostr_fallback", "admission.go", "if v.transport == SwarmEnvelopeV2 && v.Code != CodeNoGrant {", "if false {", "TestA2ADecisionTable", "lifecycle exchange mapping", 1},
		{"accept_any_transport", "sender.go", "if !proof.Transport.valid() || proof.Transport != c.transport {", "if false {", "TestSenderUnknownTransport", "verdict contract", 2},
		{"skip_key_format", "checker.go", "if !validKey(peer) {", "if false {", "TestSenderKeyFormat", "verdict contract", 1},
		{"ignore_transport_pin", "sender.go", "if !proof.Transport.valid() || proof.Transport != c.transport {", "if !proof.Transport.valid() {", "TestSenderTransportPin", "verdict contract", 2},
	}
	for _, p := range plants {
		source := filepath.Join(root, p.file)
		raw, err := os.ReadFile(source)
		if err != nil {
			return err
		}
		if strings.Count(string(raw), p.old) != p.occurrences {
			return fmt.Errorf("%s: plant did not apply exactly", p.name)
		}
		replacement := filepath.Join(runDir, p.name+".go")
		if err = os.WriteFile(replacement, []byte(strings.ReplaceAll(string(raw), p.old, p.replacement)), 0600); err != nil {
			return err
		}
		overlay := filepath.Join(runDir, p.name+".json")
		data, _ := json.Marshal(struct{ Replace map[string]string }{map[string]string{source: replacement}})
		if err = os.WriteFile(overlay, data, 0600); err != nil {
			return err
		}
		for _, mutant := range []bool{false, true} {
			args := []string{"test", "-count=1", "-v", "-run", "^" + p.test + "$", "."}
			label := p.name + "-baseline"
			if mutant {
				args = append([]string{"test", "-overlay=" + overlay}, args[1:]...)
				label = p.name
			}
			cmd := exec.Command("go", args...)
			cmd.Env = append(os.Environ(), "CG1_REGTEST=0", "GOTOOLCHAIN=local", "GOWORK=off")
			var output bytes.Buffer
			cmd.Stdout, cmd.Stderr = &output, &output
			if err = cmd.Start(); err != nil {
				return err
			}
			pid := cmd.Process.Pid
			waitErr := cmd.Wait()
			code := cmd.ProcessState.ExitCode()
			log := append([]byte(fmt.Sprintf("owned PID %d; exit %d\n", pid, code)), output.Bytes()...)
			if err = os.WriteFile(filepath.Join(runDir, label+".log"), log, 0600); err != nil {
				return err
			}
			ok := code == 0 && bytes.Contains(log, []byte("--- PASS: "+p.test))
			if mutant {
				ok = code == 1 && bytes.Contains(log, []byte("--- FAIL: "+p.test)) && bytes.Contains(log, []byte(p.witness)) && !bytes.Contains(log, []byte("[build failed]")) && !bytes.Contains(log, []byte("panic:")) && !bytes.Contains(log, []byte("--- SKIP:"))
			}
			fmt.Printf("%s test=%s exit=%d detected=%v\n", label, p.test, code, ok)
			if !ok {
				return fmt.Errorf("%s did not reach intended assertion: %v", label, waitErr)
			}
		}
	}
	fmt.Println("overlay evidence:", runDir)
	return nil
}
