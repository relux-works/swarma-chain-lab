// Run from model-proxy: go run .scripts/daily-ceiling-guards.go -out .temp/daily-guards.
// Compiler overlays leave the candidate source unchanged. A compile failure,
// panic or unrelated assertion is never a killed mutant.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type plant struct{ Name, Old, New, Test, Failure, Witness string }

var plants = []plant{
	{"drop_ceiling_check", `if !ok || dailyNext > s.cfg.DailyCostCeilingNanoUSD {`, `if false && (!ok || dailyNext > s.cfg.DailyCostCeilingNanoUSD) {`, `^TestDailyCeilingBoundary$/^229$`, `TestDailyCeilingBoundary/229`, `daily ceiling+1 forwarded or charged`},
	{"allow_ceiling_plus_one", `dailyNext > s.cfg.DailyCostCeilingNanoUSD`, `dailyNext > s.cfg.DailyCostCeilingNanoUSD+1`, `^TestDailyCeilingBoundary$/^229$`, `TestDailyCeilingBoundary/229`, `daily ceiling+1 forwarded or charged`},
	{"missing_accounting_as_zero", `if !initialize {`, `if false && !initialize {`, `^TestDailyAccountingInitialization$`, `TestDailyAccountingInitialization`, `missing accounting initialized as zero`},
	{"release_pre_header_daily", "\tvar verdict error\n\tif u != nil {", "\tif u == nil && p.Day == s.state.Daily.Day {\n\t\ts.state.Daily.Committed -= p.Cost\n\t}\n\tvar verdict error\n\tif u != nil {", `^TestResponsesPreHeaderClosure$`, `TestResponsesPreHeaderClosure/expired`, `Responses pre-header daily reservation changed`},
}

type result struct {
	Name                        string
	Command                     []string
	PID, Exit                   int
	Detected                    bool
	SourceSHA256, OverlaySHA256 string
}

func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	out := flag.String("out", ".temp/daily-guards", "evidence directory")
	flag.Parse()
	root, e := os.Getwd()
	if e != nil {
		return e
	}
	source := filepath.Join(root, "registry.go")
	original, e := os.ReadFile(source)
	if e != nil {
		return e
	}
	evidence, e := filepath.Abs(*out)
	if e != nil {
		return e
	}
	if e = os.MkdirAll(evidence, 0700); e != nil {
		return e
	}
	evidence, e = os.MkdirTemp(evidence, "run-")
	if e != nil {
		return e
	}
	runTest := func(name, pattern, overlay string) (result, []byte, error) {
		args := []string{"test", "-race", "-count=1", "-v"}
		if overlay != "" {
			args = append(args, "-overlay", overlay)
		}
		args = append(args, "-run", pattern, ".")
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "go", args...)
		cmd.Env = append(os.Environ(), "GOWORK=off", "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off")
		var output bytes.Buffer
		cmd.Stdout = &output
		cmd.Stderr = &output
		r := result{Name: name, Command: append([]string{"go"}, args...), SourceSHA256: hash(original)}
		if e := cmd.Start(); e != nil {
			return r, nil, e
		}
		r.PID = cmd.Process.Pid
		err := cmd.Wait()
		if err != nil {
			var x *exec.ExitError
			if !errors.As(err, &x) {
				return r, nil, err
			}
			r.Exit = x.ExitCode()
		}
		raw := output.Bytes()
		log := append([]byte(fmt.Sprintf("owned PID %d; exit %d\n", r.PID, r.Exit)), raw...)
		if e := os.WriteFile(filepath.Join(evidence, name+".log"), log, 0600); e != nil {
			return r, nil, e
		}
		if ctx.Err() != nil {
			return r, raw, ctx.Err()
		}
		return r, raw, nil
	}
	baseline, b, e := runTest("baseline", `^(TestDailyCeilingBoundary|TestDailyAccountingInitialization|TestResponsesPreHeaderClosure)$`, "")
	if e != nil {
		return e
	}
	if baseline.Exit != 0 || !bytes.Contains(b, []byte("--- PASS: TestDailyCeilingBoundary/230")) || !bytes.Contains(b, []byte("--- PASS: TestDailyCeilingBoundary/229")) || !bytes.Contains(b, []byte("--- PASS: TestDailyAccountingInitialization")) || !bytes.Contains(b, []byte("--- PASS: TestResponsesPreHeaderClosure/expired")) || !bytes.Contains(b, []byte("--- PASS: TestResponsesPreHeaderClosure/revoked")) {
		return fmt.Errorf("baseline did not pass named positive and negative controls: exit %d", baseline.Exit)
	}
	results := []result{baseline}
	for _, p := range plants {
		if strings.Count(string(original), p.Old) != 1 {
			return fmt.Errorf("%s overlay anchor is not unique", p.Name)
		}
		mutated := []byte(strings.Replace(string(original), p.Old, p.New, 1))
		replacement := filepath.Join(evidence, p.Name+".go")
		if e = os.WriteFile(replacement, mutated, 0600); e != nil {
			return e
		}
		overlay := filepath.Join(evidence, p.Name+".json")
		raw, _ := json.Marshal(map[string]any{"Replace": map[string]string{source: replacement}})
		if e = os.WriteFile(overlay, raw, 0600); e != nil {
			return e
		}
		r, b, e := runTest(p.Name, p.Test, overlay)
		if e != nil {
			return e
		}
		r.OverlaySHA256 = hash(mutated)
		r.Detected = r.Exit == 1 && bytes.Contains(b, []byte("--- FAIL: "+p.Failure)) && bytes.Contains(b, []byte(p.Witness)) && !bytes.Contains(b, []byte("[build failed]")) && !bytes.Contains(b, []byte("panic:")) && !bytes.Contains(b, []byte("WARNING: DATA RACE"))
		results = append(results, r)
		raw, _ = json.MarshalIndent(results, "", "  ")
		if e = os.WriteFile(filepath.Join(evidence, "results.json"), append(raw, '\n'), 0600); e != nil {
			return e
		}
		fmt.Printf("%s exit=%d detected=%t\n", p.Name, r.Exit, r.Detected)
		if !r.Detected {
			return fmt.Errorf("%s survived or failed outside its named assertion", p.Name)
		}
	}
	after, e := os.ReadFile(source)
	if e != nil {
		return e
	}
	if !bytes.Equal(original, after) {
		return errors.New("candidate source changed during overlay controls")
	}
	return nil
}
