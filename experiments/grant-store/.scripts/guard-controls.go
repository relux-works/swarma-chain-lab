// Run from the grant-store module: go run .scripts/guard-controls.go -out .temp/guards
// Each mutation lives in a fresh private copy. Dependencies are read-only symlink
// targets; no product source, shared runtime, wallet or live store is modified.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/relux-works/swarma-chain-lab/deploy/workspace"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type plant struct{ Name, File, Old, New, Test, Witness string }

var plants = []plant{
	{"authorization_order", "http.go", "\tif !s.authorized(a, action, hash, r.URL.Path) {\n\t\tdeny(w, r, 403)\n\t\treturn\n\t}\n\tif status, e := s.reserve(a, now); e != nil {\n\t\tdeny(w, r, status)\n\t\treturn\n\t}\n", "\tif status, e := s.reserve(a, now); e != nil {\n\t\tdeny(w, r, status)\n\t\treturn\n\t}\n\tif !s.authorized(a, action, hash, r.URL.Path) {\n\t\tdeny(w, r, 403)\n\t\treturn\n\t}\n", "TestUnauthorizedDoesNotReserve/get", "unauthorized request changed replay journal"},
	{"own_empty_list", "http.go", "\t\treturn false\n\tcase \"get\", \"delete\":", "\t\treturn true\n\tcase \"get\", \"delete\":", "TestUnauthorizedDoesNotReserve/own_empty_list", "unauthorized refusal=200 want403"},
	{"per_key_quota", "store.go", "if keySlots >= s.cfg.MaxReplayPerKey {", "if keySlots >= s.cfg.MaxReplayPerKey && false {", "TestPerKeyQuota", "per-key cap status=200 want429"},
	{"per_key_accounting", "store.go", "if v.PubKey == a.Event.PubKey {", "if v.PubKey == a.Event.PubKey && false {", "TestPerKeyQuota", "per-key cap status=200 want429"},
	{"persisted_signer", "store.go", "PubKey: a.Event.PubKey", "PubKey: \"\"", "TestPerKeyQuota", "per-key cap status=200 want429"},
	{"legacy_ids", "replay.go", "legacy.Version = 2", "legacy.Entries = []replayEntry{}\n\tlegacy.Version = 2", "TestLegacyReplayMigration", "legacy consumed ID reset"},
	{"crypto_admission", "auth.go", "!ev.CheckID() || nostr.VerifySignature(ev) != nil || ", "", "TestUploadControls/bad_id", "rejection status=201 want=401"},
	{"signature", "auth.go", "nostr.VerifySignature(ev) != nil || ", "", "TestUploadControls/bad_sig", "rejection status=201 want=401"},
	{"writer_allowlist", "http.go", "allowed = allowed || writer == a.Event.PubKey", "allowed = allowed || writer != \"\"", "TestUploadControls/nonwriter", "rejection status=201 want=403"},
	{"body_hash", "auth.go", "(hash != \"\" && !matchedHash)", "(hash != \"\" && !matchedHash && false)", "TestUploadControls/wrong_hash", "rejection status=201 want=401"},
	{"expiry", "auth.go", "exp <= now || ", "", "TestUploadControls/expired", "rejection status=201 want=401"},
	{"future_skew", "auth.go", "ev.CreatedAt > now+skew", "ev.CreatedAt > now+skew+1000", "TestUploadControls/future", "rejection status=201 want=401"},
	{"action", "auth.go", "tag[1] != action || counts[\"t\"] != 1", "counts[\"t\"] != 1", "TestUploadControls/wrong_action", "rejection status=201 want=401"},
	{"kind", "auth.go", "ev.Kind != KindAuth || ", "", "TestUploadControls/wrong_kind", "rejection status=201 want=401"},
	{"reader_acl", "http.go", "allowed = allowed || reader == a.Event.PubKey", "allowed = allowed || reader != \"\"", "TestReadersAndPrivateExistence", "private GET status=200"},
	{"delete_owner", "http.go", "allowed = m.Owner == a.Event.PubKey", "allowed = true", "TestReadersAndPrivateExistence", "non-owner delete=204"},
	{"list_owner", "http.go", "owner != a.Event.PubKey || !key(owner)", "!key(owner)", "TestReadersAndPrivateExistence", "non-owner list=200"},
	{"reader_tags", "store.go", "m[p] = true", "delete(m, p)", "TestReadersAndPrivateExistence", "valid GET failed"},
	{"putter_reader", "store.go", "m := map[string]bool{a.Event.PubKey: true}", "m := map[string]bool{}", "TestReadersAndPrivateExistence", "valid GET failed"},
	{"single_use", "store.go", "if v.ID == a.Event.ID {", "if v.ID == a.Event.ID && false {", "TestReplayAndRestart", "upload replay accepted"},
	{"restart_journal", "store.go", "if e = s.load(); e != nil {", "defer func() { s.replay.Entries = []replayEntry{} }()\n\tif e = s.load(); e != nil {", "TestReplayAndRestart", "GET replay accepted after restart"},
	{"durable_reservation", "store.go", "if e := s.journal.Write(\"replay.json\", b); e != nil {", "_ = b\n\tif e := error(nil); e != nil {", "TestStorageFailureBoundaries/reserved", "reserved event reused"},
	{"immutable_owner", "store.go", "old.Owner != a.Event.PubKey || ", "", "TestConcurrentPutsAndOwnership", "ownership/ACL mutation=200"},
	{"immutable_acl", "store.go", "strings.Join(old.Readers, \",\") != strings.Join(readers, \",\")", "false", "TestConcurrentPutsAndOwnership", "ownership/ACL mutation=200"},
	{"blob_count", "store.go", "len(s.blobs) >= s.cfg.MaxBlobs || s.total+int64(len(data))", "false || s.total+int64(len(data))", "TestCapsAndClock/count", "capacity did not reject without effects"},
	{"total_bytes", "store.go", "s.total+int64(len(data)) > s.cfg.MaxTotalBytes", "false", "TestCapsAndClock/bytes", "capacity did not reject without effects"},
	{"replay_cap", "store.go", "len(next.Entries) >= s.cfg.MaxReplay", "len(next.Entries) >= s.cfg.MaxReplay+100", "TestCapsAndClock/replay", "capacity did not reject without effects"},
	{"clock_highwater", "store.go", "now < s.replay.LastTime", "now < s.replay.LastTime && false", "TestCapsAndClock/clock_rollback", "clock rollback accepted"},
	{"client_hash", "client.go", "status != 200 || Hash(raw) != hash", "status != 200", "TestClientHostileResponses/hash", "hostile response accepted"},
	{"client_redirect", "client.go", "return http.ErrUseLastResponse", "return nil", "TestClientHostileResponses/redirect", "hostile response accepted"},
}

type result struct {
	Name     string `json:"name"`
	Test     string `json:"test"`
	Exit     int    `json:"exit"`
	Detected bool   `json:"detected"`
	Witness  string `json:"witness"`
}

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	out := flag.String("out", ".temp/guards", "evidence directory")
	flag.Parse()
	root, e := os.Getwd()
	if e != nil {
		return e
	}
	if b, e := os.ReadFile(filepath.Join(root, "go.mod")); e != nil || !bytes.HasPrefix(b, []byte("module github.com/relux-works/swarma-chain-lab/experiments/grant-store\n")) {
		return errors.New("run from grant-store module")
	}
	if e = os.MkdirAll(*out, 0700); e != nil {
		return e
	}
	evidence, e := filepath.Abs(*out)
	if e != nil {
		return e
	}
	runDir, e := os.MkdirTemp(evidence, "run-")
	if e != nil {
		return e
	}
	fmt.Println("evidence:", runDir)
	work, e := os.MkdirTemp(filepath.Join(root, ".temp"), "guard-work-")
	if e != nil {
		return e
	}
	defer os.RemoveAll(work)
	for _, name := range []string{"rental-gateway", "rental", "single-use", "sealwatch", "payment-chain", "rental-booking"} {
		if e = os.Symlink(filepath.Join(filepath.Dir(root), name), filepath.Join(work, name)); e != nil {
			return e
		}
	}
	module := filepath.Join(work, "grant-store")
	if e = copyModule(root, module); e != nil {
		return e
	}
	fixtureWork, e := workspace.Isolate(root, work)
	if e != nil {
		return e
	}
	runTest := func(name, test string) (int, []byte, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "go", "test", "-count=1", "-v", "-run", "^"+strings.ReplaceAll(test, "/", "$/^")+"$", ".")
		cmd.Dir = module
		cmd.Env = append(os.Environ(), "GOWORK="+fixtureWork, "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local")
		var output bytes.Buffer
		cmd.Stdout, cmd.Stderr = &output, &output
		if e := cmd.Start(); e != nil {
			return -1, nil, e
		}
		pid := cmd.Process.Pid
		e := cmd.Wait()
		b := append([]byte(fmt.Sprintf("owned test-command PID %d\n", pid)), output.Bytes()...)
		code := 0
		if e != nil {
			var exit *exec.ExitError
			if !errors.As(e, &exit) {
				return -1, b, e
			}
			code = exit.ExitCode()
		}
		if ctx.Err() != nil {
			return code, b, ctx.Err()
		}
		if e = os.WriteFile(filepath.Join(runDir, name+".log"), b, 0600); e != nil {
			return code, b, e
		}
		return code, b, nil
	}
	code, _, e := runTest("baseline", "Test.*")
	if e != nil || code != 0 {
		return fmt.Errorf("baseline exit %d: %v", code, e)
	}
	results := []result{}
	for _, p := range plants {
		file := filepath.Join(module, p.File)
		original, e := os.ReadFile(file)
		if e != nil {
			return e
		}
		if n := strings.Count(string(original), p.Old); n != 1 {
			return fmt.Errorf("plant %s applies %d times", p.Name, n)
		}
		if e = os.WriteFile(file, []byte(strings.Replace(string(original), p.Old, p.New, 1)), 0600); e != nil {
			return e
		}
		code, b, runErr := runTest(p.Name, p.Test)
		restoreErr := os.WriteFile(file, original, 0600)
		if runErr != nil {
			return runErr
		}
		if restoreErr != nil {
			return restoreErr
		}
		detected := code == 1 && bytes.Contains(b, []byte("--- FAIL: "+p.Test)) && bytes.Contains(b, []byte(p.Witness)) && !bytes.Contains(b, []byte("[build failed]")) && !bytes.Contains(b, []byte("panic:"))
		results = append(results, result{p.Name, p.Test, code, detected, p.Witness})
		raw, _ := json.MarshalIndent(results, "", "  ")
		if e = os.WriteFile(filepath.Join(runDir, "results.json"), append(raw, '\n'), 0600); e != nil {
			return e
		}
		fmt.Printf("%s exit=%d detected=%v\n", p.Name, code, detected)
		if !detected {
			return fmt.Errorf("plant %s did not reach intended assertion", p.Name)
		}
	}
	fmt.Printf("%d/%d intended guard failures\n", len(results), len(plants))
	return nil
}
func copyModule(src, dst string) error {
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
		if d.Type()&os.ModeSymlink != 0 {
			return errors.New("unexpected module symlink")
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0600)
	})
}
