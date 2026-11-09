package grantstore

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// A dedicated child exits without defers at each filesystem boundary. This
// models process interruption on a live filesystem, not power-loss hardware.
func TestProcessInterruption(t *testing.T) {
	for _, stage := range []string{"reserved", "blob_synced", "before_publish", "published", "before_delete", "deleted"} {
		t.Run(stage, func(t *testing.T) {
			l := newLab(t)
			data := []byte("crash")
			hash := Hash(data)
			method, path, action := "PUT", "/upload", "upload"
			if stage == "before_delete" || stage == "deleted" {
				l.put(string(data), l.reader.PubKeyHex())
				method, path, action = "DELETE", "/"+hash, "delete"
			}
			h := l.auth(l.writer, action, hash)
			if action == "upload" {
				h = l.auth(l.writer, action, hash, l.reader.PubKeyHex())
			}
			cfg := l.s.cfg
			l.s.Close()
			dir := t.TempDir()
			fixture := struct {
				Config                      Config
				Header, Stage, Method, Path string
			}{cfg, h, stage, method, path}
			raw, _ := json.Marshal(fixture)
			p := filepath.Join(dir, "fixture.json")
			if e := os.WriteFile(p, raw, 0600); e != nil {
				t.Fatal(e)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestCrashChild$")
			cmd.Env = append(os.Environ(), "GRANT_STORE_CRASH_FIXTURE="+p)
			var output bytes.Buffer
			cmd.Stdout, cmd.Stderr = &output, &output
			if e := cmd.Start(); e != nil {
				t.Fatal(e)
			}
			t.Logf("owned crash-child PID %d", cmd.Process.Pid)
			e := cmd.Wait()
			out := output.Bytes()
			if exit, ok := e.(*exec.ExitError); !ok || exit.ExitCode() != 73 {
				t.Fatalf("child did not reach boundary: %v %s", e, out)
			}
			l.reopen()
			s, _, _ := l.do(method, path, h, data)
			want := 401
			if stage == "deleted" {
				want = 403
			}
			if s != want {
				t.Fatalf("interrupted auth reused: %d", s)
			}
			exists := stage == "published" || stage == "before_delete"
			if exists {
				l.read(l.reader, hash, "crash")
			} else {
				s, _, _ = l.do("GET", "/"+hash, l.auth(l.reader, "get", hash), nil)
				if s != 403 {
					t.Fatal("interrupted object visible")
				}
			}
			if stage == "deleted" {
				l.put("crash", l.reader.PubKeyHex())
				s, _, _ = l.do(method, path, h, data)
				if s != 401 {
					t.Fatal("interrupted delete replay after recreation")
				}
				l.read(l.reader, hash, "crash")
			}
			valid := l.put("after-crash")
			l.read(l.writer, valid, "after-crash")
		})
	}
}
func TestCrashChild(t *testing.T) {
	p := os.Getenv("GRANT_STORE_CRASH_FIXTURE")
	if p == "" {
		t.Skip("invoked only by process-interruption parent")
	}
	b, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	var f struct {
		Config                      Config
		Header, Stage, Method, Path string
	}
	if e = json.Unmarshal(b, &f); e != nil {
		t.Fatal(e)
	}
	s, e := Open(f.Config)
	if e != nil {
		t.Fatal(e)
	}
	s.now = func() time.Time { return time.Unix(500, 0) }
	s.hook = func(stage string) error {
		if stage == f.Stage {
			os.Exit(73)
		}
		return nil
	}
	r := httptest.NewRequest(f.Method, f.Path, bytes.NewReader([]byte("crash")))
	r.Header.Set("Authorization", f.Header)
	s.ServeHTTP(httptest.NewRecorder(), r)
	t.Fatal("boundary not reached")
}
