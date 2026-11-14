package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

var fundedTraceCall = regexp.MustCompile(`^\s*[0-9]+\s+([a-zA-Z0-9_]+)\((.*)`)
var fundedTraceString = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)

// Only loader/Go runtime bootstrap inputs are exempted. This is intentionally
// not an allowlist of /etc, /proc, arbitrary libraries, or fixture directories.
func fundedRuntimeInput(path string) bool {
	switch path {
	case "/etc/ld.so.preload", "/etc/ld.so.cache", "/proc/self/maps", "/proc/self/cgroup", "/proc/self/mountinfo",
		"/sys/kernel/mm/transparent_hugepage/hpage_pmd_size", "/sys/kernel/mm/transparent_hugepage/enabled":
		return true
	}
	if strings.HasPrefix(path, "/sys/fs/cgroup/") {
		switch filepath.Base(path) {
		case "cpu.max", "cpu.cfs_quota_us", "cpu.cfs_period_us", "memory.max", "memory.limit_in_bytes":
			return true
		}
	}
	// Both merged-/usr and older Ubuntu loader paths, on the supported
	// Linux architectures. Do not admit arbitrary files under library roots.
	for _, root := range []string{"/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/"} {
		for _, arch := range []string{"", "x86_64-linux-gnu/", "aarch64-linux-gnu/"} {
			for _, base := range []string{"libc.so.6", "ld-linux-x86-64.so.2", "ld-linux-aarch64.so.1"} {
				if path == root+arch+base {
					return true
				}
			}
		}
	}
	return false
}

// Trace attempts, including unsuccessful ones. No network syscall, extra
// application pathname, child exec, writable open or non-output write is valid.
func fundedTraceViolations(trace, binary, params string) []string {
	var violations []string
	execs, reads := 0, 0
	for _, line := range strings.Split(trace, "\n") {
		m := fundedTraceCall.FindStringSubmatch(line)
		if m == nil {
			if strings.TrimSpace(line) != "" && !strings.Contains(line, "--- SIG") && !strings.Contains(line, "+++ exited") {
				violations = append(violations, "unclassified trace: "+line)
			}
			continue
		}
		call, args := m[1], m[2]
		path, _ := strconv.Unquote(fundedTraceString.FindString(args))
		switch call {
		case "execve":
			execs++
			if execs != 1 || path != binary {
				violations = append(violations, "extra exec: "+line)
			}
		case "open", "openat", "openat2":
			if strings.Contains(args, "O_WRONLY") || strings.Contains(args, "O_RDWR") || strings.Contains(args, "O_CREAT") || strings.Contains(args, "O_TRUNC") || strings.Contains(args, "O_APPEND") || strings.Contains(args, "O_TMPFILE") {
				violations = append(violations, "file write: "+line)
			} else if path == params {
				reads++
			} else if !fundedRuntimeInput(path) {
				violations = append(violations, "extra input: "+line)
			}
		case "access", "stat", "statx", "lstat", "newfstatat", "readlink", "readlinkat":
			// glibc may stat an already-open loader descriptor using an
			// empty pathname. All pathname opens are observed above.
			fdStat := call == "newfstatat" && path == "" && strings.Contains(args, "AT_EMPTY_PATH") && !strings.HasPrefix(args, "AT_FDCWD,")
			if !fdStat && path != params && !fundedRuntimeInput(path) {
				violations = append(violations, "extra pathname: "+line)
			}
		case "write", "writev", "pwrite64", "pwritev", "pwritev2":
			fd := strings.TrimSpace(strings.SplitN(args, ",", 2)[0])
			if (call != "write" && call != "writev") || (fd != "1" && fd != "2") {
				violations = append(violations, "non-output write: "+line)
			}
		default:
			violations = append(violations, "forbidden syscall: "+line)
		}
	}
	if execs != 1 || reads != 1 {
		violations = append(violations, fmt.Sprintf("observer incomplete: execs=%d parameter opens=%d", execs, reads))
	}
	return violations
}

// Claim: the observer admits a minimal valid trace and rejects each forbidden
// effect, including failed attempts. These fixtures pin the observer itself;
// actual executable scratch mutations separately establish end-to-end controls.
func TestG2FundedPreflightTraceObserver(t *testing.T) {
	const valid = "1 execve(\"/binary\", [], 0) = 0\n1 openat(AT_FDCWD, \"/params\", O_RDONLY) = 3\n1 write(1, \"ok\\n\", 3) = 3\n"
	if got := fundedTraceViolations(valid, "/binary", "/params"); len(got) != 0 {
		t.Fatal("valid trace", got)
	}
	for _, effect := range []string{
		`1 openat(AT_FDCWD, "/params", O_WRONLY|O_TRUNC) = 3`,
		`1 openat(AT_FDCWD, "/extra", O_RDONLY) = -1 ENOENT`,
		`1 socket(AF_INET, SOCK_STREAM, 0) = 3`,
		`1 connect(3, {sa_family=AF_INET}, 16) = -1 ECONNREFUSED`,
		`1 unlink("/extra") = -1 ENOENT`,
		`1 write(3, "bad", 3) = 3`,
		`1 execve("/child", [], 0) = 0`,
	} {
		if got := fundedTraceViolations(valid+effect, "/binary", "/params"); len(got) == 0 {
			t.Fatalf("observer missed %s", effect)
		}
	}
	if got := fundedTraceViolations("", "/binary", "/params"); len(got) == 0 {
		t.Fatal("empty trace admitted")
	}
}

// Claim: the built public main succeeds only for valid parameters; funded,
// parser and omission refusals exit 1 with empty stdout and named/redacted
// stderr. On every path strace observes only the supplied application input,
// stdout/stderr writes, and no network or file mutation. This Linux observer
// requires strace; other platforms skip explicitly, not as passing evidence.
func TestG2FundedPreflightPublicEntry(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux syscall observer; run this contract on Linux with strace")
	}
	strace, err := exec.LookPath("strace")
	if err != nil {
		t.Fatal("Linux public-entry contract requires strace: ", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	dir := t.TempDir()
	binary := filepath.Join(dir, "deploy-kit")
	build := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", binary, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build public main: %v\n%s", err, out)
	}
	p := fundedParams()
	good, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	rehearsal, err := json.Marshal(cliParams())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		raw  []byte
		code int
		want string
	}{
		{"valid", good, 0, ""},
		{"funded-refusal", rehearsal, 1, "SMALL_SCALAR_KEY grantee"},
		{"parser-refusal", bytes.Replace(good, []byte(p.G2.Canary.Outpoint.TxID), []byte("PLACEHOLDER_CANARY"), 1), 1, "g2.canary.outpoint.txid"},
		{"missing-false-member", omitG2Member(t, good, []string{"g2", "allow_single_use"}), 1, "g2.allow_single_use"},
		{"zero-grantee", bytes.Replace(good, []byte(p.Grantee), []byte(strings.Repeat("0", 64)), 1), 1, "grantee"},
		{"empty-receipt", bytes.Replace(good, []byte(p.ReceiptPubkey), nil, 1), 1, "receipt_pubkey"},
		{"change-me-canary", bytes.Replace(good, []byte(p.G2.Canary.Outpoint.TxID), []byte("CHANGE_ME"), 1), 1, "g2.canary.outpoint.txid"},
		{"token-canary", bytes.Replace(good, []byte(p.G2.Canary.Outpoint.TxID), []byte("@TXID@"), 1), 1, "g2.canary.outpoint.txid"},
		{"short-canary", bytes.Replace(good, []byte(p.G2.Canary.Outpoint.TxID), []byte(strings.Repeat("1", 63)), 1), 1, "g2.canary.outpoint.txid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := t.TempDir()
			params, trace := filepath.Join(fixture, "params.json"), filepath.Join(fixture, "trace.log")
			if err := os.WriteFile(params, tc.raw, 0600); err != nil {
				t.Fatal(err)
			}
			// The extra-input plant reads this synthetic file when injected. The
			// public command has no reason to open it, even if it exists nearby.
			extra := filepath.Join(fixture, "unprovided.txt")
			if err := os.WriteFile(extra, []byte("synthetic unprovided input"), 0600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.CommandContext(ctx, strace, "-f", "-qq", "-s", "4096", "-o", trace, "-e", "trace=%file,%network,write,writev,pwrite64,pwritev,pwritev2,fchmod,fchown,ftruncate,fallocate,copy_file_range,sendfile,splice,vmsplice,fsetxattr,fremovexattr", binary, "g2-funded-preflight", "-params", params)
			cmd.Dir = fixture
			cmd.Env = append(os.Environ(), "G2_PREFLIGHT_EXTRA_INPUT="+extra)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			code := 0
			if err != nil {
				var exit *exec.ExitError
				if !errors.As(err, &exit) {
					t.Fatal(err)
				}
				code = exit.ExitCode()
			}
			if code != tc.code {
				t.Errorf("public exit=%d want=%d stderr=%q", code, tc.code, stderr.String())
			}
			if tc.code == 0 {
				if stdout.String() != "G2_FUNDED_PREFLIGHT_OK\n" || stderr.Len() != 0 {
					t.Errorf("valid output: stdout=%q stderr=%q", stdout.String(), stderr.String())
				}
			} else if stdout.Len() != 0 || !strings.Contains(stderr.String(), tc.want) {
				t.Errorf("refusal output: stdout=%q stderr=%q want field %q", stdout.String(), stderr.String(), tc.want)
			}
			for _, value := range []string{p.Grantee, p.ReceiptPubkey, "PLACEHOLDER_CANARY"} {
				if strings.Contains(stdout.String()+stderr.String(), value) {
					t.Error("output echoed supplied value")
				}
			}
			after, err := os.ReadFile(params)
			if err != nil || !bytes.Equal(after, tc.raw) {
				t.Errorf("parameters changed: %v", err)
			}
			observed, err := os.ReadFile(trace)
			if err != nil {
				t.Fatal(err)
			}
			for _, violation := range fundedTraceViolations(string(observed), binary, params) {
				t.Error(violation)
			}
		})
	}
}
