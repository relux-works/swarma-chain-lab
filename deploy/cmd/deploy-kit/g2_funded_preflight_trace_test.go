package main

import (
	"regexp"
	"sort"
	"strings"
	"testing"
)

var fundedTracePID = regexp.MustCompile(`^\s*([0-9]+)\s+(.*)$`)
var fundedTraceResume = regexp.MustCompile(`^<\.\.\. ([a-zA-Z0-9_]+) resumed>(.*)$`)

// syscall_exiting_trace(), print_err_ret() and print_erestart() print the
// return token after the argument list: numeric, errno with optional text,
// or ? with optional restart text / <unavailable>. Validate that entire tail
// only AFTER finding the call's own close, never a suffix inside arguments.
// https://github.com/strace/strace/blob/v6.19/src/syscall.c#L779-L1021
// https://github.com/strace/strace/blob/v6.19/src/syscall.c#L432-L451
// https://github.com/strace/strace/blob/v6.19/src/print_fields.h#L309-L341
// Our flags enable neither -y descriptor decorations nor -T <time> suffixes;
// both remain unsupported and fail closed. No result annotations are stripped.
var fundedTraceResult = regexp.MustCompile(`^[ \t]+=[ \t]+(?:(?:0x[0-9a-fA-F]+|-?[0-9]+)(?: [A-Z][A-Z0-9_]*)?(?: \([^()\r\n]*\))?|\?(?: [A-Z][A-Z0-9_]*(?: \([^()\r\n]*\))?| <unavailable>)?)[ \t]*$`)
var fundedTraceEvent = regexp.MustCompile(`^(?:--- SIG(?:[A-Z0-9]+|RT_[0-9]+)(?: \{.*\})? ---|\+\+\+ exited with [0-9]+ \+\+\+|\+\+\+ killed by SIG(?:[A-Z0-9]+|RT_[0-9]+)(?: \(core dumped\))? \+\+\+)$`)

// string_quote() escapes quotes/backslashes, control characters, hex and octal
// bytes. printstr_ex() emits the abbreviation marker AFTER the closing quote:
// https://github.com/strace/strace/blob/v6.19/src/util.c#L1126-L1269
// https://github.com/strace/strace/blob/v6.19/src/util.c#L1479-L1489
// Scan the joined record from the actual opening parenthesis. A stack keeps
// structured arguments' {} [] () separate from the outer call boundary.
func fundedTraceComplete(line string) bool {
	call := fundedTraceCall.FindStringSubmatchIndex(line)
	if call == nil {
		return false
	}
	stack := []byte{')'}
	quoted := false
	for i := call[4]; i < len(line); i++ {
		c := line[i]
		if quoted {
			switch c {
			case '\\':
				i++
				if i == len(line) {
					return false
				}
				c = line[i]
				switch {
				case strings.ContainsRune(`"\fnrtv`, rune(c)):
				case c == 'x':
					for n := 0; n < 2; n++ {
						i++
						if i == len(line) || !strings.ContainsRune("0123456789abcdefABCDEF", rune(line[i])) {
							return false
						}
					}
				case c >= '0' && c <= '7':
					for n := 1; n < 3 && i+1 < len(line) && line[i+1] >= '0' && line[i+1] <= '7'; n++ {
						i++
					}
				default:
					return false
				}
			case '"':
				quoted = false
			case '\n', '\r':
				return false
			}
			continue
		}
		switch c {
		case '"':
			quoted = true
		case '(':
			stack = append(stack, ')')
		case '[':
			stack = append(stack, ']')
		case '{':
			stack = append(stack, '}')
		case ')', ']', '}':
			if c != stack[len(stack)-1] {
				return false
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				return fundedTraceResult.MatchString(line[i+1:])
			}
		}
	}
	return false
}

// strace(1), DESCRIPTION, documents per-thread unfinished/resumed pairs:
// https://man7.org/linux/man-pages/man1/strace.1.html
// strace v6.1 src/strace.c printleader() and droptcb() emit the unfinished
// and detached suffixes; src/syscall.c print_syscall_resume() names the call:
// https://github.com/strace/strace/blob/v6.1/src/strace.c
// https://github.com/strace/strace/blob/v6.1/src/syscall.c
// stub_sysent in v5.16 spells the empty unknown name "????"; v6.1 and v6.19
// use "???". Only the empty detached stub is an event, never call arguments:
// https://github.com/strace/strace/blob/v5.16/src/syscall.c
// https://github.com/strace/strace/blob/v6.19/src/syscall.c
// signame() emits SIGRT_<number> for realtime signals in both event forms:
// https://github.com/strace/strace/blob/v6.1/src/signal.c
// https://github.com/strace/strace/blob/v6.19/src/signal.c
// Normalize only these -f -o forms. Never discard a line merely because it
// contains '<': its arguments may describe a forbidden attempt. Unpaired or
// mismatched fragments fail closed, including when a thread exits mid-call.
func fundedTraceLines(trace string) (lines, violations []string) {
	pending := make(map[string]string)
	for _, line := range strings.Split(trace, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		pidLine := fundedTracePID.FindStringSubmatch(line)
		if pidLine == nil {
			violations = append(violations, "unclassified trace: "+line)
			continue
		}
		pid, body := pidLine[1], pidLine[2]
		// The empty unknown-name prefix plus the exact detached suffix is
		// a teardown event, not an unknown real call with arguments/result.
		if stub := strings.TrimSpace(body); stub == "???( <detached ...>" || stub == "????( <detached ...>" || fundedTraceEvent.MatchString(body) {
			continue
		}
		if resumed := fundedTraceResume.FindStringSubmatch(body); resumed != nil {
			start, ok := pending[pid]
			call := fundedTraceCall.FindStringSubmatch(start)
			if !ok || call == nil || call[1] != resumed[1] {
				violations = append(violations, "unmatched resume: "+line)
				continue
			}
			// A resume tag alone is not completion. Retain the pending entry
			// and never send partial arguments to the effect classifier.
			if !fundedTraceComplete(start + resumed[2]) {
				violations = append(violations, "incomplete resume: "+line)
				continue
			}
			line = start + resumed[2]
			delete(pending, pid)
		} else if _, ok := pending[pid]; ok && fundedTraceCall.MatchString(line) {
			violations = append(violations, "overlapping syscall: "+line)
		}
		if start, unfinished := strings.CutSuffix(line, " <unfinished ...>"); unfinished {
			if fundedTraceCall.MatchString(start) {
				pending[pid] = start
			} else {
				violations = append(violations, "unclassified trace: "+line)
			}
			continue
		}
		if fundedTraceCall.MatchString(line) && !fundedTraceComplete(line) {
			// An unsplit EOF is just as incomplete as a resumed EOF. Keep
			// it pending; preserve existing effect diagnostics below, but
			// it can never produce a violation-free observer verdict.
			violations = append(violations, "incomplete syscall: "+line)
			if _, ok := pending[pid]; !ok {
				pending[pid] = line
			}
		}
		lines = append(lines, line)
	}
	// Stable diagnostics even with multiple threads left unfinished.
	pids := make([]string, 0, len(pending))
	for pid := range pending {
		pids = append(pids, pid)
	}
	sort.Strings(pids)
	for _, pid := range pids {
		violations = append(violations, "unfinished syscall: "+pending[pid])
	}
	return lines, violations
}

// Claim: only documented events are ignored; complete and reassembled calls retain the original effect restrictions.
func TestG2FundedPreflightTraceFragments(t *testing.T) {
	const prefix = "1 execve(\"/binary\", [], 0) = 0\n"
	const input = "1 openat(AT_FDCWD, \"/params\", O_RDONLY) = 3\n"
	cases := []struct {
		name, trace, want string
	}{
		// Claim: Ordinary input and stdout calls remain allowed.
		{"normal", input + `1 write(1, "ok", 2) = 2`, ""},
		// Claim: The v5.16 empty unknown-name teardown stub is allowed.
		{"detached-unknown", input + `12794 ????( <detached ...>`, ""},
		// Claim: Both cited v6 versions' exact empty teardown stub is allowed.
		{"detached-v6-1", input + `12794 ???( <detached ...>`, ""},
		{"detached-v6-19", input + `12794 ???( <detached ...>`, ""},
		// Claim: A process exit record is an event, not a syscall.
		{"exited", input + `1 +++ exited with 1 +++`, ""},
		// Claim: A signal termination record is an event, not a syscall.
		{"killed", input + `2 +++ killed by SIGKILL +++`, ""},
		// Claim: A standalone signal delivery record is allowed.
		{"signal", input + `2 --- SIGURG {si_signo=SIGURG, si_code=SI_TKILL} ---`, ""},
		// Claim: Reassembly preserves the one permitted parameter read across another thread.
		{"split-allowed", "1 openat(AT_FDCWD, \"/params\", <unfinished ...>\n2 write(2, \"notice\", 6) = 6\n1 <... openat resumed>O_RDONLY) = 3", ""},
		// Claim: Write flags in the resumed fragment still reject a parameter write.
		{"split-write", input + "2 openat(AT_FDCWD, \"/params\", <unfinished ...>\n2 <... openat resumed>O_WRONLY|O_TRUNC) = 3", "file write:"},
		// Claim: An extra pathname in the resumed fragment is still rejected.
		{"split-extra-input", input + "2 openat(AT_FDCWD, <unfinished ...>\n2 <... openat resumed>\"/extra\", O_RDONLY) = -1 ENOENT", "extra input:"},
		// Claim: A split network connection attempt is still forbidden.
		{"split-connect", input + "2 connect(3, <unfinished ...>\n2 <... connect resumed>{sa_family=AF_INET}, 16) = -1 ECONNREFUSED", "forbidden syscall:"},
		// Claim: Same-name calls in different threads keep their own flags.
		{"interleaved", "1 openat(AT_FDCWD, \"/params\", <unfinished ...>\n2 openat(AT_FDCWD, \"/params\", <unfinished ...>\n2 <... openat resumed>O_WRONLY) = 3\n1 <... openat resumed>O_RDONLY) = 3", "file write:"},
		// Claim: An unknown-name real call is still rejected.
		{"unknown-real", input + `2 ????(3, 0, 0) = -1 ENOSYS`, "unclassified trace:"},
		// Claim: An unrecognized syscall name is still forbidden.
		{"unknown-named-real", input + `2 syscall_0xffff(3, 0, 0) = -1 ENOSYS`, "forbidden syscall:"},
		// Claim: An ordinary network connection attempt is still forbidden.
		{"normal-forbidden", input + `2 connect(3, {sa_family=AF_INET}, 16) = 0`, "forbidden syscall:"},
		// Claim: A detached marker inside an argument cannot hide a call.
		{"marker-in-argument", input + `2 connect(3, "<detached ...>", 16) = 0`, "forbidden syscall:"},
		// Claim: Exit text inside an unknown real call cannot hide it.
		{"exit-in-argument", input + `2 ????("+++ exited with 0 +++") = 0`, "unclassified trace:"},
		// Claim: Signal text inside an unknown real call cannot hide it.
		{"signal-in-argument", input + `2 ????("--- SIGURG ---") = 0`, "unclassified trace:"},
		// Claim: A detached suffix cannot hide an identified forbidden call.
		{"detached-real", input + `2 connect(3, {sa_family=AF_INET}, 16 <detached ...>`, "forbidden syscall:"},
		// Claim: A detached suffix cannot hide unknown call arguments.
		{"unknown-detached-arguments", input + `2 ????(3, 0 <detached ...>`, "unclassified trace:"},
		{"unknown-three-detached-arguments", input + `2 ???(3, 0 <detached ...>`, "unclassified trace:"},
		// Claim: Uncited unknown-name lengths remain unclassified.
		{"unknown-two-detached", input + `2 ??( <detached ...>`, "unclassified trace:"},
		{"unknown-five-detached", input + `2 ?????( <detached ...>`, "unclassified trace:"},
		// Claim: Realtime termination is allowed, but event substrings cannot hide calls.
		{"killed-realtime", input + `2 +++ killed by SIGRT_2 +++`, ""},
		{"killed-realtime-core", input + `2 +++ killed by SIGRT_2 (core dumped) +++`, ""},
		{"realtime-prefix-injection", input + `2 --- SIGRT_2 --- connect(3, NULL, 0) = 0`, "unclassified trace:"},
		{"realtime-suffix-injection", input + `2 connect(3, NULL, 0) = 0 --- SIGRT_2 ---`, "forbidden syscall:"},
		{"realtime-killed-injection", input + `2 +++ killed by SIGRT_2 +++ connect(3, NULL, 0) = 0`, "unclassified trace:"},
		{"realtime-in-argument", input + `2 ????("--- SIGRT_2 ---") = 0`, "unclassified trace:"},
		{"realtime-missing-number", input + `2 --- SIGRT_ ---`, "unclassified trace:"},
		{"realtime-nonnumeric", input + `2 +++ killed by SIGRT_bad +++`, "unclassified trace:"},
		// Claim: A resumed fragment without an entry fails closed.
		{"orphan-resume", input + `2 <... openat resumed>O_RDONLY) = 3`, "unmatched resume:"},
		// Claim: Fragments from different threads cannot pair.
		{"wrong-thread", input + "2 openat(AT_FDCWD, \"/extra\", <unfinished ...>\n3 <... openat resumed>O_RDONLY) = 3", "unmatched resume:"},
		// Claim: Fragments with different syscall names cannot pair.
		{"wrong-call", input + "2 openat(AT_FDCWD, \"/extra\", <unfinished ...>\n2 <... connect resumed>O_RDONLY) = 3", "unmatched resume:"},
		// Claim: A truncated trace fails closed.
		{"unfinished-at-eof", input + `2 openat(AT_FDCWD, "/extra", <unfinished ...>`, "unfinished syscall:"},
		// Claim: A process exit cannot erase an unobserved call remainder.
		{"unfinished-at-exit", input + "2 openat(AT_FDCWD, \"/extra\", <unfinished ...>\n2 +++ exited with 0 +++", "unfinished syscall:"},
		// Claim: A second entry cannot silently replace a pending call.
		{"duplicate-start", input + "2 openat(AT_FDCWD, \"/extra\", <unfinished ...>\n2 openat(AT_FDCWD, \"/params\", <unfinished ...>\n2 <... openat resumed>O_RDONLY) = 3", "overlapping syscall:"},
		// Claim: A teardown event cannot satisfy the required parameter read.
		{"missing-input", `12794 ????( <detached ...>`, "observer incomplete:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := fundedTraceViolations(prefix+tc.trace, "/binary", "/params")
			if tc.want == "" {
				if len(got) != 0 {
					t.Fatalf("valid trace rejected: %v", got)
				}
			} else if !strings.Contains(strings.Join(got, "\n"), tc.want) {
				t.Fatalf("want %q violation, got %v", tc.want, got)
			}
		})
	}
}

// Claim: EOF after a resume tag cannot satisfy the required read or clear its
// pending entry. Complete reads and writes still reach the effect classifier.
func TestG2FundedPreflightTraceResumeCompletion(t *testing.T) {
	const start = "1 execve(\"/binary\", [], 0) = 0\n1 openat(AT_FDCWD, \"/params\", <unfinished ...>\n1 <... openat resumed>"
	cases := []struct{ name, tail, want string }{
		{"completed-read", "O_RDONLY) = 3", ""},
		{"completed-write", "O_WRONLY|O_TRUNC) = 3", "file write:"},
		{"completed-error", "O_RDONLY) = -1 ENOENT (No such file or directory)", ""},
		{"completed-restart", "O_RDONLY) = ? ERESTARTSYS (To be restarted if SA_RESTART is set)", ""},
		{"completed-hex", "O_RDONLY) = 0x3", ""},
		{"empty-resume-at-eof", "", "incomplete resume:"},
		{"partial-write-flag-at-eof", "O_W", "incomplete resume:"},
		{"missing-result-at-eof", "O_RDONLY)", "incomplete resume:"},
		{"empty-result-at-eof", "O_RDONLY) = ", "incomplete resume:"},
		{"partial-errno-at-eof", "O_RDONLY) = -1 ENOENT (No such file", "incomplete resume:"},
		{"result-suffix-injection", "O_RDONLY) = 3 extra", "incomplete resume:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			trace := start + tc.tail
			got := strings.Join(fundedTraceViolations(trace, "/binary", "/params"), "\n")
			if tc.want == "" {
				if got != "" {
					t.Fatal(got)
				}
			} else if !strings.Contains(got, tc.want) {
				t.Fatalf("want %q, got %s", tc.want, got)
			}
			if tc.want == "incomplete resume:" {
				if !strings.Contains(got, "unfinished syscall:") || !strings.Contains(got, "parameter opens=0") {
					t.Fatalf("partial call cleared pending state or counted as input: %s", got)
				}
			}
		})
	}
}

// Claim: both real strace 6.19 handled-signal captures are accepted. Only the
// captured executable/input path prefix is replaced with a public fixture path;
// signal spelling, payload, calls, results, and record boundaries are retained.
func TestG2FundedPreflightTraceCapturedSignals(t *testing.T) {
	cases := []struct{ name, trace string }{
		{"standard", `4012521 execve("/trace-fixture/signal-probe", ["/trace-fixture/signal-probe", "/trace-fixture/params.json", "standard"], 0x7fff65c3cfb0 /* 32 vars */) = 0
4012521 access("/etc/ld.so.preload", R_OK) = -1 ENOENT (No such file or directory)
4012521 openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
4012521 openat(AT_FDCWD, "/usr/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
4012521 openat(AT_FDCWD, "/trace-fixture/params.json", O_RDONLY) = 3
4012521 --- SIGURG {si_signo=SIGURG, si_code=SI_TKILL, si_pid=4012521, si_uid=1001} ---
4012521 write(1, "ok\n", 3)             = 3
`},
		{"realtime", `4012525 execve("/trace-fixture/signal-probe", ["/trace-fixture/signal-probe", "/trace-fixture/params.json", "realtime"], 0x7fff7cebe250 /* 32 vars */) = 0
4012525 access("/etc/ld.so.preload", R_OK) = -1 ENOENT (No such file or directory)
4012525 openat(AT_FDCWD, "/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
4012525 openat(AT_FDCWD, "/usr/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
4012525 openat(AT_FDCWD, "/trace-fixture/params.json", O_RDONLY) = 3
4012525 --- SIGRT_2 {si_signo=SIGRT_2, si_code=SI_TKILL, si_pid=4012525, si_uid=1001} ---
4012525 write(1, "ok\n", 3)             = 3
`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := fundedTraceViolations(tc.trace, "/trace-fixture/signal-probe", "/trace-fixture/params.json"); len(got) != 0 {
				t.Fatalf("captured trace rejected: %v", got)
			}
		})
	}
}
