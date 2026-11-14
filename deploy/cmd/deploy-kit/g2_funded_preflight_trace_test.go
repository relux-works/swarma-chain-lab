package main

import (
	"regexp"
	"sort"
	"strings"
	"testing"
)

var fundedTracePID = regexp.MustCompile(`^\s*([0-9]+)\s+(.*)$`)
var fundedTraceResume = regexp.MustCompile(`^<\.\.\. ([a-zA-Z0-9_]+) resumed>(.*)$`)
var fundedTraceEvent = regexp.MustCompile(`^(?:--- SIG[A-Z0-9]+(?: \{.*\})? ---|\+\+\+ exited with [0-9]+ \+\+\+|\+\+\+ killed by SIG[A-Z0-9]+(?: \(core dumped\))? \+\+\+)$`)

// strace(1), DESCRIPTION, documents per-thread unfinished/resumed pairs:
// https://man7.org/linux/man-pages/man1/strace.1.html
// strace v6.1 src/strace.c printleader() and droptcb() emit the unfinished
// and detached suffixes; src/syscall.c print_syscall_resume() names the call:
// https://github.com/strace/strace/blob/v6.1/src/strace.c
// https://github.com/strace/strace/blob/v6.1/src/syscall.c
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
		if strings.TrimSpace(body) == "????( <detached ...>" || fundedTraceEvent.MatchString(body) {
			continue
		}
		if resumed := fundedTraceResume.FindStringSubmatch(body); resumed != nil {
			start, ok := pending[pid]
			call := fundedTraceCall.FindStringSubmatch(start)
			if !ok || call == nil || call[1] != resumed[1] {
				violations = append(violations, "unmatched resume: "+line)
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
		// Claim: The exact observed unknown-name teardown event is allowed.
		{"detached-unknown", input + `12794 ????( <detached ...>`, ""},
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
