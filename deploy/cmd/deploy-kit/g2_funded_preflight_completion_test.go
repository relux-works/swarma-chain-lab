package main

import (
	"fmt"
	"strings"
	"testing"
)

// Claim: result-looking payload text cannot complete a quoted argument, in either split or unsplit records.
func TestG2FundedPreflightTracePayloadEOF(t *testing.T) {
	const prefix = "1 execve(\"/binary\", [], 0) = 0\n1 openat(AT_FDCWD, \"/params\", O_RDONLY) = 3\n"
	cases := []struct{ name, call, args, tail string }{
		// Claim: readlink payload EOF fails closed while the completed neighbour is accepted.
		{"readlink", "readlink", `"/params", "target) = 0`, `", 1024) = 11`},
		// Claim: stdout payload EOF fails closed while the completed neighbour is accepted.
		{"write", "write", `1, "payload) = 0`, `", 12) = 12`},
		// Claim: an escaped quote keeps the following result-looking text inside the payload.
		{"escaped-quote", "write", `1, "payload\") = 0`, `", 13) = 13`},
		// Claim: an escaped backslash does not escape the real closing quote of a complete payload.
		{"escaped-backslash", "write", `1, "payload\\) = 0`, `", 13) = 13`},
	}
	for _, tc := range cases {
		for _, split := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/split=%t", tc.name, split), func(t *testing.T) {
				call := "2 " + tc.call + "(" + tc.args
				if split {
					call = "2 " + tc.call + "( <unfinished ...>\n2 <... " + tc.call + " resumed>" + tc.args
				}
				got := strings.Join(fundedTraceViolations(prefix+call, "/binary", "/params"), "\n")
				if !strings.Contains(got, "unfinished syscall:") {
					t.Fatalf("quoted payload EOF lost pending call: %s", got)
				}
				if got := fundedTraceViolations(prefix+call+tc.tail, "/binary", "/params"); len(got) != 0 {
					t.Fatalf("complete neighbour rejected: %v", got)
				}
			})
		}
	}
}

// Claim: completion requires balanced outer arguments and a whole result, preserving valid strace escapes and abbreviations.
func TestG2FundedPreflightTraceCallBoundary(t *testing.T) {
	const prefix = "1 execve(\"/binary\", [], 0) = 0\n1 openat(AT_FDCWD, \"/params\", O_RDONLY) = 3\n"
	cases := []struct {
		name, record string
		complete     bool
	}{
		// Claim: strace's quoted abbreviation marker is outside the closing quote, not an incomplete record.
		{"abbreviated-string", `2 write(1, "payload) = 0"..., 4097) = 4097`, true},
		{"abbreviated-no-call-end", `2 write(1, "payload) = 0"...`, false},
		// Claim: braces, arrays and nested parentheses do not close the outer call, including quoted delimiters.
		{"nested", `2 writev(1, [{iov_base="}) = 0", iov_len=htons(6)}, {iov_base="[)]", iov_len=3}], 2) = 9`, true},
		{"nested-eof", `2 writev(1, [{iov_base="}) = 0", iov_len=htons(6)`, false},
		{"mismatched-delimiter", `2 writev(1, [{iov_base="ok") = 0`, false},
		// Claim: escaped quotes/backslashes/control, hexadecimal and octal bytes retain their lexical quoting.
		{"escaped-bytes", `2 write(1, "\"\\\n\t\r\f\v\x29\051\0\12) = 0", 14) = 14`, true},
		{"dangling-escape", `2 write(1, "payload\`, false},
		{"incomplete-hex-escape", `2 write(1, "\x2`, false},
		{"invalid-escape", `2 write(1, "\q", 1) = 1`, false},
		// Claim: errno and pseudo-return forms require a closed call and complete optional explanation.
		{"errno", `2 write(1, "ok", 2) = -1 EPIPE (Broken pipe)`, true},
		{"errno-without-text", `2 write(1, "ok", 2) = -1 EPIPE`, true},
		{"unknown-errno", `2 write(1, "ok", 2) = -1 (errno 999)`, true},
		{"errno-open-text", `2 write(1, "ok", 2) = -1 EPIPE (Broken pipe`, false},
		{"question", `2 write(1, "ok", 2) = ?`, true},
		{"restart", `2 write(1, "ok", 2) = ? ERESTARTSYS (To be restarted if SA_RESTART is set)`, true},
		{"unavailable", `2 write(1, "ok", 2) = ? <unavailable>`, true},
		{"unavailable-eof", `2 write(1, "ok", 2) = ? <unavailable`, false},
		{"hex-result", `2 write(1, "ok", 2) = 0x2`, true},
		{"no-result", `2 write(1, "ok", 2) = `, false},
		{"result-junk", `2 write(1, "ok", 2) = 2 junk`, false},
		// Claim: -T timing and -y descriptor decorations are rejected because the observer enables neither mode.
		{"unsupported-time", `2 write(1, "ok", 2) = 2 <0.000001>`, false},
		{"unsupported-fd-decoration", `2 write(1, "ok", 2) = 2</tmp/output>`, false},
	}
	for _, tc := range cases {
		for _, split := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/split=%t", tc.name, split), func(t *testing.T) {
				record := tc.record
				if split {
					open := strings.IndexByte(record, '(')
					record = record[:open+1] + " <unfinished ...>\n2 <... " + record[2:open] + " resumed>" + record[open+1:]
				}
				got := strings.Join(fundedTraceViolations(prefix+record, "/binary", "/params"), "\n")
				if tc.complete && got != "" {
					t.Fatalf("complete call rejected: %s", got)
				}
				if !tc.complete && !strings.Contains(got, "unfinished syscall:") {
					t.Fatalf("incomplete call did not stay pending: %s", got)
				}
			})
		}
	}
}

// Claim: every byte prefix ending inside this captured resumed payload fails closed; its complete neighbour passes.
func TestG2FundedPreflightTraceCapturedPayloadEOF(t *testing.T) {
	// Selected records from a strace 6.19 -f -qq -s 4096 payload-probe capture;
	// only executable/input prefixes and PIDs are replaced by public fixture values.
	const start = `1 execve("/trace-fixture/probe", ["/trace-fixture/probe", "/trace-fixture/params.json"], 0x7fff66bd3a68 /* 42 vars */) = 0
1 openat(AT_FDCWD, "/trace-fixture/params.json", O_RDONLY) = 3
1 readlink("/trace-fixture/params.json" <unfinished ...>
1 <... readlink resumed>, `
	const payload = `"target) = 3`
	const end = `", 1024) = 11`
	if got := fundedTraceViolations(start+payload+end, "/trace-fixture/probe", "/trace-fixture/params.json"); len(got) != 0 {
		t.Fatalf("complete captured neighbour: %v", got)
	}
	for cut := 1; cut <= len(payload); cut++ {
		t.Run(fmt.Sprintf("payload-prefix-%d", cut), func(t *testing.T) {
			got := strings.Join(fundedTraceViolations(start+payload[:cut], "/trace-fixture/probe", "/trace-fixture/params.json"), "\n")
			if !strings.Contains(got, "unfinished syscall:") {
				t.Fatalf("captured payload EOF cleared pending call: %s", got)
			}
		})
	}
}
