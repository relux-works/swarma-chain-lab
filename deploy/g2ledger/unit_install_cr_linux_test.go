//go:build linux

package g2ledger

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Claim: unsupported CR placements refuse by name before intent, journal writes or enable effects through the public entry point.
func TestInstallCRRefused(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"inside-value", "Alias=one.ser\rvice\n"},
		{"value-separator", "Alias=one.service\rtwo.service\n"},
		{"between-assignments", "WantedBy=a.target\rAlias=b.service\n"},
		{"assignment-tokens", "\rAlias\r=\rone.service two.service\r\n"},
		{"eof", "WantedBy=a.target\r"},
		{"before-backslash", "WantedBy=a.target\r\\\n b.target\n"},
		{"after-backslash", "WantedBy=a.target\\\r b.target\n"},
		{"hash-comment", "# comment\rAlias=b.service\n"},
		{"semicolon-comment", "; comment\rAlias=b.service\n"},
		{"continuation-comment", "WantedBy=a.target\\\n# comment\r b.target\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := setup(t)
			source := installFixture(t, f, "[Install]\n"+tc.body)
			links := []UnitLink{
				{Path: filepath.Join(f.sys.unitRoot, "one.service"), Target: source},
				{Path: filepath.Join(f.sys.unitRoot, "two.service"), Target: source},
				{Path: filepath.Join(f.sys.unitRoot, "a.target.wants/demo.service"), Target: source},
				{Path: filepath.Join(f.sys.unitRoot, "b.service"), Target: source},
			}
			installReply(t, f, links, links)
			f.l.Close()
			before, err := os.ReadFile(filepath.Join(f.dir, recordsName))
			must(t, err)
			err = Run([]string{"enable", "-dir", f.dir, "-unit", "demo.service"}, f.sys, io.Discard)
			code(t, err, 1)
			if err.Error() != "g2-ledger: UNIT_INSTALL demo.service: UNIT_INSTALL_CR_REFUSED" {
				t.Fatalf("wrong refusal: %v", err)
			}
			after, err := os.ReadFile(filepath.Join(f.dir, recordsName))
			must(t, err)
			if !bytes.Equal(before, after) || f.sys.called("/usr/bin/systemctl enable") || f.sys.units["demo.service"] != "disabled" {
				t.Fatal("refusal changed journal or crossed enable boundary")
			}
			for _, link := range links {
				absent(t, link.Path)
			}
		})
	}
}

// Claim: LF and CRLF give the same declared link set, including continuations across both comment forms, and both enable and replay.
func TestInstallLFCRLFControls(t *testing.T) {
	f := setup(t)
	body := "[Install]\nWantedBy=a.target\\\n# comment\\\n; comment\n b.target\nAlias=one.service two.service\n"
	var previous []UnitLink
	for _, ending := range []string{"LF", "CRLF"} {
		t.Run(ending, func(t *testing.T) {
			raw := body
			if ending == "CRLF" {
				raw = strings.ReplaceAll(raw, "\n", "\r\n")
			}
			source := installFixture(t, f, raw)
			links := []UnitLink{
				{Path: filepath.Join(f.sys.unitRoot, "a.target.wants/demo.service"), Target: source},
				{Path: filepath.Join(f.sys.unitRoot, "b.target.wants/demo.service"), Target: source},
				{Path: filepath.Join(f.sys.unitRoot, "one.service"), Target: source},
				{Path: filepath.Join(f.sys.unitRoot, "two.service"), Target: source},
			}
			plan, err := expectedUnitInstall(f.sys, "demo.service")
			must(t, err)
			if !slices.Equal(plan.Expected, links) || !slices.Equal(plan.Missing, links) || len(plan.Existing) != 0 {
				t.Fatalf("wrong predicted links: %+v", plan)
			}
			if previous != nil && !slices.Equal(previous, plan.Expected) {
				t.Fatal("line ending changed predicted set")
			}
			previous = plan.Expected
			installReply(t, f, links, links)
			f.l.Close()
			must(t, Run([]string{"enable", "-dir", f.dir, "-unit", "demo.service"}, f.sys, io.Discard))
			for _, link := range links {
				exists(t, link.Path)
			}
			must(t, Run([]string{"replay", "-dir", f.dir, "-mode", "station"}, f.sys, io.Discard))
			for _, link := range links {
				absent(t, link.Path)
			}
		})
	}
}
