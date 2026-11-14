//go:build linux

package g2ledger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Claim: the native quoted receipt parses without changing either path; a diagnostic after it refuses the whole output.
func TestUnitReceiptNativeQuoted(t *testing.T) {
	output := "Created symlink '/etc/systemd/system/multi-user.target.wants/xcheck-fixture.service' -> '/etc/systemd/system/xcheck-fixture.service'.\n"
	if path := os.Getenv("G2LEDGER_NATIVE_ENABLE_OUTPUT"); path != "" {
		raw, err := os.ReadFile(path)
		must(t, err)
		output = string(raw)
	}
	line, rest, _ := strings.Cut(output, "\n")
	links, err := createdUnitLinks(line + "\n")
	must(t, err)
	if len(links) != 1 || links[0].Target != "/etc/systemd/system/xcheck-fixture.service" || !strings.HasSuffix(links[0].Path, "/etc/systemd/system/multi-user.target.wants/xcheck-fixture.service") {
		t.Fatalf("unexpected native receipt: %+v", links)
	}
	if fmt.Sprintf("Created symlink '%s' -> '%s'.", links[0].Path, links[0].Target) != line {
		t.Fatal("native receipt path text changed")
	}
	if rest != "" {
		if _, err := createdUnitLinks(output); err == nil || err.Error() != "UNIT_ENABLE_OUTPUT" {
			t.Fatalf("extra native diagnostic: %v", err)
		}
	}
}

// Claim: quoted current and unquoted legacy formats preserve literal spaces and backslashes without shell unescaping.
func TestUnitReceiptVersionedGrammar(t *testing.T) {
	for _, path := range []string{"/etc/systemd/system/example.service", "/a directory/example.service", `/literal\x20directory/example.service`} {
		want := []UnitLink{{Path: path, Target: "/a target/example.service"}}
		for _, format := range []string{"Created symlink '%s' -> '%s'.\n", "Created symlink %s -> %s.\n"} {
			got, err := createdUnitLinks(fmt.Sprintf(format, want[0].Path, want[0].Target))
			must(t, err)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("path text changed: got %+v, want %+v", got, want)
			}
		}
	}
	quoted, err := createdUnitLinks("Created symlink '/a. directory/link ' -> '/a. target/file '.\n")
	must(t, err)
	if !reflect.DeepEqual(quoted, []UnitLink{{Path: "/a. directory/link ", Target: "/a. target/file "}}) {
		t.Fatal("quoted period-space or trailing path spaces changed")
	}
}

// Claim: ambiguous syntax, duplicate/extra lines and invalid paths refuse by name and return no partial receipt.
func TestUnitReceiptRefusals(t *testing.T) {
	valid := "Created symlink '/path' -> '/target'.\n"
	cases := []struct{ name, output, refusal string }{
		{"unbalanced-path", "Created symlink '/path -> '/target'.\n", "UNIT_ENABLE_QUOTE"},
		{"unbalanced-target", "Created symlink '/path' -> '/target.\n", "UNIT_ENABLE_QUOTE"},
		{"mixed-forms-reverse", "Created symlink '/path' -> /target.\n", "UNIT_ENABLE_QUOTE"},
		{"mixed-forms", "Created symlink /path -> '/target'.\n", "UNIT_ENABLE_QUOTE"},
		{"embedded-path-quote", "Created symlink '/pa'th' -> '/target'.\n", "UNIT_ENABLE_QUOTE"},
		{"embedded-target-quote", "Created symlink '/path' -> '/tar'get'.\n", "UNIT_ENABLE_QUOTE"},
		{"legacy-quote", "Created symlink /pa'th -> /target.\n", "UNIT_ENABLE_QUOTE"},
		{"extra-quote-pair", "Created symlink ''/path'' -> '/target'.\n", "UNIT_ENABLE_QUOTE"},
		{"extra-text-before-period", "Created symlink '/path' -> '/target' extra.\n", "UNIT_ENABLE_QUOTE"},
		{"legacy-trailing-tab", "Created symlink /path -> /target.\textra.\n", "UNIT_ENABLE_OUTPUT"},
		{"legacy-trailing-text", "Created symlink /path -> /target. extra.\n", "UNIT_ENABLE_OUTPUT"},
		{"double-quote", "Created symlink '/pa\"th' -> '/target'.\n", "UNIT_ENABLE_QUOTE"},
		{"trailing-text", "Created symlink '/path' -> '/target'. extra\n", "UNIT_ENABLE_OUTPUT"},
		{"trailing-chunk-with-period", "Created symlink '/path' -> '/target'. extra.\n", "UNIT_ENABLE_QUOTE"},
		{"second-arrow", "Created symlink '/path' -> '/target' -> '/other'.\n", "UNIT_ENABLE_ARROW"},
		{"arrow-in-path", "Created symlink '/pa->th' -> '/target'.\n", "UNIT_ENABLE_ARROW"},
		{"unicode-arrow", "Created symlink '/path' → '/target'.\n", "UNIT_ENABLE_ARROW"},
		{"unicode-in-target", "Created symlink '/path' -> '/tar→get'.\n", "UNIT_ENABLE_ARROW"},
		{"newline-in-path", "Created symlink '/pa\nth' -> '/target'.\n", "UNIT_ENABLE_OUTPUT"},
		{"duplicate-other-target", valid + "Created symlink '/path' -> '/other'.\n", "UNIT_ENABLE_DUPLICATE"},
		{"duplicate", valid + valid, "UNIT_ENABLE_DUPLICATE"},
		{"extra-line", valid + "unexpected\n", "UNIT_ENABLE_OUTPUT"},
		{"blank-line", valid + "\n", "UNIT_ENABLE_OUTPUT"},
		{"empty", "", "UNIT_ENABLE_EMPTY"},
		{"relative-path", "Created symlink 'relative' -> '/target'.\n", "UNIT_ENABLE_LINK"},
		{"relative-target", "Created symlink '/path' -> 'relative'.\n", "UNIT_ENABLE_LINK"},
		{"unclean-path", "Created symlink '/a/../path' -> '/target'.\n", "UNIT_ENABLE_LINK"},
		{"root-target", "Created symlink '/path' -> '/'.\n", "UNIT_ENABLE_LINK"},
		{"nul-target", "Created symlink '/path' -> '/tar\x00get'.\n", "UNIT_ENABLE_LINK"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			links, err := createdUnitLinks(tc.output)
			if err == nil || err.Error() != tc.refusal || links != nil {
				t.Fatalf("got %+v, %v; want no receipt and %s", links, err, tc.refusal)
			}
		})
	}
	links, err := createdUnitLinks(valid)
	must(t, err)
	if len(links) != 1 || links[0].Path != "/path" || links[0].Target != "/target" {
		t.Fatal("valid neighbor changed")
	}
}

// Claim: quoted enable receipts with spaces undo cleanly; retargeting preserves the changed link and older work.
func TestLedgerQuotedReceiptUndo(t *testing.T) {
	for _, retarget := range []bool{false, true} {
		t.Run(fmt.Sprint(retarget), func(t *testing.T) {
			f := setup(t)
			older := f.create(t, "older", "file", "remove")
			f.sys.unitRoot = filepath.Join(f.sys.unitRoot, "a directory")
			must(t, os.Mkdir(f.sys.unitRoot, 0700))
			must(t, os.WriteFile(filepath.Join(f.sys.unitRoot, "demo.service"), []byte("[Install]\nAlias=alias.service\n"), 0600))
			link := UnitLink{Path: filepath.Join(f.sys.unitRoot, "alias.service"), Target: filepath.Join(f.sys.unitRoot, "demo.service")}
			f.sys.fault = func(cmd string, args []string) (fakeReply, bool) {
				if cmd != "/usr/bin/systemctl" || args[0] != "enable" {
					return fakeReply{}, false
				}
				must(t, os.Symlink(link.Target, link.Path))
				f.sys.unitLinks["demo.service"] = []UnitLink{link}
				f.sys.units["demo.service"] = "enabled"
				return fakeReply{fmt.Sprintf("Created symlink '%s' -> '%s'.\n", link.Path, link.Target), 0, nil}, true
			}
			must(t, f.l.Enable("demo.service"))
			f.sys.fault = nil
			got := f.l.rows[len(f.l.rows)-1].Body.Result.Identities[0].Unit.Links[0]
			if got.Path != link.Path || got.Target != link.Target || got.Ino == 0 || got.Mode == 0 {
				t.Fatalf("incomplete quoted receipt: %+v", got)
			}
			if retarget {
				must(t, os.Remove(link.Path))
				must(t, os.Symlink(link.Target+".changed", link.Path))
			}
			f.l.Close()
			err := Run([]string{"replay", "-dir", f.dir, "-mode", "station"}, f.sys, io.Discard)
			if retarget {
				code(t, err, 1)
				if !strings.Contains(err.Error(), "UNIT_LINK_IDENTITY") {
					t.Fatal(err)
				}
				target, err := os.Readlink(link.Path)
				must(t, err)
				if target != link.Target+".changed" || f.sys.called("/usr/bin/systemctl daemon-reload") {
					t.Fatal("retargeted link mutated or replay continued")
				}
				exists(t, older)
			} else {
				must(t, err)
				absent(t, link.Path)
				absent(t, older)
			}
		})
	}
}

// Claim: malformed quoted output after a real fake-boundary effect leaves an orphan and preserves links and older work.
func TestLedgerQuotedReceiptOrphan(t *testing.T) {
	for _, change := range []string{"embedded-quote", "duplicate", "trailing-text", "extra-line"} {
		t.Run(change, func(t *testing.T) {
			f := setup(t)
			older := f.create(t, "older", "file", "remove")
			link := UnitLink{Path: filepath.Join(f.sys.unitRoot, "a link"), Target: filepath.Join(f.sys.unitRoot, "target")}
			if change == "embedded-quote" {
				link.Path += "'quoted"
			}
			f.sys.fault = func(cmd string, args []string) (fakeReply, bool) {
				if cmd != "/usr/bin/systemctl" || args[0] != "enable" {
					return fakeReply{}, false
				}
				must(t, os.Symlink(link.Target, link.Path))
				output := fmt.Sprintf("Created symlink '%s' -> '%s'.\n", link.Path, link.Target)
				switch change {
				case "duplicate":
					output += output
				case "trailing-text":
					output = strings.TrimSuffix(output, "\n") + " extra.\n"
				case "extra-line":
					output += "unexpected\n"
				}
				return fakeReply{output, 0, nil}, true
			}
			code(t, f.l.Enable("demo.service"), 3)
			f.l.Close()
			code(t, Run([]string{"replay", "-dir", f.dir, "-mode", "station"}, f.sys, io.Discard), 3)
			target, err := os.Readlink(link.Path)
			must(t, err)
			if target != link.Target || f.sys.called("/usr/bin/systemctl daemon-reload") {
				t.Fatal("orphan permitted undo")
			}
			exists(t, older)
		})
	}
}
