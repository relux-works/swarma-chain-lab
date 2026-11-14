//go:build linux

package g2ledger

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Claim: Install.Also (including whitespace, continuation and reset forms) refuses before intent/enable; comments and another section are valid.
func TestLedgerUnitAlsoRefusedBeforeEffect(t *testing.T) {
	for _, body := range []string{
		"[Install]\nAlso=preexisting.service\n",
		"[Install]\n Also = preexisting.service\n",
		"[Install]\nAlso=\\\n preexisting.service\n",
		"[Install]\nAlso=\n",
		"[Unit]\nDescription=Also=example\n[Install]\n# Also=ignored.service\nWantedBy=multi-user.target\n",
	} {
		t.Run(strings.ReplaceAll(body, "\n", "/"), func(t *testing.T) {
			f := setup(t)
			f.sys.units["preexisting.service"] = "enabled"
			f.sys.unitFiles["demo.service"] = body
			must(t, os.WriteFile(filepath.Join(f.sys.unitRoot, "demo.service"), []byte(body), 0600))
			if strings.Contains(body, "Also=ignored") { // positive neighbour: no Also directive
				must(t, f.l.Enable("demo.service"))
				must(t, f.l.Replay("station"))
				return
			}
			f.sys.also["demo.service"] = []string{"preexisting.service"}
			f.l.Close()
			err := Run([]string{"enable", "-dir", f.dir, "-unit", "demo.service"}, f.sys, io.Discard)
			code(t, err, 1)
			if !strings.Contains(err.Error(), "UNIT_ALSO_REFUSED") {
				t.Fatal(err)
			}
			if f.sys.called("/usr/bin/systemctl enable") {
				t.Fatal("enable crossed refusal")
			}
			if f.sys.units["preexisting.service"] != "enabled" || f.sys.units["demo.service"] != "disabled" {
				t.Fatal("collateral effect")
			}
			f.reopen(t)
			if len(f.l.rows) != 1 {
				t.Fatal("refusal wrote intent")
			}
		})
	}
}

// Claim: public replay removes only the enable receipt, preserves a foreign
// link, and stops before any effect if a recorded link is retargeted (including
// when is-enabled says disabled). Unchanged links undo and retry successfully.
func TestLedgerUnitUndoOnlyRecordedLinks(t *testing.T) {
	for _, change := range []string{"unchanged", "foreign", "retargeted", "retargeted-disabled", "regular-file", "missing"} {
		t.Run(change, func(t *testing.T) {
			f := setup(t)
			older := f.create(t, "older", "file", "remove")
			must(t, f.l.Enable("demo.service"))
			link := f.l.rows[len(f.l.rows)-1].Body.Result.Identities[0].Unit.Links[0]
			foreign := filepath.Join(filepath.Dir(link.Path), "foreign.service")
			if change == "foreign" {
				must(t, os.Symlink(link.Target, foreign))
			}
			if change == "retargeted" || change == "retargeted-disabled" {
				must(t, os.Remove(link.Path))
				must(t, os.Symlink(link.Target+".other", link.Path))
			}
			if change == "retargeted-disabled" {
				f.sys.units["demo.service"] = "disabled"
			}
			if change == "regular-file" {
				must(t, os.Remove(link.Path))
				must(t, os.WriteFile(link.Path, []byte("foreign"), 0600))
			}
			if change == "missing" {
				must(t, os.Remove(link.Path))
				f.sys.units["demo.service"] = "disabled"
			}
			f.l.Close()
			err := Run([]string{"replay", "-dir", f.dir, "-mode", "station"}, f.sys, io.Discard)
			if strings.HasPrefix(change, "retargeted") || change == "regular-file" {
				code(t, err, 1)
				if !strings.Contains(err.Error(), "UNIT_LINK_IDENTITY") {
					t.Fatal(err)
				}
				exists(t, link.Path)
				exists(t, older)
				if f.sys.called("/usr/bin/systemctl daemon-reload") {
					t.Fatal("effect after mismatch")
				}
			} else if change == "foreign" {
				// The foreign enablement remains: refuse the final state instead
				// of widening undo authority. Older work has not been touched.
				code(t, err, 1)
				exists(t, older)
				absent(t, link.Path)
				target, err := os.Readlink(foreign)
				must(t, err)
				if target != link.Target {
					t.Fatal("foreign link changed")
				}
			} else {
				must(t, err)
				absent(t, link.Path)
				absent(t, older)
				must(t, Run([]string{"replay", "-dir", f.dir, "-mode", "station"}, f.sys, io.Discard))
			}
			if f.sys.called("/usr/bin/systemctl disable") {
				t.Fatal("unbounded disable used")
			}
		})
	}
}

// Claim: a malformed enable receipt or an absent reported link leaves an orphan;
// neither can authorize later undo. The real-output positive is exercised above.
func TestLedgerUnitReceiptRejectsUnprovenLinks(t *testing.T) {
	for _, output := range []string{"", "Created symlink relative -> /absolute.\n", "Created symlink /abs -> relative.\n", "unrecognized\n", "Created symlink /abs -> /target.\nCreated symlink /abs -> /target.\n"} {
		if _, err := createdUnitLinks(output); err == nil {
			t.Fatalf("accepted %q", output)
		}
	}
	f := setup(t)
	f.sys.fault = func(cmd string, args []string) (fakeReply, bool) {
		return fakeReply{"Created symlink " + filepath.Join(f.sys.unitRoot, "not-created") + " -> /target.\n", 0, nil}, cmd == "/usr/bin/systemctl" && args[0] == "enable"
	}
	code(t, f.l.Enable("demo.service"), 3)
	f.l.Close()
	_, err := Open(f.dir, f.sys)
	code(t, err, 3)
}

// Claim: the fake itself demonstrates disable's broader documented effect set:
// Also units and a manually added matching link are removed by raw disable.
// Ledger undo must therefore preserve them without calling this command.
func TestLedgerFakeModelsEnableAndDisableEffectSets(t *testing.T) {
	f := setup(t)
	f.sys.units["other.service"] = "disabled"
	f.sys.also["demo.service"] = []string{"other.service"}
	out, status, err := f.sys.Run("/usr/bin/systemctl", "enable", "demo.service")
	must(t, err)
	links, err := createdUnitLinks(out)
	must(t, err)
	if status != 0 || len(links) != 2 || f.sys.units["other.service"] != "enabled" {
		t.Fatal("Also enable omitted")
	}
	foreign := filepath.Join(f.sys.unitRoot, "manual.service")
	must(t, os.Symlink(links[0].Target, foreign))
	_, status, err = f.sys.Run("/usr/bin/systemctl", "disable", "demo.service")
	must(t, err)
	if status != 0 || f.sys.units["other.service"] != "disabled" {
		t.Fatal("Also disable omitted")
	}
	absent(t, foreign)
	for _, link := range links {
		absent(t, link.Path)
	}
}

// Claim: the whole receipt is validated before the first unlink. Retargeting
// only the second of two recorded links preserves BOTH links and older work.
func TestLedgerUnitValidatesWholeSetBeforeUnlink(t *testing.T) {
	for _, retarget := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "second-retargeted"}[retarget], func(t *testing.T) {
			f := setup(t)
			older := f.create(t, "older", "file", "remove")
			links := []UnitLink{{Path: filepath.Join(f.sys.unitRoot, "first"), Target: filepath.Join(f.sys.unitRoot, "demo.service")}, {Path: filepath.Join(f.sys.unitRoot, "second"), Target: filepath.Join(f.sys.unitRoot, "demo.service")}}
			must(t, os.WriteFile(filepath.Join(f.sys.unitRoot, "demo.service"), []byte("[Install]\nAlias=first.service second.service\n"), 0600))
			links[0].Path += ".service"
			links[1].Path += ".service"
			f.sys.fault = func(cmd string, args []string) (fakeReply, bool) {
				if cmd != "/usr/bin/systemctl" || args[0] != "enable" {
					return fakeReply{}, false
				}
				output := ""
				for _, link := range links {
					must(t, os.Symlink(link.Target, link.Path))
					output += "Created symlink " + link.Path + " -> " + link.Target + ".\n"
				}
				f.sys.unitLinks["demo.service"] = links
				f.sys.units["demo.service"] = "enabled"
				return fakeReply{output, 0, nil}, true
			}
			must(t, f.l.Enable("demo.service"))
			f.sys.fault = nil
			if retarget {
				must(t, os.Remove(links[1].Path))
				must(t, os.Symlink(links[1].Target+".foreign", links[1].Path))
			}
			f.l.Close()
			err := Run([]string{"replay", "-dir", f.dir, "-mode", "station"}, f.sys, io.Discard)
			if retarget {
				code(t, err, 1)
				exists(t, older)
				for _, link := range links {
					exists(t, link.Path)
				}
			} else {
				must(t, err)
				absent(t, older)
				for _, link := range links {
					absent(t, link.Path)
				}
			}
		})
	}
}
