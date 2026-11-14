//go:build linux

package g2ledger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func installFixture(t *testing.T, f *fixture, body string) string {
	t.Helper()
	path := filepath.Join(f.sys.unitRoot, "demo.service")
	must(t, os.WriteFile(path, []byte(body), 0600))
	return path
}

// The command model consumes explicit test expectations, never the production Install parser.
func installReply(t *testing.T, f *fixture, created, reported []UnitLink) {
	t.Helper()
	f.sys.fault = func(cmd string, args []string) (fakeReply, bool) {
		if cmd != "/usr/bin/systemctl" || args[0] != "enable" {
			return fakeReply{}, false
		}
		for _, link := range created {
			must(t, os.MkdirAll(filepath.Dir(link.Path), 0700))
			must(t, os.Symlink(link.Target, link.Path))
		}
		f.sys.units["demo.service"] = "enabled"
		f.sys.unitLinks["demo.service"] = created
		output := ""
		for _, link := range reported {
			output += fmt.Sprintf("Created symlink '%s' -> '%s'.\n", link.Path, link.Target)
		}
		return fakeReply{output, 0, nil}, true
	}
}

// Claim: matching foreign receipts cannot grant undo; exact requested-unit receipts still enable and replay.
func TestReviewForeignReceiptCannotGrantUndo(t *testing.T) {
	for _, attack := range []string{"valid", "extra-unrelated", "wrong-path", "wrong-target", "wrong-path-and-target", "missing"} {
		t.Run(attack, func(t *testing.T) {
			f := setup(t)
			older := f.create(t, "older", "file", "remove")
			source := installFixture(t, f, "[Install]\nWantedBy=multi-user.target\nAlias=demo-alias.service\n")
			want := []UnitLink{
				{Path: filepath.Join(f.sys.unitRoot, "multi-user.target.wants", "demo.service"), Target: source},
				{Path: filepath.Join(f.sys.unitRoot, "demo-alias.service"), Target: source},
			}
			foreign := UnitLink{Path: filepath.Join(f.sys.unitRoot, "other.service"), Target: filepath.Join(f.sys.unitRoot, "other-unit.service")}
			must(t, os.Symlink(foreign.Target, foreign.Path))
			original, present, err := observeUnitLink(foreign)
			must(t, err)
			if !present {
				t.Fatal("missing foreign fixture")
			}
			created := append([]UnitLink(nil), want...)
			reported := append([]UnitLink(nil), want...)
			switch attack {
			case "extra-unrelated":
				reported = append(reported, foreign)
			case "wrong-path":
				reported[0].Path = filepath.Join(f.sys.unitRoot, "unrelated.service")
				created = append(created, reported[0])
			case "wrong-target":
				created[0].Target = foreign.Target
				reported[0] = created[0]
			case "wrong-path-and-target":
				reported[0] = foreign
			case "missing":
				reported = reported[:1]
			}
			installReply(t, f, created, reported)
			f.l.Close()
			err = Run([]string{"enable", "-dir", f.dir, "-unit", "demo.service"}, f.sys, io.Discard)
			if attack == "valid" {
				must(t, err)
				must(t, Run([]string{"replay", "-dir", f.dir, "-mode", "station"}, f.sys, io.Discard))
				for _, link := range want {
					absent(t, link.Path)
				}
				absent(t, older)
			} else {
				code(t, err, 3)
				if err.Error() != "g2-ledger: ORPHAN demo.service UNIT_ENABLE_SET_MISMATCH" {
					t.Fatal(err)
				}
				code(t, Run([]string{"replay", "-dir", f.dir, "-mode", "station"}, f.sys, io.Discard), 3)
				for _, link := range created {
					exists(t, link.Path)
				}
				exists(t, older)
				raw, readErr := os.ReadFile(filepath.Join(f.dir, recordsName))
				must(t, readErr)
				lines := bytes.Split(bytes.TrimSuffix(raw, []byte("\n")), []byte("\n"))
				var last Record
				must(t, json.Unmarshal(lines[len(lines)-1], &last))
				if last.Body.Op != "intent" || last.Body.Result != nil {
					t.Fatal("untrusted receipt recorded a result")
				}
				if f.sys.called("/usr/bin/systemctl daemon-reload") {
					t.Fatal("orphan authorized undo")
				}
			}
			got, present, err := observeUnitLink(foreign)
			must(t, err)
			if !present || got != original {
				t.Fatal("unrelated pre-existing link changed")
			}
		})
	}
}

// Claim: aliases, repeated/multiple dependency lists, resets, comments and continuation produce exactly their declared links.
func TestLedgerUnitInstallExpectedSets(t *testing.T) {
	cases := []struct {
		name, body string
		paths      []string
	}{
		{"alias", "[Install]\nAlias=alias.service\n", []string{"alias.service"}},
		{"multiple-wanted", "[Install]\nWantedBy=one.target two.target\nWantedBy=three.target\n", []string{"one.target.wants/demo.service", "two.target.wants/demo.service", "three.target.wants/demo.service"}},
		{"blank-ends-continuation", "[Install]\nWantedBy=one.target\\\n\nWantedBy=two.target\n", []string{"one.target.wants/demo.service", "two.target.wants/demo.service"}},
		{"required-upheld", "[Install]\nRequiredBy=one.target two.target\nUpheldBy=three.target\nUpheldBy=four.target\n", []string{"one.target.requires/demo.service", "two.target.requires/demo.service", "three.target.upholds/demo.service", "four.target.upholds/demo.service"}},
		{"resets", "[Install]\nWantedBy=old.target\nRequiredBy=old.target\nUpheldBy=old.target\nAlias=old.service\nWantedBy=\nRequiredBy=\nUpheldBy=\nAlias=\nWantedBy=one.target\nAlias=new.service\n", []string{"one.target.wants/demo.service", "new.service"}},
		{"continuation-comments-quotes", "# ignored\n[Unit]\nDescription=example\n[Install]\n WantedBy = 'one.target' \\\n# skipped during continuation\n; also skipped\n \"two.target\"\nWantedBy=one.target\nAlias=alias.service\n", []string{"one.target.wants/demo.service", "two.target.wants/demo.service", "alias.service"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := setup(t)
			source := installFixture(t, f, tc.body)
			links := []UnitLink{}
			for _, path := range tc.paths {
				links = append(links, UnitLink{Path: filepath.Join(f.sys.unitRoot, path), Target: source})
			}
			installReply(t, f, links, links)
			must(t, f.l.Enable("demo.service"))
			got := f.l.rows[len(f.l.rows)-1].Body.Result.Identities[0].Unit.Links
			if len(got) != len(links) {
				t.Fatalf("recorded %d links, want %d", len(got), len(links))
			}
			for j, link := range got {
				if link.Path != links[j].Path || link.Target != source || link.Ino == 0 {
					t.Fatalf("wrong receipt: %+v", link)
				}
			}
			must(t, f.l.Replay("station"))
			for _, link := range links {
				absent(t, link.Path)
			}
		})
	}
}

// Claim: an existing correct link is excluded from receipts and survives replay; conflicting paths and adoption refuse.
func TestLedgerUnitPreexistingExpectedLinks(t *testing.T) {
	for _, mode := range []string{"correct", "wrong-target", "regular-file", "adopt-reported", "all-existing", "changed-during-enable"} {
		t.Run(mode, func(t *testing.T) {
			f := setup(t)
			source := installFixture(t, f, "[Install]\nAlias=existing.service fresh.service\n")
			old := UnitLink{Path: filepath.Join(f.sys.unitRoot, "existing.service"), Target: source}
			fresh := UnitLink{Path: filepath.Join(f.sys.unitRoot, "fresh.service"), Target: source}
			if mode == "wrong-target" {
				old.Target = filepath.Join(f.sys.unitRoot, "other.service")
			}
			if mode == "regular-file" {
				must(t, os.WriteFile(old.Path, []byte("foreign"), 0600))
			} else {
				must(t, os.Symlink(old.Target, old.Path))
			}
			if mode == "all-existing" {
				must(t, os.Symlink(fresh.Target, fresh.Path))
			}
			created, reported := []UnitLink{fresh}, []UnitLink{fresh}
			if mode == "adopt-reported" {
				reported = append(reported, old)
			}
			installReply(t, f, created, reported)
			if mode == "changed-during-enable" {
				original := f.sys.fault
				f.sys.fault = func(cmd string, args []string) (fakeReply, bool) {
					r, ok := original(cmd, args)
					if ok {
						must(t, os.Remove(old.Path))
						must(t, os.Symlink(source+".other", old.Path))
					}
					return r, ok
				}
			}
			err := f.l.Enable("demo.service")
			switch mode {
			case "wrong-target", "regular-file", "all-existing":
				code(t, err, 1)
				reason := "UNIT_LINK_RETARGETED"
				if mode == "all-existing" {
					reason = "UNIT_NO_NEW_LINKS"
				}
				if !strings.Contains(err.Error(), reason) || f.sys.called("/usr/bin/systemctl enable") || len(f.l.rows) != 1 {
					t.Fatal("precondition refusal changed state", err)
				}
			case "adopt-reported", "changed-during-enable":
				code(t, err, 3)
				reason := "UNIT_ENABLE_SET_MISMATCH"
				if mode == "changed-during-enable" {
					reason = "UNIT_EXISTING_LINK_CHANGED"
				}
				if !strings.Contains(err.Error(), reason) {
					t.Fatal(err)
				}
				code(t, f.l.Replay("station"), 3)
				exists(t, fresh.Path)
			default:
				must(t, err)
				got := f.l.rows[len(f.l.rows)-1].Body.Result.Identities[0].Unit.Links
				if len(got) != 1 || got[0].Path != fresh.Path {
					t.Fatal("pre-existing link adopted", got)
				}
				// The surviving alias keeps the model enabled: replay must stop
				// on final-state mismatch after removing only the created link.
				code(t, f.l.Replay("station"), 1)
				absent(t, fresh.Path)
			}
			exists(t, old.Path)
			if mode != "regular-file" {
				target, err := os.Readlink(old.Path)
				must(t, err)
				want := old.Target
				if mode == "changed-during-enable" {
					want = source + ".other"
				}
				if target != want {
					t.Fatal("pre-existing link changed")
				}
			}
		})
	}
}

// Claim: unmodeled Install syntax and every template/specifier/default instance refuse before any intent or enable.
func TestLedgerUnitUnmodeledInstallRefused(t *testing.T) {
	cases := []struct{ name, body, reason string }{
		{"demo@.service", "[Install]\nWantedBy=one.target\n", "UNIT_TEMPLATE_REFUSED"},
		{"demo@one.service", "[Install]\nWantedBy=one.target\n", "UNIT_TEMPLATE_REFUSED"},
		{"demo.service", "[Install]\nWantedBy=%n.target\n", "UNIT_SPECIFIER_REFUSED"},
		{"demo.service", "[Install]\nAlias=demo%%.service\n", "UNIT_SPECIFIER_REFUSED"},
		{"demo.service", "[Install]\nDefaultInstance=one\n", "UNIT_DEFAULT_INSTANCE_REFUSED"},
		{"demo.service", "[Install]\nDefaultInstance=\n", "UNIT_DEFAULT_INSTANCE_REFUSED"},
		{"demo.service", "[Install]\nWantedBy=one@two.target\n", "UNIT_TEMPLATE_REFUSED"},
		{"demo.service", "[Install]\nWantedBy=one\\x20two.target\n", "UNIT_INSTALL_ESCAPE_REFUSED"},
		{"demo.service", "[Install]\nWantedBy=one.target # inline text\n", "UNIT_INSTALL_NAME"},
		{"demo.service", "[Install]\nWantedBy=one.target\\ \n two.target\n", "UNIT_INSTALL_ESCAPE_REFUSED"},
		{"demo.service", "[Install]\nUnknown=value\n", "UNIT_INSTALL_DIRECTIVE_REFUSED"},
		{"demo.service", "[Install]\nAlias=wrong.target\n", "UNIT_ALIAS_REFUSED"},
		{"demo.service", "[Install]\nWantedBy=one.target\\\n", "UNIT_INCOMPLETE"},
	}
	for j, tc := range cases {
		t.Run(fmt.Sprint(j), func(t *testing.T) {
			f := setup(t)
			installFixture(t, f, tc.body)
			err := f.l.Enable(tc.name)
			code(t, err, 1)
			if !strings.Contains(err.Error(), tc.reason) || len(f.l.rows) != 1 || f.sys.called("/usr/bin/systemctl enable") {
				t.Fatal("unmodeled install crossed precondition", err)
			}
		})
	}
}

// Claim: unit/type/dashed-prefix Install drop-ins refuse; a Service-only drop-in remains a valid neighbor.
func TestLedgerUnitInstallDropinsRefused(t *testing.T) {
	for _, sub := range []string{"demo.service.d", "service.d", "demo-.service.d"} {
		for _, section := range []string{"Install", "Service"} {
			t.Run(sub+section, func(t *testing.T) {
				f := setup(t)
				name := "demo.service"
				if sub == "demo-.service.d" {
					name = "demo-child.service"
					f.sys.units[name] = "disabled"
					must(t, os.WriteFile(filepath.Join(f.sys.unitRoot, name), []byte("[Install]\nWantedBy=multi-user.target\n"), 0600))
				}
				dir := filepath.Join(f.sys.unitRoot, "vendor", sub)
				must(t, os.MkdirAll(dir, 0700))
				body := "[" + section + "]\n"
				if section == "Install" {
					body += "WantedBy=other.target\n"
				} else {
					body += "Environment=EXAMPLE=1\n"
				}
				must(t, os.WriteFile(filepath.Join(dir, "override.conf"), []byte(body), 0600))
				if section == "Service" {
					_, err := expectedUnitInstall(f.sys, name)
					must(t, err)
					return
				}
				err := f.l.Enable(name)
				code(t, err, 1)
				if !strings.Contains(err.Error(), "UNIT_INSTALL_DROPIN_REFUSED") || len(f.l.rows) != 1 || f.sys.called("/usr/bin/systemctl enable") {
					t.Fatal(err)
				}
			})
		}
	}
}

// Claim: search precedence binds targets to the selected source; a selected alias/mask never falls through to a vendor file.
func TestLedgerUnitInstallSourceResolution(t *testing.T) {
	for _, mode := range []string{"local", "vendor", "selected-symlink", "missing"} {
		t.Run(mode, func(t *testing.T) {
			f := setup(t)
			local := filepath.Join(f.sys.unitRoot, "demo.service")
			vendor := filepath.Join(f.sys.unitRoot, "vendor", "demo.service")
			must(t, os.MkdirAll(filepath.Dir(vendor), 0700))
			must(t, os.WriteFile(vendor, []byte("[Install]\nAlias=vendor-alias.service\n"), 0600))
			if mode != "local" {
				must(t, os.Remove(local))
			}
			if mode == "selected-symlink" {
				must(t, os.Symlink(vendor, local))
			}
			if mode == "missing" {
				must(t, os.Remove(vendor))
			}
			plan, err := expectedUnitInstall(f.sys, "demo.service")
			if mode == "selected-symlink" || mode == "missing" {
				reason := "UNIT_FILE_REFUSED"
				if mode == "missing" {
					reason = "UNIT_FILE_MISSING"
				}
				if err == nil || err.Error() != reason {
					t.Fatalf("got %v, want %s", err, reason)
				}
				return
			}
			must(t, err)
			want := UnitLink{Path: filepath.Join(f.sys.unitRoot, "multi-user.target.wants", "demo.service"), Target: local}
			if mode == "vendor" {
				want = UnitLink{Path: filepath.Join(f.sys.unitRoot, "vendor-alias.service"), Target: vendor}
			}
			if len(plan.Expected) != 1 || plan.Expected[0] != want || len(plan.Missing) != 1 || len(plan.Existing) != 0 {
				t.Fatalf("unexpected source/links: %+v, want %+v", plan, want)
			}
		})
	}
}

// Claim: UpheldBy is modeled only on audited supporting versions; ordinary WantedBy remains valid on older versions.
func TestLedgerUnitUpheldByVersionBound(t *testing.T) {
	for _, version := range []string{"249", "253", "254", "259", "260", "unknown"} {
		for _, directive := range []string{"WantedBy", "UpheldBy"} {
			t.Run(version+directive, func(t *testing.T) {
				f := setup(t)
				installFixture(t, f, "[Install]\n"+directive+"=one.target\n")
				f.sys.fault = func(cmd string, args []string) (fakeReply, bool) {
					if cmd == "/usr/bin/systemd-analyze" {
						return fakeReply{"systemd " + version + " (example)\n", 0, nil}, true
					}
					return fakeReply{}, false
				}
				plan, err := expectedUnitInstall(f.sys, "demo.service")
				if directive == "WantedBy" || version == "254" || version == "259" {
					must(t, err)
					if len(plan.Missing) != 1 {
						t.Fatal("missing valid expected link")
					}
				} else if err == nil || err.Error() != "UNIT_UPHELD_BY_VERSION_REFUSED" {
					t.Fatalf("got %v, want named version refusal", err)
				}
			})
		}
	}
}
