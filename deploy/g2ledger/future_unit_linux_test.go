//go:build linux

package g2ledger

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type futureFixture struct {
	*fixture
	baseline, manifest, scopeFile string
	payloads                      []string
}

func newFutureFixture(t *testing.T) *futureFixture {
	t.Helper()
	root := t.TempDir()
	f := &futureFixture{fixture: &fixture{root: root, dir: filepath.Join(root, "ledger"), sys: newSystem()},
		baseline: filepath.Join(root, "baseline"), manifest: filepath.Join(root, "manifest.json"), scopeFile: filepath.Join(root, "scope.json")}
	f.sys.unitRoot = filepath.Join(root, "etc/systemd/system")
	// Model is-enabled's not-found result from real file absence, including after rollback.
	f.sys.fault = func(cmd string, args []string) (fakeReply, bool) {
		if cmd == "/usr/bin/systemctl" && args[0] == "is-enabled" {
			if _, err := os.Lstat(filepath.Join(f.sys.unitRoot, args[1])); os.IsNotExist(err) {
				return fakeReply{"not-found\n", 4, nil}, true
			}
		}
		return fakeReply{}, false
	}
	stage := filepath.Join(root, "stage")
	wants := filepath.Join(f.sys.unitRoot, "multi-user.target.wants")
	for _, dir := range []string{f.baseline, stage, wants} {
		must(t, os.MkdirAll(dir, 0700))
	}
	must(t, os.WriteFile(filepath.Join(f.baseline, "taken-at.txt"), []byte("captured\n"), 0600))
	must(t, os.WriteFile(filepath.Join(f.baseline, "errors.txt"), nil, 0600))
	raw, err := os.ReadFile("testdata/release-manifest.json")
	must(t, err)
	must(t, os.WriteFile(f.manifest, raw, 0600))
	f.scope.Reused = []string{f.sys.unitRoot, wants, stage}
	f.scope.Users, f.scope.Groups = []string{}, []string{}
	for _, name := range []string{"swarma-slotd-demo.service", "swarma-wallet.service"} {
		body := []byte("[Unit]\nDescription=public fixture\n[Service]\nExecStart=/bin/true\n[Install]\nWantedBy=multi-user.target\n")
		payload := filepath.Join(root, name+".payload")
		must(t, os.WriteFile(payload, body, 0600))
		f.payloads = append(f.payloads, payload)
		source, target := filepath.Join(stage, name), filepath.Join(f.sys.unitRoot, name)
		f.scope.Units = append(f.scope.Units, name)
		f.scope.Paths = append(f.scope.Paths, ScopePath{Path: source, Kind: "file"}, ScopePath{Path: target, Kind: "file"})
		f.scope.FutureUnits = append(f.scope.FutureUnits, FutureUnit{Name: name, Source: source, SHA256: digest(body),
			Links: []FutureUnitLink{{Path: filepath.Join(wants, name), Target: target}}})
	}
	return f
}

func (f *futureFixture) init(t *testing.T) error {
	t.Helper()
	must(t, os.WriteFile(f.scopeFile, canonical(f.scope), 0600))
	return Run([]string{"init", "-dir", f.dir, "-manifest", f.manifest, "-baseline", f.baseline, "-purpose", "station", "-scope", f.scopeFile}, f.sys, &bytes.Buffer{})
}
func (f *futureFixture) open(t *testing.T) {
	t.Helper()
	var err error
	f.l, err = Open(f.dir, f.sys)
	must(t, err)
	t.Cleanup(func() { f.l.Close() })
}
func (f *futureFixture) install(t *testing.T) {
	t.Helper()
	for i, unit := range f.scope.FutureUnits {
		must(t, f.l.CreateFS(unit.Source, f.payloads[i], "file", "remove", uint32(os.Geteuid()), uint32(os.Getegid()), 0600))
		must(t, f.l.CreateFS(unit.Links[0].Target, unit.Source, "file", "remove", uint32(os.Geteuid()), uint32(os.Getegid()), 0600))
		f.sys.units[unit.Name] = "disabled"
	}
}
func (f *futureFixture) noEnable(t *testing.T, err error, reason string, count int) {
	t.Helper()
	code(t, err, 1)
	if !strings.Contains(err.Error(), reason) || f.sys.called("/usr/bin/systemctl enable") || len(f.l.rows) != count {
		t.Fatalf("refusal/effect boundary: %v rows=%d want=%d", err, len(f.l.rows), count)
	}
	for _, unit := range f.scope.FutureUnits {
		for _, link := range unit.Links {
			absent(t, link.Path)
		}
	}
}

// Claim: station-shaped init needs neither staged nor installed units; matching later installs enable and name each link as its reused-parent cause.
func TestLedgerFutureUnitStationAbsentInitAndEnable(t *testing.T) {
	f := newFutureFixture(t)
	for _, unit := range f.scope.FutureUnits {
		absent(t, unit.Source)
		absent(t, unit.Links[0].Target)
	}
	code(t, f.init(t), 0)
	f.open(t)
	if !bytes.Equal(canonical(f.scope), canonical(f.l.rows[0].Body.Genesis.Scope)) {
		t.Fatal("future plan not bound to genesis")
	}
	f.install(t)
	// The original scope file is no longer authoritative after sealing.
	must(t, os.WriteFile(f.scopeFile, []byte("{}"), 0600))
	for _, name := range f.scope.Units {
		must(t, f.l.Enable(name))
	}
	f.reopen(t)
	var out bytes.Buffer
	f.l.output = &out
	must(t, f.l.Replay("station"))
	row := parentRow(t, comparisonRows(t, &out), filepath.Dir(f.scope.FutureUnits[0].Links[0].Path))
	if row.Verdict != "ALLOWED-NAMED" || len(row.Causes) != 2 {
		t.Fatalf("missing link causes: %+v", row)
	}
	for _, unit := range f.scope.FutureUnits {
		found := false
		for _, cause := range row.Causes {
			found = found || cause.Object == unit.Links[0].Path
		}
		if !found {
			t.Fatalf("missing cause %s: %+v", unit.Name, row)
		}
	}
}

// Claim: changed installed bytes with an unchanged Install inventory refuse by unit name before intent or any link; the exact bytes work above.
func TestLedgerFutureUnitSHA256BeforeEffect(t *testing.T) {
	f := newFutureFixture(t)
	must(t, f.init(t))
	f.open(t)
	f.install(t)
	unit := f.scope.FutureUnits[0]
	raw, err := os.ReadFile(unit.Links[0].Target)
	must(t, err)
	must(t, os.WriteFile(unit.Links[0].Target, append(raw, []byte("# changed bytes\n")...), 0600))
	count := len(f.l.rows)
	f.noEnable(t, f.l.Enable(unit.Name), "FUTURE_UNIT_SHA256_MISMATCH "+unit.Name, count)
}

// Claim: hash-matching units with extra, omitted, retargeted or renamed declared links refuse before intent/effect; exact unordered sets work.
func TestLedgerFutureUnitInventoryBeforeEffect(t *testing.T) {
	for _, variant := range []string{"extra-actual", "missing-actual", "wrong-target", "wrong-path", "valid-unordered"} {
		t.Run(variant, func(t *testing.T) {
			f := newFutureFixture(t)
			unit := &f.scope.FutureUnits[0]
			body, err := os.ReadFile(f.payloads[0])
			must(t, err)
			if variant == "extra-actual" || variant == "valid-unordered" {
				body = append(body, []byte("Alias=extra.service\n")...)
				unit.SHA256 = digest(body)
				must(t, os.WriteFile(f.payloads[0], body, 0600))
			}
			extra := FutureUnitLink{Path: filepath.Join(f.sys.unitRoot, "extra.service"), Target: unit.Links[0].Target}
			switch variant {
			case "missing-actual":
				unit.Links = append(unit.Links, extra)
			case "wrong-target":
				unit.Links[0].Target = filepath.Join(f.sys.unitRoot, "vendor", unit.Name)
			case "wrong-path":
				unit.Links[0].Path = filepath.Join(filepath.Dir(unit.Links[0].Path), "other.service")
			case "valid-unordered":
				unit.Links = append([]FutureUnitLink{extra}, unit.Links...)
			}
			must(t, f.init(t))
			f.open(t)
			// Install into the real search path even for a deliberately false declaration.
			for i, u := range f.scope.FutureUnits {
				must(t, os.WriteFile(u.Source, mustRead(t, f.payloads[i]), 0600))
				must(t, os.WriteFile(filepath.Join(f.sys.unitRoot, u.Name), mustRead(t, f.payloads[i]), 0600))
				f.sys.units[u.Name] = "disabled"
			}
			count := len(f.l.rows)
			if variant == "valid-unordered" {
				// The fake's explicit inventory is independent of the Install parser.
				f.sys.fault = func(cmd string, args []string) (fakeReply, bool) {
					if cmd != "/usr/bin/systemctl" || args[0] != "enable" {
						return fakeReply{}, false
					}
					output := ""
					for _, link := range unit.Links {
						must(t, os.Symlink(link.Target, link.Path))
						output += "Created symlink '" + link.Path + "' -> '" + link.Target + "'.\n"
					}
					f.sys.units[unit.Name] = "enabled"
					return fakeReply{output, 0, nil}, true
				}
				must(t, f.l.Enable(unit.Name))
				return
			}
			f.noEnable(t, f.l.Enable(unit.Name), "FUTURE_UNIT_LINK_SET_MISMATCH "+unit.Name, count)
			absent(t, extra.Path)
			absent(t, filepath.Join(f.sys.unitRoot, "multi-user.target.wants", unit.Name))
		})
	}
}
func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	must(t, err)
	return raw
}

// Claim: plan parents must be reused or future-created under reused ancestors, and unused reuse still refuses at init without a ledger.
func TestLedgerFutureUnitParentDeclarations(t *testing.T) {
	for _, variant := range []string{"undeclared", "unused", "absent-wants", "valid"} {
		t.Run(variant, func(t *testing.T) {
			f := newFutureFixture(t)
			wants := filepath.Dir(f.scope.FutureUnits[0].Links[0].Path)
			reason := ""
			switch variant {
			case "undeclared":
				f.scope.Reused = []string{f.sys.unitRoot, filepath.Dir(f.scope.FutureUnits[0].Source)}
				reason = "UNIT_LINK_PARENT_NOT_DECLARED " + wants
			case "unused":
				unused := filepath.Join(f.root, "unused")
				must(t, os.Mkdir(unused, 0700))
				f.scope.Reused = append(f.scope.Reused, unused)
				reason = "REUSED_PARENT_NOT_PROSPECTIVE " + unused
			case "absent-wants":
				must(t, os.Remove(wants))
				f.scope.Reused = []string{f.sys.unitRoot, filepath.Dir(f.scope.FutureUnits[0].Source)}
			}
			err := f.init(t)
			if reason == "" {
				must(t, err)
				f.open(t)
				f.install(t)
				must(t, f.l.Enable(f.scope.Units[0]))
			} else {
				code(t, err, 1)
				if !strings.Contains(err.Error(), reason) {
					t.Fatal(err)
				}
				absent(t, f.dir)
			}
		})
	}
}

// Claim: legacy scopes require every declared unit file even when reuse is justified by file paths; present units preserve init and enable behavior.
func TestLedgerFutureUnitLegacyRequiresInstalled(t *testing.T) {
	for _, variant := range []string{"absent", "one-absent", "present", "absent-path-parents-only"} {
		t.Run(variant, func(t *testing.T) {
			f := newFutureFixture(t)
			units := f.scope.FutureUnits
			f.scope.FutureUnits = nil
			if variant == "absent-path-parents-only" {
				f.scope.Reused = []string{f.sys.unitRoot, filepath.Dir(units[0].Source)}
			}
			if variant == "present" || variant == "one-absent" {
				for i, unit := range units {
					if variant == "one-absent" && i == 1 {
						continue
					}
					must(t, os.WriteFile(unit.Links[0].Target, mustRead(t, f.payloads[i]), 0600))
					f.sys.units[unit.Name] = "disabled"
				}
			}
			err := f.init(t)
			if variant == "present" {
				must(t, err)
				f.open(t)
				must(t, f.l.Enable(units[0].Name))
			} else {
				code(t, err, 1)
				name := units[0].Name
				if variant == "one-absent" {
					name = units[1].Name
				}
				if !strings.Contains(err.Error(), "REUSED_PROSPECTIVE_UNIT_PLAN "+name+": UNIT_FILE_MISSING") {
					t.Fatal(err)
				}
				absent(t, f.dir)
			}
		})
	}
}

// Claim: closed future-plan schemas reject malformed hashes/paths, duplicate or missing units/links and unknown nested fields before journal creation.
func TestLedgerFutureUnitClosedSchema(t *testing.T) {
	for _, variant := range []string{"hash", "relative-source", "relative-link", "relative-target", "duplicate-unit", "duplicate-link", "missing-unit", "unknown-unit", "empty", "empty-links", "unknown-field", "link-identity", "null"} {
		t.Run(variant, func(t *testing.T) {
			f := newFutureFixture(t)
			switch variant {
			case "hash":
				f.scope.FutureUnits[0].SHA256 = strings.Repeat("A", 64)
			case "relative-source":
				f.scope.FutureUnits[0].Source = "stage/unit"
			case "relative-link":
				f.scope.FutureUnits[0].Links[0].Path = "relative"
			case "relative-target":
				f.scope.FutureUnits[0].Links[0].Target = "relative"
			case "duplicate-unit":
				f.scope.FutureUnits = append(f.scope.FutureUnits, f.scope.FutureUnits[0])
			case "duplicate-link":
				f.scope.FutureUnits[0].Links = append(f.scope.FutureUnits[0].Links, f.scope.FutureUnits[0].Links[0])
			case "missing-unit":
				f.scope.FutureUnits = f.scope.FutureUnits[:1]
			case "unknown-unit":
				f.scope.FutureUnits[0].Name = "unknown.service"
			case "empty":
				f.scope.FutureUnits = []FutureUnit{}
			case "empty-links":
				f.scope.FutureUnits[0].Links = []FutureUnitLink{}
			}
			raw := canonical(f.scope)
			if variant == "empty" {
				raw = bytes.Replace(raw, []byte(`"reused":`), []byte(`"future_units":[],"reused":`), 1)
			}
			if variant == "unknown-field" {
				raw = bytes.Replace(raw, []byte(`"source":`), []byte(`"extra":true,"source":`), 1)
			}
			if variant == "link-identity" {
				raw = bytes.Replace(raw, []byte(`"target":`), []byte(`"dev":1,"target":`), 1)
			}
			if variant == "null" {
				var fields map[string]json.RawMessage
				must(t, json.Unmarshal(raw, &fields))
				fields["future_units"] = json.RawMessage(`null`)
				raw = canonical(fields)
			}
			must(t, os.WriteFile(f.scopeFile, raw, 0600))
			err := Run([]string{"init", "-dir", f.dir, "-manifest", f.manifest, "-baseline", f.baseline, "-scope", f.scopeFile}, f.sys, &bytes.Buffer{})
			code(t, err, 1)
			if !strings.Contains(err.Error(), "FUTURE_UNIT_") && !strings.Contains(err.Error(), "SCOPE_SCHEMA") {
				t.Fatal(err)
			}
			absent(t, f.dir)
		})
	}
}

// Claim: changing installed bytes after durable intent refuses by hash before enable; a quiescent intent succeeds.
func TestLedgerFutureUnitSHA256AfterIntent(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(map[bool]string{false: "unchanged", true: "changed"}[changed], func(t *testing.T) {
			f := newFutureFixture(t)
			must(t, f.init(t))
			f.open(t)
			f.install(t)
			unit := f.scope.FutureUnits[0]
			if changed {
				f.l.afterIntent = func(Action) error {
					raw := mustRead(t, unit.Links[0].Target)
					return os.WriteFile(unit.Links[0].Target, append(raw, []byte("# changed after intent\n")...), 0600)
				}
			}
			count := len(f.l.rows)
			err := f.l.Enable(unit.Name)
			if changed {
				f.noEnable(t, err, "FUTURE_UNIT_SHA256_MISMATCH "+unit.Name, count+1)
			} else {
				must(t, err)
			}
		})
	}
}

// Claim: a pre-existing declared link is preserved and refuses the bound creation inventory before intent; an absent link enables above.
func TestLedgerFutureUnitExistingLinkBeforeEffect(t *testing.T) {
	f := newFutureFixture(t)
	must(t, f.init(t))
	f.open(t)
	f.install(t)
	unit := f.scope.FutureUnits[0]
	link := unit.Links[0]
	must(t, os.Symlink(link.Target, link.Path))
	before, present, err := observeUnitLink(UnitLink{Path: link.Path, Target: link.Target})
	must(t, err)
	if !present {
		t.Fatal("missing pre-existing control")
	}
	count := len(f.l.rows)
	err = f.l.Enable(unit.Name)
	code(t, err, 1)
	if !strings.Contains(err.Error(), "FUTURE_UNIT_LINK_SET_MISMATCH "+unit.Name) || f.sys.called("/usr/bin/systemctl enable") || len(f.l.rows) != count {
		t.Fatal(err)
	}
	after, present, err := observeUnitLink(UnitLink{Path: link.Path, Target: link.Target})
	must(t, err)
	if !present || before != after {
		t.Fatal("pre-existing link changed")
	}
}
