//go:build linux

package g2run

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/swarma-chain-lab/deploy/g2ledger"
	"golang.org/x/sys/unix"
)

func portFixture(t *testing.T, name string, dst any) {
	t.Helper()
	b, e := os.ReadFile("../testdata/g2run-ports/" + name + ".json")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, dst); e != nil {
		t.Fatal(e)
	}
}
func portWrite(t *testing.T, p string, b []byte) {
	t.Helper()
	if e := os.WriteFile(p, b, 0600); e != nil {
		t.Fatal(e)
	}
}
func portMkdir(t *testing.T, p string) {
	t.Helper()
	if e := os.MkdirAll(p, 0700); e != nil {
		t.Fatal(e)
	}
}
func portFS(t *testing.T) (PortFS, string) {
	t.Helper()
	root := t.TempDir()
	return PortFS{Roots: []string{root}}, root
}
func portSHA(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// Claim: the source's staged-unit, parent-closure and purpose vectors produce
// the same complete scope. Every source refusal leaves its output absent; an
// existing output remains byte-for-byte unchanged. These are fixture paths only.
func TestScopeOriginalVectors(t *testing.T) {
	var v struct {
		Commit, Wallet, Slot string
		Expected             map[string]g2ledger.Scope
		Cases                []struct {
			Name, Mutation string
			OK             bool
		}
	}
	portFixture(t, "scope", &v)
	for _, tc := range v.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			fs, root := portFS(t)
			stage := root + "/stage"
			portMkdir(t, stage+"/slotd")
			wallet := stage + "/swarma-wallet.service"
			slot := stage + "/slotd/swarma-slotd-demo.service"
			portWrite(t, wallet, []byte(v.Wallet))
			portWrite(t, slot, []byte(v.Slot))
			purpose := "station"
			if tc.Mutation == "rehearsal" {
				purpose = "rehearsal"
			}
			wantRaw, _ := json.Marshal(v.Expected[purpose])
			var want g2ledger.Scope
			json.Unmarshal(wantRaw, &want)
			spec := ScopeSpec{Purpose: purpose, Commit: v.Commit, Stage: stage, UnitDirectory: "/etc/systemd/system", WantsDirectory: "/etc/systemd/system/multi-user.target.wants", Paths: append([]g2ledger.ScopePath(nil), want.Paths...), Users: want.Users, Groups: want.Groups, Reused: append([]string(nil), want.Reused...), Node: want.Node}
			for i := range spec.Paths {
				spec.Paths[i].Path = strings.ReplaceAll(spec.Paths[i].Path, v.Commit[:12], "@VERSION@")
			}
			for _, u := range want.FutureUnits {
				rel := strings.TrimPrefix(u.Source, "@STAGE@/")
				pin := ""
				if strings.HasPrefix(rel, "slotd/") {
					pin = u.SHA256
				}
				spec.Units = append(spec.Units, StagedUnitSpec{u.Name, rel, pin})
			}
			for i := range want.FutureUnits {
				want.FutureUnits[i].Source = strings.ReplaceAll(want.FutureUnits[i].Source, "@STAGE@", stage)
			}
			out := root + "/scope.json"
			switch tc.Mutation {
			case "short-commit":
				spec.Commit = "0123"
			case "bad-purpose":
				spec.Purpose = "bogus"
			case "exists":
				portWrite(t, out, []byte("keep"))
			case "missing-reused":
				for i, r := range spec.Reused {
					if r == "/usr/local/sbin" {
						spec.Reused = append(spec.Reused[:i], spec.Reused[i+1:]...)
						break
					}
				}
			case "missing":
				if e := os.Remove(wallet); e != nil {
					t.Fatal(e)
				}
			case "symlink":
				if e := os.Rename(wallet, stage+"/real"); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink("real", wallet); e != nil {
					t.Fatal(e)
				}
			case "dir-symlink":
				if e := os.Rename(stage+"/slotd", stage+"/real"); e != nil {
					t.Fatal(e)
				}
				if e := os.Symlink("real", stage+"/slotd"); e != nil {
					t.Fatal(e)
				}
			case "fifo":
				if e := os.Remove(wallet); e != nil {
					t.Fatal(e)
				}
				if e := unix.Mkfifo(wallet, 0600); e != nil {
					t.Fatal(e)
				}
			case "token":
				portWrite(t, wallet, []byte(strings.ReplaceAll(v.Wallet, v.Commit[:12], "@VERSION@")))
			case "install":
				portWrite(t, wallet, []byte(strings.ReplaceAll(v.Wallet, "WantedBy=multi-user.target", "WantedBy=multi-user.target graphical.target")))
			case "alias":
				portWrite(t, wallet, []byte(v.Wallet+"Alias=g2.service\n"))
			case "pin":
				portWrite(t, slot, []byte(v.Slot+"\n"))
			case "relative":
				spec.Stage = "stage-relative"
			}
			e := WriteScope(fs, spec, out)
			if (e == nil) != tc.OK {
				t.Fatalf("ok=%v error=%v", tc.OK, e)
			}
			if !tc.OK {
				if tc.Mutation == "exists" {
					b, _ := os.ReadFile(out)
					if string(b) != "keep" {
						t.Fatal("output changed")
					}
				} else if _, e := os.Lstat(out); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("refusal wrote output")
				}
				return
			}
			raw, e := fs.read(out)
			if e != nil {
				t.Fatal(e)
			}
			var got g2ledger.Scope
			if e = json.Unmarshal(raw, &got); e != nil {
				t.Fatal(e)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("scope mismatch\ngot %+v\nwant %+v", got, want)
			}
			st, _ := os.Stat(out)
			if st.Mode().Perm() != 0600 {
				t.Fatal("scope permissions")
			}
		})
	}
}

// Claim: all supplied landlord type, pin, pending and safe-output vectors agree
// with the source oracle. Refusals return no success bytes and no raw controls.
func TestLandlordOriginalVectors(t *testing.T) {
	var v struct {
		Name  string
		Cases []struct {
			Name, Show, Pending, Grant, Seal, Output, Refusal string
			OK                                                bool
		}
	}
	portFixture(t, "landlord", &v)
	for _, tc := range v.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			out, e := CheckLandlord([]byte(tc.Show), []byte(tc.Pending), LandlordPin{v.Name, tc.Grant, tc.Seal})
			if (e == nil) != tc.OK {
				t.Fatalf("ok=%v error=%v", tc.OK, e)
			}
			if !tc.OK && (e == nil || e.Error() != tc.Refusal) {
				t.Fatalf("refusal %v != %s", e, tc.Refusal)
			}
			if tc.OK {
				if out != tc.Output {
					t.Fatalf("output %q != %q", out, tc.Output)
				}
			} else if out != "" || strings.ContainsAny(e.Error(), "\r\n") {
				t.Fatalf("unsafe refusal: %q %v", out, e)
			}
		})
	}
}

// Claim: source manifest type/compactness vectors agree, and approved or live
// digest mismatches, unknown fields and reordered file entries refuse signing.
func TestManifestOriginalVectors(t *testing.T) {
	var v struct {
		Release string
		GID     uint32
		Cases   []struct {
			Name, Raw, Approved, Refusal string
			OK                           bool
		}
	}
	portFixture(t, "manifest", &v)
	for _, tc := range v.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			fs, root := portFS(t)
			for _, name := range []string{"receipt.key", "service.json", "wallet.json"} {
				portWrite(t, root+"/"+name, []byte(name))
			}
			raw := strings.ReplaceAll(tc.Raw, "@WALLET@", root)
			approved := strings.ReplaceAll(tc.Approved, "@WALLET@", root)
			e := CheckInstallManifest(fs, []byte(raw), []byte(approved), InstallManifestSpec{v.Release, "wallet", root, v.GID})
			if !tc.OK && (e == nil || e.Error() != tc.Refusal) {
				t.Fatalf("refusal %v != %s", e, tc.Refusal)
			}
			if (e == nil) != tc.OK {
				t.Fatalf("ok=%v error=%v", tc.OK, e)
			}
		})
	}
	t.Run("approved-and-live-digests", func(t *testing.T) {
		fs, root := portFS(t)
		spec := InstallManifestSpec{v.Release, "wallet", root, v.GID}
		want := map[string]string{}
		for _, n := range []string{"receipt.key", "service.json", "wallet.json"} {
			portWrite(t, root+"/"+n, []byte(n))
			want[root+"/"+n] = portSHA([]byte(n))
		}
		raw, e := BuildInstallManifest(fs, spec)
		if e != nil {
			t.Fatal(e)
		}
		approved, _ := json.Marshal(want)
		if e = CheckInstallManifest(fs, raw, approved, spec); e != nil {
			t.Fatal(e)
		}
		wrong := bytes.Replace(approved, []byte(want[root+"/receipt.key"]), []byte(strings.Repeat("b", 64)), 1)
		if e = CheckInstallManifest(fs, raw, wrong, spec); e == nil || e.Error() != "MANIFEST_APPROVED_HASHES" {
			t.Fatal(e)
		}
		portWrite(t, root+"/receipt.key", []byte("changed"))
		if e = CheckInstallManifest(fs, raw, approved, spec); e == nil || e.Error() != "MANIFEST_LIVE_DIGEST" {
			t.Fatal(e)
		}
	})
}

// Claim: the source drift recipes preserve the whole identity (including old
// atime), refuse replacement/state collision/malformed state without target
// writes, and never follow a symlink. O_NOATIME permission errors fail the test.
func TestDriftOriginalVectors(t *testing.T) {
	var v struct {
		Cases []struct {
			Name, Mutation, Content string
			OK                      bool
		}
	}
	portFixture(t, "drift", &v)
	for _, tc := range v.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			fs, root := portFS(t)
			p, state := root+"/service.json", root+"/state.json"
			content := []byte(tc.Content)
			if tc.Mutation == "empty" {
				content = nil
			}
			portWrite(t, p, content)
			if tc.Mutation == "negative-atime" {
				if e := unix.UtimesNanoAt(unix.AT_FDCWD, p, []unix.Timespec{unix.NsecToTimespec(-1000000000), unix.NsecToTimespec(-500000000)}, 0); e != nil {
					t.Fatal(e)
				}
			}
			if tc.Mutation == "old-atime" {
				if e := unix.UtimesNanoAt(unix.AT_FDCWD, p, []unix.Timespec{unix.NsecToTimespec(1577934245111111111), unix.NsecToTimespec(1577934245222222222)}, 0); e != nil {
					t.Fatal(e)
				}
			}
			before, e := ReadDriftIdentity(fs, p)
			if e != nil {
				t.Fatal(e)
			}
			switch tc.Mutation {
			case "symlink":
				link := root + "/link"
				if e = os.Symlink(p, link); e != nil {
					t.Fatal(e)
				}
				_, e = ReadDriftIdentity(fs, link)
			case "bad-state":
				portWrite(t, state, []byte("{bad"))
				e = RestoreDrift(fs, p, state)
			case "exists":
				portWrite(t, state, []byte("x"))
				e = FlipDrift(fs, p, state)
			default:
				e = FlipDrift(fs, p, state)
				if e == nil {
					flipped, err := ReadDriftIdentity(fs, p)
					if err != nil {
						t.Fatal(err)
					}
					if flipped.Ino != before.Ino || flipped.SHA256 == before.SHA256 {
						t.Fatal("flip did not change same inode")
					}
				}
				if tc.Mutation == "replace" {
					portWrite(t, p+".new", []byte("REPLACED"))
					if e = os.Rename(p+".new", p); e != nil {
						t.Fatal(e)
					}
				}
				if e == nil {
					e = RestoreDrift(fs, p, state)
				}
			}
			if (e == nil) != tc.OK {
				t.Fatalf("ok=%v error=%v", tc.OK, e)
			}
			after, err := ReadDriftIdentity(fs, p)
			if err != nil {
				t.Fatal(err)
			}
			if tc.OK && after != before {
				t.Fatalf("identity changed: %+v vs %+v", after, before)
			}
			if !tc.OK && tc.Mutation != "replace" && after != before {
				t.Fatal("refusal modified target")
			}
			if tc.OK {
				if _, e := os.Lstat(state); !errors.Is(e, os.ErrNotExist) {
					t.Fatal("state not removed")
				}
			}
		})
	}
}

func ownsRecords(t *testing.T, fs PortFS, p string, abort bool) []byte {
	t.Helper()
	id, e := ReadDriftIdentity(fs, p)
	if e != nil {
		t.Fatal(e)
	}
	stat := g2ledger.FSIdentity{Dev: id.Dev, Ino: id.Ino, Type: "file", Mode: id.Mode, UID: id.UID, GID: id.GID, Size: id.Size, MtimeNS: id.MtimeNS, SHA256: id.SHA256}
	op := "commit"
	if abort {
		op = "abort"
	}
	records := []any{map[string]any{"seq": 0, "body": map[string]any{"op": "genesis"}}, map[string]any{"seq": 1, "body": map[string]any{"op": "intent", "action": map[string]any{"kind": "file", "paths": []string{p}}}}, map[string]any{"seq": 2, "body": map[string]any{"op": op, "result": map[string]any{"intent": 1, "identities": []any{map[string]any{"path": p, "fs": stat}}}}}}
	var b []byte
	for _, r := range records {
		raw, e := json.Marshal(r)
		if e != nil {
			t.Fatal(e)
		}
		b = append(b, raw...)
		b = append(b, '\n')
	}
	return b
}

// Claim: original committed/replaced/appended/aborted/malformed-ledger vectors
// have the same three outcomes. Metadata mismatch does not read the file, and
// a matching-metadata digest mismatch is still NOT OWNED without moving atime.
func TestLedgerOwnsOriginalVectors(t *testing.T) {
	var v struct {
		Cases []struct {
			Name, Mutation string
			OracleRC       int `json:"oracle_rc"`
		}
	}
	portFixture(t, "ledger_owns", &v)
	for _, tc := range v.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			fs, root := portFS(t)
			p := root + "/unit.service"
			portWrite(t, p, []byte("[Service]\nExecStart=/usr/bin/true\n"))
			portMkdir(t, root+"/ledger")
			if tc.Mutation == "negative-atime" {
				if e := unix.UtimesNanoAt(unix.AT_FDCWD, p, []unix.Timespec{unix.NsecToTimespec(-1000000000), unix.NsecToTimespec(-500000000)}, 0); e != nil {
					t.Fatal(e)
				}
			}
			records := ownsRecords(t, fs, p, tc.Mutation == "abort")
			if tc.Mutation == "malformed" {
				records = []byte("{bad\n")
			}
			portWrite(t, root+"/ledger/records.jsonl", records)
			if tc.Mutation == "replace" {
				portWrite(t, p+".new", []byte("replacement"))
				if e := os.Rename(p+".new", p); e != nil {
					t.Fatal(e)
				}
			}
			if tc.Mutation == "append" {
				f, e := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0)
				if e != nil {
					t.Fatal(e)
				}
				_, e = f.WriteString("#")
				if e != nil {
					t.Fatal(e)
				}
				if e = f.Close(); e != nil {
					t.Fatal(e)
				}
			}
			owned, e := LedgerOwns(fs, root+"/ledger", p)
			rc := 0
			if e != nil {
				rc = 2
			} else if !owned {
				rc = 1
			}
			if rc != tc.OracleRC {
				t.Fatalf("rc=%d want=%d error=%v", rc, tc.OracleRC, e)
			}
		})
	}
	t.Run("metadata-no-read-and-digest-mismatch", func(t *testing.T) {
		fs, root := portFS(t)
		p := root + "/unit"
		portWrite(t, p, []byte("SERVICE"))
		portMkdir(t, root+"/ld")
		times := []unix.Timespec{unix.NsecToTimespec(1577934245111111111), unix.NsecToTimespec(1577934245222222222)}
		if e := unix.UtimesNanoAt(unix.AT_FDCWD, p, times, 0); e != nil {
			t.Fatal(e)
		}
		records := ownsRecords(t, fs, p, false)
		portWrite(t, root+"/ld/records.jsonl", records)
		portWrite(t, p, []byte("CHANGED"))
		if e := unix.UtimesNanoAt(unix.AT_FDCWD, p, times, 0); e != nil {
			t.Fatal(e)
		}
		ok, e := LedgerOwns(fs, root+"/ld", p)
		if e != nil || ok {
			t.Fatal(ok, e)
		}
		var st unix.Stat_t
		if e = unix.Stat(p, &st); e != nil {
			t.Fatal(e)
		}
		if st.Atim != times[0] {
			t.Fatal("hash moved atime")
		}
		if e = os.Chmod(p, 0000); e != nil {
			t.Fatal(e)
		}
		defer os.Chmod(p, 0600)
		ok, e = LedgerOwns(fs, root+"/ld", p)
		if e != nil || ok {
			t.Fatalf("metadata mismatch attempted inaccessible read: %v %v", ok, e)
		}
	})
}

// Claim: node readback agrees with well-typed source outputs and refuses missing
// fields. Additional malformed-output refusals deliberately tighten the script,
// whose oracle_rc is retained so the behavioral difference remains visible.
func TestNodeRestartedOriginalVectors(t *testing.T) {
	var v struct {
		Cases []struct {
			Name, Raw, Output string
			OK                bool
		}
	}
	portFixture(t, "node_restarted", &v)
	for _, tc := range v.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			out, e := CheckNodeRestarted([]byte(tc.Raw))
			if (e == nil) != tc.OK {
				t.Fatal(e)
			}
			if out != tc.Output {
				t.Fatalf("output %q != %q", out, tc.Output)
			}
		})
	}
}

// Claim: mode/count parsing accepts only the declared bases and bounds, and the
// d30 arithmetic witness is data rejected as a mode; no expression is evaluated.
func TestPortNumericDecode(t *testing.T) {
	for _, tc := range []struct {
		s  string
		ok bool
	}{{"0700", true}, {"644", true}, {"0000", true}, {"777", true}, {"1000", false}, {"888", false}, {"-1", false}, {"+1", false}, {"700+0*OPTIND[x]", false}, {"", false}, {"0x40", false}} {
		t.Run("mode-"+tc.s, func(t *testing.T) {
			_, e := ParsePortMode(tc.s)
			if (e == nil) != tc.ok {
				t.Fatal(e)
			}
		})
	}
	for _, tc := range []struct {
		s  string
		ok bool
	}{{"0", true}, {"10", true}, {"11", false}, {"010", true}, {"1+1", false}, {"-1", false}, {"+1", false}, {"0x1", false}, {"", false}, {"18446744073709551616", false}} {
		t.Run("count-"+tc.s, func(t *testing.T) {
			_, e := ParsePortCount(tc.s, 10)
			if (e == nil) != tc.ok {
				t.Fatal(e)
			}
		})
	}
}

// Claim: the declared-root file boundary refuses symlink ancestors, traversal,
// special files and collisions while ordinary private atomic writes succeed.
func TestPortFileBoundary(t *testing.T) {
	fs, root := portFS(t)
	out := root + "/ok"
	if e := fs.writeAtomic(out, []byte("ok"), 0640); e != nil {
		t.Fatal(e)
	}
	st, _ := os.Stat(out)
	if st.Mode().Perm() != 0640 {
		t.Fatal(st.Mode())
	}
	for _, p := range []string{out, root + "/../escape", "/outside"} {
		if e := fs.writeAtomic(p, []byte("bad"), 0600); e == nil {
			t.Fatal("accepted", p)
		}
	}
	portMkdir(t, root+"/real")
	if e := os.Symlink("real", root+"/link"); e != nil {
		t.Fatal(e)
	}
	if e := fs.writeAtomic(root+"/link/x", []byte("bad"), 0600); e == nil {
		t.Fatal("followed ancestor")
	}
	if e := os.Symlink("ok", root+"/sym"); e != nil {
		t.Fatal(e)
	}
	if _, e := fs.read(root + "/sym"); e == nil {
		t.Fatal("followed file")
	}
	if e := unix.Mkfifo(root+"/fifo", 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := fs.read(root + "/fifo"); e == nil {
		t.Fatal("read FIFO")
	}
	entries, e := os.ReadDir(root)
	if e != nil {
		t.Fatal(e)
	}
	for _, en := range entries {
		if strings.HasPrefix(en.Name(), ".g2-") {
			t.Fatal("temporary leaked")
		}
	}
}

// Claim: on this test mount, an ordinary read moves the deliberately old atime;
// a restore of content alone leaves a detectable identity difference. These
// controls establish that the drift assertions can detect their named failures.
func TestDriftDetectorControls(t *testing.T) {
	fs, root := portFS(t)
	p := root + "/file"
	portWrite(t, p, []byte("SERVICE"))
	times := []unix.Timespec{unix.NsecToTimespec(1577934245111111111), unix.NsecToTimespec(1577934245222222222)}
	if e := unix.UtimesNanoAt(unix.AT_FDCWD, p, times, 0); e != nil {
		t.Fatal(e)
	}
	before, e := ReadDriftIdentity(fs, p)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = os.ReadFile(p); e != nil {
		t.Fatal(e)
	}
	after, e := ReadDriftIdentity(fs, p)
	if e != nil {
		t.Fatal(e)
	}
	if after.AtimeNS == before.AtimeNS {
		t.Fatal("CONTROL: mount did not update old atime")
	}
	if e = FlipDrift(fs, p, root+"/state"); e != nil {
		t.Fatal(e)
	}
	f, e := fs.open(p, unix.O_RDWR, false)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.WriteAt([]byte{'S'}, 0); e != nil {
		t.Fatal(e)
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
	got, e := ReadDriftIdentity(fs, p)
	if e != nil {
		t.Fatal(e)
	}
	if got == after {
		t.Fatal("CONTROL: content-only restore escaped identity check")
	}
}

// Claim: the complete generic scope generator compiles the original fixed path
// shapes and produces the entire independently captured source scope for both
// purposes. A missing upstream pin or malformed root refuses, rather than
// silently dropping a target or binding arbitrary upstream bytes.
func TestInstallScopeLayoutOriginalVectors(t *testing.T) {
	var v struct {
		Commit, Wallet, Slot string
		Layout               InstallScopeLayout
		Expected             map[string]g2ledger.Scope
	}
	portFixture(t, "scope", &v)
	for _, purpose := range []string{"station", "rehearsal"} {
		t.Run(purpose, func(t *testing.T) {
			fs, root := portFS(t)
			stage := root + "/stage"
			portMkdir(t, stage+"/slotd")
			portWrite(t, stage+"/swarma-wallet.service", []byte(v.Wallet))
			portWrite(t, stage+"/slotd/swarma-slotd-demo.service", []byte(v.Slot))
			l := v.Layout
			l.Purpose = purpose
			l.Commit = v.Commit
			l.Stage = stage
			got, e := BuildInstallScope(fs, l)
			if e != nil {
				t.Fatal(e)
			}
			raw, _ := json.Marshal(v.Expected[purpose])
			raw = bytes.ReplaceAll(raw, []byte("@STAGE@"), []byte(stage))
			var want g2ledger.Scope
			if e = json.Unmarshal(raw, &want); e != nil {
				t.Fatal(e)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("compiled shapes differ\ngot %+v\nwant %+v", got, want)
			}
			if purpose == "station" {
				l.SlotUnitPin = ""
				_, e = BuildInstallScope(fs, l)
				if e == nil || e.Error() != "SCOPE_LAYOUT_STATION" {
					t.Fatal("missing upstream pin", e)
				}
			}
			l = v.Layout
			l.Purpose = purpose
			l.Commit = v.Commit
			l.Stage = stage
			l.Data = "relative"
			if _, e = BuildInstallScope(fs, l); e == nil || e.Error() != "SCOPE_LAYOUT_PATH" {
				t.Fatal("invalid root", e)
			}
		})
	}
}
