//go:build linux

package g2ledger

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

type fixture struct {
	root, dir, src string
	l              *Ledger
	sys            *fakeSystem
	scope          Scope
}

func setup(t *testing.T) *fixture { return setupWith(t, "station", nil) }
func setupWith(t *testing.T, purpose string, prepare func(*fixture)) *fixture {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "ledger")
	base := filepath.Join(root, "baseline")
	must(t, os.Mkdir(base, 0700))
	must(t, os.WriteFile(filepath.Join(base, "taken-at.txt"), []byte("captured\n"), 0600))
	must(t, os.WriteFile(filepath.Join(base, "errors.txt"), nil, 0600))
	manifest := filepath.Join(root, "manifest.json")
	manifestRaw, e := os.ReadFile("testdata/release-manifest.json")
	must(t, e)
	must(t, os.WriteFile(manifest, manifestRaw, 0600))
	f := &fixture{root: root, dir: dir, src: filepath.Join(root, "source"), sys: newSystem()}
	f.sys.unitRoot = t.TempDir()
	f.scope = Scope{Users: []string{"demo", "foreign"}, Groups: []string{"demo", "foreign", "primary", "access"}, Units: []string{"demo.service"}}
	f.sys.units["demo.service"] = "disabled"
	for _, name := range []string{"older", "newer", "own", "foreign", "public", "pre-existing", "valid", "never-created", "full-write", "not-created", "target", "ordinary", "owned", "orphan", "normal", "old.key", "wallet.json", "service.json", "probe", "config", "cli-file", "file", "parent/file", "parent/newer", "remove"} {
		f.declare(name, "file")
	}
	for _, name := range []string{"key", "pending.key", "writer.key", "outputs/key"} {
		f.declare(name, "secret")
	}
	for _, name := range []string{"directory", "state"} {
		f.declare(name, "dir")
	}
	must(t, os.WriteFile(f.src, []byte("fixture public bytes\n"), 0600))
	if prepare != nil {
		prepare(f)
	}
	must(t, Init(dir, manifest, base, InitOptions{Purpose: purpose, Scope: f.scope, System: f.sys}))
	f.l, e = Open(dir, f.sys)
	must(t, e)
	t.Cleanup(func() { f.l.Close() })
	return f
}
func (f *fixture) declare(name, kind string) {
	path := filepath.Join(f.root, name)
	for j, p := range f.scope.Paths {
		if p.Path == path {
			f.scope.Paths[j].Kind = kind
			return
		}
	}
	f.scope.Paths = append(f.scope.Paths, ScopePath{Path: path, Kind: kind})
}

func must(t *testing.T, e error) {
	t.Helper()
	if e != nil {
		t.Fatal(e)
	}
}
func code(t *testing.T, e error, want int) {
	t.Helper()
	if got := ExitCode(e); got != want {
		t.Fatalf("exit=%d want=%d err=%v", got, want, e)
	}
}
func exists(t *testing.T, p string) {
	t.Helper()
	if _, e := os.Lstat(p); e != nil {
		t.Fatalf("expected retained %s: %v", filepath.Base(p), e)
	}
}
func absent(t *testing.T, p string) {
	t.Helper()
	if _, e := os.Lstat(p); !os.IsNotExist(e) {
		t.Fatalf("expected absent %s: %v", filepath.Base(p), e)
	}
}
func (f *fixture) create(t *testing.T, name, kind, ret string) string {
	t.Helper()
	p := filepath.Join(f.root, name)
	mode := uint32(0600)
	if kind == "dir" {
		mode = 0700
	}
	must(t, f.l.CreateFS(p, f.src, kind, ret, uint32(os.Geteuid()), uint32(os.Getegid()), mode))
	return p
}
func (f *fixture) reopen(t *testing.T) {
	t.Helper()
	f.l.Close()
	l, e := Open(f.dir, f.sys)
	must(t, e)
	f.l = l
}

// Claim: init exclusively creates private state and binds attempt, release pins
// and baseline digest to the supplied manifest, refusing false or missing pins.
func TestLedgerInitDerivesManifestPinsD9_7(t *testing.T) {
	f := setup(t)
	g := f.l.rows[0].Body.Genesis
	raw, e := os.ReadFile(filepath.Join(f.root, "manifest.json"))
	must(t, e)
	if g.H12 != strings.Repeat("a", 12) || g.Commit != strings.Repeat("a", 40) || g.ReleaseSHA != digest(raw) || g.ManifestSHA256 != g.ReleaseSHA || !isHex(g.Attempt, 16) || !isHex(g.BaselineSHA256, 32) {
		t.Fatal("genesis binding")
	}
	for p, m := range map[string]os.FileMode{f.dir: 0700, filepath.Join(f.dir, recordsName): 0600, filepath.Join(f.dir, "HEAD"): 0600, filepath.Join(f.dir, "LOCK"): 0600} {
		s, e := os.Lstat(p)
		must(t, e)
		if s.Mode().Perm() != m {
			t.Fatal("private mode")
		}
	}
	code(t, Init(f.dir, filepath.Join(f.root, "manifest.json"), g.Baseline), 1)
	must(t, os.WriteFile(filepath.Join(f.root, "manifest.json"), []byte(`{"version":1,"commit":"bad"}`), 0600))
	p := filepath.Join(f.root, "bad-ledger")
	code(t, Init(p, filepath.Join(f.root, "manifest.json"), g.Baseline), 1)
	absent(t, p)
}

// Claim: a separate real process can create only a new exclusive object; this
// subprocess is also the foreign-creator witness, not a fake filesystem.
func TestLedgerCreatorProcess(t *testing.T) {
	p := os.Getenv("G2_LEDGER_TEST_CREATE")
	if p == "" {
		return
	}
	if os.Getenv("G2_LEDGER_TEST_KIND") == "dir" {
		if os.Mkdir(p, 0700) != nil {
			os.Exit(9)
		}
	} else {
		f, e := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			os.Exit(9)
		}
		if checkedWrite(f, []byte("foreign fixture\n")) != nil || f.Sync() != nil || f.Close() != nil {
			os.Exit(10)
		}
	}
	os.Exit(0)
}
func foreign(t *testing.T, path, kind string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestLedgerCreatorProcess$")
	cmd.Env = append(os.Environ(), "G2_LEDGER_TEST_CREATE="+path, "G2_LEDGER_TEST_KIND="+kind)
	if e := cmd.Run(); e != nil {
		t.Fatal("foreign subprocess", e)
	}
}

// Claim: absence at baseline or before intent grants no authority; EEXIST from
// the creating syscall refuses foreign files/directories without deleting them.
func TestLedgerAuthorityForeignCreatorD9_1(t *testing.T) {
	for _, kind := range []string{"file", "dir"} {
		for _, when := range []string{"after-baseline", "after-intent"} {
			t.Run(kind+"/"+when, func(t *testing.T) {
				f := setupWith(t, "station", func(f *fixture) { f.declare("foreign", kind); f.declare("own", kind) })
				p := filepath.Join(f.root, "foreign")
				if when == "after-baseline" {
					foreign(t, p, kind)
				} else {
					f.l.afterIntent = func(Action) error { foreign(t, p, kind); return nil }
				}
				mode := uint32(0600)
				if kind == "dir" {
					mode = 0700
				}
				code(t, f.l.CreateFS(p, f.src, kind, "remove", uint32(os.Geteuid()), uint32(os.Getegid()), mode), 1)
				f.l.afterIntent = nil
				f.reopen(t)
				code(t, f.l.Replay("station"), 1)
				exists(t, p)
				good := f.create(t, "own", kind, "remove")
				code(t, f.l.Replay("station"), 1)
				absent(t, good)
				exists(t, p)
			})
		}
	}
}

// Claim: a creation interrupted after durable intent is a named preserved
// orphan (exit 3), including a real child-created key-shaped file.
func TestLedgerCrashAfterIntentD9_3(t *testing.T) {
	f := setup(t)
	older := f.create(t, "older", "file", "remove")
	p := filepath.Join(f.root, "pending.key")
	f.l.afterIntent = func(Action) error { foreign(t, p, "file"); return errors.New("simulated interruption") }
	e := f.l.CreateFS(p, f.src, "secret", "d6", uint32(os.Geteuid()), uint32(os.Getegid()), 0600)
	code(t, e, 3)
	if !strings.Contains(e.Error(), p) {
		t.Fatal("orphan path omitted")
	}
	f.l.Close()
	_, e = Open(f.dir, f.sys)
	code(t, e, 3)
	exists(t, p)
	exists(t, older)
	// A separate resolved attempt is the valid neighbour.
	good := setupWith(t, "rehearsal", nil)
	own := good.create(t, "own", "file", "remove")
	must(t, good.l.Replay("rehearsal"))
	absent(t, own)
}

// Claim: every filesystem identity is complete and secret records contain no
// content digest or content; normal files, directories and root-valued IDs are typed.
func TestLedgerTypedCompleteIdentityAndSecret(t *testing.T) {
	f := setup(t)
	secret := []byte("private fixture scalar, never logged")
	must(t, os.WriteFile(f.src, secret, 0600))
	f.create(t, "key", "secret", "d6")
	f.create(t, "public", "file", "remove")
	f.create(t, "directory", "dir", "remove")
	for _, r := range f.l.rows {
		if r.Body.Op == "commit" {
			a := f.l.rows[r.Body.Result.Intent].Body.Action
			for _, i := range r.Body.Result.Identities {
				must(t, validateIdentity(i, a.Kind))
				if a.Kind == "secret" && i.FS.SHA256 != "" {
					t.Fatal("secret hash")
				}
			}
		}
	}
	raw, e := os.ReadFile(filepath.Join(f.dir, recordsName))
	must(t, e)
	if bytes.Contains(raw, secret) {
		t.Fatal("secret content recorded")
	}
	code(t, validateIdentity(Identity{Path: "/fixture", FS: &FSIdentity{}}, "file"), 2)
	i := Identity{Path: "/fixture", FS: &FSIdentity{Dev: 1, Ino: 2, Type: "file", Mode: 0600, Size: 1, MtimeNS: 1, SHA256: digest([]byte("x"))}}
	must(t, validateIdentity(i, "file"))
	raw = canonical(i)
	raw = bytes.Replace(raw, []byte(`"gid":0,`), nil, 1)
	var decoded Identity
	if strict(raw, &decoded) == nil {
		t.Fatal("omitted gid accepted")
	}
}

func writeRows(t *testing.T, f *fixture, rows []Record, updateHead bool) {
	t.Helper()
	prev := zeroHash
	var b []byte
	for j := range rows {
		rows[j].Seq = uint64(j)
		rows[j].Prev = prev
		rows[j].Hash = recordHash(rows[j])
		prev = rows[j].Hash
		b = append(b, canonical(rows[j])...)
		b = append(b, '\n')
	}
	must(t, os.WriteFile(filepath.Join(f.dir, recordsName), b, 0600))
	if updateHead {
		must(t, os.WriteFile(filepath.Join(f.dir, "HEAD"), canonical(head{uint64(len(rows)), prev}), 0600))
	}
}
func rejectedWithoutEffects(t *testing.T, f *fixture, paths ...string) {
	t.Helper()
	f.l.Close()
	l, e := Open(f.dir, f.sys)
	if e == nil {
		e = l.Replay("station")
		l.Close()
	}
	code(t, e, 1)
	for _, p := range paths {
		exists(t, p)
	}
}

// Claim: the same hand-added, empty-identity, renumbered duplicate/reorder,
// dropped-tail and forged-HEAD witness shapes fail before any replay effect.
// Recomputed hashes/HEAD in selected cases isolate schema/order/duplicate checks.
func TestLedgerTamperingD9_2(t *testing.T) {
	for _, attack := range []string{"hand-added-valid-seq", "empty-identity", "renumbered-duplicate", "renumbered-reorder", "drop-tail", "forged-head", "unknown-kind", "unknown-op", "bad-retention", "missing-gid", "unknown-field", "duplicate-field", "partial-record"} {
		t.Run(attack, func(t *testing.T) {
			f := setup(t)
			older := f.create(t, "older", "file", "remove")
			newer := f.create(t, "newer", "file", "remove")
			foreignPath := filepath.Join(f.root, "pre-existing")
			foreign(t, foreignPath, "file")
			rows := append([]Record(nil), f.l.rows...)
			f.l.Close()
			switch attack {
			case "hand-added-valid-seq":
				id, e := observe(foreignPath, "file")
				must(t, e)
				a := Action{Kind: "file", Ret: "remove", Paths: []string{foreignPath}, UID: id.FS.UID, GID: id.FS.GID, Mode: id.FS.Mode}
				seq := uint64(len(rows))
				rows = append(rows, Record{Body: Body{Op: "intent", Action: &a}}, Record{Body: Body{Op: "commit", Result: &Result{Intent: seq, Identities: []Identity{*id}}}})
				writeRows(t, f, rows, false)
			case "empty-identity":
				r := *rows[4].Body.Result
				r.Identities = []Identity{{Path: newer, FS: &FSIdentity{}}}
				rows[4].Body.Result = &r
				writeRows(t, f, rows, true)
			case "renumbered-duplicate":
				a := *rows[1].Body.Action
				r := *rows[2].Body.Result
				r.Intent = uint64(len(rows))
				rows = append(rows, Record{Body: Body{Op: "intent", Action: &a}}, Record{Body: Body{Op: "commit", Result: &r}})
				writeRows(t, f, rows, true)
			case "renumbered-reorder":
				rows[3], rows[4] = rows[4], rows[3]
				writeRows(t, f, rows, true)
			case "drop-tail":
				writeRows(t, f, rows[:3], false)
			case "forged-head":
				must(t, os.WriteFile(filepath.Join(f.dir, "HEAD"), canonical(head{uint64(len(rows)), zeroHash}), 0600))
			case "unknown-kind", "bad-retention":
				a := *rows[3].Body.Action
				if attack == "unknown-kind" {
					a.Kind = "create-tree"
				} else {
					a.Ret = "wildcard"
				}
				rows[3].Body.Action = &a
				writeRows(t, f, rows, true)
			case "unknown-op":
				rows[3].Body.Op = "invented"
				writeRows(t, f, rows, true)
			default:
				b, e := os.ReadFile(filepath.Join(f.dir, recordsName))
				must(t, e)
				switch attack {
				case "missing-gid":
					b = bytes.Replace(b, []byte(fmt.Sprintf(`"gid":%d,`, os.Getegid())), nil, 1)
				case "unknown-field":
					b = bytes.Replace(b, []byte(`"op":"intent"`), []byte(`"unexpected":1,"op":"intent"`), 1)
				case "duplicate-field":
					b = bytes.Replace(b, []byte(`"op":"intent"`), []byte(`"op":"intent","op":"intent"`), 1)
				case "partial-record":
					b = b[:len(b)-5]
				}
				must(t, os.WriteFile(filepath.Join(f.dir, recordsName), b, 0600))
			}
			rejectedWithoutEffects(t, f, older, newer, foreignPath)
		})
	}
	f := setup(t)
	p := f.create(t, "valid", "file", "remove")
	f.reopen(t)
	must(t, f.l.Replay("station"))
	absent(t, p)
}

// Claim: a valid-prefix truncation requires the sealed terminal HEAD check;
// verification must refuse before removing the surviving older entry.
func TestLedgerHeadDetectsValidPrefixTruncation(t *testing.T) {
	f := setup(t)
	older := f.create(t, "older", "file", "remove")
	newer := f.create(t, "newer", "file", "remove")
	rows := append([]Record(nil), f.l.rows...)
	f.l.Close()
	writeRows(t, f, rows[:3], false)
	rejectedWithoutEffects(t, f, older, newer)
}

// Claim: an actual short or zero append write never lets the caller proceed;
// any partial record is retained and rejected. The durable guard refuses even
// a zero-write failed append after reopen, preserving the uncertain evidence.
func TestLedgerShortWriteD9_6(t *testing.T) {
	for _, short := range []bool{false, true} {
		t.Run(fmt.Sprint(short), func(t *testing.T) {
			f := setup(t)
			p := filepath.Join(f.root, "never-created")
			f.l.write = func(w io.Writer, b []byte) error {
				n := 0
				if short {
					n = len(b) / 2
				}
				return checkedWrite(shortWriter{w, n}, b)
			}
			e := f.l.CreateFS(p, f.src, "file", "remove", uint32(os.Geteuid()), uint32(os.Getegid()), 0600)
			if ExitCode(e) == 0 {
				t.Fatal("short append succeeded")
			}
			absent(t, p)
			f.l.Close()
			_, e = Open(f.dir, f.sys)
			code(t, e, 1) // durable guard also refuses a zero-write failed append
		})
	}
	f := setup(t)
	p := f.create(t, "full-write", "file", "remove")
	exists(t, p)
	f.reopen(t)
}

type shortWriter struct {
	w io.Writer
	n int
}

func (w shortWriter) Write(b []byte) (int, error) { return w.w.Write(b[:w.n]) }

// Claim: an fsync-only EIO at the record descriptor (which remains open)
// refuses before creation and survives reopen. Removing record fsync alone
// makes this control fail; Close still succeeds and cannot mask that rule.
func TestLedgerAppendSyncFailure(t *testing.T) {
	f := setup(t)
	injected := false
	f.l.sync = func(file *os.File) error {
		if file.Name() == recordsName {
			injected = true
			return syscall.EIO
		}
		return file.Sync()
	}
	p := filepath.Join(f.root, "not-created")
	err := f.l.CreateFS(p, f.src, "file", "remove", uint32(os.Geteuid()), uint32(os.Getegid()), 0600)
	code(t, err, 1)
	if !injected || !strings.Contains(err.Error(), "APPEND_WRITE_SYNC") {
		t.Fatal("record fsync not exercised", err)
	}
	absent(t, p)
	f.l.Close()
	_, err = Open(f.dir, f.sys)
	code(t, err, 1)
}

// Claim: symlinks in parents or targets, replacement inodes, content/mode drift
// and a foreign directory child stop replay while preserving older entries.
func TestLedgerFilesystemDriftAndNoFollow(t *testing.T) {
	for _, change := range []string{"content", "inode", "mode", "symlink", "parent-symlink", "foreign-child"} {
		t.Run(change, func(t *testing.T) {
			f := setupWith(t, "station", func(f *fixture) {
				if change == "foreign-child" {
					f.declare("target", "dir")
				}
			})
			older := f.create(t, "older", "file", "remove")
			kind := "file"
			if change == "foreign-child" {
				kind = "dir"
			}
			p := f.create(t, "target", kind, "remove")
			info, err := os.Stat(p)
			must(t, err)
			switch change {
			case "content":
				content, err := os.ReadFile(p)
				must(t, err)
				content[0] ^= 1
				must(t, os.WriteFile(p, content, 0600))
				must(t, os.Chtimes(p, info.ModTime(), info.ModTime()))
			case "inode":
				must(t, os.Rename(p, p+".original"))
				must(t, os.WriteFile(p, []byte("fixture public bytes\n"), 0600))
				must(t, os.Chtimes(p, info.ModTime(), info.ModTime()))
			case "mode":
				must(t, os.Chmod(p, 0644))
			case "symlink":
				must(t, os.Rename(p, p+".original"))
				must(t, os.Symlink(older, p))
			case "parent-symlink":
				d := filepath.Join(f.root, "parent")
				must(t, os.Mkdir(d, 0700))
				nested := filepath.Join(d, "file")
				must(t, f.l.CreateFS(nested, f.src, "file", "remove", uint32(os.Geteuid()), uint32(os.Getegid()), 0600))
				must(t, os.Rename(d, d+".original"))
				must(t, os.Symlink(d+".original", d))
			case "foreign-child":
				foreign(t, filepath.Join(p, "child"), "file")
			}
			code(t, f.l.Replay("station"), 1)
			exists(t, older)
			exists(t, p)
		})
	}
	f := setupWith(t, "rehearsal", nil)
	p := f.create(t, "ordinary", "file", "remove")
	must(t, f.l.Replay("rehearsal"))
	absent(t, p)
}

// Claim: an EACCES lookup at the newest entry stops immediately, leaving older
// objects intact; a valid lookup removes the same-shaped owned objects.
func TestLedgerLookupEACCESStopsD9_4(t *testing.T) {
	f := setupWith(t, "station", func(f *fixture) { must(t, os.Mkdir(filepath.Join(f.root, "parent"), 0700)) })
	older := f.create(t, "older", "file", "remove")
	parentPath := filepath.Join(f.root, "parent")
	p := filepath.Join(parentPath, "newer")
	must(t, f.l.CreateFS(p, f.src, "file", "remove", uint32(os.Geteuid()), uint32(os.Getegid()), 0600))
	must(t, os.Chmod(parentPath, 0))
	t.Cleanup(func() { os.Chmod(parentPath, 0700) })
	code(t, f.l.Replay("station"), 1)
	exists(t, older)
	must(t, os.Chmod(parentPath, 0700))
	exists(t, p)
	must(t, f.l.Replay("station"))
	absent(t, older)
	absent(t, p)
}

// Claim: a private ledger lock excludes a second writer without altering any
// records. A later opener can verify after the first owner releases the lock.
func TestLedgerSerializesWriters(t *testing.T) {
	f := setup(t)
	_, e := Open(f.dir, f.sys)
	code(t, e, 1)
	if !strings.Contains(e.Error(), "BUSY") {
		t.Fatal(e)
	}
	f.reopen(t)
}

// Claim: incomplete S0 evidence, symlinked evidence and a malformed release
// manifest refuse before creating the exclusive ledger directory.
func TestLedgerInitRefusesIncompleteEvidence(t *testing.T) {
	for _, change := range []string{"errors", "missing-timestamp", "symlink", "missing-manifest-field", "false-h12"} {
		t.Run(change, func(t *testing.T) {
			f := setup(t)
			base := f.l.rows[0].Body.Genesis.Baseline
			manifest := filepath.Join(f.root, "manifest.json")
			switch change {
			case "errors":
				must(t, os.WriteFile(filepath.Join(base, "errors.txt"), []byte("inspection failed\n"), 0600))
			case "missing-timestamp":
				must(t, os.Remove(filepath.Join(base, "taken-at.txt")))
			case "symlink":
				must(t, os.Symlink(f.src, filepath.Join(base, "linked")))
			case "missing-manifest-field":
				raw, e := os.ReadFile(manifest)
				must(t, e)
				raw = bytes.Replace(raw, []byte(`"version": 1,`), nil, 1)
				must(t, os.WriteFile(manifest, raw, 0600))
			case "false-h12":
				raw, e := os.ReadFile(manifest)
				must(t, e)
				raw = bytes.Replace(raw, []byte(`"version": 1,`), []byte(`"h12":"000000000000","version":1,`), 1)
				must(t, os.WriteFile(manifest, raw, 0600))
			}
			dir := filepath.Join(f.root, "new-ledger")
			code(t, Init(dir, manifest, base), 1)
			absent(t, dir)
		})
	}
}

// Claim: stored state must remain private regular owner files and cannot be
// replaced by a symlink or a hardlink; verify refuses without replay effects.
func TestLedgerPrivateStorageNoFollow(t *testing.T) {
	for _, change := range []string{"dir-mode", "record-mode", "head-symlink", "record-hardlink"} {
		t.Run(change, func(t *testing.T) {
			f := setup(t)
			p := f.create(t, "owned", "file", "remove")
			f.l.Close()
			switch change {
			case "dir-mode":
				must(t, os.Chmod(f.dir, 0755))
			case "record-mode":
				must(t, os.Chmod(filepath.Join(f.dir, recordsName), 0644))
			case "head-symlink":
				must(t, os.Rename(filepath.Join(f.dir, "HEAD"), filepath.Join(f.root, "saved-head")))
				must(t, os.Symlink(filepath.Join(f.root, "saved-head"), filepath.Join(f.dir, "HEAD")))
			case "record-hardlink":
				must(t, os.Link(filepath.Join(f.dir, recordsName), filepath.Join(f.root, "linked-records")))
			}
			rejectedWithoutEffects(t, f, p)
		})
	}
}

// Claim: sentinel IDs and empty/wildcard identities are invalid, while actual
// root-valued ownership remains an explicit valid identity rather than absence.
func TestLedgerSchemaRejectsWildcardIDs(t *testing.T) {
	valid := FSIdentity{Dev: 1, Ino: 2, Type: "file", Mode: 0600, Size: 1, MtimeNS: 1, SHA256: digest([]byte("public"))}
	must(t, validateIdentity(Identity{Path: "/fixture", FS: &valid}, "file"))
	for _, field := range []string{"uid", "gid", "ino", "type", "hash"} {
		bad := valid
		switch field {
		case "uid":
			bad.UID = ^uint32(0)
		case "gid":
			bad.GID = ^uint32(0)
		case "ino":
			bad.Ino = 0
		case "type":
			bad.Type = "*"
		case "hash":
			bad.SHA256 = ""
		}
		if validateIdentity(Identity{Path: "/fixture", FS: &bad}, "file") == nil {
			t.Fatal("wildcard accepted", field)
		}
	}
	if validateAction(&Action{Kind: "file", Ret: "remove", Paths: []string{"/fixture"}, UID: ^uint32(0), Mode: 0600}) == nil {
		t.Fatal("wildcard action accepted")
	}
}

// Claim: failure after creation but before commit leaves a named orphan; a
// short payload write never commits a partial file as a successful creation.
func TestLedgerShortPayloadAndCommitFailure(t *testing.T) {
	for _, where := range []string{"payload", "commit"} {
		t.Run(where, func(t *testing.T) {
			f := setup(t)
			p := filepath.Join(f.root, "orphan")
			calls := 0
			f.l.write = func(w io.Writer, b []byte) error {
				calls++
				failAt := 3
				if where == "commit" {
					failAt = 4
				}
				if calls == failAt {
					return checkedWrite(shortWriter{w, len(b) / 2}, b)
				}
				return checkedWrite(w, b)
			}
			e := f.l.CreateFS(p, f.src, "file", "remove", uint32(os.Geteuid()), uint32(os.Getegid()), 0600)
			code(t, e, 3)
			if !strings.Contains(e.Error(), p) {
				t.Fatal("orphan unnamed")
			}
			exists(t, p)
			f.l.Close()
			_, e = Open(f.dir, f.sys)
			if ExitCode(e) == 0 {
				t.Fatal("incomplete creation validated")
			}
		})
	}
	f := setup(t)
	f.create(t, "normal", "file", "remove")
	f.reopen(t)
}

// Claim: a privileged chown failure leaves the actually created filesystem
// object as an orphan, never commits an invented owner identity, and stops.
func TestLedgerChownFailureIsOrphan(t *testing.T) {
	f := setup(t)
	f.sys.chownError = os.ErrPermission
	p := filepath.Join(f.root, "orphan")
	code(t, f.l.CreateFS(p, f.src, "file", "remove", 123, 456, 0600), 3)
	exists(t, p)
	f.l.Close()
	_, e := Open(f.dir, f.sys)
	code(t, e, 3)
}
