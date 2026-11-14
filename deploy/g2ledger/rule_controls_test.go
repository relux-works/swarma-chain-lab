//go:build linux

package g2ledger

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Claim: the public adapter rejects an otherwise valid, absent secret target
// solely at creatorCommand. Positive whitelist binding uses this executable.
func TestLedgerCreatorWhitelistIsolated(t *testing.T) {
	f := setupWith(t, "rehearsal", func(f *fixture) { f.declare("target", "secret") })
	target := filepath.Join(f.root, "target")
	f.l.Close()
	f.sys.tool = func(string, []string) (string, int, error) { return "", 0, nil }
	err := Run([]string{"exec-create", "-dir", f.dir, "-kind", "secret", "-ret", "remove", "-path", target, "--", "/usr/bin/true"}, f.sys, io.Discard)
	code(t, err, 1)
	if !strings.Contains(err.Error(), "EXEC_CONTRACT") {
		t.Fatal(err)
	}
	raw, e := os.ReadFile(filepath.Join(f.dir, recordsName))
	must(t, e)
	if bytes.Count(raw, []byte{'\n'}) != 1 || f.sys.called("/usr/bin/true") {
		t.Fatal("whitelist admitted effect or intent")
	}
	absent(t, target)
	self, e := os.Executable()
	must(t, e)
	must(t, creatorCommand([]string{self, "g2-keygen", "-out", target}, []string{target}))
}

// Claim: a schema-valid retention edit changes exactly the record-hash
// predicate; stored chain links and HEAD still agree. Replay refuses before
// touching either target. The untouched positive removes a remove-ret target.
func TestLedgerRecordHashIsolated(t *testing.T) {
	for _, edit := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "valid-enum-edit"}[edit], func(t *testing.T) {
			f := setup(t)
			older := f.create(t, "older", "file", "remove")
			target := f.create(t, "target", "file", "d6")
			f.l.Close()
			if edit {
				raw, err := os.ReadFile(filepath.Join(f.dir, recordsName))
				must(t, err)
				changed := bytes.Replace(raw, []byte(`"ret":"d6"`), []byte(`"ret":"remove"`), 1)
				if bytes.Equal(raw, changed) {
					t.Fatal("plant not applied")
				}
				must(t, os.WriteFile(filepath.Join(f.dir, recordsName), changed, 0600))
			}
			err := Run([]string{"replay", "-dir", f.dir, "-mode", "station"}, f.sys, io.Discard)
			if edit {
				code(t, err, 1)
				if !strings.Contains(err.Error(), "LEDGER_CHAIN seq=3") {
					t.Fatal(err)
				}
				exists(t, older)
				exists(t, target)
			} else {
				must(t, err)
				absent(t, older)
				exists(t, target)
			}
		})
	}
}

// Claim: inode and content digest drift are independently checked while size,
// mode, uid/gid and mtime remain identical. Other cases isolate receipt fields
// with a schema-valid reseal, not an authentication claim about root writers.
func TestLedgerIdentityPredicatesIsolated(t *testing.T) {
	for _, field := range []string{"valid", "ino", "sha256", "dev", "uid", "gid", "mode", "size", "mtime"} {
		t.Run(field, func(t *testing.T) {
			f := setup(t)
			older := f.create(t, "older", "file", "remove")
			target := f.create(t, "target", "file", "remove")
			info, err := os.Stat(target)
			must(t, err)
			content, err := os.ReadFile(target)
			must(t, err)
			rows := append([]Record(nil), f.l.rows...)
			switch field {
			case "ino":
				must(t, os.Rename(target, target+".saved"))
				must(t, os.WriteFile(target, content, info.Mode().Perm()))
				must(t, os.Chtimes(target, info.ModTime(), info.ModTime()))
			case "sha256":
				content[0] ^= 1
				must(t, os.WriteFile(target, content, info.Mode().Perm()))
				must(t, os.Chtimes(target, info.ModTime(), info.ModTime()))
			case "dev":
				rows[4].Body.Result.Identities[0].FS.Dev++
			case "uid":
				rows[4].Body.Result.Identities[0].FS.UID++
				rows[3].Body.Action.UID++
			case "gid":
				rows[4].Body.Result.Identities[0].FS.GID++
				rows[3].Body.Action.GID++
			case "mode":
				rows[4].Body.Result.Identities[0].FS.Mode ^= 0040
				rows[3].Body.Action.Mode ^= 0040
			case "size":
				rows[4].Body.Result.Identities[0].FS.Size++
			case "mtime":
				rows[4].Body.Result.Identities[0].FS.MtimeNS++
			}
			if field == "ino" || field == "sha256" {
				got, err := observe(target, "file")
				must(t, err)
				before := *rows[4].Body.Result.Identities[0].FS
				if field == "ino" {
					got.FS.Ino = before.Ino
				} else {
					got.FS.SHA256 = before.SHA256
				}
				if !bytes.Equal(canonical(*got.FS), canonical(before)) {
					t.Fatal("plant changed another identity predicate")
				}
			}
			f.l.Close()
			if field != "valid" && field != "ino" && field != "sha256" {
				writeRows(t, f, rows, true)
				must(t, Run([]string{"verify", "-dir", f.dir}, f.sys, io.Discard))
			}
			err = Run([]string{"replay", "-dir", f.dir, "-mode", "station"}, f.sys, io.Discard)
			if field == "valid" {
				must(t, err)
				absent(t, target)
				absent(t, older)
			} else {
				code(t, err, 1)
				if !strings.Contains(err.Error(), "IDENTITY_MISMATCH") {
					t.Fatal(err)
				}
				exists(t, target)
				exists(t, older)
			}
		})
	}
}

// Claim: a nonuniform commit derives its actual first twelve hex characters;
// shifting the prefix by one is detected (uniform synthetic pins cannot do so).
func TestLedgerNonuniformManifestPinIsolated(t *testing.T) {
	f := setup(t)
	f.l.Close()
	manifest := filepath.Join(f.root, "manifest.json")
	raw, err := os.ReadFile(manifest)
	must(t, err)
	raw = bytes.Replace(raw, bytes.Repeat([]byte("a"), 40), []byte("0123456789abcdef0123456789abcdef01234567"), 1)
	must(t, os.WriteFile(manifest, raw, 0600))
	dir := filepath.Join(f.root, "pin-ledger")
	must(t, Init(dir, manifest, filepath.Join(f.root, "baseline"), InitOptions{Purpose: "station", Scope: f.scope, System: f.sys}))
	must(t, Run([]string{"verify", "-dir", dir}, f.sys, io.Discard))
	raw, err = os.ReadFile(filepath.Join(dir, recordsName))
	must(t, err)
	if !bytes.Contains(raw, []byte(`"h12":"0123456789ab"`)) {
		t.Fatal("wrong prefix")
	}
}
