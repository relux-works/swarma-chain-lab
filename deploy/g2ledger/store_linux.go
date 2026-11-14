package g2ledger

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/relux-works/swarma-chain-lab/deploy"
	"golang.org/x/sys/unix"
)

const recordsName = "records.jsonl"
const maxLedger = 64 << 20

// The lock covers verification, all creating calls and replay, not just append.
// A failed append poisons the open handle: no subsequent operation may proceed.
type Ledger struct {
	output      io.Writer
	root        string
	dir         *os.File
	lock        *os.File
	rows        []Record
	write       func(io.Writer, []byte) error
	poisoned    bool
	sys         System
	afterIntent func(Action) error // crash/race injection; never set by the CLI
}

func randomID() string {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b[:])
}
func Init(dir, manifest, baseline string) error {
	raw, e := readFile(manifest, 1<<20)
	if e != nil {
		return stopped("MANIFEST_READ", e)
	}
	m, manifestErr := deploy.ValidateManifest(raw)
	if manifestErr != nil {
		return fail(1, "MANIFEST_SCHEMA")
	}
	taken, e := readFile(baseline+"/taken-at.txt", 4096)
	if e != nil || len(bytes.TrimSpace(taken)) == 0 {
		return fail(1, "BASELINE_INCOMPLETE taken-at.txt")
	}
	baselineErrors, e := readFile(baseline+"/errors.txt", 1<<20)
	if e != nil || len(bytes.TrimSpace(baselineErrors)) != 0 {
		return fail(1, "BASELINE_INCOMPLETE errors.txt")
	}
	sum, e := baselineDigest(baseline)
	if e != nil {
		return stopped("BASELINE_READ", e)
	}
	d, n, e := parent(dir)
	if e != nil {
		return stopped("INIT_PARENT", e)
	}
	defer d.Close()
	if e = unix.Mkdirat(int(d.Fd()), n, 0700); e != nil {
		return stopped("INIT_EXCLUSIVE "+dir, e)
	}
	root, e := at(d, n, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if e != nil {
		return stopped("INIT_DIRECTORY", e)
	}
	// Keep incomplete initialization for inspection; never retry by adopting it.
	if e = root.Chmod(0700); e != nil {
		root.Close()
		return stopped("INIT_MODE", e)
	}
	l := &Ledger{root: dir, dir: root, write: checkedWrite, sys: RealSystem{}}
	defer l.Close()
	if e = private(root, true); e != nil {
		return stopped("INIT_PRIVATE", e)
	}
	lock, e := at(root, "LOCK", unix.O_CREAT|unix.O_EXCL|unix.O_RDWR, 0600)
	if e != nil {
		return stopped("INIT_LOCK", e)
	}
	l.lock = lock
	if e = lock.Chmod(0600); e != nil {
		return stopped("INIT_LOCK_MODE", e)
	}
	if e = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return stopped("INIT_LOCK", e)
	}
	if e = lock.Sync(); e != nil {
		return stopped("INIT_LOCK_SYNC", e)
	}
	g := &Genesis{Version: 1, Attempt: randomID(), ManifestSHA256: digest(raw), ReleaseSHA: digest(raw), Commit: m.Commit, H12: m.Commit[:12], Baseline: baseline, BaselineSHA256: sum}
	if e = l.append(Body{Op: "genesis", Genesis: g}); e != nil {
		return e
	}
	if e = d.Sync(); e != nil {
		return stopped("INIT_PARENT_SYNC", e)
	}
	return nil
}
func Open(dir string, sys System) (*Ledger, error) {
	d, e := openDir(dir)
	if e != nil {
		return nil, stopped("LEDGER_DIRECTORY", e)
	}
	l := &Ledger{root: dir, dir: d, write: checkedWrite, sys: sys}
	if sys == nil {
		l.sys = RealSystem{}
	}
	bad := func(e error) (*Ledger, error) { l.Close(); return nil, e }
	if e = private(d, true); e != nil {
		return bad(stopped("LEDGER_PRIVATE", e))
	}
	lock, e := at(d, "LOCK", unix.O_RDONLY, 0)
	if e != nil {
		return bad(stopped("LEDGER_LOCK", e))
	}
	l.lock = lock
	if e = private(lock, false); e != nil {
		return bad(stopped("LEDGER_LOCK", e))
	}
	if e = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return bad(fail(1, "LEDGER_BUSY"))
	}
	if e = l.load(); e != nil {
		return bad(e)
	}
	return l, nil
}
func (l *Ledger) Close() {
	if l.lock != nil {
		unix.Flock(int(l.lock.Fd()), unix.LOCK_UN)
		l.lock.Close()
		l.lock = nil
	}
	if l.dir != nil {
		l.dir.Close()
		l.dir = nil
	}
}
func (l *Ledger) read(name string) ([]byte, error) {
	f, e := at(l.dir, name, unix.O_RDONLY, 0)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	if e = private(f, false); e != nil {
		return nil, e
	}
	b, e := io.ReadAll(io.LimitReader(f, maxLedger+1))
	if e != nil || len(b) > maxLedger {
		return nil, errors.New("LEDGER_READ_LIMIT")
	}
	return b, nil
}
func (l *Ledger) load() error {
	b, e := l.read(recordsName)
	if e != nil {
		return stopped("LEDGER_READ", e)
	}
	if len(b) == 0 || b[len(b)-1] != '\n' {
		return fail(1, "LEDGER_PARTIAL_RECORD")
	}
	lines := bytes.Split(b[:len(b)-1], []byte{'\n'})
	rows := make([]Record, 0, len(lines))
	prev := zeroHash
	pending := map[uint64]Action{}
	created := map[string]bool{}
	for j, line := range lines {
		var r Record
		if e = strict(line, &r); e != nil {
			return stopped(fmt.Sprintf("LEDGER_SCHEMA seq=%d", j), e)
		}
		if r.Seq != uint64(j) || r.Prev != prev || r.Hash != recordHash(r) {
			return fail(1, fmt.Sprintf("LEDGER_CHAIN seq=%d", j))
		}
		body := r.Body
		switch body.Op {
		case "genesis":
			g := body.Genesis
			if j != 0 || body.Action != nil || body.Result != nil || g == nil || g.Version != 1 || !isHex(g.Attempt, 16) || !isHex(g.ManifestSHA256, 32) || g.ReleaseSHA != g.ManifestSHA256 || !isHex(g.Commit, 20) || g.H12 != g.Commit[:12] || !validPath(g.Baseline) || !isHex(g.BaselineSHA256, 32) {
				return fail(1, "LEDGER_GENESIS")
			}
		case "intent":
			if j == 0 || body.Genesis != nil || body.Result != nil || len(pending) != 0 {
				return fail(1, "LEDGER_INTENT_ORDER")
			}
			if e = validateAction(body.Action); e != nil {
				return stopped("LEDGER_ACTION", e)
			}
			a := *body.Action
			for _, key := range creationKeys(a) {
				if created[key] {
					return fail(1, "LEDGER_DUPLICATE "+key)
				}
			}
			pending[r.Seq] = a
		case "commit", "abort":
			result := body.Result
			if body.Genesis != nil || body.Action != nil || result == nil {
				return fail(1, "LEDGER_RESULT_SCHEMA")
			}
			a, ok := pending[result.Intent]
			if !ok {
				return fail(1, "LEDGER_UNPAIRED_RESULT")
			}
			if body.Op == "abort" {
				if len(result.Identities) != 0 || result.Reason != "exclusive-refused" {
					return fail(1, "LEDGER_ABORT")
				}
			} else {
				if result.Reason != "" {
					return fail(1, "LEDGER_COMMIT_REASON")
				}
				if e = validateResult(a, result.Identities); e != nil {
					return stopped("LEDGER_IDENTITY", e)
				}
				for _, key := range creationKeys(a) {
					if created[key] {
						return fail(1, "LEDGER_DUPLICATE "+key)
					}
					created[key] = true
				}
			}
			delete(pending, result.Intent)
		default:
			return fail(1, "LEDGER_UNKNOWN_OP")
		}
		rows = append(rows, r)
		prev = r.Hash
	}
	if len(rows) == 0 || rows[0].Body.Op != "genesis" {
		return fail(1, "LEDGER_MISSING_GENESIS")
	}
	hb, e := l.read("HEAD")
	if e != nil {
		return stopped("HEAD_READ", e)
	}
	var h head
	if strict(hb, &h) != nil {
		return fail(1, "HEAD_SCHEMA")
	}
	if h.Count != uint64(len(rows)) || h.Hash != prev {
		return fail(1, "HEAD_MISMATCH")
	}
	l.rows = rows
	// Validation is complete before an orphan is reported or any replay effect.
	for _, a := range pending {
		return orphan(a)
	}
	return nil
}
func creationKeys(a Action) []string {
	switch a.Kind {
	case "dir", "file", "secret":
		keys := []string{}
		for _, p := range a.Paths {
			keys = append(keys, p+"|"+a.Kind)
		}
		return keys
	case "user", "group":
		return []string{a.Name + "|" + a.Kind}
	}
	return nil
}
func (l *Ledger) append(body Body) error {
	if l.poisoned {
		return fail(1, "LEDGER_POISONED")
	}
	l.poisoned = true
	seq := uint64(len(l.rows))
	prev := zeroHash
	if seq > 0 {
		prev = l.rows[len(l.rows)-1].Hash
	}
	r := Record{Seq: seq, Prev: prev, Body: body}
	r.Hash = recordHash(r)
	flags := unix.O_WRONLY | unix.O_APPEND
	if seq == 0 {
		flags |= unix.O_CREAT | unix.O_EXCL
	}
	f, e := at(l.dir, recordsName, flags, 0600)
	if e != nil {
		return stopped("APPEND_OPEN", e)
	}
	if seq == 0 {
		e = f.Chmod(0600)
	}
	if e == nil {
		e = private(f, false)
	}
	if e == nil {
		e = l.write(f, append(canonical(r), '\n'))
	}
	if e == nil {
		e = f.Sync()
	}
	e = errors.Join(e, f.Close())
	if e != nil {
		return stopped("APPEND_WRITE_SYNC", e)
	}
	if seq == 0 {
		if e = l.dir.Sync(); e != nil {
			return stopped("APPEND_DIRECTORY_SYNC", e)
		}
	}
	tmp := ".HEAD-" + randomID()
	hf, e := at(l.dir, tmp, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY, 0600)
	if e != nil {
		return stopped("HEAD_TEMP", e)
	}
	defer unix.Unlinkat(int(l.dir.Fd()), tmp, 0)
	if e = hf.Chmod(0600); e == nil {
		e = l.write(hf, canonical(head{seq + 1, r.Hash}))
	}
	if e == nil {
		e = hf.Sync()
	}
	e = errors.Join(e, hf.Close())
	if e != nil {
		return stopped("HEAD_WRITE_SYNC", e)
	}
	if e = unix.Renameat(int(l.dir.Fd()), tmp, int(l.dir.Fd()), "HEAD"); e != nil {
		return stopped("HEAD_RENAME", e)
	}
	if e = l.dir.Sync(); e != nil {
		return stopped("HEAD_DIRECTORY_SYNC", e)
	}
	l.rows = append(l.rows, r)
	l.poisoned = false
	return nil
}
func (l *Ledger) begin(a Action) (uint64, error) {
	if e := validateAction(&a); e != nil {
		return 0, stopped("ACTION", e)
	}
	if l.poisoned {
		return 0, fail(1, "LEDGER_POISONED")
	}
	if len(l.rows) > 0 && l.rows[len(l.rows)-1].Body.Op == "intent" {
		return 0, orphan(*l.rows[len(l.rows)-1].Body.Action)
	}
	for _, p := range a.Paths {
		base := l.rows[0].Body.Genesis.Baseline
		if p == l.root || strings.HasPrefix(p, l.root+"/") || strings.HasPrefix(l.root, p+"/") || p == base || strings.HasPrefix(p, base+"/") || strings.HasPrefix(base, p+"/") {
			return 0, fail(1, "LEDGER_TARGET_OVERLAP "+p)
		}
	}
	// Reject repeats before a syscall, even within one long-lived API handle.
	for _, r := range l.rows {
		if r.Body.Op == "commit" {
			old := l.rows[r.Body.Result.Intent].Body.Action
			for _, x := range creationKeys(*old) {
				for _, y := range creationKeys(a) {
					if x == y {
						return 0, fail(1, "DUPLICATE_CREATION "+y)
					}
				}
			}
		}
	}
	seq := uint64(len(l.rows))
	if e := l.append(Body{Op: "intent", Action: &a}); e != nil {
		return 0, e
	}
	if l.afterIntent != nil {
		if e := l.afterIntent(a); e != nil {
			l.poisoned = true
			return 0, orphan(a)
		}
	}
	return seq, nil
}
func (l *Ledger) commit(seq uint64, a Action, ids []Identity) error {
	if e := validateResult(a, ids); e != nil {
		l.poisoned = true
		return orphan(a)
	}
	if e := l.append(Body{Op: "commit", Result: &Result{Intent: seq, Identities: ids}}); e != nil {
		return fail(3, "ORPHAN "+actionName(a)+" COMMIT_FAILED "+e.Error())
	}
	return nil
}
func (l *Ledger) abort(seq uint64, a Action) error {
	if e := l.append(Body{Op: "abort", Result: &Result{Intent: seq, Reason: "exclusive-refused"}}); e != nil {
		return e
	}
	return namedError("EXCLUSIVE_REFUSED", a)
}
