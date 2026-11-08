//go:build darwin || linux

package singleuse

import (
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
)

type journalRecord struct {
	Version int    `json:"version"`
	Binding string `json:"binding"`
	Request string `json:"request_sha256"`
	Spend   string `json:"spend_txid"`
	Phase   string `json:"phase"`
}
type journal struct {
	root, path string
	lock       *os.File
}

func privateRegular(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && info.Mode().IsRegular() && info.Mode().Perm() == 0600 && int(stat.Uid) == os.Getuid() && stat.Nlink == 1
}

func openJournal(p Policy) (*journal, error) {
	info, e := os.Lstat(p.StateDir)
	if e != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return nil, fail("PRIVATE_STATE_ROOT")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Getuid() {
		return nil, fail("STATE_OWNER")
	}
	f, e := os.OpenFile(filepath.Join(p.StateDir, "executor.lock"), os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, fail("STATE_LOCK")
	}
	s, e := f.Stat()
	if e != nil || !privateRegular(s) {
		f.Close()
		return nil, fail("STATE_LOCK_FILE")
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		return nil, fail("EXECUTOR_BUSY")
	}
	point, _ := json.Marshal(p.Seal)
	name := Hash(append([]byte(p.Genesis+":"), point...))
	return &journal{p.StateDir, filepath.Join(p.StateDir, "journal-"+name+".json"), f}, nil
}
func (j *journal) close() { _ = syscall.Flock(int(j.lock.Fd()), syscall.LOCK_UN); _ = j.lock.Close() }
func (j *journal) read() (*journalRecord, error) {
	info, e := os.Lstat(j.path)
	if os.IsNotExist(e) {
		return nil, nil
	}
	if e != nil {
		return nil, fail("JOURNAL_READ")
	}
	if !privateRegular(info) {
		return nil, fail("JOURNAL_FILE")
	}
	b, e := PublicFile(j.path, 4096)
	if e != nil {
		return nil, fail("JOURNAL_READ")
	}
	var record journalRecord
	if StrictInput(b, &record) != nil || record.Version != 1 || !digestHex(record.Binding) || !digestHex(record.Request) || !digestHex(record.Spend) || (record.Phase != "reserved" && record.Phase != "complete") {
		return nil, fail("JOURNAL_CORRUPT")
	}
	return &record, nil
}
func syncDir(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func (j *journal) write(record journalRecord) error {
	b, e := json.Marshal(record)
	if e != nil {
		return fail("JOURNAL_ENCODING")
	}
	tmp, e := os.CreateTemp(j.root, ".journal-")
	if e != nil {
		return fail("JOURNAL_WRITE")
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, e = tmp.Write(append(b, '\n')); e == nil {
		e = tmp.Sync()
	}
	ce := tmp.Close()
	if e != nil || ce != nil {
		return fail("JOURNAL_FSYNC")
	}
	if os.Rename(name, j.path) != nil || syncDir(j.root) != nil {
		return fail("JOURNAL_COMMIT")
	}
	return nil
}
func (j *journal) effect(record journalRecord) error {
	f, e := os.OpenFile(filepath.Join(j.root, "effects.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return fail("EFFECT_OPEN")
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !privateRegular(info) {
		return fail("EFFECT_FILE")
	}
	b, _ := json.Marshal(map[string]any{"lab_effect": "simulated-repository.create", "request_sha256": record.Request, "spend_txid": record.Spend, "production_effect_authorized": false})
	if _, e = f.Write(append(b, '\n')); e != nil {
		return fail("EFFECT_WRITE_UNCERTAIN")
	}
	if f.Sync() != nil || syncDir(j.root) != nil {
		return fail("EFFECT_FSYNC_UNCERTAIN")
	}
	return nil
}
