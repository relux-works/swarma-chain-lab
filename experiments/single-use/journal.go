//go:build darwin || linux

package singleuse

import (
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"

	"github.com/relux-works/swarma-chain-lab/experiments/single-use/durable"
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
	store      *durable.Store
}

func privateRegular(info os.FileInfo) bool {
	return durable.PrivateRegular(info)
}

func openJournal(p Policy) (*journal, error) {
	store, e := durable.Open(p.StateDir, "executor.lock")
	if e != nil {
		if e.Error() == "STATE_BUSY" {
			return nil, fail("EXECUTOR_BUSY")
		}
		return nil, e
	}
	point, _ := json.Marshal(p.Seal)
	name := Hash(append([]byte(p.Genesis+":"), point...))
	return &journal{p.StateDir, filepath.Join(p.StateDir, "journal-"+name+".json"), store}, nil
}
func (j *journal) close() { j.store.Close() }
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
	return durable.SyncDir(path)
}
func (j *journal) write(record journalRecord) error {
	b, e := json.Marshal(record)
	if e != nil {
		return fail("JOURNAL_ENCODING")
	}
	return j.store.Write(filepath.Base(j.path), append(b, '\n'))
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
