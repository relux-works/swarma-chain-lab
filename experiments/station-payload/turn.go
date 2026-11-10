package payload

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/durable"
)

const ErrJournal Code = "PAYLOAD_JOURNAL"
const TurnUncertain = "uncertain"
const maxTurns = 1024
const maxTurnBytes = 1 << 20

type turn struct {
	Checksum  string `json:"checksum"`
	ID        string `json:"id"`
	Input     string `json:"input"`
	InputHash string `json:"input_hash"`
	Phase     string `json:"phase"`
	Reply     string `json:"reply"`
}
type turnJournal struct {
	root   string
	disk   *durable.Store
	turns  map[string]turn
	failed bool
}

func turnHash(s string) string { b := sha256.Sum256([]byte(s)); return hex.EncodeToString(b[:]) }
func turnID(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
func turnChecksum(t turn) string {
	t.Checksum = ""
	raw, _ := json.Marshal(t)
	return turnHash(string(raw))
}

func validTurn(v turn) bool {
	if v.Checksum != turnChecksum(v) || !turnID(v.ID) || !utf8.ValidString(v.Input) || len(v.Input) > 65535 || v.InputHash != turnHash(v.Input) || !utf8.ValidString(v.Reply) || len(v.Reply) > MaxText {
		return false
	}
	switch v.Phase {
	case "received", "in-flight":
		return v.Reply == ""
	case "ready", "accepted":
		return true
	}
	return false
}

// Infra owns creation and lifecycle of this explicit private directory. Refuse
// symlinked/noncanonical paths and writable ancestry before opening any state.
func safeTurnRoot(root string) bool {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return false
	}
	resolved, e := filepath.EvalSymlinks(root)
	if e != nil || resolved != root {
		return false
	}
	for p := root; ; p = filepath.Dir(p) {
		info, e := os.Lstat(p)
		if e != nil || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
			return false
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	return true
}
func openTurns(root, binding string) (*turnJournal, error) {
	if !safeTurnRoot(root) {
		return nil, ErrJournal
	}
	disk, e := durable.Open(root, "delivery.lock")
	if e != nil {
		return nil, ErrJournal
	}
	j := &turnJournal{root: root, disk: disk, turns: map[string]turn{}}
	ok := false
	defer func() {
		if !ok {
			disk.Close()
		}
	}()
	raw, e := disk.Read("binding.json", 256)
	if e != nil {
		return nil, ErrJournal
	}
	var b struct {
		Hash string `json:"hash"`
	}
	entries, e := os.ReadDir(root)
	if e != nil {
		return nil, ErrJournal
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == "binding.json" || name == "delivery.lock" || strings.HasPrefix(name, ".journal-") {
			continue
		}
		if entry.IsDir() || !strings.HasPrefix(name, "turn-") || !strings.HasSuffix(name, ".json") {
			return nil, ErrJournal
		}
		data, e := disk.Read(name, maxTurnBytes)
		if e != nil {
			return nil, ErrJournal
		}
		var t turn
		if su.StrictInput(data, &t) != nil || !turnKeys(data) || !validTurn(t) || name != "turn-"+t.ID+".json" || len(j.turns) >= maxTurns {
			return nil, ErrJournal
		}
		j.turns[t.ID] = t
	}
	if len(raw) == 0 {
		if len(j.turns) != 0 {
			return nil, ErrJournal
		}
		b.Hash = binding
		raw, _ = json.Marshal(b)
		if disk.Write("binding.json", raw) != nil {
			return nil, ErrJournal
		}
	} else if su.StrictInput(raw, &b) != nil || b.Hash != binding {
		return nil, ErrJournal
	}
	// An in-flight model call may have completed remotely. Never regenerate it.
	for _, t := range j.turns {
		if t.Phase == "in-flight" {
			t.Phase = "ready"
			t.Reply = TurnUncertain
			if j.save(t) != nil {
				return nil, ErrJournal
			}
		}
	}
	ok = true
	return j, nil
}
func (j *turnJournal) close() { j.disk.Close() }

// save uses the same fsync/rename/directory-sync contract as durable.Store,
// with a larger bounded record for escaped input plus reply. The lifetime lock
// is held by j.disk; any ambiguous write poisons this process until reopen.
func (j *turnJournal) save(t turn) (err error) {
	t.Checksum = turnChecksum(t)
	if j.failed || !validTurn(t) {
		return ErrJournal
	}
	defer func() {
		if err != nil {
			j.failed = true
		}
	}()
	raw, e := json.Marshal(t)
	if e != nil || len(raw) > maxTurnBytes {
		return ErrJournal
	}
	name := "turn-" + t.ID + ".json"
	if _, e = j.disk.Read(name, maxTurnBytes); e != nil {
		return ErrJournal
	}
	f, e := os.CreateTemp(j.root, ".journal-")
	if e != nil {
		return ErrJournal
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, e = f.Write(raw); e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		return ErrJournal
	}
	if os.Rename(tmp, filepath.Join(j.root, name)) != nil || durable.SyncDir(j.root) != nil {
		return ErrJournal
	}
	j.turns[t.ID] = t
	return nil
}
func (j *turnJournal) receive(id, input string) (turn, error) {
	if j.failed || !turnID(id) || !utf8.ValidString(input) || len(input) > 65535 {
		return turn{}, ErrJournal
	}
	if t, ok := j.turns[id]; ok {
		if t.Input != input {
			return turn{}, ErrJournal
		}
		return t, nil
	}
	if len(j.turns) >= maxTurns {
		return turn{}, ErrJournal
	}
	t := turn{ID: id, Input: input, InputHash: turnHash(input), Phase: "received"}
	if e := j.save(t); e != nil {
		return turn{}, e
	}
	return j.turns[t.ID], nil
}

func turnKeys(raw []byte) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 6 {
		return false
	}
	for _, key := range []string{"checksum", "id", "input", "input_hash", "phase", "reply"} {
		if _, ok := fields[key]; !ok {
			return false
		}
	}
	return true
}
