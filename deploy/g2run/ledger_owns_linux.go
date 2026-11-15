//go:build linux

package g2run

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/relux-works/swarma-chain-lab/deploy/g2ledger"
	"golang.org/x/sys/unix"
)

// LedgerOwns is the read-only g2-ledger-owns port. false,nil means NOT OWNED;
// true,nil means OWNED; an error is a refusal. The caller MUST first verify the
// ledger hash chain through E2 Ledger; this predicate grants no stop authority by
// itself. Metadata mismatches are resolved without opening or reading the target.
func LedgerOwns(fs PortFS, ledger, target string) (bool, error) {
	refuse := func(s string) (bool, error) { return false, errors.New("LEDGER_OWNS_" + s) }
	if !fs.allowed(target) {
		return refuse("PATH")
	}
	f, e := fs.open(ledger+"/records.jsonl", unix.O_RDONLY, false)
	if e != nil {
		return refuse("READ")
	}
	defer f.Close()
	intents := map[uint64]bool{}
	var committed *g2ledger.FSIdentity
	scan := bufio.NewScanner(io.LimitReader(f, (64<<20)+1))
	scan.Buffer(make([]byte, 4096), 1<<20)
	count, total := 0, 0
	for scan.Scan() {
		raw := scan.Bytes()
		total += len(raw) + 1
		count++
		if total > 64<<20 || count > 1<<20 {
			return refuse("LIMIT")
		}
		if len(strings.TrimSpace(string(raw))) == 0 {
			continue
		}
		var rec map[string]any
		if decodePortJSON(raw, &rec) != nil {
			return refuse("JSON")
		}
		seq, ok := portUint(rec["seq"], ^uint64(0))
		if !ok {
			return refuse("SEQ")
		}
		body, ok := portObject(rec["body"])
		if !ok {
			return refuse("BODY")
		}
		op, ok := body["op"].(string)
		if !ok {
			return refuse("OP")
		}
		switch op {
		case "intent":
			a, ok := portObject(body["action"])
			if !ok {
				return refuse("ACTION")
			}
			if a["kind"] != "file" {
				continue
			}
			paths, ok := a["paths"].([]any)
			if !ok {
				return refuse("PATHS")
			}
			for _, p := range paths {
				if p == target {
					intents[seq] = true
				}
			}
		case "commit":
			r, ok := portObject(body["result"])
			if !ok {
				return refuse("RESULT")
			}
			intent, ok := portUint(r["intent"], ^uint64(0))
			if !ok {
				return refuse("INTENT")
			}
			if !intents[intent] {
				continue
			}
			ids, ok := r["identities"].([]any)
			if !ok {
				return refuse("IDENTITIES")
			}
			for _, v := range ids {
				id, ok := portObject(v)
				if !ok {
					return refuse("IDENTITY")
				}
				if id["path"] != target {
					continue
				}
				fm, ok := portObject(id["fs"])
				if !ok {
					return refuse("FS")
				}
				if committed != nil {
					return refuse("TWO_CREATIONS")
				}
				if _, ok := portInt(fm["mtime_ns"]); !ok {
					return refuse("FS_NUMBER")
				}
				for _, k := range []string{"dev", "ino", "mode", "uid", "gid", "size"} {
					max := uint64(1<<63 - 1)
					if k == "dev" || k == "ino" {
						max = ^uint64(0)
					}
					if _, ok := portUint(fm[k], max); !ok {
						return refuse("FS_NUMBER")
					}
				}
				b, _ := json.Marshal(fm)
				var got g2ledger.FSIdentity
				if json.Unmarshal(b, &got) != nil || !portHex(got.SHA256, 64) {
					return refuse("FS_SCHEMA")
				}
				committed = &got
			}
		}
	}
	if scan.Err() != nil {
		return refuse("READ")
	}
	if committed == nil {
		return false, nil
	}
	parent, name, e := fs.parent(target)
	if e != nil {
		return refuse("TARGET_PARENT")
	}
	defer parent.Close()
	var st unix.Stat_t
	if e = unix.Fstatat(int(parent.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); e != nil {
		if errors.Is(e, unix.ENOENT) {
			return false, nil
		}
		return refuse("STAT")
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return refuse("NOT_REGULAR")
	}
	mode := st.Mode & 07777
	if committed.Mode > 07777 {
		mode = st.Mode
	}
	if st.Dev != committed.Dev || st.Ino != committed.Ino || mode != committed.Mode || st.Uid != committed.UID || st.Gid != committed.GID || st.Size != committed.Size || st.Mtim.Nano() != committed.MtimeNS {
		return false, nil
	}
	tf, opened, e := fs.openDrift(target, unix.O_RDONLY)
	if e != nil {
		return refuse("NOATIME_OPEN")
	}
	defer tf.Close()
	if opened.Dev != st.Dev || opened.Ino != st.Ino {
		return refuse("INODE")
	}
	got, e := driftIdentity(tf, opened)
	if e != nil {
		return refuse("HASH")
	}
	if e = fs.samePath(target, &st); e != nil {
		return refuse("PATH_IDENTITY")
	}
	return got.SHA256 == committed.SHA256, nil
}
