package signerservice

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/relux-works/swarma-chain-lab/experiments/single-use/durable"
)

func privateRoot(root string) error {
	resolved, e := filepath.EvalSymlinks(root)
	if e != nil || resolved != root || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return fail("PRIVATE_ROOT")
	}
	st, e := os.Lstat(root)
	if e != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
		return fail("PRIVATE_ROOT")
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() {
		return fail("PRIVATE_ROOT")
	}
	return nil
}
func privateRead(path string, limit int64) ([]byte, error) {
	st, e := os.Lstat(path)
	if e != nil || !durable.PrivateRegular(st) || st.Size() < 1 || st.Size() > limit {
		return nil, fail("PRIVATE_FILE")
	}
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, fail("PRIVATE_FILE")
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(st, opened) || !durable.PrivateRegular(opened) {
		return nil, fail("PRIVATE_FILE")
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	after, se := f.Stat()
	if e != nil || se != nil || int64(len(b)) != st.Size() || after.Size() != st.Size() || after.ModTime() != st.ModTime() {
		return nil, fail("PRIVATE_FILE")
	}
	return b, nil
}

// FileSource reads an append-only index of content hashes and immutable
// <hash>.json records. A cursor commits the exact prefix and absolute source
// root. A rewritten/truncated prefix refuses; callers persist intake before
// accepting After. No URLs or authority flags come from the records.
type FileSource struct{ root string }

func OpenFileSource(root string) (*FileSource, error) {
	if e := privateRoot(root); e != nil {
		return nil, e
	}
	return &FileSource{root}, nil
}

type fileCursor struct {
	Version int    `json:"version"`
	Source  string `json:"source"`
	Offset  int    `json:"offset"`
	Prefix  string `json:"prefix"`
}

func (f *FileSource) Pull(ctx context.Context, after string, limit int) ([]Pulled, error) {
	if ctx.Err() != nil {
		return nil, fail("CANCELED")
	}
	if limit < 1 || limit > MaxRecords {
		return nil, fail("PULL_BOUND")
	}
	if e := privateRoot(f.root); e != nil {
		return nil, e
	}
	b, e := privateRead(filepath.Join(f.root, "index.json"), 1<<20)
	if e != nil {
		return nil, e
	}
	var index []string
	if json.Unmarshal(b, &index) != nil || index == nil || len(index) > 4096 {
		return nil, fail("OUTBOX_INDEX")
	}
	seen := map[string]bool{}
	for _, id := range index {
		if !digest(id) || seen[id] {
			return nil, fail("OUTBOX_INDEX")
		}
		seen[id] = true
	}
	c := fileCursor{Version: 1, Source: hash([]byte(f.root)), Prefix: hash(encode(index[:0]))}
	if after != "" {
		c = fileCursor{}
		if strict([]byte(after), &c) != nil || c.Version != 1 || c.Source != hash([]byte(f.root)) || c.Offset < 0 || c.Offset > len(index) || c.Prefix != hash(encode(index[:c.Offset])) {
			return nil, fail("OUTBOX_CURSOR")
		}
	}
	result := []Pulled{}
	end := min(len(index), c.Offset+limit)
	for i := c.Offset; i < end; i++ {
		raw, e := privateRead(filepath.Join(f.root, index[i]+".json"), 65536)
		if e != nil {
			return nil, e
		}
		if hash(raw) != index[i] {
			return nil, fail("OUTBOX_HASH")
		}
		c.Offset = i + 1
		c.Prefix = hash(encode(index[:i+1]))
		result = append(result, Pulled{raw, string(encode(c))})
	}
	return result, nil
}
