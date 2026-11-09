package signerservice

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Probe the real booking export in isolated Core fixture directories. The
// FileSource refuses visible partial/missing/hash-conflicting/duplicate data;
// unindexed scratch is ignored, and restoring exact producer bytes recovers.
func checkBookingFileSource(t *testing.T, source *FileSource, expected []Pulled) {
	t.Helper()
	ctx := context.Background()
	indexPath := filepath.Join(source.root, "index.json")
	original, e := os.ReadFile(indexPath)
	if e != nil {
		t.Fatal(e)
	}
	h := hash(expected[0].Raw)
	path := filepath.Join(source.root, h+".json")
	put := func(p string, b []byte) {
		t.Helper()
		if e := os.WriteFile(p, b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	for _, mode := range []string{"partial-index", "duplicate", "missing", "hash", "orphan"} {
		t.Run("export-"+mode, func(t *testing.T) {
			want := "OUTBOX_INDEX"
			switch mode {
			case "partial-index":
				put(indexPath, []byte("["))
			case "duplicate":
				put(indexPath, encode([]string{h, h}))
			case "missing":
				if e := os.Remove(path); e != nil {
					t.Fatal(e)
				}
				want = "PRIVATE_FILE"
			case "hash":
				put(path, []byte("{"))
				want = "OUTBOX_HASH"
			case "orphan":
				put(filepath.Join(source.root, hash([]byte("orphan"))+".json"), []byte("{"))
				want = ""
			}
			got, e := source.Pull(ctx, "", MaxRecords)
			put(indexPath, original)
			put(path, expected[0].Raw)
			if want == "" {
				if e != nil || len(got) != 1 || !bytes.Equal(got[0].Raw, expected[0].Raw) {
					t.Fatal("unindexed artifact consumed", e)
				}
			} else if e == nil || e.Error() != want || got != nil {
				t.Fatal("partial producer file consumed", mode, e)
			}
			got, e = source.Pull(ctx, "", MaxRecords)
			if e != nil || len(got) != 1 || !bytes.Equal(got[0].Raw, expected[0].Raw) || got[0].After != expected[0].After {
				t.Fatal("restored export refused", e)
			}
		})
	}
}

// A legacy booking root has no SG1 index; FileSource refuses it without any
// conversion or invented payment tuple. Explicit manually provisioned SG1 v1
// sources retain their existing separate consumer contract.
func TestLegacyBookingRootRefused(t *testing.T) {
	root := dir(t)
	write(t, filepath.Join(root, "state.json"), []byte(`{"version":1}`))
	source, e := OpenFileSource(root)
	if e != nil {
		t.Fatal(e)
	}
	if rows, e := source.Pull(context.Background(), "", MaxRecords); e == nil || e.Error() != "PRIVATE_FILE" || rows != nil {
		t.Fatal("legacy root silently converted", e)
	}
	write(t, filepath.Join(root, "index.json"), []byte("[]"))
	if rows, e := source.Pull(context.Background(), "", MaxRecords); e != nil || len(rows) != 0 {
		t.Fatal("empty explicit source refused", e)
	}
}
