package operatorfile

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// Regular bytes up to the bound are returned exactly; oversized files,
// directories and symlinks refuse without partial bytes. FIFO behavior is
// exercised at every caller's boundary with bounded waiting in CLI helpers.
func TestRegularFileAndRefusals(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "input")
	if err := os.WriteFile(path, []byte("abc"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, limit := range []int64{3, 4} {
		raw, err := Read(path, limit)
		if err != nil || !bytes.Equal(raw, []byte("abc")) {
			t.Fatalf("regular: %q %v", raw, err)
		}
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, path string
		limit      int64
	}{
		{"oversize", path, 2}, {"directory", dir, 3}, {"symlink", link, 3}, {"missing", filepath.Join(dir, "missing"), 3},
	} {
		t.Run(c.name, func(t *testing.T) {
			raw, err := Read(c.path, c.limit)
			if err == nil || err.Error() != "FILE_READ" || raw != nil {
				t.Fatalf("refusal: %q %v", raw, err)
			}
		})
	}
}
