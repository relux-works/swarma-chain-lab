package configguard

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// This seam substitutes ownership only. Real file modes, kinds, paths, descriptors
// and bytes are exercised; it does not prove host root ownership or Linux ACLs.
func fixture(t *testing.T) (Reader, string) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "ancestor", "service")
	mkdirMode(t, filepath.Dir(dir), 0755)
	mkdirMode(t, dir, 0750)
	path := filepath.Join(dir, "service.json")
	writeMode(t, path, []byte("{}"), 0640)
	r := Reader{FixtureRoot: root, EUID: os.Geteuid(), GID: os.Getegid(), Metadata: func(_ string, s *unix.Stat_t) { s.Uid = 0 }}
	return r, path
}
func mkdirMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if e := os.Mkdir(path, mode); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(path, mode); e != nil {
		t.Fatal(e)
	}
}

func code(t *testing.T, got error, want string) {
	t.Helper()
	if got == nil || got.Error() != want {
		t.Fatalf("installed refusal: got %v want %s", got, want)
	}
}

// Every invalid installed-file neighbor refuses with no returned bytes. The
// original valid file remains readable, preventing a reject-everything reader.
func TestInstalledRefusals(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		change       func(string)
	}{
		{"0644", "DK5_FILE_MODE", func(p string) { os.Chmod(p, 0644) }},
		{"0660", "DK5_FILE_MODE", func(p string) { os.Chmod(p, 0660) }},
		{"0666", "DK5_FILE_MODE", func(p string) { os.Chmod(p, 0666) }},
		{"dir0755", "DK5_DIRECTORY_MODE", func(p string) { os.Chmod(filepath.Dir(p), 0755) }},
		{"dir0770", "DK5_DIRECTORY_MODE", func(p string) { os.Chmod(filepath.Dir(p), 0770) }},
		{"symlink", "DK5_FILE_OPEN", func(p string) { os.Rename(p, p+".real"); os.Symlink(p+".real", p) }},
		{"directory", "DK5_FILE_KIND", func(p string) { os.Remove(p); os.Mkdir(p, 0640) }},
		{"fifo", "DK5_FILE_KIND", func(p string) { os.Remove(p); unix.Mkfifo(p, 0640) }},
		{"hardlink", "DK5_FILE_LINKS", func(p string) { os.Link(p, p+".link") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, p := fixture(t)
			if b, e := r.Read(p, 32); e != nil || string(b) != "{}" {
				t.Fatalf("valid installed neighbor: %s %v", b, e)
			}
			tc.change(p)
			b, e := r.Read(p, 32)
			code(t, e, tc.reason)
			if b != nil {
				t.Fatal("returned rejected bytes")
			}
		})
	}
}

// Ownership mismatch is a labelled synthetic stat seam; mode/read behavior stays real.
func TestOwnershipSeam(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		change       func(*unix.Stat_t)
	}{
		{"owner", "DK5_FILE_OWNER", func(s *unix.Stat_t) { s.Uid = 42 }},
		{"group", "DK5_FILE_GROUP", func(s *unix.Stat_t) { s.Gid++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, p := fixture(t)
			if _, e := r.Read(p, 32); e != nil {
				t.Fatal(e)
			}
			base := r.Metadata
			r.Metadata = func(path string, s *unix.Stat_t) {
				base(path, s)
				if path == p {
					tc.change(s)
				}
			}
			b, e := r.Read(p, 32)
			code(t, e, tc.reason)
			if b != nil {
				t.Fatal("returned ownership-rejected bytes")
			}
		})
	}
}
func TestAncestorAndReadBoundary(t *testing.T) {
	r, p := fixture(t)
	dir := filepath.Dir(p)
	link := dir + "-link"
	if e := os.Symlink(dir, link); e != nil {
		t.Fatal(e)
	}
	defer os.Remove(link)
	_, e := r.Read(filepath.Join(link, filepath.Base(p)), 32)
	code(t, e, "DK5_DIRECTORY_OPEN")
	if _, e = r.Read(p, 32); e != nil {
		t.Fatal(e)
	}
	original := r.Metadata
	r.Metadata = func(path string, s *unix.Stat_t) {
		original(path, s)
		if path == r.FixtureRoot {
			s.Mode |= 0002
		}
	}
	_, e = r.Read(p, 32)
	code(t, e, "DK5_ANCESTOR_MODE")
	r.Metadata = original
	r.EUID = 0
	_, e = r.Read(p, 32)
	code(t, e, "DK5_SERVICE_IDENTITY")
	if !errors.Is(fail("DK5_PATH"), fail("DK5_PATH")) {
		t.Fatal("stable reason identity")
	}
}

// Directory ownership/group and a post-read change have distinct exact refusals;
// the mutation is confined to this fixture and returns no content to the caller.
func TestDirectoryOwnershipAndChangedFile(t *testing.T) {
	for _, name := range []string{"owner", "group", "changed"} {
		t.Run(name, func(t *testing.T) {
			r, p := fixture(t)
			if _, e := r.Read(p, 32); e != nil {
				t.Fatal(e)
			}
			original := r.Metadata
			reads := 0
			r.Metadata = func(path string, s *unix.Stat_t) {
				original(path, s)
				if path == filepath.Dir(p) {
					if name == "owner" {
						s.Uid = 42
					}
					if name == "group" {
						s.Gid++
					}
				}
				if path == p && name == "changed" {
					reads++
					if reads == 2 {
						if e := os.WriteFile(p, []byte("changed"), 0640); e != nil {
							t.Fatal(e)
						}
						// Explicitly separated timestamp makes this witness independent of
						// filesystem clock granularity; content hash remains authoritative.
						if e := os.Chtimes(p, time.Unix(1, 0), time.Unix(1, 0)); e != nil {
							t.Fatal(e)
						}
					}
				}
			}
			b, e := r.Read(p, 32)
			want := map[string]string{"owner": "DK5_DIRECTORY_OWNER", "group": "DK5_DIRECTORY_GROUP", "changed": "DK5_FILE_CHANGED"}[name]
			code(t, e, want)
			if b != nil {
				t.Fatal("returned refused bytes")
			}
		})
	}
}

// Each real ancestor mode and synthetic non-root owner is rejected before the
// file is read. The ancestor is neither the fixture root nor the file parent.
func TestAncestorSubclasses(t *testing.T) {
	for _, tc := range []struct {
		name  string
		mode  uint32
		owner bool
	}{
		{"group_writable", 0775, false}, {"setuid", 04755, false},
		{"setgid", 02755, false}, {"sticky", 01755, false},
		{"non_root", 0755, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, p := fixture(t)
			if b, e := r.Read(p, 32); e != nil || string(b) != "{}" {
				t.Fatalf("valid ancestor neighbor: %v", e)
			}
			ancestor := filepath.Dir(filepath.Dir(p))
			if e := unix.Chmod(ancestor, tc.mode); e != nil {
				t.Fatal(e)
			}
			var observed unix.Stat_t
			if e := unix.Stat(ancestor, &observed); e != nil || uint32(observed.Mode)&07777 != tc.mode {
				t.Fatalf("ancestor mode plant not applied: %v", e)
			}
			base := r.Metadata
			reads := 0
			r.Metadata = func(path string, s *unix.Stat_t) {
				base(path, s)
				if path == ancestor && tc.owner {
					s.Uid = 42
				}
				if path == p {
					reads++
				}
			}
			b, e := r.Read(p, 32)
			want := "DK5_ANCESTOR_MODE"
			if tc.owner {
				want = "DK5_DIRECTORY_OWNER"
			}
			code(t, e, want)
			if b != nil || reads != 0 {
				t.Fatal("unsafe ancestor reached file")
			}
		})
	}
}

// A sticky outer temp directory reproduces the hosted-runner environment. Only
// the explicitly selected fixture boundary ignores host ancestors; native
// traversal still rejects them. All modes inside that boundary remain real.
func TestFixtureRootBoundary(t *testing.T) {
	r, p := fixture(t)
	outer := r.FixtureRoot
	if e := unix.Chmod(outer, 01777); e != nil {
		t.Fatal(e)
	}
	r.FixtureRoot = filepath.Join(outer, "ancestor")
	if b, e := r.Read(p, 32); e != nil || string(b) != "{}" {
		t.Fatalf("hermetic fixture neighbor: %v", e)
	}
	native := r
	native.FixtureRoot = ""
	b, e := native.Read(p, 32)
	code(t, e, "DK5_ANCESTOR_MODE")
	if b != nil {
		t.Fatal("native traversal returned unsafe bytes")
	}
	if b, e := r.Read(filepath.Join(outer, "outside"), 32); e == nil || e.Error() != "DK5_PATH" || b != nil {
		t.Fatalf("fixture escape: %v", e)
	}
}

// The production constructor has no fixture root or metadata substitution and
// binds identity to this process. Test seams cannot become native defaults.
func TestNativeDefaults(t *testing.T) {
	r := Native()
	if r.FixtureRoot != "" || r.Metadata != nil || r.EUID != os.Geteuid() || r.GID != os.Getegid() {
		t.Fatal("native constructor selected fixture authority")
	}
}
