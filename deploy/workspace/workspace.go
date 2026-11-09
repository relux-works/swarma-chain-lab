// Package workspace selects the committed chain-lab workspace for build tools
// and maps copied modules into isolated mutation-test workspaces.
package workspace

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// Find ignores the caller's GOWORK and searches ancestors of the source path.
func Find(source string) (string, error) {
	dir, err := filepath.Abs(source)
	if err != nil {
		return "", err
	}
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		return "", err
	}
	for {
		p := filepath.Join(dir, "go.work")
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			return p, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("committed workspace not found")
		}
		dir = parent
	}
}

// Isolate maps this repository's flattened guard fixture layout. Existing
// scratch modules (including nested modules) win; other modules use source.
// The caller must finish copying modules before calling this function.
func Isolate(source, scratch string) (string, error) {
	work, err := Find(source)
	if err != nil {
		return "", err
	}
	var manifest struct {
		Go      string
		Use     []struct{ DiskPath string }
		Replace []json.RawMessage
	}
	cmd := exec.Command("go", "work", "edit", "-json", work)
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOTOOLCHAIN=local")
	raw, err := cmd.Output()
	if err != nil || json.Unmarshal(raw, &manifest) != nil || manifest.Go == "" || len(manifest.Use) == 0 || len(manifest.Replace) != 0 {
		return "", errors.New("invalid source workspace")
	}
	root := filepath.Dir(work)
	var b strings.Builder
	b.WriteString("go " + manifest.Go + "\n\nuse (\n")
	for _, entry := range manifest.Use {
		rel := filepath.Clean(entry.DiskPath)
		if !filepath.IsLocal(rel) || rel == "." {
			return "", errors.New("nonlocal workspace module")
		}
		flat := strings.TrimPrefix(filepath.ToSlash(rel), "experiments/")
		selected := filepath.Join(root, rel)
		candidate := filepath.Join(scratch, filepath.FromSlash(flat))
		if st, err := os.Stat(filepath.Join(candidate, "go.mod")); err == nil && st.Mode().IsRegular() {
			selected = candidate
		}
		if st, err := os.Stat(filepath.Join(selected, "go.mod")); err != nil || !st.Mode().IsRegular() {
			return "", errors.New("workspace module missing")
		}
		selected, err = filepath.Abs(selected)
		if err != nil {
			return "", err
		}
		selected, err = filepath.EvalSymlinks(selected)
		if err != nil {
			return "", err
		}
		b.WriteString("\t" + strconv.Quote(selected) + "\n")
	}
	b.WriteString(")\n")
	path, err := filepath.Abs(filepath.Join(scratch, "go.work"))
	if err != nil {
		return "", err
	}
	// Never overwrite a caller workspace or a previous fixture.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", err
	}
	_, err = f.WriteString(b.String())
	closeErr := f.Close()
	if err != nil {
		return "", err
	}
	return path, closeErr
}
