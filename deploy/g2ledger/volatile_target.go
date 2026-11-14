package g2ledger

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const volatileRuntimeReason = "VOLATILE_RUNTIME_OBJECT_TMPFILES"

var errVolatileRuntime = errors.New(volatileRuntimeReason)

func runtimePath(path string) bool {
	return path == "/run" || strings.HasPrefix(path, "/run/") || path == "/var/run" || strings.HasPrefix(path, "/var/run/")
}

// targetPathPolicy resolves existing symlinks, including dangling links whose
// missing suffix is under /run. It never creates or opens the target for writing.
// Protected parents and serialized privileged writers remain prerequisites.
func targetPathPolicy(path string) error {
	return resolveTargetPolicy(filepath.Clean(path), 0)
}
func resolveTargetPolicy(path string, links int) error {
	if runtimePath(path) {
		return fmt.Errorf("%w %s", errVolatileRuntime, path)
	}
	if links > 40 {
		return errors.New("TARGET_PATH_SYMLINK_LOOP")
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	current := "/"
	for j, part := range parts {
		current = filepath.Join(current, part)
		if runtimePath(current) {
			return fmt.Errorf("%w %s", errVolatileRuntime, current)
		}
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("TARGET_PATH_LOOKUP: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(current)
			if err != nil {
				return fmt.Errorf("TARGET_PATH_READLINK: %w", err)
			}
			if !filepath.IsAbs(target) {
				target = filepath.Join(filepath.Dir(current), target)
			}
			tail := append([]string{target}, parts[j+1:]...)
			return resolveTargetPolicy(filepath.Join(tail...), links+1)
		}
	}
	return nil
}
