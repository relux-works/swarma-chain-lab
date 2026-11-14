package g2ledger

import (
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"path/filepath"
	"strings"
)

// targetPathPolicy walks unresolved components in filesystem order. In
// particular, a symlink preceding .. must be expanded before taking its parent.
// Protected parents and serialized privileged writers remain prerequisites;
// this read-only policy check is not a namespace-race transaction.
func resolveTargetPolicy(path string, links int) error {
	if !filepath.IsAbs(path) {
		return errors.New("TARGET_PATH_NOT_ABSOLUTE")
	}
	root, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("TARGET_PATH_LOOKUP: %w", err)
	}
	dirs := []int{root}
	defer func() {
		for _, fd := range dirs {
			unix.Close(fd)
		}
	}()
	names := []string{}
	missing := 0
	parts := strings.Split(path, "/")
	for len(parts) > 0 {
		part := parts[0]
		parts = parts[1:]
		switch part {
		case "", ".":
			continue
		case "..":
			if len(names) > 0 {
				names = names[:len(names)-1]
				if missing > 0 {
					missing--
				} else {
					unix.Close(dirs[len(dirs)-1])
					dirs = dirs[:len(dirs)-1]
				}
			}
			continue
		}
		// An absent component cannot currently contain symlinks. Its prospective
		// suffix is therefore lexical; once .. returns to an existing ancestor,
		// resume filesystem inspection so existing sibling links are still followed.
		if missing > 0 {
			names = append(names, part)
			missing++
			continue
		}
		fd := dirs[len(dirs)-1]
		var st unix.Stat_t
		err := unix.Fstatat(fd, part, &st, unix.AT_SYMLINK_NOFOLLOW)
		if errors.Is(err, unix.ENOENT) {
			names = append(names, part)
			missing = 1
			continue
		}
		if err != nil {
			return fmt.Errorf("TARGET_PATH_LOOKUP: %w", err)
		}
		if st.Mode&unix.S_IFMT == unix.S_IFLNK {
			links++
			if links > 40 {
				return fmt.Errorf("TARGET_PATH_SYMLINK_LOOP: %w", unix.ELOOP)
			}
			var target string
			for size := 256; ; size *= 2 {
				buf := make([]byte, size)
				n, err := unix.Readlinkat(fd, part, buf)
				if err != nil {
					return fmt.Errorf("TARGET_PATH_READLINK: %w", err)
				}
				if n < len(buf) {
					target = string(buf[:n])
					break
				}
				if size >= 65536 {
					return errors.New("TARGET_PATH_LINK_TOO_LONG")
				}
			}
			if filepath.IsAbs(target) {
				for len(dirs) > 1 {
					unix.Close(dirs[len(dirs)-1])
					dirs = dirs[:len(dirs)-1]
				}
				names = nil
			}
			parts = append(strings.Split(target, "/"), parts...)
			continue
		}
		names = append(names, part)
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			if len(parts) > 0 {
				return fmt.Errorf("TARGET_PATH_LOOKUP: %w", unix.ENOTDIR)
			}
			break
		}
		next, err := unix.Openat(fd, part, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("TARGET_PATH_LOOKUP: %w", err)
		}
		dirs = append(dirs, next)
	}
	resolved := "/" + strings.Join(names, "/")
	if runtimePath(resolved) {
		return fmt.Errorf("%w %s", errVolatileRuntime, resolved)
	}
	return nil
}
