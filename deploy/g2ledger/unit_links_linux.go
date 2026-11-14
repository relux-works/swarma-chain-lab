package g2ledger

import (
	"errors"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// systemd.unit(5): Also installs/deinstalls additional units. Inspect the unit
// plus drop-ins via cat; reject any Also assignment in [Install], even resets.
func unitInstallSafe(sys System, name string) error {
	raw, status, err := sys.Run("/usr/bin/systemctl", "cat", name)
	if err != nil {
		return err
	}
	if status != 0 {
		return errors.New("UNIT_CAT_FAILED")
	}
	section, pending := "", ""
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		line = pending + line
		if strings.HasSuffix(line, `\`) {
			pending = strings.TrimSuffix(line, `\`) + " "
			continue
		}
		pending = ""
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return errors.New("UNIT_SECTION")
			}
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		key, _, ok := strings.Cut(line, "=")
		if !ok {
			return errors.New("UNIT_DIRECTIVE")
		}
		if section == "Install" && strings.TrimSpace(key) == "Also" {
			return errors.New("UNIT_ALSO_REFUSED")
		}
	}
	if pending != "" || strings.TrimSpace(raw) == "" {
		return errors.New("UNIT_INCOMPLETE")
	}
	return nil
}

// systemctl enable emits: Created symlink A -> B. Only that exact C-locale
// output grants a receipt. Unknown diagnostics, duplicates and empty sets orphan.
func createdUnitLinks(output string) ([]UnitLink, error) {
	var links []UnitLink
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(output, "\n"), "\n") {
		if !strings.HasPrefix(line, "Created symlink ") || !strings.HasSuffix(line, ".") {
			return nil, errors.New("UNIT_ENABLE_OUTPUT")
		}
		path, target, ok := strings.Cut(strings.TrimSuffix(strings.TrimPrefix(line, "Created symlink "), "."), " -> ")
		if !ok || !validPath(path) || !validPath(target) || seen[path] {
			return nil, errors.New("UNIT_ENABLE_LINK")
		}
		seen[path] = true
		links = append(links, UnitLink{Path: path, Target: target})
	}
	if len(links) == 0 {
		return nil, errors.New("UNIT_ENABLE_EMPTY")
	}
	return links, nil
}

// observeUnitLinkAt uses lstat/readlinkat on one pinned parent, never follows
// the link, and checks that its identity stayed stable while reading its text.
func observeUnitLinkAt(d *os.File, n string, link UnitLink) (UnitLink, bool, error) {
	var st unix.Stat_t
	if err := unix.Fstatat(int(d.Fd()), n, &st, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return UnitLink{}, false, nil
	} else if err != nil {
		return UnitLink{}, false, err
	}
	b := make([]byte, 4096)
	count, err := unix.Readlinkat(int(d.Fd()), n, b)
	if err != nil || count == len(b) || string(b[:count]) != link.Target {
		return UnitLink{}, false, errors.New("UNIT_LINK_RETARGETED " + link.Path)
	}
	var again unix.Stat_t
	if err := unix.Fstatat(int(d.Fd()), n, &again, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return UnitLink{}, false, err
	}
	if st.Dev != again.Dev || st.Ino != again.Ino || st.Uid != again.Uid || st.Gid != again.Gid || st.Mode != again.Mode || st.Mode&unix.S_IFMT != unix.S_IFLNK {
		return UnitLink{}, false, errors.New("UNIT_LINK_CHANGED " + link.Path)
	}
	return UnitLink{Path: link.Path, Target: string(b[:count]), Dev: uint64(st.Dev), Ino: st.Ino, UID: st.Uid, GID: st.Gid, Mode: st.Mode}, true, nil
}
func observeUnitLink(link UnitLink) (UnitLink, bool, error) {
	d, n, err := parent(link.Path)
	if errors.Is(err, unix.ENOENT) {
		return UnitLink{}, false, nil
	}
	if err != nil {
		return UnitLink{}, false, err
	}
	defer d.Close()
	return observeUnitLinkAt(d, n, link)
}
func unitLinkPresent(link UnitLink) (bool, error) {
	got, present, err := observeUnitLink(link)
	if err != nil || !present {
		return present, err
	}
	if got != link {
		return false, errors.New("UNIT_LINK_REPLACED " + link.Path)
	}
	return true, nil
}
func checkUnitLinks(links []UnitLink) error {
	for _, link := range links {
		if _, err := unitLinkPresent(link); err != nil {
			return err
		}
	}
	return nil
}
func removeUnitLink(link UnitLink) error {
	d, n, err := parent(link.Path)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	defer d.Close()
	// Recheck every receipt field on the SAME pinned parent used by unlinkat.
	// Privileged namespace writers must remain quiescent during replay.
	got, present, err := observeUnitLinkAt(d, n, link)
	if err != nil || !present {
		return err
	}
	if got != link {
		return errors.New("UNIT_LINK_REPLACED " + link.Path)
	}
	if err = unix.Unlinkat(int(d.Fd()), n, 0); err != nil {
		return err
	}
	return d.Sync()
}
