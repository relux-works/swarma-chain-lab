package g2ledger

import (
	"errors"
	"golang.org/x/sys/unix"
	"strings"
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
		links = append(links, UnitLink{path, target})
	}
	if len(links) == 0 {
		return nil, errors.New("UNIT_ENABLE_EMPTY")
	}
	return links, nil
}
func unitLinkPresent(link UnitLink) (bool, error) {
	d, n, err := parent(link.Path)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer d.Close()
	var st unix.Stat_t
	if err = unix.Fstatat(int(d.Fd()), n, &st, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	b := make([]byte, 4096)
	count, err := unix.Readlinkat(int(d.Fd()), n, b)
	if err != nil || count == len(b) || string(b[:count]) != link.Target {
		return false, errors.New("UNIT_LINK_RETARGETED " + link.Path)
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
	present, err := unitLinkPresent(link)
	if err != nil || !present {
		return err
	}
	d, n, err := parent(link.Path)
	if err != nil {
		return err
	}
	defer d.Close()
	// The privileged namespace must remain quiescent, as for all ledger undo.
	b := make([]byte, 4096)
	count, err := unix.Readlinkat(int(d.Fd()), n, b)
	if err != nil || count == len(b) || string(b[:count]) != link.Target {
		return errors.New("UNIT_LINK_RETARGETED " + link.Path)
	}
	if err = unix.Unlinkat(int(d.Fd()), n, 0); err != nil {
		return err
	}
	return d.Sync()
}
