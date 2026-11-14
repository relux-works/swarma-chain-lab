package g2ledger

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// This deliberately excludes escaped names, templates and instances. Unmodeled
// syntax refuses rather than borrowing systemd's permissive error recovery.
var installUnitName = regexp.MustCompile(`^[a-zA-Z0-9_:.-]+\.(service|socket|device|mount|automount|swap|target|path|timer|slice|scope)$`)

// systemd v259: src/fundamental/string-util-fundamental.h WHITESPACE,
// used by conf-parser.c strstrip() and extract-word.c's default separators.
const installWhitespace = " \t\n\r"

func installName(name string) error {
	if strings.Contains(name, "%") {
		return errors.New("UNIT_SPECIFIER_REFUSED")
	}
	if strings.Contains(name, "@") {
		return errors.New("UNIT_TEMPLATE_REFUSED")
	}
	if len(name) > 255 || !installUnitName.MatchString(name) {
		return errors.New("UNIT_INSTALL_NAME")
	}
	return nil
}

// installLists models the supported systemd.syntax(7) subset. Quotes around a
// whole simple name are supported; C escapes and other unmodeled values refuse.
// Section detection is identical for unit files and drop-ins.
func installLists(raw string, dropin bool) (map[string][]string, error) {
	lists := map[string][]string{}
	section, pending := "", ""
	// systemd v259 fileio.c:1443-1453,1517-1560 consumes CR as an EOL,
	// before conf-parser.c:354-405 handles comments and continuations.
	// Support LF/CRLF; refuse every other CR placement before interpreting it.
	for i := range len(raw) {
		if raw[i] == '\r' && (i+1 == len(raw) || raw[i+1] != '\n') {
			return nil, errors.New("UNIT_INSTALL_CR_REFUSED")
		}
	}
	if strings.ContainsAny(raw, "\x00\v\f") {
		return nil, errors.New("UNIT_INSTALL_TEXT_REFUSED")
	}
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	for _, physical := range strings.Split(strings.TrimSuffix(raw, "\n"), "\n") {
		trimmed := strings.TrimLeft(physical, installWhitespace)
		if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		line := pending + physical
		// Only an unescaped backslash at the physical end continues a line.
		// In particular, whitespace after it and an even backslash pair do not.
		backslashes := len(line) - len(strings.TrimRight(line, `\`))
		if backslashes%2 != 0 {
			pending = strings.TrimSuffix(line, `\`) + " "
			continue
		}
		pending = ""
		line = strings.Trim(line, installWhitespace)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return nil, errors.New("UNIT_SECTION")
			}
			section = line[1 : len(line)-1]
			if section != strings.TrimSpace(section) {
				return nil, errors.New("UNIT_SECTION")
			}
			if dropin && section == "Install" {
				return nil, errors.New("UNIT_INSTALL_DROPIN_REFUSED")
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, errors.New("UNIT_DIRECTIVE")
		}
		if section != "Install" {
			continue
		}
		key, value = strings.Trim(key, installWhitespace), strings.Trim(value, installWhitespace)
		for i := range len(key) {
			if key[i] >= 0x80 {
				return nil, errors.New("UNIT_INSTALL_KEY_NON_ASCII")
			}
		}
		switch key {
		case "Also":
			return nil, errors.New("UNIT_ALSO_REFUSED")
		case "DefaultInstance":
			return nil, errors.New("UNIT_DEFAULT_INSTANCE_REFUSED")
		case "WantedBy", "RequiredBy", "UpheldBy", "Alias":
		default:
			return nil, errors.New("UNIT_INSTALL_DIRECTIVE_REFUSED")
		}
		for _, r := range value {
			if r > 0x7f && (unicode.IsSpace(r) || r == '\ufeff') {
				return nil, errors.New("UNIT_INSTALL_VALUE_WHITESPACE_REFUSED")
			}
		}
		if strings.Contains(value, "%") {
			return nil, errors.New("UNIT_SPECIFIER_REFUSED")
		}
		if strings.Contains(value, `\`) {
			return nil, errors.New("UNIT_INSTALL_ESCAPE_REFUSED")
		}
		if value == "" {
			lists[key] = nil
			continue
		}
		for _, word := range strings.FieldsFunc(value, func(r rune) bool { return strings.ContainsRune(installWhitespace, r) }) {
			if strings.HasPrefix(word, `"`) || strings.HasPrefix(word, "'") {
				if len(word) < 2 || word[len(word)-1] != word[0] {
					return nil, errors.New("UNIT_INSTALL_QUOTE_REFUSED")
				}
				word = word[1 : len(word)-1]
			}
			if err := installName(word); err != nil {
				return nil, err
			}
			lists[key] = append(lists[key], word)
		}
	}
	if pending != "" {
		return nil, errors.New("UNIT_INCOMPLETE")
	}
	return lists, nil
}

type unitInstall struct {
	Expected []UnitLink
	Existing []UnitLink
	Missing  []UnitLink
}

func (p unitInstall) equal(q unitInstall) bool {
	return slices.Equal(p.Expected, q.Expected) && slices.Equal(p.Existing, q.Existing) && slices.Equal(p.Missing, q.Missing)
}

// Read the first named file in systemd's own search order. A selected symlink
// (including a mask/alias) is outside this model and fails the no-follow read.
// Drop-ins at unit, dashed-prefix and type levels are inspected in every search
// directory; any Install section refuses even if a higher file would mask it.
func expectedUnitInstall(sys System, name string) (unitInstall, error) {
	var plan unitInstall
	if err := installName(name); err != nil {
		return plan, err
	}
	paths, config, err := sys.UnitPaths()
	if err != nil {
		return plan, err
	}
	if len(paths) == 0 || !validPath(config) {
		return plan, errors.New("UNIT_SEARCH_PATH")
	}
	var source string
	var raw []byte
	for _, dir := range paths {
		if !validPath(dir) {
			return plan, errors.New("UNIT_SEARCH_PATH")
		}
		candidate := filepath.Join(dir, name)
		st, statErr := os.Lstat(candidate)
		err = statErr
		if errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return plan, err
		}
		if !st.Mode().IsRegular() {
			return plan, errors.New("UNIT_FILE_REFUSED")
		}
		raw, err = readFile(candidate, 1<<20)
		if err != nil {
			return plan, errors.New("UNIT_FILE_REFUSED")
		}
		source = candidate
		break
	}
	if source == "" {
		return plan, errors.New("UNIT_FILE_MISSING")
	}
	lists, err := installLists(string(raw), false)
	if err != nil {
		return plan, err
	}
	if _, usesUpheldBy := lists["UpheldBy"]; usesUpheldBy {
		// UpheldBy is absent in older receipt-compatible releases. Only the
		// audited versions with this install directive are modeled here.
		out, status, err := sys.Run("/usr/bin/systemd-analyze", "--version")
		fields := strings.Fields(out)
		version := 0
		if len(fields) >= 2 && fields[0] == "systemd" {
			version, _ = strconv.Atoi(fields[1])
		}
		if err != nil || status != 0 || version < 254 || version > 259 {
			return plan, errors.New("UNIT_UPHELD_BY_VERSION_REFUSED")
		}
	}
	suffix := filepath.Ext(name)
	dropdirs := []string{name + ".d", suffix[1:] + ".d"}
	prefix := strings.TrimSuffix(name, suffix)
	for j := strings.IndexByte(prefix, '-'); j >= 0; {
		dropdirs = append(dropdirs, prefix[:j+1]+suffix+".d")
		next := strings.IndexByte(prefix[j+1:], '-')
		if next < 0 {
			break
		}
		j += next + 1
	}
	for _, dir := range paths {
		for _, sub := range dropdirs {
			entries, err := os.ReadDir(filepath.Join(dir, sub))
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return plan, err
			}
			for _, entry := range entries {
				if !strings.HasSuffix(entry.Name(), ".conf") {
					continue
				}
				b, err := readFile(filepath.Join(dir, sub, entry.Name()), 1<<20)
				if err != nil {
					return plan, errors.New("UNIT_DROPIN_FILE_REFUSED")
				}
				if _, err = installLists(string(b), true); err != nil {
					return plan, err
				}
			}
		}
	}
	seen := map[string]bool{}
	for _, key := range []string{"WantedBy", "RequiredBy", "UpheldBy", "Alias"} {
		for _, value := range lists[key] {
			path := filepath.Join(config, value)
			if key == "Alias" {
				if filepath.Ext(value) != suffix || value == name {
					return plan, errors.New("UNIT_ALIAS_REFUSED")
				}
			} else {
				ext := map[string]string{"WantedBy": ".wants", "RequiredBy": ".requires", "UpheldBy": ".upholds"}[key]
				path = filepath.Join(config, value+ext, name)
			}
			if !seen[path] {
				plan.Expected = append(plan.Expected, UnitLink{Path: path, Target: source})
				seen[path] = true
			}
		}
	}
	slices.SortFunc(plan.Expected, func(a, b UnitLink) int { return strings.Compare(a.Path, b.Path) })
	if len(plan.Expected) == 0 {
		return plan, errors.New("UNIT_INSTALL_EMPTY")
	}
	for _, link := range plan.Expected {
		got, present, err := observeUnitLink(link)
		if err != nil {
			return plan, err
		}
		if present {
			plan.Existing = append(plan.Existing, got)
		} else {
			plan.Missing = append(plan.Missing, link)
		}
	}
	return plan, nil
}

// Exact PATH/TARGET equality with only the absent-before subset is required.
// Receipt order is immaterial; pre-existing links never grant undo authority.
func unitReceiptMatches(links, missing []UnitLink) bool {
	if len(links) != len(missing) {
		return false
	}
	want := make(map[string]string, len(missing))
	for _, link := range missing {
		want[link.Path] = link.Target
	}
	for _, link := range links {
		if target, ok := want[link.Path]; !ok || target != link.Target {
			return false
		}
		delete(want, link.Path)
	}
	return len(want) == 0
}
