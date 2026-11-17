package g2run

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// The typed values every operation is built from. Each one is parsed ONCE (from the parameters file or a compiled
// literal) and refused by name when malformed; nothing downstream ever re-reads it as text to be evaluated.

// Path is an absolute, clean path with no NUL, CR or LF, never "/" and never starting with "-".
type Path string

func (p Path) Validate() error {
	s := string(p)
	if !filepath.IsAbs(s) || filepath.Clean(s) != s || s == "/" || strings.ContainsAny(s, "\x00\r\n") {
		return fmt.Errorf("PATH_REFUSED %q", s)
	}
	return nil
}

// Mode is a file permission. It is parsed from three or four octal digits ("0755", "640") with ParseUint base 8 and
// must be at most 07777; anything else, an arithmetic expression included, is refused at decode.
type Mode uint32

var modePattern = regexp.MustCompile(`^[0-7]{3,4}$`)

func ParseMode(s string) (Mode, error) {
	if !modePattern.MatchString(s) {
		return 0, fmt.Errorf("MODE_REFUSED %q", s)
	}
	v, e := strconv.ParseUint(s, 8, 32)
	if e != nil || v > 0o7777 {
		return 0, fmt.Errorf("MODE_REFUSED %q", s)
	}
	return Mode(v), nil
}

func (m Mode) String() string { return fmt.Sprintf("%04o", uint32(m)) }

func (m *Mode) UnmarshalJSON(b []byte) error {
	var s string
	if e := json.Unmarshal(b, &s); e != nil {
		return fmt.Errorf("MODE_REFUSED %s", b)
	}
	v, e := ParseMode(s)
	if e != nil {
		return e
	}
	*m = v
	return nil
}

func (m Mode) MarshalJSON() ([]byte, error) { return json.Marshal(m.String()) }

// Name is an account or group name.
type Name string

var namePattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

func (n Name) Validate() error {
	if !namePattern.MatchString(string(n)) {
		return fmt.Errorf("NAME_REFUSED %q", string(n))
	}
	return nil
}

// Unit is a systemd unit name.
type Unit string

var unitPattern = regexp.MustCompile(`^[a-zA-Z0-9_@.:-]+\.(service|socket|timer|target)$`)

func (u Unit) Validate() error {
	if !unitPattern.MatchString(string(u)) || strings.HasPrefix(string(u), "-") {
		return fmt.Errorf("UNIT_REFUSED %q", string(u))
	}
	return nil
}

// Hex64 is a sha256 digest in lowercase hex.
type Hex64 string

func (h Hex64) Validate() error {
	if !hex64Pattern.MatchString(string(h)) {
		return fmt.Errorf("DIGEST_REFUSED %q", string(h))
	}
	return nil
}

var hex64Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ID is a numeric uid or gid, parsed base 10, within the ordinary range.
type ID uint32

func ParseID(s string) (ID, error) {
	if s == "" || strings.TrimLeft(s, "0123456789") != "" || (len(s) > 1 && s[0] == '0') {
		return 0, fmt.Errorf("ID_REFUSED %q", s)
	}
	v, e := strconv.ParseUint(s, 10, 32)
	if e != nil || v > 4294967294 {
		return 0, fmt.Errorf("ID_REFUSED %q", s)
	}
	return ID(v), nil
}

func (i ID) String() string { return strconv.FormatUint(uint64(i), 10) }

// Ret is a ledger retention class.
type Ret string

func (r Ret) Validate() error {
	switch r {
	case "d6", "state", "remove", "rehearsal":
		return nil
	}
	return fmt.Errorf("RET_REFUSED %q", string(r))
}

// validateAll returns the first error of a list of validators.
func validateAll(vs ...interface{ Validate() error }) error {
	for _, v := range vs {
		if e := v.Validate(); e != nil {
			return e
		}
	}
	return nil
}
