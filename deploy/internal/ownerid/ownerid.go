// Package ownerid resolves optional creation ownership without treating lookup
// failures as an absent account or permission to use the caller's identity.
package ownerid

import (
	"errors"
	"os/user"
	"strconv"
	"strings"
)

var ErrID = errors.New("invalid creation owner or group")

// Spec is an optional flag value. The empty default means no ownership change;
// an explicitly empty flag is invalid.
type Spec string

func (s *Spec) String() string { return string(*s) }
func (s *Spec) Set(v string) error {
	if v == "" || strings.ContainsAny(v, "\x00\t\r\n :/") {
		return ErrID
	}
	*s = Spec(v)
	return nil
}

// Resolver is passed by value so tests can model NSS failures without changing
// global lookups. Lookup results must themselves be canonical numeric IDs.
type Resolver struct {
	User  func(string) (string, error)
	Group func(string) (string, error)
}

func System() Resolver {
	return Resolver{
		User: func(name string) (string, error) {
			u, err := user.Lookup(name)
			if err != nil {
				return "", err
			}
			return u.Uid, nil
		},
		Group: func(name string) (string, error) {
			g, err := user.LookupGroup(name)
			if err != nil {
				return "", err
			}
			return g.Gid, nil
		},
	}
}

func decimal(s string) (int, error) {
	n, err := strconv.ParseUint(s, 10, 32)
	// All-ones is fchown's "leave unchanged" sentinel, never an explicit ID.
	if err != nil || n == 1<<32-1 || strconv.FormatUint(n, 10) != s {
		return 0, ErrID
	}
	return int(n), nil
}

func resolve(s Spec, lookup func(string) (string, error)) (int, error) {
	if s == "" {
		return -1, nil
	}
	var checked Spec
	if err := checked.Set(string(s)); err != nil {
		return 0, err
	}
	if strings.Trim(string(s), "0123456789") == "" || s[0] == '+' || s[0] == '-' {
		return decimal(string(s))
	}
	id, err := lookup(string(s))
	if err != nil {
		return 0, err
	}
	return decimal(id)
}

// Resolve resolves both specified fields before the caller creates any file.
// -1 means the flag was absent and preserves the kernel's creation ownership.
func (r Resolver) Resolve(owner, group Spec) (int, int, error) {
	uid, err := resolve(owner, r.User)
	if err != nil {
		return 0, 0, err
	}
	gid, err := resolve(group, r.Group)
	if err != nil {
		return 0, 0, err
	}
	return uid, gid, nil
}
