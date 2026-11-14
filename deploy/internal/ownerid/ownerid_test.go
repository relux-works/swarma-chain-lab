package ownerid

import (
	"errors"
	"os"
	"os/user"
	"strconv"
	"syscall"
	"testing"
)

// Claim: canonical IDs bypass name lookups, names use the correct lookup, and omitted fields remain unchanged.
func TestResolveNamesNumbersAndDefaults(t *testing.T) {
	calls := 0
	resolver := Resolver{User: func(s string) (string, error) {
		calls++
		if s != "fixture-owner" {
			t.Fatal("wrong user")
		}
		return "12345", nil
	}, Group: func(s string) (string, error) {
		calls++
		if s != "fixture-group" {
			t.Fatal("wrong group")
		}
		return "23456", nil
	}}
	for _, c := range []struct {
		owner, group        Spec
		uid, gid, wantCalls int
	}{
		{"fixture-owner", "fixture-group", 12345, 23456, 2}, {"12345", "23456", 12345, 23456, 0}, {"0", "4294967294", 0, 4294967294, 0}, {"", "", -1, -1, 0}, {"12345", "", 12345, -1, 0}, {"", "23456", -1, 23456, 0},
	} {
		calls = 0
		uid, gid, err := resolver.Resolve(c.owner, c.group)
		if err != nil || uid != c.uid || gid != c.gid || calls != c.wantCalls {
			t.Fatal("resolution changed identity")
		}
	}
	u, err := user.LookupId(strconv.Itoa(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	g, err := user.LookupGroupId(strconv.Itoa(os.Getegid()))
	if err != nil {
		t.Fatal(err)
	}
	uid, gid, err := System().Resolve(Spec(u.Username), Spec(g.Name))
	if err != nil || uid != os.Geteuid() || gid != os.Getegid() {
		t.Fatal("system names did not resolve")
	}
}

// Claim: unknown names, backend errors and invalid lookup results are errors, never permission to use the caller's IDs.
func TestResolveErrorsNeverMeanAbsence(t *testing.T) {
	for _, failure := range []error{user.UnknownUserError("missing-fixture-account"), user.UnknownGroupError("missing-fixture-group"), syscall.EIO} {
		for _, field := range []string{"owner", "group"} {
			resolver := Resolver{User: func(string) (string, error) { return "12345", nil }, Group: func(string) (string, error) { return "23456", nil }}
			bad := func(string) (string, error) { return "", failure }
			if field == "owner" {
				resolver.User = bad
			} else {
				resolver.Group = bad
			}
			if _, _, err := resolver.Resolve("fixture-owner", "fixture-group"); !errors.Is(err, failure) {
				t.Fatal("lookup error discarded")
			}
		}
	}
	for _, value := range []string{"", "01", "+1", "-1", "4294967295", "4294967296"} {
		resolver := Resolver{User: func(string) (string, error) { return value, nil }, Group: func(string) (string, error) { return value, nil }}
		if _, _, err := resolver.Resolve("fixture-owner", ""); !errors.Is(err, ErrID) {
			t.Fatal("invalid user lookup ID accepted")
		}
		if _, _, err := resolver.Resolve("", "fixture-group"); !errors.Is(err, ErrID) {
			t.Fatal("invalid group lookup ID accepted")
		}
	}
}
