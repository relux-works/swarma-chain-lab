//go:build linux

package g2ledger

import (
	"io"
	"strings"
	"testing"
)

// Claim: either login.defs setting refuses unrecorded/retained same-name groups, permits a removable recorded pair, and preserves a differently named primary group.
func TestLedgerUserRemovalHasNoImplicitGroupEffect(t *testing.T) {
	for _, origin := range []string{"unrecorded", "d6", "remove", "different-name"} {
		for _, auto := range []bool{false, true} {
			t.Run(origin+map[bool]string{false: "/USERGROUPS_ENAB=no", true: "/USERGROUPS_ENAB=yes"}[auto], func(t *testing.T) {
				f := setupWith(t, "rehearsal", func(f *fixture) {
					f.sys.usergroups = auto
					if origin == "unrecorded" {
						f.sys.groups["demo"] = Account{Name: "demo", GID: 301}
					}
					if origin == "different-name" {
						f.sys.groups["primary"] = Account{Name: "primary", GID: 301}
					}
				})
				older := f.create(t, "older", "file", "remove")
				if origin == "d6" || origin == "remove" {
					must(t, f.l.CreateAccount("group", "demo", origin, 0, 301))
				}
				must(t, f.l.CreateAccount("user", "demo", "remove", 301, 301))
				f.l.Close()
				err := Run([]string{"replay", "-dir", f.dir, "-mode", "rehearsal"}, f.sys, io.Discard)
				if origin == "different-name" || origin == "remove" {
					must(t, err)
					absent(t, older)
					if _, ok := f.sys.users["demo"]; ok {
						t.Fatal("user retained")
					}
					if origin == "different-name" {
						if _, ok := f.sys.groups["primary"]; !ok {
							t.Fatal("group lost")
						}
					} else if _, ok := f.sys.groups["demo"]; ok {
						t.Fatal("paired group retained")
					}
				} else {
					code(t, err, 1)
					if !strings.Contains(err.Error(), "USER_SAME_NAME_GROUP demo") {
						t.Fatal(err)
					}
					if f.sys.called("/usr/sbin/userdel") || f.sys.called("/usr/sbin/groupdel") {
						t.Fatal("effect before refusal")
					}
					if _, ok := f.sys.groups["demo"]; !ok {
						t.Fatal("group lost")
					}
					if _, ok := f.sys.users["demo"]; !ok {
						t.Fatal("partial user deletion")
					}
					exists(t, older)
				}
			})
		}
	}
}
