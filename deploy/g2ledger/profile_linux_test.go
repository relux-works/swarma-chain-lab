package g2ledger

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func profileFixture(t *testing.T, home, gecos string) *fixture {
	t.Helper()
	return profileFixtureFor(t, home, gecos, "rehearsal")
}
func profileFixtureFor(t *testing.T, home, gecos, purpose string) *fixture {
	t.Helper()
	f := setupWith(t, purpose, nil)
	ret := "rehearsal"
	if purpose == "station" {
		ret = "state"
	}
	must(t, f.l.CreateAccount("group", "primary", ret, 0, 230302))
	f.l.Close()
	must(t, Run([]string{"create-user", "-dir", f.dir, "-name", "demo", "-uid", "230301", "-gid", "230302", "-home", home, "-gecos", gecos, "-shell", "/usr/sbin/nologin", "-ret", ret}, f.sys, &bytes.Buffer{}))
	var err error
	f.l, err = Open(f.dir, f.sys)
	must(t, err)
	return f
}

// Claim: the CLI records exact passwd profile fields, including empty GECOS and root home, without creating the home directory; valid rehearsal replay restores S0.
func TestLedgerUserProfileRecorded(t *testing.T) {
	for _, tc := range []struct{ name, home, gecos string }{{"service", "/var/lib/swarma-wallet", "Swarma G2 pay executor"}, {"agent", "/", ""}, {"no-home-creation", filepath.Join(t.TempDir(), "not-created"), ""}} {
		t.Run(tc.name, func(t *testing.T) {
			f := profileFixture(t, tc.home, tc.gecos)
			a := f.l.rows[3].Body.Action
			got := f.l.rows[4].Body.Result.Identities[0].Account
			if a.Home != tc.home || a.Description != tc.gecos || got.Home != tc.home || got.Description != tc.gecos || got.Shell != "/usr/sbin/nologin" {
				t.Fatal("profile not bound", a, got)
			}
			if !strings.Contains(strings.Join(f.sys.calls, "\n"), "-d "+tc.home+" -c "+tc.gecos) {
				t.Fatal("creator did not receive profile")
			}
			if tc.name == "no-home-creation" {
				absent(t, tc.home)
			}
			must(t, f.l.Replay("rehearsal"))
			if len(f.sys.users) != 0 || len(f.sys.groups) != 0 {
				t.Fatal("valid profile not removed")
			}
		})
	}
}

// Claim: home drift and GECOS drift each stop at the user before any removal, preserve journal, user and primary group, and pass after restoring the exact profile.
func TestLedgerUserProfileReplayDriftStops(t *testing.T) {
	for _, field := range []string{"home", "gecos"} {
		t.Run(field, func(t *testing.T) {
			f := profileFixture(t, "/var/lib/swarma-wallet", "Swarma G2 pay executor")
			original := f.sys.users["demo"]
			changed := original
			if field == "home" {
				changed.Home = "/var/lib/other"
			} else {
				changed.Description = "Other executor"
			}
			f.sys.users["demo"] = changed
			before, err := os.ReadFile(filepath.Join(f.dir, "records.jsonl"))
			must(t, err)
			calls := len(f.sys.calls)
			err = f.l.Replay("rehearsal")
			code(t, err, 1)
			if !strings.Contains(err.Error(), "IDENTITY_MISMATCH demo") {
				t.Fatal(err)
			}
			after, err := os.ReadFile(filepath.Join(f.dir, "records.jsonl"))
			must(t, err)
			if !bytes.Equal(before, after) || f.sys.users["demo"] != changed || len(f.sys.groups) != 1 {
				t.Fatal("refusal changed state")
			}
			for _, call := range f.sys.calls[calls:] {
				if strings.Contains(call, "/userdel ") || strings.Contains(call, "/groupdel ") {
					t.Fatal("refusal removed an account", call)
				}
			}
			f.sys.users["demo"] = original
			must(t, f.l.Replay("rehearsal"))
			if len(f.sys.users) != 0 || len(f.sys.groups) != 0 {
				t.Fatal("valid neighbour not restored")
			}
		})
	}
}

// Claim: invalid homes, GECOS record separators, login shells and unneeded uppercase names refuse before opening or writing the ledger; exact profiles remain valid in the paired positive test.
func TestLedgerUserProfileInvalidFlags(t *testing.T) {
	for _, tc := range []struct{ flag, value string }{{"-home", "relative"}, {"-home", ""}, {"-gecos", "bad:gecos"}, {"-gecos", "bad\ngecos"}, {"-shell", "/bin/sh"}, {"-name", "G2-agent"}} {
		t.Run(tc.flag+tc.value, func(t *testing.T) {
			f := setup(t)
			before := len(f.l.rows)
			calls := len(f.sys.calls)
			args := []string{"create-user", "-dir", f.dir, "-name", "demo", "-uid", "230301", "-gid", "230302", "-home", "/", "-gecos", "", "-shell", "/usr/sbin/nologin", "-ret", "state", tc.flag, tc.value}
			code(t, Run(args, f.sys, &bytes.Buffer{}), 2)
			if len(f.l.rows) != before || len(f.sys.calls) != calls {
				t.Fatal("invalid flags accessed ledger/system")
			}
		})
	}
}

// Claim: retained station users also stop on either profile field drifting, then retain the exact account after the original profile is restored.
func TestLedgerUserProfileStationDriftStops(t *testing.T) {
	for _, field := range []string{"home", "gecos"} {
		t.Run(field, func(t *testing.T) {
			f := profileFixtureFor(t, "/var/lib/swarma-wallet", "Swarma G2 pay executor", "station")
			original := f.sys.users["demo"]
			changed := original
			if field == "home" {
				changed.Home = "/var/lib/other"
			} else {
				changed.Description = "Other executor"
			}
			f.sys.users["demo"] = changed
			err := f.l.Replay("station")
			code(t, err, 1)
			if !strings.Contains(err.Error(), "IDENTITY_MISMATCH demo") || f.sys.users["demo"] != changed || len(f.sys.groups) != 1 {
				t.Fatal("station drift failed to preserve", err)
			}
			f.sys.users["demo"] = original
			must(t, f.l.Replay("station"))
			if f.sys.users["demo"] != original || len(f.sys.groups) != 1 {
				t.Fatal("station neighbour not retained")
			}
		})
	}
}

// Claim: a creator returning a different profile or nologin path cannot commit a receipt and is preserved as an orphan; exact profile creation has a nearby positive control above.
func TestLedgerUserProfileCreatorMismatchOrphan(t *testing.T) {
	for _, field := range []string{"home", "gecos", "shell"} {
		t.Run(field, func(t *testing.T) {
			f := setupWith(t, "rehearsal", nil)
			must(t, f.l.CreateAccount("group", "primary", "rehearsal", 0, 230302))
			f.sys.fault = func(command string, args []string) (fakeReply, bool) {
				if command != "/usr/sbin/useradd" {
					return fakeReply{}, false
				}
				got := Account{Name: "demo", UID: 230301, GID: 230302, Home: "/var/lib/swarma-wallet", Description: "Swarma G2 pay executor", Shell: "/usr/sbin/nologin"}
				switch field {
				case "home":
					got.Home = "/var/lib/other"
				case "gecos":
					got.Description = "Other executor"
				case "shell":
					got.Shell = "/sbin/nologin"
				}
				f.sys.users["demo"] = got
				return fakeReply{}, true
			}
			err := f.l.CreateUserProfile("demo", "rehearsal", 230301, 230302, "/var/lib/swarma-wallet", "Swarma G2 pay executor")
			code(t, err, 3)
			if !strings.Contains(err.Error(), "ORPHAN demo") || f.l.rows[len(f.l.rows)-1].Body.Op != "intent" {
				t.Fatal("mismatch granted receipt", err)
			}
			f.l.Close()
			_, err = Open(f.dir, f.sys)
			code(t, err, 3)
			if _, ok := f.sys.users["demo"]; !ok {
				t.Fatal("orphan removed")
			}
		})
	}
}
