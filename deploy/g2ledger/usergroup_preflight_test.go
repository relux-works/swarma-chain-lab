//go:build linux

package g2ledger

import (
	"errors"
	"strconv"
	"strings"
	"testing"
)

// Claim: successful group listings missing or contradicting the known pair or
// another present recorded group refuse without effects; a complete listing
// restores the baseline. These injected reads do not prove native NSS completeness.
func TestLedgerUserGroupEnumerationComplete(t *testing.T) {
	for _, auto := range []bool{false, true} {
		for _, variant := range []string{"empty", "unrelated", "wrong-gid", "missing-recorded", "wrong-recorded-gid", "complete"} {
			t.Run(strconv.FormatBool(auto)+"/"+variant, func(t *testing.T) {
				f := userGroupFixture(t, "rehearsal", auto)
				must(t, f.l.CreateAccount("group", "swarma-wallet-peer", "state", 0, 210101))
				newer := f.create(t, "newer", "file", "remove")
				if variant != "complete" {
					f.sys.groups["unrelated"] = Account{Name: "unrelated", GID: 240002}
					f.sys.members["unrelated"] = map[string]bool{pairName: true, "outsider": true}
				}
				f.sys.fault = func(cmd string, args []string) (fakeReply, bool) {
					if cmd != "/usr/bin/getent" || len(args) != 1 || args[0] != "group" {
						return fakeReply{}, false
					}
					pair := fakeGroup(f.sys, f.sys.groups[pairName])
					other := fakeGroup(f.sys, f.sys.groups["swarma-wallet-peer"])
					switch variant {
					case "empty":
						return fakeReply{}, true
					case "unrelated":
						return fakeReply{out: "unrelated:x:240002:\n"}, true
					case "wrong-gid":
						pair = strings.Replace(pair, ":210201:", ":210202:", 1)
					case "missing-recorded":
						other = ""
					case "wrong-recorded-gid":
						other = strings.Replace(other, ":210101:", ":210102:", 1)
					case "complete":
						return fakeReply{}, false
					}
					return fakeReply{out: pair + other}, true
				}
				if variant != "complete" {
					name := pairName
					if strings.Contains(variant, "recorded") {
						name = "swarma-wallet-peer"
					}
					requirePairStop(t, f, "PAIRED_USER_GROUPS "+pairName+": GROUP_INCOMPLETE "+name)
					exists(t, newer)
				}
				delete(f.sys.members["unrelated"], pairName)
				f.sys.fault = nil
				out, err := replayPair(t, f, "rehearsal")
				must(t, err)
				requireCleanPairBaseline(t, out)
				absent(t, newer)
			})
		}
	}
}

// Claim: passwd enumeration must include every other recorded user still
// present, with its exact identity; an empty or unrelated listing cannot stand
// in for the paired user. Repaired listings allow a complete rollback.
func TestLedgerUserGroupPasswdEnumerationComplete(t *testing.T) {
	for _, variant := range []string{"empty", "unrelated", "missing-recorded", "changed-recorded", "complete"} {
		t.Run(variant, func(t *testing.T) {
			f := userGroupFixture(t, "rehearsal", false)
			must(t, f.l.CreateAccount("group", "primary", "state", 0, 301))
			must(t, f.l.CreateAccount("user", "demo", "state", 301, 301))
			newer := f.create(t, "newer", "file", "remove")
			f.sys.fault = func(cmd string, args []string) (fakeReply, bool) {
				if cmd != "/usr/bin/getent" || len(args) != 1 || args[0] != "passwd" {
					return fakeReply{}, false
				}
				pair := fakePasswd(f.sys.users[pairName])
				switch variant {
				case "empty":
					return fakeReply{}, true
				case "unrelated":
					return fakeReply{out: "unrelated:x:302:302::/:/bin/sh\n"}, true
				case "missing-recorded":
					return fakeReply{out: pair}, true
				case "changed-recorded":
					other := f.sys.users["demo"]
					other.UID++
					return fakeReply{out: pair + fakePasswd(other)}, true
				}
				return fakeReply{}, false
			}
			if variant != "complete" {
				reason := "PASSWD_INCOMPLETE demo"
				if variant == "empty" || variant == "unrelated" {
					reason = "PASSWD_USER_MISSING"
				}
				requirePairStop(t, f, "PAIRED_GROUP_PASSWD "+pairName+": "+reason)
				exists(t, newer)
			}
			f.sys.fault = nil
			out, err := replayPair(t, f, "rehearsal")
			must(t, err)
			requireCleanPairBaseline(t, out)
			absent(t, newer)
		})
	}
}

// Claim: conditions already present before replay (foreign supplementary or
// primary membership, lookup errors, or incomplete group/passwd listings) refuse
// before even a newer file is removed; clean and recorded-membership neighbours
// reverse the file and pair fully under both modeled userdel policies.
func TestLedgerUserGroupPreflightBeforeNewerFile(t *testing.T) {
	for _, auto := range []bool{false, true} {
		for _, variant := range []string{"foreign", "primary", "group-error", "passwd-error", "group-empty", "passwd-empty", "clean", "recorded"} {
			t.Run(strconv.FormatBool(auto)+"/"+variant, func(t *testing.T) {
				f := setupWith(t, "rehearsal", func(f *fixture) {
					f.sys.usergroups = auto
					f.scope.Users = append(f.scope.Users, pairName)
					f.scope.Groups = append(f.scope.Groups, pairName)
					if variant == "recorded" {
						f.scope.Groups = append(f.scope.Groups, "unrelated")
					}
					f.sys.groups["unrelated"] = Account{Name: "unrelated", GID: 240002}
					f.sys.members["unrelated"] = map[string]bool{"outsider": true}
				})
				older := f.create(t, "older", "file", "remove")
				must(t, f.l.CreateAccount("group", pairName, "state", 0, 210201))
				must(t, f.l.CreateUserProfile(pairName, "state", 210201, 210201, "/var/lib/swarma-wallet", "Swarma G2 pay executor"))
				if variant == "recorded" {
					must(t, f.l.AddMember(pairName, "unrelated"))
				}
				newer := f.create(t, "newer", "file", "remove")
				reason := ""
				switch variant {
				case "foreign":
					f.sys.members["unrelated"][pairName] = true
					reason = "PAIRED_USER_GROUPS " + pairName + ": USER_OTHER_SUPPLEMENTARY_GROUP unrelated"
				case "primary":
					f.sys.users["unrelated"] = Account{Name: "unrelated", UID: 240001, GID: 210201, Home: "/", Shell: "/bin/sh"}
					reason = "PAIRED_GROUP_PASSWD " + pairName + ": PAIRED_GROUP_OTHER_PRIMARY_USER"
				case "group-error", "passwd-error", "group-empty", "passwd-empty":
					db := strings.Split(variant, "-")[0]
					f.sys.fault = func(cmd string, args []string) (fakeReply, bool) {
						if cmd == "/usr/bin/getent" && len(args) == 1 && args[0] == db {
							if strings.HasSuffix(variant, "-empty") {
								return fakeReply{}, true
							}
							return fakeReply{err: errors.New("injected enumeration failure")}, true
						}
						return fakeReply{}, false
					}
					prefix := "PAIRED_USER_GROUPS " + pairName + ": "
					inner := "GROUP_INCOMPLETE " + pairName
					if db == "passwd" {
						prefix = "PAIRED_GROUP_PASSWD " + pairName + ": "
						inner = "PASSWD_USER_MISSING"
					}
					if strings.HasSuffix(variant, "-error") {
						inner = "injected enumeration failure"
					}
					reason = prefix + inner
				}
				if reason != "" {
					requirePairStop(t, f, reason)
					exists(t, newer)
					exists(t, older)
					delete(f.sys.members["unrelated"], pairName)
					delete(f.sys.users, "unrelated")
					f.sys.fault = nil
				}
				out, err := replayPair(t, f, "rehearsal")
				must(t, err)
				requireCleanPairBaseline(t, out)
				absent(t, newer)
				absent(t, older)
				if len(f.sys.users) != 0 || len(f.sys.groups) != 1 || f.sys.groups["unrelated"].GID != 240002 || len(f.sys.members["unrelated"]) != 1 || !f.sys.members["unrelated"]["outsider"] {
					t.Fatal("rollback retained pair or changed unrelated state")
				}
			})
		}
	}
}

// Claim: a foreign membership or partial listing appearing only after preflight
// is still refused at user undo, preserving both accounts. This does not promise
// transactional reversal of effects that preceded the new external change.
func TestLedgerUserGroupSupplementaryRecheckStops(t *testing.T) {
	for _, variant := range []string{"foreign", "empty"} {
		t.Run(variant, func(t *testing.T) {
			f := userGroupFixture(t, "rehearsal", true)
			f.sys.groups["unrelated"] = Account{Name: "unrelated", GID: 240002}
			f.sys.members["unrelated"] = map[string]bool{"outsider": true}
			user, group := f.sys.users[pairName], f.sys.groups[pairName]
			calls := 0
			f.sys.calls = nil
			f.sys.fault = func(cmd string, args []string) (fakeReply, bool) {
				if cmd == "/usr/bin/getent" && len(args) == 1 && args[0] == "group" {
					calls++
					if calls == 2 {
						if variant == "empty" {
							return fakeReply{}, true
						}
						f.sys.members["unrelated"][pairName] = true
					}
				}
				return fakeReply{}, false
			}
			out, err := replayPair(t, f, "rehearsal")
			code(t, err, 1)
			inner := "USER_OTHER_SUPPLEMENTARY_GROUP unrelated"
			if variant == "empty" {
				inner = "GROUP_INCOMPLETE " + pairName
			}
			requirePairReason(t, err, "PAIRED_USER_GROUPS "+pairName+": "+inner)
			if calls != 2 || out != "" || f.sys.users[pairName] != user || f.sys.groups[pairName] != group || f.sys.called("/usr/sbin/userdel") || f.sys.called("/usr/sbin/groupdel") || f.sys.called("/usr/bin/gpasswd") {
				t.Fatal("undo did not recheck safely after preflight")
			}
			if variant == "foreign" && !f.sys.members["unrelated"][pairName] {
				t.Fatal("late foreign membership consumed")
			}
			delete(f.sys.members["unrelated"], pairName)
			f.sys.fault = nil
			out, err = replayPair(t, f, "rehearsal")
			must(t, err)
			requireCleanPairBaseline(t, out)
		})
	}
}

// Claim: baseline accounts are also known records, not just this attempt's
// creations. Omitting or changing their enumeration rows refuses before a newer
// file reversal, and the repaired listing preserves the exact baseline accounts.
func TestLedgerUserGroupBaselineEnumerationComplete(t *testing.T) {
	for _, db := range []string{"group", "passwd"} {
		for _, drift := range []string{"missing", "changed"} {
			t.Run(db+"/"+drift, func(t *testing.T) {
				f := setupWith(t, "rehearsal", func(f *fixture) {
					f.scope.Users = append(f.scope.Users, pairName)
					f.scope.Groups = append(f.scope.Groups, pairName)
					f.sys.groups["foreign"] = Account{Name: "foreign", GID: 240002}
					f.sys.users["foreign"] = Account{Name: "foreign", UID: 240003, GID: 240002, Home: "/", Shell: "/bin/sh"}
				})
				must(t, f.l.CreateAccount("group", pairName, "state", 0, 210201))
				must(t, f.l.CreateUserProfile(pairName, "state", 210201, 210201, "/var/lib/swarma-wallet", "Swarma G2 pay executor"))
				newer := f.create(t, "newer", "file", "remove")
				f.sys.fault = func(cmd string, args []string) (fakeReply, bool) {
					if cmd != "/usr/bin/getent" || len(args) != 1 || args[0] != db {
						return fakeReply{}, false
					}
					out := fakeGroup(f.sys, f.sys.groups[pairName])
					if db == "passwd" {
						out = fakePasswd(f.sys.users[pairName])
					}
					if drift == "changed" {
						if db == "group" {
							other := f.sys.groups["foreign"]
							other.GID++
							out += fakeGroup(f.sys, other)
						} else {
							other := f.sys.users["foreign"]
							other.UID++
							out += fakePasswd(other)
						}
					}
					return fakeReply{out: out}, true
				}
				prefix := "PAIRED_USER_GROUPS " + pairName + ": GROUP"
				if db == "passwd" {
					prefix = "PAIRED_GROUP_PASSWD " + pairName + ": PASSWD"
				}
				requirePairStop(t, f, prefix+"_INCOMPLETE foreign")
				exists(t, newer)
				f.sys.fault = nil
				out, err := replayPair(t, f, "rehearsal")
				must(t, err)
				requireCleanPairBaseline(t, out)
				absent(t, newer)
				if len(f.sys.users) != 1 || len(f.sys.groups) != 1 || f.sys.users["foreign"].UID != 240003 || f.sys.groups["foreign"].GID != 240002 {
					t.Fatal("rollback changed baseline accounts")
				}
			})
		}
	}
}
