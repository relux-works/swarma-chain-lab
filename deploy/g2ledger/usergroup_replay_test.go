//go:build linux

package g2ledger

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"
)

const pairName = "swarma-wallet"

func userGroupFixture(t *testing.T, purpose string, auto bool, roles ...string) *fixture {
	t.Helper()
	f := setupWith(t, purpose, func(f *fixture) {
		f.sys.usergroups = auto
		f.scope.Users = append(f.scope.Users, pairName)
		f.scope.Groups = append(f.scope.Groups, pairName, "swarma-wallet-peer", "swarma-wallet-status")
	})
	must(t, f.l.CreateAccount("group", pairName, "state", 0, 210201))
	must(t, f.l.CreateUserProfile(pairName, "state", 210201, 210201, "/var/lib/swarma-wallet", "Swarma G2 pay executor", roles...))
	return f
}

func replayPair(t *testing.T, f *fixture, mode string) (string, error) {
	t.Helper()
	f.reopen(t)
	var out bytes.Buffer
	f.l.output = &out
	err := f.l.Replay(mode)
	return out.String(), err
}

func requirePairReason(t *testing.T, err error, want string) {
	t.Helper()
	var failure *Failure
	if !errors.As(err, &failure) || failure.Reason != want {
		t.Fatalf("want exact Failure.Reason %q, got %v", want, err)
	}
}

func requirePairStop(t *testing.T, f *fixture, reason string) {
	t.Helper()
	f.sys.calls = nil
	state := func() []byte {
		return canonical(struct {
			Users, Groups map[string]Account
			Members       map[string]map[string]bool
		}{f.sys.users, f.sys.groups, f.sys.members})
	}
	before := state()
	out, err := replayPair(t, f, "rehearsal")
	code(t, err, 1)
	if f.sys.called("/usr/sbin/userdel") || f.sys.called("/usr/sbin/groupdel") || f.sys.called("/usr/bin/gpasswd") {
		t.Fatal("refusal performed an account effect")
	}
	if !bytes.Equal(before, state()) {
		t.Fatal("refusal changed account state")
	}
	requirePairReason(t, err, reason)
	if out != "" {
		t.Fatalf("want %s without final compare, got %v, %q", reason, err, out)
	}
}

func requireCleanPairBaseline(t *testing.T, out string) {
	t.Helper()
	var summary CompareSummary
	dec := json.NewDecoder(strings.NewReader(out))
	must(t, dec.Decode(&summary))
	if summary.Type != "baseline_summary" || summary.Mode != "rehearsal" || summary.Compared == 0 || summary.Retained != 0 || summary.Unlisted != 0 {
		t.Fatalf("baseline not clean: %s", out)
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		t.Fatal("unexpected additional JSONL")
	}
	t.Logf("final baseline JSONL: %s", strings.TrimSpace(out))
}

// Claim: the sysusers-shaped user/group plus two recorded supplementary groups fully restore S0 JSONL under either USERGROUPS_ENAB value, including retry.
func TestLedgerUserGroupSysusersRollback(t *testing.T) {
	for _, auto := range []bool{false, true} {
		t.Run(map[bool]string{false: "USERGROUPS_ENAB=no", true: "USERGROUPS_ENAB=yes"}[auto], func(t *testing.T) {
			f := userGroupFixture(t, "rehearsal", auto)
			for i, group := range []string{"swarma-wallet-peer", "swarma-wallet-status"} {
				must(t, f.l.CreateAccount("group", group, "state", 0, uint32(210101+i*200)))
				must(t, f.l.AddMember(pairName, group))
			}
			out, err := replayPair(t, f, "rehearsal")
			must(t, err)
			requireCleanPairBaseline(t, out)
			if len(f.sys.users) != 0 || len(f.sys.groups) != 0 || len(f.sys.members) != 0 {
				t.Fatal("accounts or membership retained")
			}
			user := callIndex(f.sys, "/usr/sbin/userdel "+pairName)
			for _, group := range []string{"swarma-wallet-peer", "swarma-wallet-status"} {
				member := callIndex(f.sys, "/usr/bin/gpasswd -d "+pairName+" "+group)
				if member < 0 || user <= member {
					t.Fatal("user removed before membership")
				}
			}
			groupdel := -1
			// Match the exact command, excluding similarly prefixed supplementary groups.
			for i, call := range f.sys.calls {
				if call == "/usr/sbin/groupdel "+pairName {
					groupdel = i
				}
			}
			if (groupdel >= 0) == auto || !auto && groupdel <= user {
				t.Fatal("wrong documented userdel outcome handling")
			}
			f.sys.calls = nil
			out, err = replayPair(t, f, "rehearsal")
			must(t, err)
			requireCleanPairBaseline(t, out)
			if f.sys.called("/usr/sbin/userdel") || f.sys.called("/usr/sbin/groupdel") {
				t.Fatal("retry repeated deletion")
			}
		})
	}
}

// Claim: an unrecorded same-name group is preserved with USER_SAME_NAME_GROUP before any reversal under either policy setting.
func TestLedgerUserGroupPreexistingRefuses(t *testing.T) {
	for _, auto := range []bool{false, true} {
		t.Run(map[bool]string{false: "no", true: "yes"}[auto], func(t *testing.T) {
			f := setupWith(t, "rehearsal", func(f *fixture) {
				f.sys.usergroups = auto
				f.scope.Users = append(f.scope.Users, "swarma-wallet-peer")
				f.scope.Groups = append(f.scope.Groups, "swarma-wallet-peer")
				f.sys.groups["swarma-wallet-peer"] = Account{Name: "swarma-wallet-peer", GID: 210101}
			})
			older := f.create(t, "older", "file", "remove")
			must(t, f.l.CreateUserProfile("swarma-wallet-peer", "state", 210101, 210101, "/", ""))
			requirePairStop(t, f, "USER_SAME_NAME_GROUP swarma-wallet-peer")
			exists(t, older)
			if f.sys.groups["swarma-wallet-peer"].GID != 210101 || f.sys.users["swarma-wallet-peer"].UID != 210101 {
				t.Fatal("unrecorded group or user changed")
			}
		})
	}
}

// Claim: foreign supplementary membership refuses preflight before account or file effects; removing that foreign membership restores the valid pair neighbour.
func TestLedgerUserGroupForeignSupplementaryStops(t *testing.T) {
	f := userGroupFixture(t, "rehearsal", true)
	newer := f.create(t, "newer", "file", "remove")
	f.sys.members[pairName] = map[string]bool{"foreign": true}
	requirePairStop(t, f, "UNLISTED_DIFFERENCE group:"+pairName+"/member:foreign")
	exists(t, newer)
	if !f.sys.members[pairName]["foreign"] {
		t.Fatal("foreign membership removed")
	}
	delete(f.sys.members[pairName], "foreign")
	out, err := replayPair(t, f, "rehearsal")
	must(t, err)
	requireCleanPairBaseline(t, out)
}

// Claim: another passwd user's primary GID blocks before every reversal even when userdel would preserve the group; a different GID permits rollback.
func TestLedgerUserGroupOtherPrimaryStops(t *testing.T) {
	for _, auto := range []bool{false, true} {
		t.Run(map[bool]string{false: "no", true: "yes"}[auto], func(t *testing.T) {
			f := userGroupFixture(t, "rehearsal", auto)
			newer := f.create(t, "newer", "file", "remove")
			foreign := Account{Name: "unscoped", UID: 240001, GID: 210201, Home: "/", Shell: "/bin/sh"}
			f.sys.users[foreign.Name] = foreign
			requirePairStop(t, f, "PAIRED_GROUP_PASSWD "+pairName+": PAIRED_GROUP_OTHER_PRIMARY_USER")
			exists(t, newer)
			if f.sys.users[foreign.Name] != foreign {
				t.Fatal("foreign primary user changed")
			}
			foreign.GID++
			f.sys.users[foreign.Name] = foreign
			out, err := replayPair(t, f, "rehearsal")
			must(t, err)
			requireCleanPairBaseline(t, out)
		})
	}
}

// Claim: changed user/profile/group identities, a missing paired group, and a retained group refuse before effects; restoring the exact receipt permits rollback.
func TestLedgerUserGroupIdentityAndRetentionStops(t *testing.T) {
	for _, field := range []string{"uid", "gid", "home", "gecos", "shell", "group-gid", "missing-group", "retained-group", "non-primary-group"} {
		t.Run(field, func(t *testing.T) {
			f := userGroupFixture(t, "rehearsal", false)
			user, group := f.sys.users[pairName], f.sys.groups[pairName]
			changed := user
			reason := "IDENTITY_MISMATCH"
			switch field {
			case "uid":
				changed.UID++
			case "gid":
				changed.GID++
			case "home":
				changed.Home = "/"
			case "gecos":
				changed.Description = "Changed service"
			case "shell":
				changed.Shell = "/bin/sh"
			case "group-gid":
				g := group
				g.GID++
				f.sys.groups[pairName] = g
				reason = "PAIRED_GROUP_IDENTITY"
			case "missing-group":
				delete(f.sys.groups, pairName)
				reason = "PAIRED_GROUP_MISSING"
			case "retained-group":
				// Build an independently valid retained-group journal instead of corrupting a receipt.
				f = setupWith(t, "rehearsal", nil)
				must(t, f.l.CreateAccount("group", "demo", "d6", 0, 301))
				must(t, f.l.CreateAccount("user", "demo", "state", 301, 301))
				requirePairStop(t, f, "USER_SAME_NAME_GROUP demo")
				return
			case "non-primary-group":
				f = setupWith(t, "rehearsal", nil)
				must(t, f.l.CreateAccount("group", "primary", "state", 0, 301))
				must(t, f.l.CreateAccount("group", "demo", "state", 0, 302))
				must(t, f.l.CreateAccount("user", "demo", "state", 301, 301))
				requirePairStop(t, f, "PAIRED_GROUP_PRIMARY_GID demo")
				return
			}
			f.sys.users[pairName] = changed
			newer := f.create(t, "newer", "file", "remove")
			requirePairStop(t, f, reason+" "+pairName)
			exists(t, newer)
			f.sys.users[pairName], f.sys.groups[pairName] = user, group
			out, err := replayPair(t, f, "rehearsal")
			must(t, err)
			requireCleanPairBaseline(t, out)
		})
	}
}

// Claim: station purpose retains both exact accounts and refuses rehearsal mode before account deletion under either USERGROUPS_ENAB setting.
func TestLedgerUserGroupStationRetains(t *testing.T) {
	for _, auto := range []bool{false, true} {
		f := userGroupFixture(t, "station", auto)
		user, group := f.sys.users[pairName], f.sys.groups[pairName]
		_, err := replayPair(t, f, "station")
		must(t, err)
		_, err = replayPair(t, f, "rehearsal")
		code(t, err, 1)
		requirePairReason(t, err, "MODE_PURPOSE_MISMATCH purpose=station mode=rehearsal")
		if f.sys.users[pairName] != user || f.sys.groups[pairName] != group || f.sys.called("/usr/sbin/userdel") || f.sys.called("/usr/sbin/groupdel") {
			t.Fatal("station account protection changed", err)
		}
	}
}

// Claim: passwd enumeration errors, unsupported enumeration, malformed/duplicate rows, and missing/changed allowed users stop before effects; the unfaulted neighbour rolls back.
func TestLedgerUserGroupPasswdLookupStops(t *testing.T) {
	for _, variant := range []string{"error", "status", "unsupported", "malformed", "duplicate", "carriage-return", "missing", "changed", "bad-id", "late-error"} {
		t.Run(variant, func(t *testing.T) {
			f := userGroupFixture(t, "rehearsal", true)
			calls := 0
			f.sys.fault = func(cmd string, args []string) (fakeReply, bool) {
				if cmd != "/usr/bin/getent" || len(args) != 1 || args[0] != "passwd" {
					return fakeReply{}, false
				}
				calls++
				if variant == "late-error" && calls == 1 {
					return fakeReply{}, false
				}
				line := fakePasswd(f.sys.users[pairName])
				switch variant {
				case "error", "late-error":
					return fakeReply{err: errors.New("injected lookup failure")}, true
				case "status":
					return fakeReply{status: 2}, true
				case "unsupported":
					return fakeReply{status: 3}, true
				case "malformed":
					return fakeReply{out: line + "invalid\n"}, true
				case "duplicate":
					return fakeReply{out: line + line}, true
				case "carriage-return":
					return fakeReply{out: strings.Replace(line, "\n", "\r\n", 1)}, true
				case "missing":
					return fakeReply{}, true
				case "changed":
					return fakeReply{out: strings.Replace(line, "/var/lib/swarma-wallet", "/", 1)}, true
				default:
					return fakeReply{out: strings.Replace(line, ":210201:", ":invalid:", 1)}, true
				}
			}
			reason := map[string]string{
				"error": "injected lookup failure", "late-error": "injected lookup failure",
				"status": "PASSWD_STATUS_2", "unsupported": "PASSWD_STATUS_3",
				"malformed": "PASSWD_SCHEMA", "duplicate": "PASSWD_SCHEMA", "carriage-return": "PASSWD_SCHEMA",
				"missing": "PASSWD_USER_MISSING", "changed": "PASSWD_USER_CHANGED", "bad-id": "PASSWD_IDENTITY",
			}[variant]
			requirePairStop(t, f, "PAIRED_GROUP_PASSWD "+pairName+": "+reason)
			f.sys.fault = nil
			out, err := replayPair(t, f, "rehearsal")
			must(t, err)
			requireCleanPairBaseline(t, out)
		})
	}
}

// Claim: userdel/groupdel errors, partial success, drift, foreign arrivals, and outcome lookup errors stop before older reversals, with both documented policy outcomes exercised.
func TestLedgerUserGroupOutcomeStops(t *testing.T) {
	for _, variant := range []string{"userdel-error", "userdel-noop", "user-lookup-error", "implicit-group-lookup-error", "surviving-group-lookup-error", "group-changed", "foreign-member", "foreign-primary", "groupdel-error", "groupdel-noop", "groupdel-lookup-error"} {
		t.Run(variant, func(t *testing.T) {
			auto := variant == "implicit-group-lookup-error"
			f := setupWith(t, "rehearsal", func(f *fixture) {
				f.sys.usergroups = auto
				f.scope.Users = append(f.scope.Users, pairName)
				f.scope.Groups = append(f.scope.Groups, pairName)
			})
			must(t, f.l.CreateAccount("group", pairName, "state", 0, 210201))
			// This reversal is older than the user but newer than the group receipt.
			older := f.create(t, "older", "file", "remove")
			must(t, f.l.CreateUserProfile(pairName, "state", 210201, 210201, "/var/lib/swarma-wallet", "Swarma G2 pay executor"))
			deletedUser, deletedGroup := false, false
			var fault func(string, []string) (fakeReply, bool)
			fault = func(cmd string, args []string) (fakeReply, bool) {
				if cmd == "/usr/sbin/userdel" {
					if variant == "userdel-error" {
						return fakeReply{status: 8}, true
					}
					if variant == "userdel-noop" {
						return fakeReply{}, true
					}
					// Execute the normal fake (including USERGROUPS_ENAB), then inject a post-tool observation.
					f.sys.fault = nil
					out, status, err := f.sys.Run(cmd, args...)
					f.sys.fault = fault
					deletedUser = true
					switch variant {
					case "group-changed":
						g := f.sys.groups[pairName]
						g.GID++
						f.sys.groups[pairName] = g
					case "foreign-member":
						f.sys.members[pairName] = map[string]bool{"foreign": true}
					case "foreign-primary":
						f.sys.users["unscoped"] = Account{Name: "unscoped", UID: 240001, GID: 210201, Shell: "/bin/sh", Home: "/"}
					}
					return fakeReply{out, status, err}, true
				}
				if cmd == "/usr/sbin/groupdel" {
					if variant == "groupdel-error" {
						return fakeReply{status: 10}, true
					}
					if variant == "groupdel-noop" {
						return fakeReply{}, true
					}
					deletedGroup = true
				}
				if cmd == "/usr/bin/getent" && len(args) == 2 && args[1] == pairName && deletedUser {
					if variant == "user-lookup-error" && args[0] == "passwd" ||
						(variant == "implicit-group-lookup-error" || variant == "surviving-group-lookup-error") && args[0] == "group" ||
						variant == "groupdel-lookup-error" && deletedGroup && args[0] == "group" {
						return fakeReply{err: errors.New("injected outcome lookup failure")}, true
					}
				}
				return fakeReply{}, false
			}
			f.sys.fault = fault
			out, err := replayPair(t, f, "rehearsal")
			exists(t, older)
			code(t, err, 1)
			reason := map[string]string{
				"userdel-error":                "REMOVE_ACCOUNT " + pairName + ": COMMAND_STATUS_8",
				"userdel-noop":                 "ACCOUNT_STILL_PRESENT " + pairName,
				"user-lookup-error":            "REMOVE_ACCOUNT_LOOKUP " + pairName + ": injected outcome lookup failure",
				"implicit-group-lookup-error":  "PAIRED_GROUP_LOOKUP " + pairName + ": injected outcome lookup failure",
				"surviving-group-lookup-error": "PAIRED_GROUP_LOOKUP " + pairName + ": injected outcome lookup failure",
				"group-changed":                "PAIRED_GROUP_IDENTITY " + pairName,
				"foreign-member":               "PAIRED_GROUP_NOT_EMPTY " + pairName,
				"foreign-primary":              "PAIRED_GROUP_PASSWD " + pairName + ": PAIRED_GROUP_OTHER_PRIMARY_USER",
				"groupdel-error":               "REMOVE_ACCOUNT " + pairName + ": COMMAND_STATUS_10",
				"groupdel-noop":                "PAIRED_GROUP_STILL_PRESENT " + pairName,
				"groupdel-lookup-error":        "PAIRED_GROUP_LOOKUP " + pairName + ": injected outcome lookup failure",
			}[variant]
			requirePairReason(t, err, reason)
			if out != "" {
				t.Fatalf("want refusal without final compare, got %v %q", err, out)
			}
			if strings.HasPrefix(variant, "userdel-") {
				if len(f.sys.users) != 1 || len(f.sys.groups) != 1 {
					t.Fatal("failed userdel lost accounts")
				}
			}
			if variant == "group-changed" || strings.HasPrefix(variant, "foreign-") {
				if f.sys.called("/usr/sbin/groupdel") || len(f.sys.groups) != 1 {
					t.Fatal("changed/foreign group was removed")
				}
			}
		})
	}
}

// Claim: identity/member drift or disappearance during a passwd scan is detected before userdel or groupdel, rather than trusting a stale group observation.
func TestLedgerUserGroupScanBoundaryStops(t *testing.T) {
	for _, phase := range []string{"preflight", "user", "group"} {
		for _, drift := range []string{"gid", "member", "gone"} {
			t.Run(phase+"/"+drift, func(t *testing.T) {
				f := userGroupFixture(t, "rehearsal", false)
				calls := 0
				f.sys.fault = func(cmd string, args []string) (fakeReply, bool) {
					if cmd != "/usr/bin/getent" || len(args) != 1 || args[0] != "passwd" {
						return fakeReply{}, false
					}
					calls++
					if calls != map[string]int{"preflight": 1, "user": 2, "group": 3}[phase] {
						return fakeReply{}, false
					}
					switch drift {
					case "gid":
						g := f.sys.groups[pairName]
						g.GID++
						f.sys.groups[pairName] = g
					case "member":
						f.sys.members[pairName] = map[string]bool{"foreign": true}
					case "gone":
						delete(f.sys.groups, pairName)
					}
					return fakeReply{}, false
				}
				out, err := replayPair(t, f, "rehearsal")
				code(t, err, 1)
				reason := map[string]string{"gid": "PAIRED_GROUP_IDENTITY", "member": "PAIRED_GROUP_NOT_EMPTY", "gone": "PAIRED_GROUP_MISSING"}[drift]
				if phase == "preflight" && drift == "member" {
					reason = "UNLISTED_DIFFERENCE group:" + pairName + "/member:foreign"
				}
				if !(phase == "preflight" && drift == "member") {
					reason += " " + pairName
				}
				requirePairReason(t, err, reason)
				if out != "" || f.sys.called("/usr/sbin/groupdel") || phase != "group" && f.sys.called("/usr/sbin/userdel") {
					t.Fatalf("scan-boundary refusal failed: %v %q", err, out)
				}
			})
		}
	}
}

// Claim: a verified paired removal consumes only that group's older receipt and refuses a reappearing group before another deletion, under either tool policy.
func TestLedgerUserGroupReappearanceStops(t *testing.T) {
	for _, auto := range []bool{false, true} {
		t.Run(map[bool]string{false: "no", true: "yes"}[auto], func(t *testing.T) {
			f := userGroupFixture(t, "rehearsal", auto)
			confirmedAbsent := false
			f.sys.fault = func(cmd string, args []string) (fakeReply, bool) {
				if cmd == "/usr/bin/getent" && len(args) == 2 && args[0] == "group" && args[1] == pairName && len(f.sys.users) == 0 && len(f.sys.groups) == 0 {
					if confirmedAbsent {
						f.sys.groups[pairName] = Account{Name: pairName, GID: 210201}
					} else {
						confirmedAbsent = true
					}
				}
				return fakeReply{}, false
			}
			out, err := replayPair(t, f, "rehearsal")
			code(t, err, 1)
			requirePairReason(t, err, "PAIRED_GROUP_REAPPEARED "+pairName)
			if out != "" || len(f.sys.groups) != 1 {
				t.Fatalf("reappearing group not preserved: %v %q", err, out)
			}
			deletions := 0
			for _, call := range f.sys.calls {
				if call == "/usr/sbin/groupdel "+pairName {
					deletions++
				}
			}
			if deletions != map[bool]int{false: 1, true: 0}[auto] {
				t.Fatal("reappearing group removed")
			}
		})
	}
}

// Claim: after userdel succeeds but groupdel fails, retry refuses a foreign primary user or failed passwd scan before any effect, then restores S0 when repaired.
func TestLedgerUserGroupInterruptedRetry(t *testing.T) {
	for _, fault := range []string{"primary-user", "lookup-error", "valid"} {
		t.Run(fault, func(t *testing.T) {
			f := userGroupFixture(t, "rehearsal", false)
			f.sys.fault = func(cmd string, args []string) (fakeReply, bool) {
				return fakeReply{status: 10}, cmd == "/usr/sbin/groupdel"
			}
			out, err := replayPair(t, f, "rehearsal")
			code(t, err, 1)
			requirePairReason(t, err, "REMOVE_ACCOUNT "+pairName+": COMMAND_STATUS_10")
			if out != "" || len(f.sys.users) != 0 || len(f.sys.groups) != 1 {
				t.Fatal("wrong interrupted pair state", err, out)
			}
			f.sys.fault = nil
			switch fault {
			case "primary-user":
				f.sys.users["foreign"] = Account{Name: "foreign", UID: 240001, GID: 210201, Home: "/", Shell: "/bin/sh"}
			case "lookup-error":
				f.sys.fault = func(cmd string, args []string) (fakeReply, bool) {
					return fakeReply{err: errors.New("injected retry lookup failure")}, cmd == "/usr/bin/getent" && len(args) == 1
				}
			}
			if fault != "valid" {
				reason := map[string]string{"primary-user": "PAIRED_GROUP_OTHER_PRIMARY_USER", "lookup-error": "injected retry lookup failure"}[fault]
				requirePairStop(t, f, "PAIRED_GROUP_PASSWD "+pairName+": "+reason)
			}
			delete(f.sys.users, "foreign")
			f.sys.fault = nil
			out, err = replayPair(t, f, "rehearsal")
			must(t, err)
			requireCleanPairBaseline(t, out)
			if len(f.sys.users) != 0 || len(f.sys.groups) != 0 {
				t.Fatal("retry retained accounts")
			}
		})
	}
}

// Claim: each valid committed role permits its exact pair, while an intent/result role mismatch refuses during load before any lookup or effect.
func TestLedgerUserGroupRoleReceiptStops(t *testing.T) {
	for _, role := range []string{"service", "tree-owner"} {
		for _, tampered := range []bool{false, true} {
			t.Run(role+"/tampered="+strconv.FormatBool(tampered), func(t *testing.T) {
				f := userGroupFixture(t, "rehearsal", true, role)
				if !tampered {
					out, err := replayPair(t, f, "rehearsal")
					must(t, err)
					requireCleanPairBaseline(t, out)
					return
				}
				f.l.Close()
				rows := append([]Record(nil), f.l.rows...)
				a := *rows[3].Body.Action
				a.Role = map[string]string{"service": "tree-owner", "tree-owner": "service"}[role]
				rows[3].Body.Action = &a
				writeRows(t, f, rows, true)
				f.sys.calls = nil
				var out bytes.Buffer
				err := Run([]string{"replay", "-dir", f.dir, "-mode", "rehearsal"}, f.sys, &out)
				code(t, err, 1)
				requirePairReason(t, err, "LEDGER_IDENTITY: RESULT_USER_ROLE")
				if len(f.sys.calls) != 0 || out.Len() != 0 || len(f.sys.users) != 1 || len(f.sys.groups) != 1 {
					t.Fatal("role mismatch granted pair authority", err, out.String())
				}
			})
		}
	}
}

// Claim: an unrecorded supplementary membership in an unrelated pre-existing,
// unscoped group refuses before paired deletion under either policy; clean and
// same-attempt recorded membership neighbours restore S0 without adopting it.
func TestLedgerUserGroupUnrecordedSupplementaryStops(t *testing.T) {
	for _, auto := range []bool{false, true} {
		for _, variant := range []string{"unrecorded", "clean", "recorded"} {
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
				must(t, f.l.CreateAccount("group", pairName, "state", 0, 210201))
				older := f.create(t, "older", "file", "remove")
				must(t, f.l.CreateUserProfile(pairName, "state", 210201, 210201, "/var/lib/swarma-wallet", "Swarma G2 pay executor"))
				group := f.sys.groups["unrelated"]
				switch variant {
				case "unrecorded":
					f.sys.members["unrelated"][pairName] = true
					requirePairStop(t, f, "PAIRED_USER_GROUPS "+pairName+": USER_OTHER_SUPPLEMENTARY_GROUP unrelated")
					exists(t, older)
					if !f.sys.members["unrelated"][pairName] {
						t.Fatal("foreign membership changed")
					}
					// Repair only the unrecorded change; the exact clean layout must pass.
					delete(f.sys.members["unrelated"], pairName)
				case "recorded":
					must(t, f.l.AddMember(pairName, "unrelated"))
				}
				out, err := replayPair(t, f, "rehearsal")
				must(t, err)
				requireCleanPairBaseline(t, out)
				absent(t, older)
				if len(f.sys.users) != 0 || len(f.sys.groups) != 1 || f.sys.groups["unrelated"] != group ||
					len(f.sys.members["unrelated"]) != 1 || !f.sys.members["unrelated"]["outsider"] {
					t.Fatal("rollback changed foreign group/membership or retained pair")
				}
				if variant == "recorded" {
					undo := callIndex(f.sys, "/usr/bin/gpasswd -d "+pairName+" unrelated")
					scan := -1
					for i, call := range f.sys.calls {
						if call == "/usr/bin/getent group" {
							scan = i
						}
					}
					userdel := callIndex(f.sys, "/usr/sbin/userdel "+pairName)
					if undo < 0 || scan <= undo || userdel <= scan {
						t.Fatal("supplementary scan did not follow recorded membership reversal before userdel")
					}
				}
			})
		}
	}
}

// Claim: complete group enumeration errors and malformed records refuse with
// their exact classifier before any paired effect; each repaired control passes.
func TestLedgerUserGroupSupplementaryLookupStops(t *testing.T) {
	for _, variant := range []string{"error", "status", "unsupported", "malformed", "duplicate", "carriage-return", "bad-id", "invalid-member", "duplicate-member", "trailing-member"} {
		t.Run(variant, func(t *testing.T) {
			f := userGroupFixture(t, "rehearsal", true)
			f.sys.fault = func(cmd string, args []string) (fakeReply, bool) {
				if cmd != "/usr/bin/getent" || len(args) != 1 || args[0] != "group" {
					return fakeReply{}, false
				}
				line := fakeGroup(f.sys, f.sys.groups[pairName])
				switch variant {
				case "error":
					return fakeReply{err: errors.New("injected group enumeration failure")}, true
				case "status":
					return fakeReply{status: 2}, true
				case "unsupported":
					return fakeReply{status: 3}, true
				case "malformed":
					return fakeReply{out: line + "invalid\n"}, true
				case "duplicate":
					return fakeReply{out: line + line}, true
				case "carriage-return":
					return fakeReply{out: strings.Replace(line, "\n", "\r\n", 1)}, true
				case "bad-id":
					return fakeReply{out: line + "unrelated:x:invalid:\n"}, true
				case "invalid-member":
					return fakeReply{out: line + "unrelated:x:240002:invalid member\n"}, true
				case "duplicate-member":
					return fakeReply{out: line + "unrelated:x:240002:outsider,outsider\n"}, true
				default:
					return fakeReply{out: line + "unrelated:x:240002:outsider,\n"}, true
				}
			}
			reason := map[string]string{
				"error": "injected group enumeration failure", "status": "GROUP_STATUS_2", "unsupported": "GROUP_STATUS_3",
				"malformed": "GROUP_SCHEMA", "duplicate": "GROUP_SCHEMA", "carriage-return": "GROUP_SCHEMA",
				"bad-id": "GROUP_IDENTITY", "invalid-member": "GROUP_MEMBERS", "duplicate-member": "GROUP_MEMBERS", "trailing-member": "GROUP_MEMBERS",
			}[variant]
			requirePairStop(t, f, "PAIRED_USER_GROUPS "+pairName+": "+reason)
			f.sys.fault = nil
			out, err := replayPair(t, f, "rehearsal")
			must(t, err)
			requireCleanPairBaseline(t, out)
		})
	}
}

// Claim: supplementary enumeration cannot invalidate the last paired-group
// observation and still permit userdel; repaired group controls roll back.
func TestLedgerUserGroupSupplementaryScanBoundaryStops(t *testing.T) {
	for _, drift := range []string{"gid", "member", "gone"} {
		t.Run(drift, func(t *testing.T) {
			f := userGroupFixture(t, "rehearsal", true)
			group := f.sys.groups[pairName]
			f.sys.fault = func(cmd string, args []string) (fakeReply, bool) {
				if cmd == "/usr/bin/getent" && len(args) == 1 && args[0] == "group" {
					switch drift {
					case "gid":
						changed := group
						changed.GID++
						f.sys.groups[pairName] = changed
					case "member":
						f.sys.members[pairName] = map[string]bool{"foreign": true}
					case "gone":
						delete(f.sys.groups, pairName)
					}
				}
				return fakeReply{}, false
			}
			out, err := replayPair(t, f, "rehearsal")
			code(t, err, 1)
			// The preflight scan now observes this drift before the undo step.
			reason := "PAIRED_USER_GROUPS " + pairName + ": GROUP_INCOMPLETE " + pairName
			if drift == "member" {
				reason = "UNLISTED_DIFFERENCE group:" + pairName + "/member:foreign"
			}
			requirePairReason(t, err, reason)
			if out != "" || f.sys.called("/usr/sbin/userdel") || f.sys.called("/usr/sbin/groupdel") {
				t.Fatal("supplementary scan drift permitted deletion", err, out)
			}
			f.sys.groups[pairName] = group
			delete(f.sys.members, pairName)
			f.sys.fault = nil
			out, err = replayPair(t, f, "rehearsal")
			must(t, err)
			requireCleanPairBaseline(t, out)
		})
	}
}
