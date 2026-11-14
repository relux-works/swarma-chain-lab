//go:build linux

package g2ledger

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"
)

// Claim: the audited creator accepts final ownership in numeric/name and inline forms while rejecting unknown/duplicate/noncanonical flags before intent.
func TestLedgerCreatorOwnerFlags(t *testing.T) {
	self, err := os.Executable()
	must(t, err)
	u, err := user.LookupId(strconv.Itoa(os.Geteuid()))
	must(t, err)
	g, err := user.LookupGroupId(strconv.Itoa(os.Getegid()))
	must(t, err)
	f := setupWith(t, "rehearsal", func(f *fixture) { f.declare("owned-key", "secret") })
	p := filepath.Join(f.root, "owned-key")
	for _, command := range []string{"g2-keygen", "g2-rpcauth"} {
		outputFlag := "-out"
		if command == "g2-rpcauth" {
			outputFlag = "-wallet-config-out"
		}
		base := []string{self, command, outputFlag, p}
		for _, extra := range [][]string{{"-owner", u.Uid, "-group", g.Gid}, {"--owner=" + u.Username, "--group=" + g.Name}} {
			argv := append(append([]string{}, base...), extra...)
			must(t, creatorCommand(argv, []string{p}))
			_, uid, gid, mode, err := creatorMetadata(argv)
			must(t, err)
			wantMode := uint32(0600)
			if command == "g2-rpcauth" {
				wantMode = 0640
			}
			if uid != os.Geteuid() || gid != os.Getegid() || mode != wantMode {
				t.Fatal("creator metadata lost")
			}
		}
		for _, extra := range [][]string{{"-owner", ""}, {"-group", ""}, {"-owner", "01"}, {"-group", "4294967295"}, {"-owner", "missing-fixture-account-7d43"}, {"-group", "missing-fixture-group-7d43"}, {"-owner", u.Uid, "--owner=" + u.Uid}, {"-group", g.Gid, "--group=" + g.Gid}, {"-unreviewed-option", "1"}} {
			argv := append(append([]string{}, base...), extra...)
			if creatorCommand(argv, []string{p}) == nil {
				t.Fatal("invalid creator flags accepted")
			}
			code(t, f.l.ExecCreate("secret", "remove", []string{p}, argv), 1)
			if len(f.l.rows) != 1 {
				t.Fatal("invalid owner wrote intent")
			}
			absent(t, p)
		}
	}
	if creatorCommand([]string{self, "g2-rpcauth", "-wallet-config-out", p, "-mode", "0600"}, []string{p}) == nil {
		t.Fatal("RPC mode invented")
	}
}

// Claim: a creator ignoring requested ownership cannot commit; intent keeps the requested IDs and the real mismatching output remains an unresolved orphan.
func TestLedgerCreatorOwnerMismatchRefusesCommit(t *testing.T) {
	f := setupWith(t, "station", func(f *fixture) { must(t, os.Mkdir(filepath.Join(f.root, "outputs"), 0700)) })
	p := filepath.Join(f.root, "outputs", "key")
	uid, gid := os.Geteuid()+1, os.Getegid()+1
	f.sys.tool = func(_ string, args []string) (string, int, error) {
		if len(args) != 7 || args[3] != "-owner" || args[4] != strconv.Itoa(uid) || args[5] != "-group" || args[6] != strconv.Itoa(gid) {
			t.Fatal("ownership arguments not passed through")
		}
		must(t, os.WriteFile(p, []byte("private fixture"), 0600))
		return "PUBLIC_FIXTURE\n", 0, nil
	}
	err := f.l.execCreate("secret", "d6", []string{p}, []string{"fixture-exclusive-tool", "g2-keygen", "-out", p, "-owner", strconv.Itoa(uid), "-group", strconv.Itoa(gid)})
	if err == nil {
		t.Fatal("ownership mismatch committed")
	}
	if len(f.l.rows) != 2 || f.l.rows[1].Body.Action.UID != uint32(uid) || f.l.rows[1].Body.Action.GID != uint32(gid) {
		t.Fatal("requested IDs lost from intent")
	}
	exists(t, p)
	f.l.Close()
	_, err = Open(f.dir, f.sys)
	code(t, err, 3)
}
