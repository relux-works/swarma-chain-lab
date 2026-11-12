package deploy

// Owner S5 (PX1): the end-to-end tripwire of the freeze-amendment-1 target-host
// flow. RunG2HostFlow is driven over a fixture G2AccountDB whose state the fake
// sysusers apply changes the way systemd-sysusers can (exact UID, substituted
// UID, missing or extra groups). Nothing here touches a host account.

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// g2FixtureDB is an in-memory account database. Every lookup is logged, so a
// test can prove which checks ran before and after the apply.
type g2FixtureDB struct {
	users  map[string]uint32
	groups map[string][]uint32
	outage bool
	log    *[]string
}

func newG2FixtureDB(log *[]string) *g2FixtureDB {
	return &g2FixtureDB{users: map[string]uint32{}, groups: map[string][]uint32{}, log: log}
}

func (d *g2FixtureDB) add(name string, uid uint32, gids ...uint32) {
	d.users[name] = uid
	d.groups[name] = append([]uint32{uid}, gids...)
}

func (d *g2FixtureDB) UserUID(name string) (uint32, error) {
	*d.log = append(*d.log, "UserUID")
	if d.outage {
		return 0, errors.New("fixture: account database unavailable")
	}
	uid, ok := d.users[name]
	if !ok {
		return 0, fmt.Errorf("fixture user %q: %w", name, ErrG2AccountAbsent)
	}
	return uid, nil
}

func (d *g2FixtureDB) UIDUser(uid uint32) (string, error) {
	*d.log = append(*d.log, "UIDUser")
	if d.outage {
		return "", errors.New("fixture: account database unavailable")
	}
	for name, id := range d.users {
		if id == uid {
			return name, nil
		}
	}
	return "", fmt.Errorf("fixture uid %d: %w", uid, ErrG2AccountAbsent)
}

func (d *g2FixtureDB) UserGroups(name string) ([]uint32, error) {
	*d.log = append(*d.log, "UserGroups")
	if d.outage {
		return nil, errors.New("fixture: account database unavailable")
	}
	if _, ok := d.users[name]; !ok {
		return nil, fmt.Errorf("fixture user %q: %w", name, ErrG2AccountAbsent)
	}
	return append([]uint32{}, d.groups[name]...), nil
}

// g2FlowRun drives RunG2HostFlow with a fake apply that records the bytes it
// was given and then applies outcome to the database, and a fake activation.
// It returns the step log ("apply", "activate" between the lookups), the
// applied bytes and the flow error.
func g2FlowRun(p G2PayParameters, setup, outcome func(*g2FixtureDB), applyErr error) ([]string, []byte, error) {
	var log []string
	db := newG2FixtureDB(&log)
	if setup != nil {
		setup(db)
	}
	var applied []byte
	e := RunG2HostFlow(p, db, G2HostSteps{
		Apply: func(conf []byte) error {
			log = append(log, "apply")
			applied = append([]byte{}, conf...)
			if outcome != nil {
				outcome(db)
			}
			return applyErr
		},
		Activate: func() error {
			log = append(log, "activate")
			return nil
		},
	})
	return log, applied, e
}

func g2Has(log []string, step string) bool {
	for _, s := range log {
		if s == step {
			return true
		}
	}
	return false
}

// g2PeerMembers lists the user of every "m <user> <group>" line for group.
func g2Members(conf, group string) []string {
	var out []string
	for _, line := range strings.Split(conf, "\n") {
		f := strings.Fields(line)
		if len(f) == 3 && f[0] == "m" && f[2] == group {
			out = append(out, f[1])
		}
	}
	sort.Strings(out)
	return out
}

// Claim (end-to-end tripwire, amendment 1 A3/A8): driven over the fixture
// account database, the target-host flow (a) stops before the apply on every
// preflight refusal (an existing name at another UID, a UID owned by another
// name, an outage, no database); (b) stops after the apply and before any
// activation on every post-apply mismatch (a substituted UID, also one whose
// own group kept GID agent_uid so that only the frozen UID check sees it, a
// missing peer
// membership, an operator-group membership, an account the apply did not
// create, a failed apply, and, by the condition-9 exact group set, an
// account whose own group sits at another GID and an account with a third
// group, both of which pass the frozen check); (c) reaches activation exactly
// once, last, on the clean first-install and existing-account paths and on an
// account whose list repeats a GID (a duplicate is not an extra group), with
// the post-apply checks between apply and activation; and (g) the T18
// readback (R9 as adopted): the clean account's group list, its own primary
// group plus swarma-wallet-peer, passes CheckG2AgentGroups and is activated,
// while an existing account with an extra group of its own is now refused
// before activation and by the readback, as is the old socket-GID-only set.
// Every refusal row has the clean path as its valid neighbour. Limit: the apply is a fake; the real consumer's behaviour on the
// same rendered bytes, including the primary GID, is grounded in
// g2_sysusers_test.go.
func TestPX1S5HostFlowTripwire(t *testing.T) {
	p := g2Params()
	created := func(gids ...uint32) func(*g2FixtureDB) {
		return func(db *g2FixtureDB) { db.add(p.AgentUser, p.AgentUID, gids...) }
	}
	clean := created(p.AgentSocketGID)

	// Each section is its own subtest, so every broken guard reports its own
	// marker even when another section fails too.
	// (c) clean paths: the valid neighbours of every refusal below.
	t.Run("clean", func(t *testing.T) {
		for _, c := range []struct {
			name           string
			setup, outcome func(*g2FixtureDB)
		}{
			{"first-install", nil, clean},
			{"existing-account", clean, nil},
			{"existing-duplicate-group", created(p.AgentSocketGID, p.AgentSocketGID, p.AgentUID), nil},
		} {
			log, applied, e := g2FlowRun(p, c.setup, c.outcome, nil)
			if e != nil || len(log) == 0 || log[len(log)-1] != "activate" || strings.Count(strings.Join(log, ","), "activate") != 1 {
				t.Fatalf("G2_FLOW_CLEAN %s: err=%v log=%v", c.name, e, log)
			}
			i := strings.Index(strings.Join(log, ","), "apply")
			post := strings.Split(strings.Join(log, ",")[i:], ",")
			// The required post-apply check and the exact group set run
			// between apply and activation.
			if !reflect.DeepEqual(post, []string{"apply", "UserUID", "UserGroups", "UserGroups", "activate"}) || i == 0 {
				t.Fatalf("G2_FLOW_CLEAN %s: post-apply check not between apply and activation: %v", c.name, log)
			}
			files, _ := RenderG2PayTemplates(p)
			if !bytes.Equal(applied, files[G2FileSysusers]) {
				t.Fatalf("G2_FLOW_CLEAN %s: applied bytes are not the rendered sysusers.conf", c.name)
			}
		}
	})

	// (a) preflight refusals stop before the apply.
	t.Run("preflight", func(t *testing.T) {
		for _, c := range []struct {
			name  string
			setup func(*g2FixtureDB)
			nilDB bool
		}{
			{"existing-other-uid", func(db *g2FixtureDB) { db.add(p.AgentUser, p.AgentUID+1, p.AgentSocketGID) }, false},
			{"uid-owned-by-other-name", func(db *g2FixtureDB) { db.add("someone", p.AgentUID) }, false},
			{"outage", func(db *g2FixtureDB) { db.outage = true }, false},
			{"nil-db", nil, true},
		} {
			var log []string
			var e error
			if c.nilDB {
				e = RunG2HostFlow(p, nil, G2HostSteps{Apply: func([]byte) error { log = append(log, "apply"); return nil }, Activate: func() error { log = append(log, "activate"); return nil }})
			} else {
				log, _, e = g2FlowRun(p, c.setup, clean, nil)
			}
			if !errors.Is(e, ErrPolicy) || g2Has(log, "apply") || g2Has(log, "activate") || !strings.Contains(fmt.Sprint(e), "preflight") {
				t.Fatalf("G2_FLOW_PREFLIGHT %s: the flow went past a refused preflight: err=%v log=%v", c.name, e, log)
			}
		}
	})

	// (b) post-apply mismatches stop before activation.
	t.Run("post-apply", func(t *testing.T) {
		for _, c := range []struct {
			name     string
			outcome  func(*g2FixtureDB)
			applyErr error
		}{
			{"uid-substituted", func(db *g2FixtureDB) { db.add(p.AgentUser, 999, p.AgentSocketGID) }, nil},
			// UID substituted while the own group kept GID agent_uid: the
			// group set is exactly {agent_uid, socket}, so only the frozen
			// UID check refuses it.
			{"uid-substituted-group-kept", func(db *g2FixtureDB) {
				db.users[p.AgentUser] = 999
				db.groups[p.AgentUser] = []uint32{p.AgentUID, p.AgentSocketGID}
			}, nil},
			{"missing-peer-membership", created(), nil},
			{"operator-group-membership", created(p.AgentSocketGID, p.OperatorGID), nil},
			{"operator-group-only", created(p.OperatorGID), nil},
			{"apply-created-nothing", nil, nil},
			{"post-apply-outage", func(db *g2FixtureDB) { clean(db); db.outage = true }, nil},
			{"apply-failed", clean, errors.New("fixture: sysusers exit 1")},
			// Condition 9: the frozen check passes these, the exact set does not.
			{"own-group-at-other-gid", func(db *g2FixtureDB) {
				db.users[p.AgentUser] = p.AgentUID
				db.groups[p.AgentUser] = []uint32{p.AgentUID + 300, p.AgentSocketGID}
			}, nil},
			{"extra-third-group", created(p.AgentSocketGID, 4242), nil},
		} {
			log, _, e := g2FlowRun(p, nil, c.outcome, c.applyErr)
			if e == nil || !g2Has(log, "apply") || g2Has(log, "activate") {
				t.Fatalf("G2_FLOW_POST_APPLY %s: activation was reached after a failed apply or post-apply check: err=%v log=%v", c.name, e, log)
			}
			if c.applyErr == nil && (!errors.Is(e, ErrPolicy) || !strings.Contains(fmt.Sprint(e), "post-apply")) {
				t.Fatalf("G2_FLOW_POST_APPLY %s: wrong refusal %v", c.name, e)
			}
		}
	})

	// (g) the T18 readback of the activated account's group list.
	t.Run("t18-readback", func(t *testing.T) {
		primary, socket, e := G2AgentSlotGIDs(p)
		if e != nil {
			t.Fatal("G2_FLOW_T18_READBACK derivation", e)
		}
		for _, c := range []struct {
			name     string
			state    func(*g2FixtureDB)
			readback bool
		}{
			{"first-install", clean, true},
			{"existing-with-own-groups", created(p.AgentSocketGID, 4242), false},
		} {
			// Since condition 9 the flow activates exactly the accounts
			// whose readback passes: the post-apply set equals the T18 set.
			log, _, e := g2FlowRun(p, nil, c.state, nil)
			if (e == nil && g2Has(log, "activate")) != c.readback {
				t.Fatalf("G2_FLOW_T18_READBACK %s: activation %v, want %v: err=%v log=%v", c.name, e == nil, c.readback, e, log)
			}
			var l []string
			db := newG2FixtureDB(&l)
			c.state(db)
			gids, _ := db.UserGroups(p.AgentUser)
			if c.readback && !reflect.DeepEqual(gids, []uint32{primary, socket}) {
				t.Fatalf("G2_FLOW_T18_READBACK %s: the clean account is not {primary %d, socket %d}: %v", c.name, primary, socket, gids)
			}
			if (CheckG2AgentGroups(p, gids) == nil) != c.readback {
				t.Fatalf("G2_FLOW_T18_READBACK %s: readback of %v passed=%v, want %v", c.name, gids, !c.readback, c.readback)
			}
		}
		if CheckG2AgentGroups(p, []uint32{p.AgentSocketGID}) == nil {
			t.Fatal("G2_FLOW_T18_READBACK the old socket-GID-only credential set passed")
		}
	})

	// Invalid parameters never reach the account database; missing steps
	// refuse before anything runs.
	t.Run("inputs", func(t *testing.T) {
		bad := p
		bad.ServiceUID = bad.AgentUID
		if log, _, e := g2FlowRun(bad, nil, clean, nil); !errors.Is(e, ErrPolicy) || len(log) != 0 {
			t.Fatalf("G2_FLOW_PREFLIGHT render refusal reached the host: err=%v log=%v", e, log)
		}
		var log []string
		if e := RunG2HostFlow(p, newG2FixtureDB(&log), G2HostSteps{Apply: func([]byte) error { return nil }}); e != ErrInput || len(log) != 0 {
			t.Fatalf("G2_FLOW_PREFLIGHT missing activation step accepted: err=%v log=%v", e, log)
		}
	})
}

// Claim (tripwire, rendered artifacts): (d) sysusers.conf carries
// G2AgentSysusers(p) verbatim, so the numeric "u <agent_user> <agent_uid>"
// declaration precedes the agent's only membership; the service account has
// its numeric UID; the only members of swarma-wallet-peer are the service and
// the agent, and the only member of swarma-wallet-status is the service (no
// operator peer membership, no agent operator membership); (e) tmpfiles.conf
// creates the status directory 0750 owned by the service with the operator
// group; (f) custody-spec.json denies the status directory; and no rendered
// file carries a placeholder, while the status directory appears in no
// agent-facing file. Checked on main and regtest renders.
func TestPX1S5HostFlowArtifacts(t *testing.T) {
	for _, network := range []string{"main", "regtest"} {
		p := g2Params()
		if network == "regtest" {
			p.Network, p.Genesis = "regtest", regtestGenesis
		}
		files, e := RenderG2PayTemplates(p)
		if e != nil {
			t.Fatal(e)
		}
		for name, b := range files {
			if bytes.Contains(bytes.ToUpper(b), []byte("PLACEHOLDER")) {
				t.Fatalf("G2_FLOW_PLACEHOLDER %s %s still carries a placeholder:\n%s", network, name, b)
			}
		}

		sys := string(files[G2FileSysusers])
		agent, e := G2AgentSysusers(p)
		if e != nil || strings.Count(sys, agent) != 1 || !strings.HasPrefix(agent, "u cedar 1201\nm cedar swarma-wallet-peer\n") {
			t.Fatalf("G2_FLOW_SYSUSERS %s: agent declaration not verbatim: %q in\n%s", network, agent, sys)
		}
		if !strings.Contains(sys, "\nu swarma-wallet 1101 ") {
			t.Fatalf("G2_FLOW_SYSUSERS %s: service account without its numeric UID\n%s", network, sys)
		}
		if got := g2Members(sys, G2AgentSocketGroup); !reflect.DeepEqual(got, []string{"cedar", "swarma-wallet"}) {
			t.Fatalf("G2_FLOW_SYSUSERS %s: %s members %v (the operator is never a peer member)", network, G2AgentSocketGroup, got)
		}
		if got := g2Members(sys, G2OperatorGroup); !reflect.DeepEqual(got, []string{"swarma-wallet"}) {
			t.Fatalf("G2_FLOW_SYSUSERS %s: %s members %v", network, G2OperatorGroup, got)
		}
		var mLines int
		for _, line := range strings.Split(sys, "\n") {
			if strings.HasPrefix(line, "m ") {
				mLines++
			}
		}
		if mLines != 3 {
			t.Fatalf("G2_FLOW_SYSUSERS %s: unexpected membership lines\n%s", network, sys)
		}

		statusLine := fmt.Sprintf("d %s %04o swarma-wallet %s -\n", G2StatusSocketDir, G2StatusSocketDirMode, G2OperatorGroup)
		if statusLine != "d /run/swarma-wallet-status 0750 swarma-wallet swarma-wallet-status -\n" || strings.Count(string(files[G2FileTmpfiles]), statusLine) != 1 {
			t.Fatalf("G2_FLOW_TMPFILES %s: status directory missing\n%s", network, files[G2FileTmpfiles])
		}

		spec, e := ParseCustodySpec(bytes.TrimSuffix(files[G2FileCustodySpec], []byte("\n")))
		if e != nil {
			t.Fatal(e)
		}
		denied := 0
		for _, d := range spec.DeniedReads {
			if d == G2StatusSocketDir {
				denied++
			}
		}
		if denied != 1 || ValidateG2CustodyLaunchSpec(spec) != nil {
			t.Fatalf("G2_FLOW_CUSTODY %s: status directory not denied exactly once: %v", network, spec.DeniedReads)
		}

		for _, name := range []string{G2FileClientConfig, G2FileServiceConfig, G2FileSysusers, G2FileRPCWhitelist} {
			if bytes.Contains(files[name], []byte(G2StatusSocketDir)) {
				t.Fatalf("G2_FLOW_SLOT %s: %s names the status directory", network, name)
			}
		}
		if !bytes.Contains(files[G2FileClientConfig], []byte(`"socket":"`+G2WalletSocketPath+`"`)) {
			t.Fatalf("G2_FLOW_SLOT %s: client socket", network)
		}
	}
}

// Claim (condition 9, GID == UID): the post-apply group rule admits exactly
// the set {agent_uid, agent_socket_gid}, in either order and with repeats;
// it refuses ErrPolicy for an own group at another GID, a third group (the
// operator group or any other), a missing own or socket group, an empty
// list, a failed lookup, a nil database, and parameters whose socket GID
// equals agent_uid (the set can then never hold both). Valid neighbour: the
// exact set beside each refusal.
func TestPX1S5AgentGroupSet(t *testing.T) {
	p := g2Params()
	run := func(gids []uint32, outage bool, q G2PayParameters) error {
		var log []string
		db := newG2FixtureDB(&log)
		db.users[q.AgentUser] = q.AgentUID
		db.groups[q.AgentUser] = gids
		db.outage = outage
		return g2AgentGroupSet(q, db)
	}
	for _, c := range []struct {
		name string
		gids []uint32
		ok   bool
	}{
		{"exact", []uint32{p.AgentUID, p.AgentSocketGID}, true},
		{"reordered", []uint32{p.AgentSocketGID, p.AgentUID}, true},
		{"repeated", []uint32{p.AgentUID, p.AgentSocketGID, p.AgentUID, p.AgentSocketGID}, true},
		{"own-group-at-other-gid", []uint32{p.AgentUID + 300, p.AgentSocketGID}, false},
		{"third-group", []uint32{p.AgentUID, p.AgentSocketGID, 4242}, false},
		{"operator-group", []uint32{p.AgentUID, p.AgentSocketGID, p.OperatorGID}, false},
		{"missing-socket", []uint32{p.AgentUID}, false},
		{"missing-own", []uint32{p.AgentSocketGID}, false},
		{"empty", nil, false},
	} {
		if e := run(c.gids, false, p); (e == nil) != c.ok || (e != nil && !errors.Is(e, ErrPolicy)) {
			t.Fatalf("G2_GROUP_SET %s %v: err=%v, want ok=%v", c.name, c.gids, e, c.ok)
		}
	}
	if e := run([]uint32{p.AgentUID, p.AgentSocketGID}, true, p); !errors.Is(e, ErrPolicy) {
		t.Fatalf("G2_GROUP_SET outage admitted: %v", e)
	}
	if e := g2AgentGroupSet(p, nil); !errors.Is(e, ErrPolicy) {
		t.Fatalf("G2_GROUP_SET nil database admitted: %v", e)
	}
	same := p
	same.AgentSocketGID = same.AgentUID
	if e := run([]uint32{same.AgentUID}, false, same); !errors.Is(e, ErrPolicy) {
		t.Fatalf("G2_GROUP_SET socket GID == agent_uid admitted: %v", e)
	}
}
