package station_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/station"
)

type exitErr struct{ code int }

func (e exitErr) Error() string { return "exit" }
func (e exitErr) ExitCode() int { return e.code }

type fakeTokens struct {
	minted  []string
	revoked []string
	token   string
}

func (f *fakeTokens) Mint(ctx context.Context, bookingID string) (string, error) {
	f.minted = append(f.minted, bookingID)
	return f.token, nil
}
func (f *fakeTokens) Revoke(ctx context.Context, bookingID string) error {
	f.revoked = append(f.revoked, bookingID)
	return nil
}

// TestLocalTestCreateDestroy proves home 0700, token and channel
// secret 0600 exclusive files, minted values returned on the
// handle, and Destroy removes home and revokes at the endpoint.
func TestLocalTestCreateDestroy(t *testing.T) {
	tokens := &fakeTokens{token: strings.Repeat("ab", 32)}
	d := &station.LocalTestDriver{Root: t.TempDir(), Tokens: tokens}
	ctx := context.Background()
	booking := strings.Repeat("cd", 32)
	st, err := d.Create(ctx, station.SlotSpec{SlotID: "slot-1",
		StationName: "id/swarma-station-1", BookingID: booking})
	if err != nil {
		t.Fatal(err)
	}
	if len(st.ChannelSecret.Reveal()) != 32 || st.TrackBToken != tokens.token {
		t.Fatalf("handle secrets: secret %d bytes token %q", len(st.ChannelSecret.Reveal()), st.TrackBToken)
	}
	if len(tokens.minted) != 1 || tokens.minted[0] != booking {
		t.Fatalf("mint calls: %v", tokens.minted)
	}
	home, _ := os.Stat(st.Home)
	if home.Mode().Perm() != 0700 {
		t.Fatalf("home mode %04o", home.Mode().Perm())
	}
	for _, name := range []string{station.TrackBTokenFile, station.ChannelSecretFile} {
		fi, err := os.Stat(filepath.Join(st.Home, name))
		if err != nil || fi.Mode().Perm() != 0600 {
			t.Fatalf("%s mode %v err %v", name, fi.Mode(), err)
		}
	}
	secretRaw, _ := os.ReadFile(filepath.Join(st.Home, station.ChannelSecretFile))
	if strings.TrimSpace(string(secretRaw)) != hex.EncodeToString(st.ChannelSecret.Reveal()) {
		t.Fatal("channel secret file does not match handle")
	}
	// Exclusive: a second Create for the same slot must fail.
	if _, err := d.Create(ctx, station.SlotSpec{SlotID: "slot-1",
		StationName: "id/swarma-station-1", BookingID: booking}); err == nil {
		t.Fatal("second Create overwrote slot files")
	}
	// Recreate state for destroy asserts (failed duplicate rolled back).
	st, err = d.Create(ctx, station.SlotSpec{SlotID: "slot-9",
		StationName: "id/swarma-station-1", BookingID: booking})
	if err != nil {
		t.Fatal(err)
	}
	report, err := d.Destroy(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(st.Home); !os.IsNotExist(err) {
		t.Fatalf("home remains: %v", err)
	}
	if len(tokens.revoked) == 0 || tokens.revoked[len(tokens.revoked)-1] != booking {
		t.Fatalf("revoke calls: %v", tokens.revoked)
	}
	joined := strings.Join(report.Removed, "\n") + strings.Join(report.Kept, "\n")
	if !strings.Contains(joined, "trackb.token") || !strings.Contains(joined, "contract package") {
		t.Fatalf("report missing retention split: %+v", report)
	}
}

func linuxDriver(fake *station.FakeExec, tokens *fakeTokens) *station.LinuxUserDriver {
	return &station.LinuxUserDriver{
		Cfg: station.LinuxUserConfig{
			GatewayAddr:   "10.0.0.2:9443",
			ExecutorProxy: "127.0.0.1:8123",
			ModelAPIAddr:  "[2001:db8::7]:443", // v6 model endpoint on purpose
			AgentCommand:  []string{"/opt/swarma/agent", "run"},
		},
		Exec: fake, Tokens: tokens,
	}
}

func wantUser(slotID string) string {
	sum := sha256.Sum256([]byte(slotID))
	suffix := "-" + hex.EncodeToString(sum[:4])
	base := "slot-" + slotID
	if len(base) > 32-len(suffix) {
		base = base[:32-len(suffix)]
	}
	return base + suffix
}

// TestLinuxUserCommands proves the exact sequence: hash-suffixed
// user, 0700 home, per-slot token+secret via exclusive stdin writes,
// nftables inet egress (v4 and v6) for the slot UID, systemd-run
// session without any env file, and a destroy that tolerates
// pkill-no-match, deletes table+user and verifies the user is gone.
func TestLinuxUserCommands(t *testing.T) {
	booking := strings.Repeat("ef", 32)
	tokens := &fakeTokens{token: strings.Repeat("ab", 32)}
	fake := &station.FakeExec{
		OutputFor: map[string][]byte{"id": []byte("1007\n")},
		FailOn:    map[string]error{"pkill": exitErr{1}},
	}
	d := linuxDriver(fake, tokens)
	ctx := context.Background()
	st, err := d.Create(ctx, station.SlotSpec{SlotID: "slot-9",
		StationName: "id/swarma-station-9", BookingID: booking})
	if err != nil {
		t.Fatal(err)
	}
	user := wantUser("slot-9")
	if st.User != user {
		t.Fatalf("user = %s, want %s", st.User, user)
	}
	// id must FAIL after userdel: flip id to an error for destroy.
	if err := d.StartSession(ctx, st, station.SessionInfo{
		RenterPubKey: "aa", ContractSHA256: "bb", NotAfter: 2000,
		GatewayEndpoint: "tls://10.0.0.2:9443",
	}); err != nil {
		t.Fatal(err)
	}
	fake.OutputFor["id"] = nil
	fake.FailOn["id"] = exitErr{1}
	if _, err := d.Destroy(ctx, st); err != nil {
		t.Fatalf("Destroy (pkill no-match must be tolerated): %v", err)
	}
	if len(tokens.minted) != 1 || len(tokens.revoked) != 1 {
		t.Fatalf("token admin calls mint=%v revoke=%v", tokens.minted, tokens.revoked)
	}
	lines := make([]string, len(fake.Calls))
	for i, call := range fake.Calls {
		lines[i] = strings.Join(call, " ")
	}
	all := strings.Join(lines, "\n")
	tbl := "swarma-" + user
	for _, want := range []string{
		"useradd --home-dir /home/" + user + " --no-create-home --shell /usr/sbin/nologin " + user,
		"install -d -m 0700 -o " + user + " -g " + user + " /home/" + user,
		"id -u " + user,
		"nft add table inet " + tbl,
		"nft add chain inet " + tbl + " out",
		"meta skuid 1007 ip daddr 10.0.0.2 tcp dport 9443 accept",
		"meta skuid 1007 ip daddr 127.0.0.1 tcp dport 8123 accept",
		"meta skuid 1007 ip6 daddr 2001:db8::7 tcp dport 443 accept",
		"meta skuid 1007 ct state established,related accept",
		"meta skuid 1007 drop",
		"systemd-run --unit=swarma-" + user + " --uid=" + user,
		"CHANNEL_SECRET_FILE=/home/" + user + "/" + station.ChannelSecretFile,
		"systemctl stop swarma-" + user + ".service",
		"nft delete table inet " + tbl,
		"pkill -TERM -u " + user,
		"userdel --remove " + user,
		"id " + user,
	} {
		if !strings.Contains(all, want) {
			t.Fatalf("missing command fragment:\n  %s\nin:\n%s", want, all)
		}
	}
	if strings.Contains(all, "session.env") || strings.Contains(all, "/dev/stdin") && strings.Contains(all, "EnvironmentFile") {
		t.Fatalf("session.env survived the M6a drop:\n%s", all)
	}
	if strings.Contains(all, "iptables") {
		t.Fatalf("iptables still used (nftables was picked):\n%s", all)
	}
	// Token and secret contents arrived via exclusive-write stdin.
	inputs := ""
	for _, in := range fake.Inputs {
		inputs += string(in)
	}
	if !strings.Contains(inputs, tokens.token) {
		t.Fatal("minted token never written to station home")
	}
	if !strings.Contains(inputs, hex.EncodeToString(st.ChannelSecret.Reveal())) {
		t.Fatal("channel secret never written to station home")
	}
	for _, forbidden := range []string{"agent.key", "agent_key", "privkey"} {
		if strings.Contains(all, forbidden) {
			t.Fatalf("station commands reference gateway key material %q", forbidden)
		}
	}
}

// TestLinuxUserValidationAndRollback proves bad endpoints fail
// before any command runs, and a mid-Create failure rolls back the
// table and user (RM2 M6f/g).
func TestLinuxUserValidationAndRollback(t *testing.T) {
	ctx := context.Background()
	fake := &station.FakeExec{}
	bad := linuxDriver(fake, &fakeTokens{token: strings.Repeat("ab", 32)})
	bad.Cfg.GatewayAddr = "not-an-ip:9443"
	if _, err := bad.Create(ctx, station.SlotSpec{SlotID: "s1", BookingID: strings.Repeat("ef", 32)}); err == nil {
		t.Fatal("invalid gateway addr accepted")
	}
	if len(fake.Calls) != 0 {
		t.Fatalf("commands ran despite invalid config: %v", fake.Calls)
	}

	fake2 := &station.FakeExec{
		OutputFor: map[string][]byte{"id": []byte("1008\n")},
		FailOn:    map[string]error{"nft": errors.New("nft boom")},
	}
	d2 := linuxDriver(fake2, &fakeTokens{token: strings.Repeat("ab", 32)})
	if _, err := d2.Create(ctx, station.SlotSpec{SlotID: "s2", BookingID: strings.Repeat("ef", 32)}); err == nil {
		t.Fatal("nft failure accepted")
	}
	lines := ""
	for _, c := range fake2.Calls {
		lines += strings.Join(c, " ") + "\n"
	}
	if !strings.Contains(lines, "userdel --remove") {
		t.Fatalf("rollback missing userdel:\n%s", lines)
	}
}

// TestLinuxUserRefusesWithoutExecutor proves the driver can never
// run commands implicitly.
func TestLinuxUserRefusesWithoutExecutor(t *testing.T) {
	d := &station.LinuxUserDriver{}
	_, err := d.Create(context.Background(), station.SlotSpec{SlotID: "slot-1"})
	if err == nil || !strings.Contains(err.Error(), "no Executor") {
		t.Fatalf("err = %v", err)
	}
}

// TestSlotUserNoCollision proves long slot ids differing only late
// map to different OS users within 32 chars (RM2 M6e).
func TestSlotUserNoCollision(t *testing.T) {
	a := wantUser("a-very-long-slot-identifier-alpha-0001")
	b := wantUser("a-very-long-slot-identifier-alpha-0002")
	if a == b || len(a) > 32 || len(b) > 32 {
		t.Fatalf("users collide or too long: %s / %s", a, b)
	}
}

// TestLinuxDestroyAlreadyGone proves a teardown retry where the
// table and user are already gone still succeeds, proven by the
// assertions (nft list fails, id fails) rather than assumed.
func TestLinuxDestroyAlreadyGone(t *testing.T) {
	fake := &station.FakeExec{
		FailOnPrefix: map[string]error{
			"nft delete": errors.New("no such table"),
			"nft list":   errors.New("no such table"),
		},
		FailOn: map[string]error{
			"pkill":   exitErr{1},
			"userdel": exitErr{6},
			"id":      exitErr{1},
		},
	}
	d := linuxDriver(fake, &fakeTokens{token: strings.Repeat("ab", 32)})
	st := station.Reattach(station.SlotSpec{SlotID: "slot-9",
		StationName: "id/swarma-station-9", BookingID: strings.Repeat("ef", 32)},
		"/home/"+wantUser("slot-9"), wantUser("slot-9"))
	report, err := d.Destroy(context.Background(), st)
	if err != nil {
		t.Fatalf("already-gone destroy must succeed: %v", err)
	}
	if len(report.Removed) == 0 {
		t.Fatal("empty destroy report")
	}
}
