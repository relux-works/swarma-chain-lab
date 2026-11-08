package station_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"relux.works/swarma-chain-lab/experiments/rental-gateway/station"
)

// TestLocalTestCreateDestroy proves the station home is 0700, the
// Track B token 0600, and Destroy removes both while reporting what
// is kept elsewhere.
func TestLocalTestCreateDestroy(t *testing.T) {
	d := &station.LocalTestDriver{Root: t.TempDir()}
	ctx := context.Background()
	st, err := d.Create(ctx, station.SlotSpec{SlotID: "slot-1", StationName: "id/swarma-station-1"})
	if err != nil {
		t.Fatal(err)
	}
	home, err := os.Stat(st.Home)
	if err != nil || home.Mode().Perm() != 0700 {
		t.Fatalf("home mode = %v, %v", home.Mode(), err)
	}
	tok, err := os.Stat(filepath.Join(st.Home, station.TrackBTokenFile))
	if err != nil || tok.Mode().Perm() != 0600 {
		t.Fatalf("token mode = %v, %v", tok.Mode(), err)
	}
	report, err := d.Destroy(ctx, st)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(st.Home); !os.IsNotExist(err) {
		t.Fatalf("home remains: %v", err)
	}
	joined := strings.Join(report.Removed, "\n") + strings.Join(report.Kept, "\n")
	if !strings.Contains(joined, "Track B token") || !strings.Contains(joined, "contract package") {
		t.Fatalf("report missing retention split: %+v", report)
	}
}

// TestLinuxUserCommands proves the exact command sequence: fresh
// per-slot user, 0700 home, 0600 token owned by the slot user,
// per-UID egress chain allowing only the configured endpoints with
// default DROP, session under systemd-run as the slot user, and a
// destroy that removes user, home and rules. No command references
// any agent key path: the station user structurally cannot read the
// gateway's key (different UID + gateway-side 0600, tested in the
// gateway package).
func TestLinuxUserCommands(t *testing.T) {
	fake := &station.FakeExec{}
	d := &station.LinuxUserDriver{
		Cfg: station.LinuxUserConfig{
			GatewayAddr:   "10.0.0.2:9443",
			ExecutorProxy: "127.0.0.1:8123",
			ModelAPIAddr:  "203.0.113.7:443",
			AgentCommand:  []string{"/opt/swarma/agent", "run"},
		},
		Exec: fake,
	}
	ctx := context.Background()
	st, err := d.Create(ctx, station.SlotSpec{SlotID: "slot-9", StationName: "id/swarma-station-9"})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.StartSession(ctx, st, station.SessionInfo{
		RenterPubKey: "aa", ContractSHA256: "bb", NotAfter: 2000,
		GatewayEndpoint: "tls://10.0.0.2:9443",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Destroy(ctx, st); err != nil {
		t.Fatal(err)
	}
	lines := make([]string, len(fake.Calls))
	for i, call := range fake.Calls {
		lines[i] = strings.Join(call, " ")
	}
	all := strings.Join(lines, "\n")
	for _, want := range []string{
		"useradd --home-dir /home/slot-slot-9 --no-create-home --shell /usr/sbin/nologin slot-slot-9",
		"install -d -m 0700 -o slot-slot-9 -g slot-slot-9 /home/slot-slot-9",
		"install -m 0600 -o slot-slot-9 -g slot-slot-9",
		"iptables -N SWARMA-SLOT-SLOT-9",
		"iptables -A SWARMA-SLOT-SLOT-9 -p tcp -d 10.0.0.2 --dport 9443 -j ACCEPT",
		"iptables -A SWARMA-SLOT-SLOT-9 -p tcp -d 127.0.0.1 --dport 8123 -j ACCEPT",
		"iptables -A SWARMA-SLOT-SLOT-9 -p tcp -d 203.0.113.7 --dport 443 -j ACCEPT",
		"iptables -A SWARMA-SLOT-SLOT-9 -j DROP",
		"iptables -A OUTPUT -m owner --uid-owner slot-slot-9 -j SWARMA-SLOT-SLOT-9",
		"systemd-run --unit=swarma-slot-slot-9 --uid=slot-slot-9",
		"systemctl stop swarma-slot-slot-9.service",
		"iptables -X SWARMA-SLOT-SLOT-9",
		"userdel --remove slot-slot-9",
	} {
		if !strings.Contains(all, want) {
			t.Fatalf("missing command:\n  %s\nin:\n%s", want, all)
		}
	}
	for _, forbidden := range []string{"agent.key", "agent_key", "privkey", "swarma-gateway"} {
		if strings.Contains(all, forbidden) {
			t.Fatalf("station commands reference gateway key material %q:\n%s", forbidden, all)
		}
	}
	// No blanket ACCEPT (free internet) anywhere.
	for _, call := range fake.Calls {
		line := strings.Join(call, " ")
		if strings.Contains(line, "-j ACCEPT") && !strings.Contains(line, "--dport") &&
			!strings.Contains(line, "ESTABLISHED") {
			t.Fatalf("unbounded egress ACCEPT: %s", line)
		}
	}
}

// TestLinuxUserRefusesWithoutExecutor proves the driver can never
// run commands implicitly (no execution on a developer machine).
func TestLinuxUserRefusesWithoutExecutor(t *testing.T) {
	d := &station.LinuxUserDriver{}
	_, err := d.Create(context.Background(), station.SlotSpec{SlotID: "slot-1"})
	if err == nil || !strings.Contains(err.Error(), "no Executor") {
		t.Fatalf("err = %v", err)
	}
}
