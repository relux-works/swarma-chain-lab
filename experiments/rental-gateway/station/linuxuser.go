package station

import (
	"context"
	"fmt"
	"strings"
)

// Executor runs one host command. The linux-user driver builds every
// command through this interface so tests can assert the exact argv
// sequence with a fake, and so nothing in this driver ever runs on a
// developer Mac by accident.
type Executor interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// FakeExec records commands instead of running them (tests).
type FakeExec struct {
	Calls [][]string
	Err   error
}

// Run implements Executor.
func (f *FakeExec) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	f.Calls = append(f.Calls, append([]string{name}, args...))
	return nil, f.Err
}

// LinuxUserConfig pins the egress allowlist endpoints (architecture
// 2: gateway, executor via station-side proxy, model API, optional
// package proxy; no free internet). All values are IP:port pairs
// resolved by the station manager at slot start (firewall rules must
// not depend on station-side DNS).
type LinuxUserConfig struct {
	GatewayAddr      string // gateway TCP+mTLS listener, IP:port
	ExecutorProxy    string // station-side executor proxy, IP:port (127.0.0.1 ok)
	ModelAPIAddr     string // model API, IP:port (443)
	PackageProxyAddr string // optional, IP:port; empty = no rule
	HomeRoot         string // default /home
	// AgentCommand is the session command run as the slot user via
	// systemd-run; it receives the gateway endpoint by env file.
	AgentCommand []string
}

// LinuxUserDriver creates one fresh OS user per slot with a home of
// mode 0700 and per-UID egress allowlist rules. REAL EXECUTION
// HAPPENS ONLY on the Infra Linux VM; every command goes through the
// injected Executor, and unit tests use FakeExec exclusively.
type LinuxUserDriver struct {
	Cfg  LinuxUserConfig
	Exec Executor
}

func slotUser(slotID string) string {
	// Linux user names: lowercase, dash kept, bounded length.
	u := "slot-" + strings.ToLower(slotID)
	if len(u) > 32 {
		u = u[:32]
	}
	return u
}

func (d *LinuxUserDriver) run(ctx context.Context, name string, args ...string) error {
	if d.Exec == nil {
		return fmt.Errorf("linux-user: no Executor injected (refusing to run %s)", name)
	}
	_, err := d.Exec.Run(ctx, name, args...)
	return err
}

func (d *LinuxUserDriver) home(st *Station) string {
	root := d.Cfg.HomeRoot
	if root == "" {
		root = "/home"
	}
	return root + "/" + st.User
}

func (d *LinuxUserDriver) chain(st *Station) string {
	return "SWARMA-" + strings.ToUpper(st.User)
}

// egressRules returns the ordered iptables commands for one slot:
// dedicated chain, allowlist destinations only, default DROP, and
// the per-UID jump from OUTPUT. DNS is not allowed (endpoints are
// pre-resolved IPs), and loopback is allowed only to the executor
// proxy port, not generally.
func (d *LinuxUserDriver) egressRules(st *Station) [][]string {
	chain := d.chain(st)
	cmds := [][]string{
		{"iptables", "-N", chain},
	}
	allow := func(dest string) {
		if dest == "" {
			return
		}
		host, port, _ := strings.Cut(dest, ":")
		cmds = append(cmds, []string{"iptables", "-A", chain, "-p", "tcp",
			"-d", host, "--dport", port, "-j", "ACCEPT"})
	}
	allow(d.Cfg.GatewayAddr)
	allow(d.Cfg.ExecutorProxy)
	allow(d.Cfg.ModelAPIAddr)
	allow(d.Cfg.PackageProxyAddr)
	// Established return traffic for allowed outbound connections.
	cmds = append(cmds,
		[]string{"iptables", "-A", chain, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
		[]string{"iptables", "-A", chain, "-j", "DROP"},
		[]string{"iptables", "-A", "OUTPUT", "-m", "owner", "--uid-owner", st.User, "-j", chain},
	)
	return cmds
}

func (d *LinuxUserDriver) egressCleanup(st *Station) [][]string {
	chain := d.chain(st)
	return [][]string{
		{"iptables", "-D", "OUTPUT", "-m", "owner", "--uid-owner", st.User, "-j", chain},
		{"iptables", "-F", chain},
		{"iptables", "-X", chain},
	}
}

// Create makes the slot OS user, its 0700 home, the Track B token
// file (0600, owned by the slot user) and the egress allowlist.
func (d *LinuxUserDriver) Create(ctx context.Context, spec SlotSpec) (*Station, error) {
	st := &Station{SlotID: spec.SlotID, StationName: spec.StationName, User: slotUser(spec.SlotID)}
	st.Home = d.home(st)
	steps := [][]string{
		{"useradd", "--home-dir", st.Home, "--no-create-home",
			"--shell", "/usr/sbin/nologin", st.User},
		{"install", "-d", "-m", "0700", "-o", st.User, "-g", st.User, st.Home},
		{"install", "-m", "0600", "-o", st.User, "-g", st.User,
			"/etc/swarma/trackb-template", st.Home + "/" + TrackBTokenFile},
	}
	steps = append(steps, d.egressRules(st)...)
	for _, argv := range steps {
		if err := d.run(ctx, argv[0], argv[1:]...); err != nil {
			return nil, fmt.Errorf("linux-user create %v: %w", argv, err)
		}
	}
	return st, nil
}

// StartSession writes the session env file (gateway endpoint for the
// station-initiated link, renter key, contract hash, end time) and
// starts the agent as the slot user in its own systemd scope. The
// agent key is never written anywhere near the station.
func (d *LinuxUserDriver) StartSession(ctx context.Context, st *Station, info SessionInfo) error {
	envFile := st.Home + "/session.env"
	write := []string{"install", "-m", "0600", "-o", st.User, "-g", st.User,
		"/dev/stdin", envFile}
	if err := d.run(ctx, write[0], write[1:]...); err != nil {
		return fmt.Errorf("linux-user session env: %w", err)
	}
	if len(d.Cfg.AgentCommand) == 0 {
		return fmt.Errorf("linux-user: AgentCommand not configured")
	}
	unit := "swarma-" + st.User
	argv := append([]string{"systemd-run", "--unit=" + unit,
		"--uid=" + st.User, "--gid=" + st.User,
		"--working-directory=" + st.Home,
		"--setenv=GATEWAY_ENDPOINT=" + info.GatewayEndpoint,
		"--setenv=SLOT_ID=" + st.SlotID}, d.Cfg.AgentCommand...)
	if err := d.run(ctx, argv[0], argv[1:]...); err != nil {
		return fmt.Errorf("linux-user start: %w", err)
	}
	return nil
}

// End stops the slot's systemd unit (the whole per-slot scope).
func (d *LinuxUserDriver) End(ctx context.Context, st *Station, reason string) error {
	return d.run(ctx, "systemctl", "stop", "swarma-"+st.User+".service")
}

// Destroy ends the session, removes egress rules, kills any leftover
// slot-UID processes, and deletes the user with its home (including
// the Track B token file). Nothing in the station is kept.
func (d *LinuxUserDriver) Destroy(ctx context.Context, st *Station) (DestroyReport, error) {
	_ = d.End(ctx, st, "destroy")
	for _, argv := range d.egressCleanup(st) {
		if err := d.run(ctx, argv[0], argv[1:]...); err != nil {
			return DestroyReport{}, fmt.Errorf("linux-user egress cleanup %v: %w", argv, err)
		}
	}
	steps := [][]string{
		// Scoped to the fresh per-slot UID only (safe by construction).
		{"pkill", "-TERM", "-u", st.User},
		{"userdel", "--remove", st.User},
	}
	for _, argv := range steps {
		if err := d.run(ctx, argv[0], argv[1:]...); err != nil {
			return DestroyReport{}, fmt.Errorf("linux-user destroy %v: %w", argv, err)
		}
	}
	return DestroyReport{
		Removed: []string{
			"station OS user " + st.User,
			"station home " + st.Home + " (including per-slot Track B token file)",
			"per-UID egress chain " + d.chain(st),
			"agent systemd unit swarma-" + st.User,
		},
		Kept: append([]string(nil), KeptElsewhere...),
	}, nil
}
