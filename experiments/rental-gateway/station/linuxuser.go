package station

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Executor runs one host command, optionally with stdin content.
// The linux-user driver builds every command through this interface
// so tests can assert exact argv with a fake, and so nothing in this
// driver ever runs on a developer Mac by accident.
type Executor interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
	RunInput(ctx context.Context, input []byte, name string, args ...string) ([]byte, error)
}

// FakeExec records commands instead of running them (tests).
// FailOn maps argv[0] to the error that command returns; OutputFor
// maps argv[0] to stdout bytes (e.g. "1007\n" for id -u).
type FakeExec struct {
	Calls     [][]string
	Inputs    [][]byte
	FailOn    map[string]error
	OutputFor map[string][]byte
}

// Run implements Executor.
func (f *FakeExec) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return f.RunInput(ctx, nil, name, args...)
}

// RunInput implements Executor.
func (f *FakeExec) RunInput(ctx context.Context, input []byte, name string, args ...string) ([]byte, error) {
	f.Calls = append(f.Calls, append([]string{name}, args...))
	f.Inputs = append(f.Inputs, append([]byte(nil), input...))
	if err := f.FailOn[name]; err != nil {
		return nil, err
	}
	return f.OutputFor[name], nil
}

// ExitCoder is satisfied by exec.ExitError and test fakes.
type ExitCoder interface{ ExitCode() int }

func exitCodeIs(err error, code int) bool {
	var ec ExitCoder
	return errors.As(err, &ec) && ec.ExitCode() == code
}

// LinuxUserConfig pins the egress allowlist endpoints (architecture
// 2: gateway, executor via station-side proxy, model API, optional
// package proxy; no free internet). All values are IP:port pairs
// resolved by the station manager at slot start.
type LinuxUserConfig struct {
	GatewayAddr      string // gateway TCP+mTLS listener, IP:port (required)
	ExecutorProxy    string // station-side executor proxy, IP:port (required)
	ModelAPIAddr     string // model API, IP:port (required)
	PackageProxyAddr string // optional, IP:port; empty = no rule
	HomeRoot         string // default /home
	AgentCommand     []string
}

func parseIPPort(what, addr string, required bool) (net.IP, int, error) {
	if addr == "" {
		if required {
			return nil, 0, fmt.Errorf("linux-user: %s is required", what)
		}
		return nil, 0, nil
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, 0, fmt.Errorf("linux-user: %s %q: %w", what, addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, 0, fmt.Errorf("linux-user: %s %q: host is not an IP", what, addr)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return nil, 0, fmt.Errorf("linux-user: %s %q: bad port", what, addr)
	}
	return ip, port, nil
}

func (c *LinuxUserConfig) validate() error {
	for _, e := range []struct {
		what string
		addr string
		req  bool
	}{
		{"gateway addr", c.GatewayAddr, true},
		{"executor proxy addr", c.ExecutorProxy, true},
		{"model API addr", c.ModelAPIAddr, true},
		{"package proxy addr", c.PackageProxyAddr, false},
	} {
		if _, _, err := parseIPPort(e.what, e.addr, e.req); err != nil {
			return err
		}
	}
	return nil
}

// LinuxUserDriver creates one fresh OS user per slot with a 0700
// home and per-UID nftables egress (inet family: IPv4+IPv6).
// REAL EXECUTION ONLY on the Infra Linux VM; unit tests use
// FakeExec exclusively.
type LinuxUserDriver struct {
	Cfg    LinuxUserConfig
	Exec   Executor
	Tokens TokenAdmin // nil = local random mint (tests only)
}

// slotUser maps a slot id to a collision-free OS user name of at
// most 32 chars: "slot-" + sanitized id (truncated) + "-" + 8 hex of
// SHA-256(slot id), so ids differing late never collide.
func slotUser(slotID string) string {
	sum := sha256.Sum256([]byte(slotID))
	suffix := "-" + hex.EncodeToString(sum[:4])
	base := "slot-" + strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			return r
		case r >= 'A' && r <= 'Z':
			return r - 'A' + 'a'
		default:
			return '-'
		}
	}, slotID)
	if max := 32 - len(suffix); len(base) > max {
		base = base[:max]
	}
	return base + suffix
}

func (d *LinuxUserDriver) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if d.Exec == nil {
		return nil, fmt.Errorf("linux-user: no Executor injected (refusing to run %s)", name)
	}
	return d.Exec.Run(ctx, name, args...)
}

func (d *LinuxUserDriver) runInput(ctx context.Context, input []byte, name string, args ...string) ([]byte, error) {
	if d.Exec == nil {
		return nil, fmt.Errorf("linux-user: no Executor injected (refusing to run %s)", name)
	}
	return d.Exec.RunInput(ctx, input, name, args...)
}

func (d *LinuxUserDriver) home(st *Station) string {
	root := d.Cfg.HomeRoot
	if root == "" {
		root = "/home"
	}
	return root + "/" + st.User
}

// nftTable is the per-slot inet family table (covers IPv4 and IPv6).
func (d *LinuxUserDriver) nftTable(st *Station) string { return "swarma-" + st.User }

// writeFileExcl writes content to path with O_EXCL semantics
// (shell noclobber), then ownership and mode 0600. Path is passed as
// $1, never interpolated.
func (d *LinuxUserDriver) writeFileExcl(ctx context.Context, st *Station, path string, content []byte) error {
	if _, err := d.runInput(ctx, content, "sh", "-c",
		`set -C; umask 077; cat > "$1"`, "sh", path); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if _, err := d.run(ctx, "chown", st.User+":"+st.User, path); err != nil {
		return fmt.Errorf("chown %s: %w", path, err)
	}
	if _, err := d.run(ctx, "chmod", "0600", path); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return nil
}

// egressRules builds the nftables inet-family commands for one
// slot UID: only allowlisted destinations (v4 or v6 per endpoint),
// established return, then DROP for that UID. Other UIDs fall
// through to the chain policy (accept): the chain restricts only
// the slot user.
func (d *LinuxUserDriver) egressRules(st *Station, uid int) ([][]string, error) {
	table := d.nftTable(st)
	uidStr := strconv.Itoa(uid)
	cmds := [][]string{
		{"nft", "add", "table", "inet", table},
		{"nft", "add", "chain", "inet", table, "out",
			"{", "type", "filter", "hook", "output", "priority", "-10;", "policy", "accept;", "}"},
	}
	for _, e := range []struct{ what, addr string }{
		{"gateway addr", d.Cfg.GatewayAddr},
		{"executor proxy addr", d.Cfg.ExecutorProxy},
		{"model API addr", d.Cfg.ModelAPIAddr},
		{"package proxy addr", d.Cfg.PackageProxyAddr},
	} {
		ip, port, err := parseIPPort(e.what, e.addr, false)
		if err != nil {
			return nil, err
		}
		if ip == nil {
			continue
		}
		fam := "ip"
		if ip.To4() == nil {
			fam = "ip6"
		}
		cmds = append(cmds, []string{"nft", "add", "rule", "inet", table, "out",
			"meta", "skuid", uidStr, fam, "daddr", ip.String(),
			"tcp", "dport", strconv.Itoa(port), "accept"})
	}
	cmds = append(cmds,
		[]string{"nft", "add", "rule", "inet", table, "out",
			"meta", "skuid", uidStr, "ct", "state", "established,related", "accept"},
		[]string{"nft", "add", "rule", "inet", table, "out",
			"meta", "skuid", uidStr, "drop"},
	)
	return cmds, nil
}

// Create mints credentials, makes the slot OS user + 0700 home,
// writes the Track B token and channel secret (0600, exclusive),
// and installs nftables egress. Any mid-sequence failure rolls back
// what was created (table, then user+home) and reports both errors.
func (d *LinuxUserDriver) Create(ctx context.Context, spec SlotSpec) (*Station, error) {
	if d.Exec == nil {
		return nil, fmt.Errorf("linux-user: no Executor injected (refusing to run useradd)")
	}
	if err := d.Cfg.validate(); err != nil {
		return nil, err
	}
	st := &Station{SlotID: spec.SlotID, StationName: spec.StationName, User: slotUser(spec.SlotID)}
	st.Home = d.home(st)
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	st.ChannelSecret = secret
	token, err := MintToken(ctx, d.Tokens, spec.BookingID)
	if err != nil {
		return nil, fmt.Errorf("linux-user: token mint: %w", err)
	}
	st.TrackBToken = token
	st.bookingID = spec.BookingID

	userCreated, tableCreated := false, false
	rollback := func(cause error) (*Station, error) {
		var rb []error
		if tableCreated {
			if _, err := d.run(ctx, "nft", "delete", "table", "inet", d.nftTable(st)); err != nil {
				rb = append(rb, err)
			}
		}
		if userCreated {
			if _, err := d.run(ctx, "userdel", "--remove", st.User); err != nil {
				rb = append(rb, err)
			}
		}
		if d.Tokens != nil && spec.BookingID != "" {
			if err := d.Tokens.Revoke(ctx, spec.BookingID); err != nil {
				rb = append(rb, err)
			}
		}
		if len(rb) > 0 {
			return nil, fmt.Errorf("%w (rollback incomplete: %v)", cause, rb)
		}
		return nil, cause
	}

	if _, err := d.run(ctx, "useradd", "--home-dir", st.Home, "--no-create-home",
		"--shell", "/usr/sbin/nologin", st.User); err != nil {
		return rollback(fmt.Errorf("linux-user create useradd: %w", err))
	}
	userCreated = true
	if _, err := d.run(ctx, "install", "-d", "-m", "0700", "-o", st.User, "-g", st.User, st.Home); err != nil {
		return rollback(fmt.Errorf("linux-user create home: %w", err))
	}
	uidOut, err := d.run(ctx, "id", "-u", st.User)
	if err != nil {
		return rollback(fmt.Errorf("linux-user create id -u: %w", err))
	}
	uid, err := strconv.Atoi(strings.TrimSpace(string(uidOut)))
	if err != nil || uid <= 0 {
		return rollback(fmt.Errorf("linux-user create: bad uid %q", strings.TrimSpace(string(uidOut))))
	}
	if err := d.writeFileExcl(ctx, st, st.Home+"/"+TrackBTokenFile, []byte(token+"\n")); err != nil {
		return rollback(fmt.Errorf("linux-user create token: %w", err))
	}
	if err := d.writeFileExcl(ctx, st, st.Home+"/"+ChannelSecretFile,
		[]byte(hex.EncodeToString(secret)+"\n")); err != nil {
		return rollback(fmt.Errorf("linux-user create channel secret: %w", err))
	}
	rules, err := d.egressRules(st, uid)
	if err != nil {
		return rollback(err)
	}
	for _, argv := range rules {
		if _, err := d.run(ctx, argv[0], argv[1:]...); err != nil {
			return rollback(fmt.Errorf("linux-user create egress %v: %w", argv, err))
		}
		if len(argv) >= 4 && argv[1] == "add" && argv[2] == "table" {
			tableCreated = true
		}
	}
	return st, nil
}

// StartSession starts the agent as the slot user in its own systemd
// unit. Session facts reach the agent in the stationlink system
// frame at hello; no env file is written (RM2 M6a decision).
func (d *LinuxUserDriver) StartSession(ctx context.Context, st *Station, info SessionInfo) error {
	if len(d.Cfg.AgentCommand) == 0 {
		return fmt.Errorf("linux-user: AgentCommand not configured")
	}
	unit := "swarma-" + st.User
	argv := append([]string{"systemd-run", "--unit=" + unit,
		"--uid=" + st.User, "--gid=" + st.User,
		"--working-directory=" + st.Home,
		"--setenv=GATEWAY_ENDPOINT=" + info.GatewayEndpoint,
		"--setenv=SLOT_ID=" + st.SlotID,
		"--setenv=STATION_NAME=" + st.StationName,
		"--setenv=CHANNEL_SECRET_FILE=" + st.Home + "/" + ChannelSecretFile,
		"--setenv=TRACKB_TOKEN_FILE=" + st.Home + "/" + TrackBTokenFile},
		d.Cfg.AgentCommand...)
	if _, err := d.run(ctx, argv[0], argv[1:]...); err != nil {
		return fmt.Errorf("linux-user start: %w", err)
	}
	return nil
}

// End stops the slot's systemd unit (the whole per-slot scope).
func (d *LinuxUserDriver) End(ctx context.Context, st *Station, reason string) error {
	_, err := d.run(ctx, "systemctl", "stop", "swarma-"+st.User+".service")
	return err
}

// Destroy ends the session, revokes the Track B token at the admin
// endpoint, removes the nftables table, kills leftover slot-UID
// processes (no-match tolerated), deletes the user with its home,
// and verifies the user is gone. Nothing in the station is kept.
func (d *LinuxUserDriver) Destroy(ctx context.Context, st *Station) (DestroyReport, error) {
	_ = d.End(ctx, st, "destroy")
	var errs []error
	if d.Tokens != nil && st.bookingID != "" {
		if err := d.Tokens.Revoke(ctx, st.bookingID); err != nil {
			errs = append(errs, fmt.Errorf("token revoke: %w", err))
		}
	}
	if _, err := d.run(ctx, "nft", "delete", "table", "inet", d.nftTable(st)); err != nil {
		errs = append(errs, fmt.Errorf("nft delete table: %w", err))
	}
	if _, err := d.run(ctx, "pkill", "-TERM", "-u", st.User); err != nil && !exitCodeIs(err, 1) {
		errs = append(errs, fmt.Errorf("pkill: %w", err))
	}
	if _, err := d.run(ctx, "userdel", "--remove", st.User); err != nil {
		errs = append(errs, fmt.Errorf("userdel: %w", err))
	} else if _, err := d.run(ctx, "id", st.User); err == nil {
		errs = append(errs, fmt.Errorf("linux-user destroy: user %s still exists after userdel", st.User))
	}
	report := DestroyReport{
		Removed: []string{
			"station OS user " + st.User,
			"station home " + st.Home + " (including per-slot Track B token and channel secret files)",
			"per-slot nftables inet table " + d.nftTable(st),
			"agent systemd unit swarma-" + st.User,
		},
		Kept: append([]string(nil), KeptElsewhere...),
	}
	if len(errs) > 0 {
		return report, errors.Join(errs...)
	}
	return report, nil
}
