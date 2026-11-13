package station

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
)

// TrackBTokenFile is the per-slot token location inside the station home.
const TrackBTokenFile = "trackb.token"

// LocalTestDriver creates stations as temporary directories with a
// scripted stub child process. It is for tests on this machine: no
// OS users, no firewall, no sudo. The child is tracked by PID and
// killed by PID only.
type LocalTestDriver struct {
	// Root holds one subdirectory per station. Created 0700.
	Root string
	// StubCommand is the agent stub process argv. It receives env
	// GATEWAY_SOCKET, SLOT_ID, STATION_NAME, CHANNEL_SECRET_FILE,
	// TRACKB_TOKEN_FILE. When empty, StartSession launches no
	// process (tests simulate the station in-process).
	StubCommand []string
	// Tokens optionally mints/revokes Track B tokens at the M4a
	// admin endpoint; nil mints locally (tests only).
	Tokens TokenAdmin

	mu      sync.Mutex
	procs   map[int]*os.Process
	waitErr map[int]chan error
}

func writeExcl0600(path, content string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Create makes the station home (0700), mints the per-slot channel
// secret and Track B token, and writes both 0600 with O_EXCL. On
// failure the partial home is removed.
func (d *LocalTestDriver) Create(ctx context.Context, spec SlotSpec) (*Station, error) {
	if err := os.MkdirAll(d.Root, 0700); err != nil {
		return nil, err
	}
	home := filepath.Join(d.Root, spec.SlotID)
	if err := os.MkdirAll(home, 0700); err != nil {
		return nil, err
	}
	st := &Station{SlotID: spec.SlotID, StationName: spec.StationName,
		Home: home, bookingID: spec.BookingID}
	fail := func(err error) (*Station, error) {
		_ = os.RemoveAll(home)
		if d.Tokens != nil && spec.BookingID != "" && !st.TrackBToken.IsZero() {
			_ = d.Tokens.Revoke(ctx, spec.BookingID)
		}
		return nil, err
	}
	if err := os.Chmod(home, 0700); err != nil {
		return fail(err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return fail(err)
	}
	st.ChannelSecret = NewChannelSecret(secret)
	token, err := MintToken(ctx, d.Tokens, spec.BookingID)
	if err != nil {
		return fail(fmt.Errorf("token mint: %w", err))
	}
	st.TrackBToken = token
	if err := writeExcl0600(filepath.Join(home, TrackBTokenFile), token.Reveal()+"\n"); err != nil {
		return fail(err)
	}
	if err := writeExcl0600(filepath.Join(home, ChannelSecretFile),
		hex.EncodeToString(secret)+"\n"); err != nil {
		return fail(err)
	}
	d.mu.Lock()
	if d.procs == nil {
		d.procs = map[int]*os.Process{}
		d.waitErr = map[int]chan error{}
	}
	d.mu.Unlock()
	return st, nil
}

// StartSession launches the scripted stub (if configured), which
// then dials the gateway itself and authenticates with the channel
// secret file. The driver never connects anywhere.
func (d *LocalTestDriver) StartSession(ctx context.Context, st *Station, info SessionInfo) error {
	if len(d.StubCommand) == 0 {
		return nil
	}
	// Not CommandContext: the stub outlives the start call; its
	// lifecycle ends via End (kill by PID).
	cmd := exec.Command(d.StubCommand[0], d.StubCommand[1:]...)
	cmd.Dir = st.Home
	cmd.Env = append(os.Environ(),
		"GATEWAY_SOCKET="+info.GatewayEndpoint,
		"SLOT_ID="+st.SlotID,
		"STATION_NAME="+st.StationName,
		"CHANNEL_SECRET_FILE="+filepath.Join(st.Home, ChannelSecretFile),
		"TRACKB_TOKEN_FILE="+filepath.Join(st.Home, TrackBTokenFile),
	)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("station stub start: %w", err)
	}
	st.PID = cmd.Process.Pid
	waitCh := make(chan error, 1)
	d.mu.Lock()
	d.procs[st.PID] = cmd.Process
	d.waitErr[st.PID] = waitCh
	d.mu.Unlock()
	go func() { waitCh <- cmd.Wait() }()
	return nil
}

// End stops the stub process by its recorded PID (if any).
func (d *LocalTestDriver) End(ctx context.Context, st *Station, reason string) error {
	if st.PID == 0 {
		return nil
	}
	d.mu.Lock()
	proc := d.procs[st.PID]
	waitCh := d.waitErr[st.PID]
	d.mu.Unlock()
	if proc == nil {
		return nil
	}
	_ = proc.Kill() // exact PID of the process this driver started
	if waitCh != nil {
		<-waitCh
	}
	d.mu.Lock()
	delete(d.procs, st.PID)
	delete(d.waitErr, st.PID)
	d.mu.Unlock()
	st.PID = 0
	return nil
}

// Destroy ends the session, revokes the Track B token at the admin
// endpoint (when configured), and removes the station home
// including token and channel-secret files.
func (d *LocalTestDriver) Destroy(ctx context.Context, st *Station) (DestroyReport, error) {
	if err := d.End(ctx, st, "destroy"); err != nil {
		return DestroyReport{}, err
	}
	var errs []error
	if d.Tokens != nil && st.bookingID != "" {
		if err := d.Tokens.Revoke(ctx, st.bookingID); err != nil {
			errs = append(errs, fmt.Errorf("token revoke: %w", err))
		}
	}
	removed := []string{}
	for _, name := range []string{TrackBTokenFile, ChannelSecretFile} {
		if _, err := os.Stat(filepath.Join(st.Home, name)); err == nil {
			removed = append(removed, "per-slot file "+name)
		}
	}
	if err := os.RemoveAll(st.Home); err != nil {
		errs = append(errs, err)
	} else {
		removed = append(removed, "station home directory and agent session files")
	}
	report := DestroyReport{Removed: removed, Kept: append([]string(nil), KeptElsewhere...)}
	return report, errors.Join(errs...)
}
