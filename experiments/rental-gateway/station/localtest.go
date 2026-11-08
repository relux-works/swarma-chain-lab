package station

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
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
	// GATEWAY_SOCKET, SLOT_ID, STATION_NAME. When empty, StartSession
	// launches no process (tests simulate the station in-process).
	StubCommand []string

	mu      sync.Mutex
	procs   map[int]*os.Process // pid -> process
	waitErr map[int]chan error
}

// Create makes the station home (0700) and the Track B token (0600).
func (d *LocalTestDriver) Create(ctx context.Context, spec SlotSpec) (*Station, error) {
	if err := os.MkdirAll(d.Root, 0700); err != nil {
		return nil, err
	}
	home := filepath.Join(d.Root, spec.SlotID)
	if err := os.MkdirAll(home, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(home, 0700); err != nil {
		return nil, err
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(home, TrackBTokenFile),
		[]byte(hex.EncodeToString(token)), 0600); err != nil {
		return nil, err
	}
	d.mu.Lock()
	if d.procs == nil {
		d.procs = map[int]*os.Process{}
		d.waitErr = map[int]chan error{}
	}
	d.mu.Unlock()
	return &Station{SlotID: spec.SlotID, StationName: spec.StationName, Home: home}, nil
}

// StartSession launches the scripted stub (if configured), which then
// dials the gateway itself. The driver never connects anywhere.
func (d *LocalTestDriver) StartSession(ctx context.Context, st *Station, info SessionInfo) error {
	if len(d.StubCommand) == 0 {
		return nil
	}
	// Deliberately not CommandContext: the stub outlives the start
	// call; its lifecycle ends via End (kill by PID).
	cmd := exec.Command(d.StubCommand[0], d.StubCommand[1:]...)
	cmd.Dir = st.Home
	cmd.Env = append(os.Environ(),
		"GATEWAY_SOCKET="+info.GatewayEndpoint,
		"SLOT_ID="+st.SlotID,
		"STATION_NAME="+st.StationName,
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
	// Kill by exact PID of the process this driver started.
	_ = proc.Kill()
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

// Destroy ends the session and removes the station home including
// the Track B token file.
func (d *LocalTestDriver) Destroy(ctx context.Context, st *Station) (DestroyReport, error) {
	if err := d.End(ctx, st, "destroy"); err != nil {
		return DestroyReport{}, err
	}
	removed := []string{}
	tokenPath := filepath.Join(st.Home, TrackBTokenFile)
	if _, err := os.Stat(tokenPath); err == nil {
		removed = append(removed, "per-slot Track B token file")
	}
	if err := os.RemoveAll(st.Home); err != nil {
		return DestroyReport{}, err
	}
	removed = append(removed, "station home directory and agent session files")
	return DestroyReport{Removed: removed, Kept: append([]string(nil), KeptElsewhere...)}, nil
}
