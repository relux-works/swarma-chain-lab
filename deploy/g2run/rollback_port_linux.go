//go:build linux

package g2run

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type RollbackDeps struct {
	Verify    PortLedgerVerifier
	Engine    PortRollbackEngine
	Units     PortUnitControl
	Inventory PortInventory
}

// RollbackPort is the thin g2-rollback.sh caller, distinct from the existing
// g2ledger rollback engine. Node stop/restore/replay/readback stay in that engine.
type RollbackPort struct {
	FS                                                                    PortFS
	Purpose, VerifiedMarker, ReleaseManifest, Ledger, Log, LogName        string
	UnitDirectory, ReceiptDirectory, WalletUnit, SlotUnit, SlotUnitPrefix string
	DriftTarget, DriftState                                               string
	SlotUIDMin, SlotUIDMax                                                uint32
	Deps                                                                  RollbackDeps
}

func (RollbackPort) Kind() string { return "rollback-port" }
func (r RollbackPort) Validate() error {
	if e := r.FS.Validate(); e != nil {
		return e
	}
	if !portPurpose(r.Purpose) || !portUnit(r.WalletUnit) {
		return errors.New("ROLLBACK_PARAMETERS")
	}
	if r.Deps.Verify == nil || r.Deps.Engine == nil || r.Deps.Units == nil {
		return errors.New("ROLLBACK_E2_DEPENDENCIES")
	}
	if e := portPaths(r.FS, r.VerifiedMarker, r.ReleaseManifest, r.Ledger, r.Log, r.UnitDirectory, r.ReceiptDirectory); e != nil {
		return e
	}
	if r.LogName != "" && (!validPackagePath(r.LogName) || filepath.Base(r.LogName) != r.LogName) {
		return errors.New("ROLLBACK_LOG_NAME")
	}
	if r.Purpose == "station" {
		if !portUnit(r.SlotUnit) || r.SlotUnit == r.WalletUnit || r.SlotUnitPrefix == "" || !ValidOperand(r.SlotUnitPrefix) || strings.ContainsAny(r.SlotUnitPrefix, "*?[]/") || r.SlotUIDMin > r.SlotUIDMax || r.SlotUIDMax == ^uint32(0) || r.Deps.Inventory == nil {
			return errors.New("ROLLBACK_SLOT_PARAMETERS")
		}
	} else if e := portPaths(r.FS, r.DriftTarget, r.DriftState); e != nil {
		return e
	}
	return nil
}
func (r RollbackPort) Do(c *Ctx) error {
	if e := r.Validate(); e != nil {
		return e
	}
	if c == nil || !portAbs(c.State) || !portWithin(r.Log, c.State) || r.Log == c.State {
		return errors.New("ROLLBACK_CONTEXT")
	}
	// No dependency is called before the two source preconditions are established.
	marker, e := r.FS.read(r.VerifiedMarker)
	pin := strings.TrimSuffix(string(marker), "\n")
	if e != nil || !portHex(pin, 64) {
		return errors.New("ROLLBACK_RELEASE_VERIFIED")
	}
	ledger, e := r.FS.open(r.Ledger, unix.O_RDONLY, true)
	if e != nil {
		return errors.New("ROLLBACK_LEDGER_MISSING")
	}
	if e = ledger.Close(); e != nil {
		return e
	}
	got, e := r.FS.hash(r.ReleaseManifest)
	if e != nil || got != pin {
		return errors.New("ROLLBACK_RELEASE_CHANGED")
	}
	if r.Purpose == "rehearsal" {
		_, e := r.FS.stat(r.DriftState)
		if e == nil {
			if e = RestoreDrift(r.FS, r.DriftTarget, r.DriftState); e != nil {
				return e
			}
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
	}
	rc, e := r.Deps.Verify.Verify(c, r.Ledger)
	if e != nil || rc != 0 && rc != 3 {
		return errors.New("ROLLBACK_LEDGER_VERIFY")
	}
	units := []string{r.WalletUnit}
	if r.Purpose == "station" {
		units = []string{r.SlotUnit, r.WalletUnit}
	}
	for _, unit := range units {
		if e = r.stopAttemptUnit(c, unit); e != nil {
			return e
		}
	}
	if r.Purpose == "station" {
		rows, e := portUnits(c, r.Deps.Inventory)
		if e != nil {
			return e
		}
		for _, row := range rows {
			if strings.HasPrefix(row.Name, r.SlotUnitPrefix) {
				return errors.New("ROLLBACK_SLOT_UNITS_REMAIN")
			}
		}
		uids, e := r.Deps.Inventory.ProcessUIDs(c)
		if e != nil || len(uids) == 0 || len(uids) > 1<<20 {
			return errors.New("ROLLBACK_PROCESS_INVENTORY")
		}
		for _, uid := range uids {
			if uid == ^uint32(0) {
				return errors.New("ROLLBACK_PROCESS_UID")
			}
			if uid >= r.SlotUIDMin && uid <= r.SlotUIDMax {
				return errors.New("ROLLBACK_SLOT_PROCESSES_REMAIN")
			}
		}
	}
	name := r.LogName
	if name == "" {
		name = "rollback-" + time.Now().UTC().Format("20060102T150405.000000000Z") + "-" + strconv.Itoa(os.Getpid()) + ".out"
	}
	log := r.Log + "/" + name
	if e = r.FS.writeAtomic(log, nil, 0600); e != nil {
		return e
	}
	out, e := r.FS.open(log, unix.O_RDWR, false)
	if e != nil {
		return e
	}
	defer out.Close()
	var st unix.Stat_t
	if e = unix.Fstat(int(out.Fd()), &st); e != nil {
		return e
	}
	if e = r.FS.samePath(log, &st); e != nil {
		return e
	}
	rc, runErr := r.Deps.Engine.Rollback(c, r.Ledger, r.Purpose, out)
	if e = out.Sync(); e != nil {
		return e
	}
	if runErr != nil {
		return runErr
	}
	if rc != 0 {
		return &PortEngineStatusError{Code: rc}
	}
	if _, e = out.Seek(0, io.SeekStart); e != nil {
		return e
	}
	raw, e := io.ReadAll(io.LimitReader(out, (16<<20)+1))
	if e != nil || len(raw) > 16<<20 {
		return errors.New("ROLLBACK_LOG_READ")
	}
	if e = r.FS.samePath(log, &st); e != nil {
		return e
	}
	if _, e = rollbackSuccessLine(raw, r.Purpose); e != nil {
		return e
	}
	return r.Deps.Units.Reload(c)
}
func (r RollbackPort) stopAttemptUnit(c *Ctx, unit string) error {
	s, e := portUnitInfo(c, r.Deps.Units, unit)
	if e != nil {
		return e
	}
	running := !((s.ActiveState == "inactive" || s.ActiveState == "failed") && s.MainPID == 0)
	if s.LoadState == "not-found" {
		if running {
			return errors.New("ROLLBACK_UNLOADED_RUNNING")
		}
		return nil
	}
	own := false
	if s.FragmentPath == r.UnitDirectory+"/"+unit {
		own, e = LedgerOwns(r.FS, r.Ledger, s.FragmentPath)
		if e != nil {
			return e
		}
	}
	if !own {
		if running {
			return errors.New("ROLLBACK_FOREIGN_RUNNING")
		}
		return nil
	}
	// The activation/slot-start step writes this receipt before its own start.
	receipt := r.ReceiptDirectory + "/started-" + unit
	f, e := r.FS.open(receipt, unix.O_RDONLY, false)
	if errors.Is(e, os.ErrNotExist) {
		if running {
			return errors.New("ROLLBACK_NOT_STARTED_RUNNING")
		}
		return nil
	}
	if e != nil {
		return errors.New("ROLLBACK_RECEIPT_READ")
	}
	info, e := f.Stat()
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	if info.Mode().Perm() != 0600 || info.Size() != 0 {
		return errors.New("ROLLBACK_RECEIPT_SHAPE")
	}
	if e = r.Deps.Units.Stop(c, unit); e != nil {
		return e
	}
	s, e = portUnitInfo(c, r.Deps.Units, unit)
	if e != nil {
		return e
	}
	if s.MainPID != 0 {
		return errors.New("ROLLBACK_PID_AFTER_STOP")
	}
	return nil
}

var rollbackStationLine = regexp.MustCompile(`^ROLLBACK_OK node=(stopped|running) config=baseline-verified retry=(reconciled|noop)$`)

func rollbackSuccessLine(raw []byte, purpose string) (string, error) {
	count := 0
	line := ""
	for _, s := range strings.Split(string(raw), "\n") {
		ok := rollbackStationLine.MatchString(s)
		if purpose == "rehearsal" {
			ok = s == "ROLLBACK_OK node=not-applicable config=not-applicable retry=reconciled"
		}
		if ok {
			count++
			line = s
		}
	}
	if count != 1 {
		return "", errors.New("ROLLBACK_OK_LINE")
	}
	return line, nil
}
