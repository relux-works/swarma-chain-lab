//go:build linux

package slotd

import (
	"io"
	"os"
	"strconv"
	"strings"

	lifecycle "github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle"
	"golang.org/x/sys/unix"
)

// SystemBootClock is host-wide, includes suspend, and has no wall-clock fallback.
// The fixed kernel pseudo-file supplies boot identity; no caller path is accepted.
func SystemBootClock() (lifecycle.CreateFence, error) {
	f, e := os.Open("/proc/sys/kernel/random/boot_id")
	if e != nil {
		return lifecycle.CreateFence{}, failure("SLOTD_CLOCK")
	}
	raw, e := io.ReadAll(io.LimitReader(f, 38))
	f.Close()
	if e != nil || len(raw) > 37 {
		return lifecycle.CreateFence{}, failure("SLOTD_CLOCK")
	}
	var ts unix.Timespec
	if e = unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); e != nil || ts.Sec < 0 || ts.Nsec < 0 || ts.Nsec >= 1_000_000_000 {
		return lifecycle.CreateFence{}, failure("SLOTD_CLOCK")
	}
	seconds := uint64(ts.Sec)
	nanos := uint64(ts.Nsec)
	if seconds > (^uint64(0)-nanos)/1_000_000_000 {
		return lifecycle.CreateFence{}, failure("SLOTD_CLOCK")
	}
	fence := lifecycle.CreateFence{BootID: strings.TrimSuffix(string(raw), "\n"), IssuedBoottimeNS: strconv.FormatUint(seconds*1_000_000_000+nanos, 10)}
	if !fence.Valid() {
		return lifecycle.CreateFence{}, failure("SLOTD_CLOCK")
	}
	return fence, nil
}
