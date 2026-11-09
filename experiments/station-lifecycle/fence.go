package lifecycle

import (
	"encoding/hex"
	"strconv"
	"strings"
)

// CreateFence is a host-local request fence, not remote slot authority. The
// manager persists the exact value before the helper client can send Create.
type CreateFence struct {
	BootID           string `json:"boot_id"`
	IssuedBoottimeNS string `json:"issued_boottime_ns"`
}

func (f CreateFence) Valid() bool {
	if len(f.BootID) != 36 || f.BootID[8] != '-' || f.BootID[13] != '-' || f.BootID[18] != '-' || f.BootID[23] != '-' {
		return false
	}
	raw := strings.ReplaceAll(f.BootID, "-", "")
	decoded, e := hex.DecodeString(raw)
	if e != nil || len(decoded) != 16 || hex.EncodeToString(decoded) != raw {
		return false
	}
	if len(f.IssuedBoottimeNS) == 0 || len(f.IssuedBoottimeNS) > 20 {
		return false
	}
	n, e := strconv.ParseUint(f.IssuedBoottimeNS, 10, 64)
	return e == nil && strconv.FormatUint(n, 10) == f.IssuedBoottimeNS
}

// Elapsed proves the old request cannot newly acquire a slot lock. Boot changes
// invalidate old requests; same-boot comparisons subtract without overflowing.
func (f CreateFence) Elapsed(now CreateFence) bool {
	if !f.Valid() || !now.Valid() {
		return false
	}
	if f.BootID != now.BootID {
		return true
	}
	issued, _ := strconv.ParseUint(f.IssuedBoottimeNS, 10, 64)
	current, _ := strconv.ParseUint(now.IssuedBoottimeNS, 10, 64)
	return current >= issued && current-issued >= 6_000_000_000
}
