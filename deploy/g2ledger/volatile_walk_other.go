//go:build !linux

package g2ledger

import "errors"

// The public ledger adapter also refuses on non-Linux platforms.
func resolveTargetPolicy(_ string, _ int) error { return errors.New("LINUX_REQUIRED") }
