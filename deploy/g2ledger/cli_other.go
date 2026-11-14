//go:build !linux

package g2ledger

import "io"

// Run leaves existing deploy-kit commands available on other platforms.
func Run(_ []string, _ any, _ io.Writer) error { return fail(1, "LINUX_REQUIRED") }
