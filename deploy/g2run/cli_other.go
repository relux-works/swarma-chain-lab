//go:build !linux

package g2run

import (
	"fmt"
	"io"
)

// Main is Linux-only: the engine relies on flock, openat flags and kernel credentials.
func Main[P any](plan Plan[P], args []string, stdout, stderr io.Writer) int {
	fmt.Fprintln(stderr, "REFUSED: g2-run runs on Linux only")
	return 2
}
