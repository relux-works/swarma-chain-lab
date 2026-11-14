package g2ledger

import (
	"errors"
	"fmt"
	"strings"
)

const volatileRuntimeReason = "VOLATILE_RUNTIME_OBJECT_TMPFILES"

var errVolatileRuntime = errors.New(volatileRuntimeReason)

func runtimePath(path string) bool {
	return path == "/run" || strings.HasPrefix(path, "/run/") || path == "/var/run" || strings.HasPrefix(path, "/var/run/")
}
func targetPathPolicy(path string) error {
	// The declared runtime namespace is forbidden even if one of its links
	// redirects elsewhere; canonical resolution must not erase this boundary.
	if runtimePath(path) {
		return fmt.Errorf("%w %s", errVolatileRuntime, path)
	}
	return resolveTargetPolicy(path, 0)
}
