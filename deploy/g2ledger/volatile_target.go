package g2ledger

import (
	"errors"
	"strings"
)

const volatileRuntimeReason = "VOLATILE_RUNTIME_OBJECT_TMPFILES"

var errVolatileRuntime = errors.New(volatileRuntimeReason)

func runtimePath(path string) bool {
	return path == "/run" || strings.HasPrefix(path, "/run/") || path == "/var/run" || strings.HasPrefix(path, "/var/run/")
}
func targetPathPolicy(path string) error { return resolveTargetPolicy(path, 0) }
