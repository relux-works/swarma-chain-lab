// Package station defines how a rental station (one slot's agent
// environment) is created, started, ended and destroyed. Stations
// hold no long-term keys: only a per-slot Track B token file, which
// Destroy removes together with the station home (architecture 5.2).
package station

import "context"

// SlotSpec identifies the slot a station is created for.
type SlotSpec struct {
	SlotID      string
	StationName string
}

// SessionInfo is handed to the agent at session start (the gateway
// delivers the same facts in the stationlink system frame).
type SessionInfo struct {
	RenterPubKey   string
	ContractSHA256 string
	NotAfter       int64
	// GatewayEndpoint is how the station reaches the gateway:
	// a unix socket path locally, a TCP+mTLS address in deployment.
	// The station always dials; the gateway never dials in.
	GatewayEndpoint string
}

// Station is a driver handle for one created station.
type Station struct {
	SlotID      string
	StationName string
	Home        string // station home directory (local-test) or OS home
	User        string // OS user (linux-user driver)
	PID         int    // child process pid (local-test driver), 0 if none
}

// DestroyReport states exactly what Destroy removed and what is kept
// elsewhere (architecture 5.2). The station itself keeps nothing.
type DestroyReport struct {
	Removed []string
	Kept    []string
}

// KeptElsewhere is the fixed 5.2 retention list outside the station.
var KeptElsewhere = []string{
	"contract package (booking/contract service)",
	"slot report (closer)",
	"executor journal: fields and hashes, no message content (executor host)",
	"gateway seen-event journal and refusal counter (gateway host)",
	"deliverables until 7-day expiry (executor deliver action)",
}

// Driver creates and tears down stations. Implementations must be
// safe to call End/Destroy after a failed Start (idempotent cleanup).
type Driver interface {
	Create(ctx context.Context, spec SlotSpec) (*Station, error)
	StartSession(ctx context.Context, st *Station, info SessionInfo) error
	End(ctx context.Context, st *Station, reason string) error
	Destroy(ctx context.Context, st *Station) (DestroyReport, error)
}
