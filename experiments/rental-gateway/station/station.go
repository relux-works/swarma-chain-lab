// Package station defines how a rental station (one slot's agent
// environment) is created, started, ended and destroyed. Stations
// hold no long-term keys: only a per-slot Track B token file, which
// Destroy removes together with the station home (architecture 5.2).
package station

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
)

// SlotSpec identifies the slot a station is created for.
type SlotSpec struct {
	SlotID      string
	StationName string
	// BookingID is the M3 booking id (64 lower hex) used as the
	// Track B admin slot key. Empty in pure local tests.
	BookingID string
}

// TokenAdmin is the M4a Track B driver admin boundary (private Unix
// socket): Mint returns the raw per-slot token exactly once,
// Revoke is idempotent and terminal. Implemented by
// TrackBAdminClient; faked in tests.
type TokenAdmin interface {
	Mint(ctx context.Context, bookingID string) (string, error)
	Revoke(ctx context.Context, bookingID string) error
}

// MintToken obtains the per-slot Track B token: from the M4a admin
// endpoint when configured (production path; booking id required),
// otherwise a local random token (tests/local demos only, never
// acceptable against a real Track B endpoint).
func MintToken(ctx context.Context, admin TokenAdmin, bookingID string) (string, error) {
	if admin != nil {
		if len(bookingID) != 64 {
			return "", errBookingID
		}
		return admin.Mint(ctx, bookingID)
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

var errBookingID = errors.New("station: Track B admin requires a 64-hex booking id")

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
	// ChannelSecret is the per-slot stationlink credential minted at
	// Create (32 random bytes). A copy lives 0600 in the station
	// home; the gateway registers this value before StartSession.
	ChannelSecret []byte
	// TrackBToken is the per-slot token (hex) minted at Create. The
	// gateway records only its SHA-256; the token itself lives only
	// in the station home and dies with Destroy.
	TrackBToken string

	bookingID string // Track B admin slot key, set at Create
}

// ChannelSecretFile / token file names inside the station home.
const (
	ChannelSecretFile = "channel.secret"
)

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

// Recoverer resolves an opaque station handle from the driver's own durable
// mapping. Unknown mappings must refuse; an empty Home is not proof of absence.
type Recoverer interface {
	Reattach(context.Context, SlotSpec) (*Station, error)
}

// ErrCleanupPending means cleanup has no confirmed result yet. The gateway
// leaves its operation started so the same operation ID can reconcile on retry.
var ErrCleanupPending = errors.New("station: cleanup pending")

// Reattach rebuilds a station handle from durable facts after a
// gateway restart. PID is deliberately zero: a pre-restart PID may
// have been reused by an unrelated process and must never be
// signalled. Linux teardown is UID-scoped (systemd unit + pkill
// -u), so Destroy works fully from this handle; the local-test
// driver's Destroy removes the home without a live handle.
func Reattach(spec SlotSpec, home, user string) *Station {
	return &Station{SlotID: spec.SlotID, StationName: spec.StationName,
		Home: home, User: user, bookingID: spec.BookingID}
}
