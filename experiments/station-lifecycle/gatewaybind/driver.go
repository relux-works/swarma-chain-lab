// Package gatewaybind adapts the independent lifecycle broker to the rental
// gateway. The core manager and its host helper do not import gateway types.
package gatewaybind

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"relux.works/swarma-chain-lab/experiments/rental-gateway/journal"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/kernel"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/station"
	lifecycle "relux.works/swarma-chain-lab/experiments/station-lifecycle"
)

type Config struct {
	StateDir          string
	Journal           *journal.Store
	PayloadID         string
	PayloadSHA256     string
	SlotMin           uint16
	SlotMax           uint16
	ManagerCertSHA256 string
	Now               func() time.Time
	StartTimeout      time.Duration
}
type Driver struct {
	cfg    Config
	broker *lifecycle.Broker
}

var _ station.Driver = (*Driver)(nil)
var _ station.Recoverer = (*Driver)(nil)

func New(c Config) (*Driver, error) {
	pin, e := hex.DecodeString(c.ManagerCertSHA256)
	if e != nil || len(pin) != 32 || hex.EncodeToString(pin) != c.ManagerCertSHA256 || c.Journal == nil {
		return nil, errors.New("LIFECYCLE_CONFIG")
	}
	b, e := lifecycle.NewBroker(lifecycle.BrokerConfig{StateDir: c.StateDir, Range: lifecycle.Range{First: c.SlotMin, Last: c.SlotMax}, Payload: lifecycle.Payload{ID: c.PayloadID, SHA256: c.PayloadSHA256}, Now: c.Now, StartTimeout: c.StartTimeout, BootstrapProfile: "gateway-stationlink-v1", EncodeBootstrap: func(key string, secret lifecycle.Secret) (lifecycle.Secret, error) {
		s, ok := c.Journal.Get(key)
		if !ok || s.BookingID != key {
			return nil, errors.New("LIFECYCLE_MAPPING")
		}
		return EncodeBootstrap(PayloadBootstrap{V: 1, BookingID: key, StationName: s.StationName, ChannelSecret: secret})
	}})
	if e != nil {
		return nil, e
	}
	return &Driver{cfg: c, broker: b}, nil
}
func (d *Driver) Handler() http.Handler { return d.broker.Handler(d.cfg.ManagerCertSHA256) }
func (d *Driver) Close() error          { return d.broker.Close() }

// Journal registration and kernel admission belong to the gateway. Deriving the
// presentation ID here checks framing only, never grants execution authority.
func (d *Driver) facts(spec station.SlotSpec) (*journal.Slot, string, error) {
	s, ok := d.cfg.Journal.Get(spec.SlotID)
	if !ok || s.ID != spec.BookingID || s.BookingID != spec.BookingID || s.StationName != spec.StationName {
		return nil, "", errors.New("LIFECYCLE_MAPPING")
	}
	raw, e := base64.StdEncoding.DecodeString(s.CertificateB64)
	if e != nil {
		return nil, "", errors.New("LIFECYCLE_GRANT")
	}
	grant, e := kernel.PresentationID(raw)
	if e != nil {
		return nil, "", errors.New("LIFECYCLE_GRANT")
	}
	return s, grant, nil
}
func (d *Driver) lookup(spec station.SlotSpec) (*journal.Slot, lifecycle.Slot, error) {
	s, grant, e := d.facts(spec)
	if e != nil {
		return nil, lifecycle.Slot{}, e
	}
	v, e := d.broker.Lookup(s.BookingID)
	if e != nil {
		return nil, lifecycle.Slot{}, e
	}
	if v.GrantID != grant || v.NotBefore != s.NotBefore || v.NotAfter != s.NotAfter {
		return nil, lifecycle.Slot{}, errors.New("LIFECYCLE_MAPPING")
	}
	return s, v, nil
}
func (d *Driver) Create(ctx context.Context, spec station.SlotSpec) (*station.Station, error) {
	if ctx.Err() != nil {
		return nil, errors.New("LIFECYCLE_CANCELLED")
	}
	s, grant, e := d.facts(spec)
	if e != nil {
		return nil, e
	}
	if s.Ended || s.Destroyed {
		return nil, errors.New("LIFECYCLE_TERMINAL")
	}
	v, e := d.broker.Allocate(s.BookingID, grant, s.NotBefore, s.NotAfter)
	if e != nil {
		return nil, e
	}
	bootstrap, e := DecodeBootstrap(v.Bootstrap)
	if e != nil || bootstrap.BookingID != s.BookingID || bootstrap.StationName != s.StationName {
		return nil, errors.New("LIFECYCLE_BOOTSTRAP")
	}
	credential, e := d.broker.Credential(s.BookingID)
	if e != nil || subtle.ConstantTimeCompare(credential, bootstrap.ChannelSecret) != 1 {
		return nil, errors.New("LIFECYCLE_BOOTSTRAP")
	}
	return &station.Station{SlotID: s.ID, StationName: s.StationName, ChannelSecret: append([]byte(nil), credential...)}, nil
}
func (d *Driver) Reattach(_ context.Context, spec station.SlotSpec) (*station.Station, error) {
	s, _, e := d.lookup(spec)
	if e != nil {
		return nil, station.ErrCleanupPending
	}
	return &station.Station{SlotID: s.ID, StationName: s.StationName}, nil
}
func specFor(st *station.Station) station.SlotSpec {
	return station.SlotSpec{SlotID: st.SlotID, StationName: st.StationName, BookingID: st.SlotID}
}
func (d *Driver) StartSession(ctx context.Context, st *station.Station, info station.SessionInfo) error {
	if st == nil {
		return errors.New("LIFECYCLE_HANDLE")
	}
	s, v, e := d.lookup(specFor(st))
	if e != nil {
		return e
	}
	bootstrap, decodeErr := DecodeBootstrap(v.Bootstrap)
	if decodeErr != nil || bootstrap.BookingID != s.BookingID || bootstrap.StationName != s.StationName {
		return errors.New("LIFECYCLE_BOOTSTRAP")
	}
	if s.Ended || s.Destroyed || info.NotAfter != s.NotAfter || info.RenterPubKey != s.RenterPubKey || info.ContractSHA256 != s.ContractSHA256 || subtle.ConstantTimeCompare(st.ChannelSecret, bootstrap.ChannelSecret) != 1 {
		return errors.New("LIFECYCLE_SESSION")
	}
	if e = d.broker.SetStart(s.BookingID); e != nil {
		return e
	}
	if _, e = d.broker.Wait(ctx, s.BookingID, "running"); e != nil {
		return errors.New("LIFECYCLE_NOT_READY")
	}
	return nil
}
func (d *Driver) stop(ctx context.Context, st *station.Station) error {
	if st == nil {
		return station.ErrCleanupPending
	}
	s, _, e := d.lookup(specFor(st))
	if e != nil {
		return station.ErrCleanupPending
	}
	if e = d.broker.SetStop(s.BookingID); e != nil {
		return station.ErrCleanupPending
	}
	if _, e = d.broker.Wait(ctx, s.BookingID, "stopped"); e != nil {
		return station.ErrCleanupPending
	}
	return nil
}
func (d *Driver) End(ctx context.Context, st *station.Station, _ string) error {
	return d.stop(ctx, st)
}
func (d *Driver) Destroy(ctx context.Context, st *station.Station) (station.DestroyReport, error) {
	if e := d.stop(ctx, st); e != nil {
		return station.DestroyReport{}, e
	}
	return station.DestroyReport{Removed: []string{"remote slot resources (helper-confirmed destroyed or absent)"}, Kept: append([]string(nil), station.KeptElsewhere...)}, nil
}
