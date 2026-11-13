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

	proxy "github.com/relux-works/swarma-chain-lab/experiments/model-proxy"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/journal"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernel"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/station"
	lifecycle "github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle"
)

// ModelRegistrar is optional public-host local administration. The private
// bootstrap is prepared before allocation, activated before Start and revoked
// independently of host cleanup. No model API credential crosses this boundary.
type ModelRegistrar interface {
	Prepare(context.Context, proxy.Binding) (proxy.Credential, error)
	Activate(context.Context, proxy.Binding) error
	Revoke(context.Context, proxy.Binding) error
}
type Config struct {
	ModelRegistrar    ModelRegistrar
	ModelCaps         proxy.Caps
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
	profile := "gateway-stationlink-v1"
	if c.ModelRegistrar != nil {
		if !c.ModelCaps.Valid() || c.ModelCaps.DefaultMaxOutputTokens == 0 {
			return nil, errors.New("MODEL_CONFIG")
		}
		// The journal binds each slot's exact signed caps. Config changes may
		// refuse new activation but must not prevent cleanup of older slots.
		profile = "gateway-model-contract-v3"
	} else if c.ModelCaps != (proxy.Caps{}) {
		return nil, errors.New("MODEL_CONFIG")
	}
	b, e := lifecycle.NewBroker(lifecycle.BrokerConfig{StateDir: c.StateDir, Range: lifecycle.Range{First: c.SlotMin, Last: c.SlotMax}, Payload: lifecycle.Payload{ID: c.PayloadID, SHA256: c.PayloadSHA256}, Now: c.Now, StartTimeout: c.StartTimeout, BootstrapProfile: profile, EncodeBootstrap: func(key string, secret lifecycle.Secret) (lifecycle.Secret, error) {
		s, ok := c.Journal.Get(key)
		if !ok || s.BookingID != key {
			return nil, errors.New("LIFECYCLE_MAPPING")
		}
		doc := PayloadBootstrap{V: 1, BookingID: key, StationName: s.StationName, ChannelSecret: NewChannelSecret(secret)}
		if c.ModelRegistrar != nil {
			binding, e := modelBinding(s, c.ModelCaps)
			if e != nil {
				return nil, e
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			credential, e := c.ModelRegistrar.Prepare(ctx, binding)
			if e != nil || !credential.Valid() {
				return nil, errors.New("MODEL_PREPARE")
			}
			doc.V = 2
			doc.ModelBearer = NewModelBearer(credential.Bearer.Reveal())
			doc.ModelEndpoint = credential.Endpoint.URL
			doc.ModelCertSHA256 = credential.Endpoint.CertSHA256
		}
		return EncodeBootstrap(doc)
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
	if d.cfg.ModelRegistrar != nil {
		if _, e = modelBinding(s, d.cfg.ModelCaps); e != nil {
			return nil, e
		}
	}
	v, e := d.broker.Allocate(s.BookingID, grant, s.NotBefore, s.NotAfter)
	if e != nil {
		return nil, e
	}
	bootstrap, e := DecodeBootstrap(v.Bootstrap.Reveal())
	if e != nil || bootstrap.BookingID != s.BookingID || bootstrap.StationName != s.StationName {
		return nil, errors.New("LIFECYCLE_BOOTSTRAP")
	}
	credential, e := d.broker.Credential(s.BookingID)
	if e != nil || subtle.ConstantTimeCompare(credential, bootstrap.ChannelSecret.Reveal()) != 1 {
		return nil, errors.New("LIFECYCLE_BOOTSTRAP")
	}
	return &station.Station{SlotID: s.ID, StationName: s.StationName, ChannelSecret: station.NewChannelSecret(append([]byte(nil), credential...))}, nil
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
	bootstrap, decodeErr := DecodeBootstrap(v.Bootstrap.Reveal())
	if decodeErr != nil || bootstrap.BookingID != s.BookingID || bootstrap.StationName != s.StationName {
		return errors.New("LIFECYCLE_BOOTSTRAP")
	}
	if s.Ended || s.Destroyed || info.NotAfter != s.NotAfter || info.RenterPubKey != s.RenterPubKey || info.ContractSHA256 != s.ContractSHA256 || subtle.ConstantTimeCompare(st.ChannelSecret.Reveal(), bootstrap.ChannelSecret.Reveal()) != 1 {
		return errors.New("LIFECYCLE_SESSION")
	}
	if d.cfg.ModelRegistrar != nil {
		binding, e := modelBinding(s, d.cfg.ModelCaps)
		if e != nil {
			return e
		}
		call, cancel := context.WithTimeout(ctx, 2*time.Second)
		e = d.cfg.ModelRegistrar.Activate(call, binding)
		cancel()
		if e != nil {
			return errors.New("MODEL_ACTIVATE")
		}
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
	var revokeErr error
	if d.cfg.ModelRegistrar != nil {
		binding, err := boundModelBinding(s)
		revokeErr = err
		if err == nil {
			call, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
			revokeErr = d.cfg.ModelRegistrar.Revoke(call, binding)
			cancel()
		}
	}
	if e = d.broker.SetStop(s.BookingID); e != nil {
		return station.ErrCleanupPending
	}
	if _, e = d.broker.Wait(ctx, s.BookingID, "stopped"); e != nil || revokeErr != nil {
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

func modelBinding(s *journal.Slot, caps proxy.Caps) (proxy.Binding, error) {
	b, e := boundModelBinding(s)
	if e != nil {
		return proxy.Binding{}, e
	}
	if b.Caps != caps {
		return proxy.Binding{}, errors.New("MODEL_CAPS_MISMATCH")
	}
	return b, nil
}
