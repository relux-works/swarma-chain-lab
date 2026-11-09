package main

import (
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"relux.works/swarma-chain-lab/experiments/rental-gateway/journal"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/station"
	"relux.works/swarma-chain-lab/experiments/station-lifecycle/gatewaybind"
)

type stationRuntime struct {
	driver          station.Driver
	endpoint        string
	payload         net.Listener
	manager         *http.Server
	managerListener net.Listener
	tracked         []*trackedListener
	closeDriver     func()
}

func (r *stationRuntime) closeTransports() {
	if r.manager != nil {
		_ = r.manager.Close()
	}
	for _, l := range r.tracked {
		l.closeAll()
	}
}
func (r *stationRuntime) close() {
	r.closeTransports()
	if r.closeDriver != nil {
		r.closeDriver()
		r.closeDriver = nil
	}
}

// TLS material is validated before any state/listen effect by serve. This
// constructor owns all listeners it opens and releases them on partial failure.
func newStationRuntime(c serveConfig, store *journal.Store, managerTLS, payloadTLS *tls.Config) (_ *stationRuntime, err error) {
	if e := c.validate(true); e != nil {
		return nil, e
	}
	r := &stationRuntime{}
	defer func() {
		if err != nil {
			r.close()
		}
	}()
	if c.Station.Driver == "local-test" {
		d := &testDriver{LocalTestDriver: &station.LocalTestDriver{Root: c.Station.Root}}
		if c.Station.StubAgent {
			self, e := os.Executable()
			if e != nil {
				return nil, errConfig
			}
			d.StubCommand = []string{self, "station-stub"}
		}
		r.driver = d
		r.closeDriver = d.close
		r.endpoint = c.StationSocket
		if e := privateDir(filepath.Dir(c.StationSocket)); e != nil {
			return nil, e
		}
		ln, e := net.Listen("unix", c.StationSocket)
		if e != nil {
			return nil, errors.New("STATION_LISTEN")
		}
		t := &trackedListener{Listener: ln, conns: map[net.Conn]bool{}}
		r.tracked = append(r.tracked, t)
		r.payload = t
		return r, nil
	}
	if managerTLS == nil || payloadTLS == nil {
		return nil, errTLS
	}
	m := c.Station.Manager
	d, e := gatewaybind.New(gatewaybind.Config{StateDir: m.StateDir, Journal: store, PayloadID: m.PayloadID, PayloadSHA256: m.PayloadSHA256, SlotMin: uint16(m.SlotMin), SlotMax: uint16(m.SlotMax), ManagerCertSHA256: m.TLS.ManagerCertSHA256, Now: time.Now, StartTimeout: time.Duration(m.StartMilliseconds) * time.Millisecond})
	if e != nil {
		return nil, errors.New("STATION_MANAGER_STATE")
	}
	r.driver = d
	r.closeDriver = func() { _ = d.Close() }
	r.endpoint = m.PayloadListen
	listen := func(address string, limit int, idle time.Duration, conf *tls.Config) (net.Listener, error) {
		ln, e := net.Listen("tcp", address)
		if e != nil {
			return nil, errors.New("STATION_LISTEN")
		}
		tracked := &trackedListener{Listener: ln, conns: map[net.Conn]bool{}, limit: limit, timeout: idle}
		r.tracked = append(r.tracked, tracked)
		// net/http must see *tls.Conn so its Request.TLS contains verified
		// manager chains. Tracking belongs below the TLS listener.
		return tls.NewListener(tracked, conf), nil
	}
	r.payload, e = listen(m.PayloadListen, 32, 5*time.Second, payloadTLS)
	if e != nil {
		return nil, e
	}
	// HTTP owns absolute header/body/write deadlines; tracking must not extend
	// them on each read from a slow peer.
	r.managerListener, e = listen(m.Listen, 4, 0, managerTLS)
	if e != nil {
		return nil, e
	}
	r.manager = managerHTTP(d.Handler())
	// TLS/HTTP diagnostics must not reflect peer-supplied input into logs.
	r.manager.ErrorLog = log.New(io.Discard, "", 0)
	return r, nil
}
