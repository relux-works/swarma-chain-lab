package rehearsal

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	lifecycle "github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle"
	"github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle/gatewaybind"
	"github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle/slotd"
)

type helperRecord struct {
	response  slotd.Response
	bootstrap []byte
	path      string
	process   *process
}
type fakeHelper struct {
	l                                      *lab
	mu                                     sync.Mutex
	listener                               net.Listener
	done                                   chan struct{}
	records                                map[string]*helperRecord
	root, payload, endpoint, pin, ca, hash string
	fence                                  lifecycle.CreateFence
}

// This helper launches only the actual pinned payload binary with operator argv.
// It claims protocol/process behavior, never Linux users, isolation or disk wipe.
func (l *lab) startHelper(p tlsPaths, endpoint, hash string) *fakeHelper {
	root := l.dir("helper")
	socket := filepath.Join(root, "s.sock")
	f := &fakeHelper{l: l, root: root, payload: l.bins["payload"], endpoint: endpoint, pin: p.serverPin, ca: p.ca, hash: hash, records: map[string]*helperRecord{}, done: make(chan struct{}), fence: lifecycle.CreateFence{BootID: "0f8e1c3a-6b2d-4e7f-9a1b-2c3d4e5f6a7b", IssuedBoottimeNS: "10000000000"}}
	l.write(socket+".clock", encoded(f.fence), 0600)
	ln, e := net.Listen("unix", socket)
	checked(l.t, e, "fake helper socket")
	checked(l.t, os.Chmod(socket, 0600), "fake socket mode")
	f.listener = ln
	go func() {
		defer close(f.done)
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			f.handle(c)
		}
	}()
	return f
}
func (f *fakeHelper) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	raw, e := bufio.NewReaderSize(c, slotd.MaxWire+1).ReadSlice('\n')
	if e != nil || len(raw) > slotd.MaxWire {
		return
	}
	var q slotd.Request
	if json.Unmarshal(raw, &q) != nil || !slotd.ValidRequest(q) || !bytes.Equal(bytes.TrimSuffix(raw, []byte{'\n'}), encoded(q)) {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.records[q.Slot]
	if r == nil {
		r = &helperRecord{response: slotd.Response{V: 1, OK: true, Slot: q.Slot, State: "absent"}}
	}
	refusal := func() {
		b := encoded(slotd.Response{V: 1, OK: false, Slot: q.Slot, Error: "invalid_state"})
		_, _ = c.Write(append(b, '\n'))
	}
	switch q.Op {
	case "create":
		if r.response.State != "absent" || *q.BootID != f.fence.BootID || *q.IssuedBoottimeNS != f.fence.IssuedBoottimeNS {
			refusal()
			return
		}
		b, e := base64.StdEncoding.DecodeString(*q.Bootstrap)
		if e != nil {
			refusal()
			return
		}
		boot, e := gatewaybind.DecodeBootstrap(b)
		if e != nil || boot.V != 2 {
			refusal()
			return
		}
		r.path = filepath.Join(f.root, "bootstrap-"+q.Slot+".json")
		file, e := os.OpenFile(r.path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			refusal()
			return
		}
		_, e = file.Write(b)
		ce := file.Close()
		if e != nil || ce != nil {
			refusal()
			return
		}
		r.bootstrap = append([]byte(nil), b...)
		r.response = slotd.Response{V: 1, OK: true, Slot: q.Slot, State: "created", NotAfter: *q.NotAfter, PayloadSHA256: f.hash, BootstrapSHA256: rental.Hash(b)}
	case "start":
		if r.response.State != "created" {
			refusal()
			return
		}
		log, e := os.OpenFile(filepath.Join(f.l.private, "payload-"+q.Slot+".log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			refusal()
			return
		}
		cmd := exec.Command(f.payload, "-bootstrap", r.path, "-ca", f.ca, "-gateway", f.endpoint, "-gateway-pin", f.pin, "-model", "fixture", "-max-tokens", "16")
		cmd.Stdout = log
		cmd.Stderr = log
		if cmd.Start() != nil {
			log.Close()
			refusal()
			return
		}
		p := &process{role: "payload-" + q.Slot, cmd: cmd, log: log, done: make(chan error, 1)}
		r.process = p
		go func() { p.done <- cmd.Wait() }()
		r.response.State = "running"
	case "stop":
		if r.response.State != "running" && r.response.State != "stopped" {
			refusal()
			return
		}
		if r.process != nil {
			f.stop(r.process)
		}
		r.response.State = "stopped"
	case "destroy":
		if r.response.State != "stopped" {
			refusal()
			return
		}
		if os.Remove(r.path) != nil {
			refusal()
			return
		}
		r.response.State = "destroyed"
	}
	f.records[q.Slot] = r
	_, _ = c.Write(append(encoded(r.response), '\n'))
}
func (f *fakeHelper) stop(p *process) {
	if p.stopped {
		return
	}
	p.stopped = true
	select {
	case <-p.done:
	default:
		_ = p.cmd.Process.Signal(os.Interrupt)
		select {
		case <-p.done:
		case <-time.After(time.Second):
			_ = p.cmd.Process.Kill()
			<-p.done
			f.l.t.Error("fake helper forced payload termination")
		}
	}
	p.log.Close()
}
func (f *fakeHelper) bootstrap(id string) (gatewaybind.PayloadBootstrap, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.records {
		b, e := gatewaybind.DecodeBootstrap(r.bootstrap)
		if e == nil && b.BookingID == id {
			return b, true
		}
	}
	return gatewaybind.PayloadBootstrap{}, false
}
func (f *fakeHelper) destroyed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.records) != 1 {
		return false
	}
	for _, r := range f.records {
		if r.response.State != "destroyed" {
			return false
		}
		if _, e := os.Stat(r.path); !os.IsNotExist(e) {
			return false
		}
	}
	return true
}
func (f *fakeHelper) close() {
	f.listener.Close()
	<-f.done
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.records {
		if r.process != nil {
			f.stop(r.process)
			f.l.pids = append(f.l.pids, r.process.cmd.Process.Pid)
		}
		if b, e := gatewaybind.DecodeBootstrap(r.bootstrap); e == nil {
			f.l.secret([]byte(b.ModelBearer))
			f.l.secret([]byte(b.ChannelSecret))
		}
	}
}
func (l *lab) startManager(p tlsPaths, endpoint, hash, socket string) *process {
	c := struct {
		StateDir string `json:"state_dir"`
		Socket   string `json:"slotd_socket"`
		Min      uint16 `json:"slot_min"`
		Max      uint16 `json:"slot_max"`
		Payload  string `json:"payload_id"`
		Hash     string `json:"payload_sha256"`
		Endpoint string `json:"gateway_endpoint"`
		Pin      string `json:"gateway_cert_sha256"`
		Cert     string `json:"client_cert"`
		Key      string `json:"client_key"`
		CA       string `json:"server_ca"`
	}{l.dir("manager"), socket, 1, 64, "rehearsal-payload", hash, "https://" + endpoint + "/v1/station-manager/poll", p.serverPin, p.client, p.clientKey, p.ca}
	path := l.json("manager.json", c, 0600)
	_, code := l.command("manager config", l.bins["manager"], "check-config", "--config", path)
	if code != 0 {
		l.t.Fatal("manager configuration")
	}
	return l.spawn("manager", "run", "--config", path)
}
