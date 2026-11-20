//go:build linux && gateway_lab

package labtest

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/model-proxy/service/internal/wire"
)

const Material = "PUBLIC-SYNTHETIC-ONLY-NOT-A-VENDOR-KEY"

type Fixture struct {
	Test         *testing.T
	Records      [][]byte
	Objects      map[string]map[string]any
	Lifetime     time.Duration
	Deadline     time.Time
	ReleaseIndex string
}

func Encode(test *testing.T, value any) []byte {
	test.Helper()
	raw, err := wire.Encode(value)
	if err != nil {
		test.Fatal(err)
	}
	return raw
}
func Object(value any) map[string]any { return value.(map[string]any) }
func Digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func Clone(test *testing.T, object map[string]any) map[string]any {
	test.Helper()
	result, err := wire.Parse(Encode(test, object))
	if err != nil {
		test.Fatal(err)
	}
	return result
}
func NewFixture(test *testing.T, path string) *Fixture {
	test.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		test.Fatal(err)
	}
	var data struct {
		Cases []struct {
			Surface string          `json:"surface"`
			Valid   json.RawMessage `json:"valid"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		test.Fatal(err)
	}
	fixture := &Fixture{Test: test, Objects: map[string]map[string]any{}, Lifetime: 10 * time.Second, Deadline: time.Now().Add(time.Minute)}
	for _, entry := range data.Cases {
		object, err := wire.Parse(entry.Valid)
		if err != nil {
			test.Fatal(err)
		}
		fixture.Objects[entry.Surface] = object
	}
	authority := fixture.Objects["swarma-broker-lab-authority/1"]
	Object(authority["gateway"])["uid"] = int64(os.Geteuid())
	Object(authority["worker"])["uid"] = int64(os.Geteuid()) + 1
	fixture.Rebuild()
	return fixture
}
func (fixture *Fixture) Rebuild() {
	authority := fixture.Objects["swarma-broker-lab-authority/1"]
	scope := Object(authority["context"])
	scope["qualification_expires_at"] = fixture.Deadline.Add(time.Minute).UTC().Format(time.RFC3339Nano)
	authority["per_use_expires_at"] = fixture.Deadline.UTC().Format(time.RFC3339Nano)
	activation := fixture.Objects["swarma-broker-lab-activation/1"]
	for key, value := range scope {
		activation[key] = value
	}
	activation["service_lease_max_lifetime_seconds"] = int64(fixture.Lifetime / time.Second)
	floor := fixture.Objects["swarma-broker-lab-consumer-high-water/1"]
	floor["context"] = scope
	authority["manager_head"] = floor["manager_prefix"]
	fence := fixture.Objects["swarma-broker-lab-start-fence/1"]
	fence["context"], fence["consumed"] = scope, true
	Object(fence["heads"])["manager"] = floor["manager_prefix"]
	release := fixture.Objects["swarma-lab-release-set/1"]
	release["context"] = scope
	release["contract_index_sha256"] = "sha256:4f9a81562d391153764b5ae75d7914cf83f03c1bb3d956461211d8eb36f6e7d8"
	if fixture.ReleaseIndex != "" {
		release["contract_index_sha256"] = fixture.ReleaseIndex
	}
	fixture.Records = [][]byte{nil, Encode(fixture.Test, authority), Encode(fixture.Test, fence), Encode(fixture.Test, floor), Encode(fixture.Test, release)}
	activation["authority_sha256"], activation["fence_sha256"], activation["release_set_sha256"] = Digest(fixture.Records[1]), Digest(fixture.Records[2]), Digest(fixture.Records[4])
	fixture.Records[0] = Encode(fixture.Test, activation)
}
func (fixture *Fixture) Lease(operation string) map[string]any {
	record := Clone(fixture.Test, fixture.Objects["anthropic-api-key-lab/1"])
	authority := fixture.Objects["swarma-broker-lab-authority/1"]
	record["context"], record["gateway"], record["caller"] = Clone(fixture.Test, Object(authority["context"])), Clone(fixture.Test, Object(authority["gateway"])), Clone(fixture.Test, Object(authority["worker"]))
	record["manager_floor"] = Clone(fixture.Test, Object(authority["manager_head"]))
	record["activation_sha256"], record["authority_sha256"], record["fence_sha256"] = Digest(fixture.Records[0]), Digest(fixture.Records[1]), Digest(fixture.Records[2])
	record["request_id"], record["revocation_sequence"] = operation, int64(5)
	bounds := Object(record["bounds"])
	now := time.Now()
	until := now.Add(fixture.Lifetime)
	if fixture.Deadline.Before(until) {
		until = fixture.Deadline
	}
	bounds["issued_at"], bounds["authorized_until"], bounds["lifetime_seconds"] = now.UTC().Format(time.RFC3339Nano), until.UTC().Format(time.RFC3339Nano), int64(fixture.Lifetime/time.Second)
	for _, name := range []string{"authority_until", "caller_until", "qualification_until", "time_until"} {
		bounds[name] = fixture.Deadline.Add(time.Minute).UTC().Format(time.RFC3339Nano)
	}
	return record
}

type Broker struct {
	Fixture     *Fixture
	Listener    net.Listener
	LeaseMode   atomic.Value
	HoldMode    atomic.Value
	CheckMode   atomic.Value
	Requests    atomic.Int64
	Renews      atomic.Int64
	Checks      atomic.Int64
	Holds       atomic.Int64
	Active      atomic.Int64
	mu          sync.Mutex
	connections map[net.Conn]bool
	operation   string
	digest      string
	mismatch    bool
}

func ShortDir(test *testing.T) string {
	test.Helper()
	directory, err := os.MkdirTemp("", "g-")
	if err != nil {
		test.Fatal(err)
	}
	test.Cleanup(func() { os.RemoveAll(directory) })
	return directory
}
func StartBroker(test *testing.T, fixture *Fixture) *Broker {
	test.Helper()
	listener, err := net.Listen("unix", filepath.Join(ShortDir(test), "b"))
	if err != nil {
		test.Fatal(err)
	}
	broker := &Broker{Fixture: fixture, Listener: listener, connections: map[net.Conn]bool{}}
	broker.LeaseMode.Store("")
	broker.HoldMode.Store("")
	broker.CheckMode.Store("")
	test.Cleanup(func() {
		listener.Close()
		broker.mu.Lock()
		defer broker.mu.Unlock()
		for conn := range broker.connections {
			conn.Close()
		}
	})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			broker.mu.Lock()
			broker.connections[conn] = true
			broker.Active.Add(1)
			broker.mu.Unlock()
			go broker.serve(conn)
		}
	}()
	return broker
}
func (broker *Broker) SameHold() bool {
	broker.mu.Lock()
	defer broker.mu.Unlock()
	return !broker.mismatch && broker.operation != ""
}
func (broker *Broker) serve(conn net.Conn) {
	defer func() {
		conn.Close()
		broker.mu.Lock()
		delete(broker.connections, conn)
		broker.Active.Add(-1)
		broker.mu.Unlock()
	}()
	for {
		raw, err := wire.Read(conn)
		if err != nil {
			return
		}
		var request struct {
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
			ID     string          `json:"request_id"`
		}
		if json.Unmarshal(raw, &request) != nil {
			return
		}
		params, err := wire.Parse(request.Params)
		if err != nil {
			return
		}
		authority := broker.Fixture.Objects["swarma-broker-lab-authority/1"]
		var result any
		switch request.Method {
		case "hello":
			result = map[string]any{"version": 1, "principal": map[string]any{"service_name": "credential-gateway", "uid": os.Geteuid(), "service_generation": Object(authority["gateway"])["generation"]}}
		case "service.lease.request", "service.lease.renew":
			if request.Method == "service.lease.request" {
				broker.Requests.Add(1)
			} else {
				broker.Renews.Add(1)
			}
			mode := broker.LeaseMode.Load().(string)
			if mode == "lost" {
				return
			}
			record := broker.Fixture.Lease(params["operation_id"].(string))
			if mode == "renew-expired" {
				if request.Method == "service.lease.request" {
					Object(record["bounds"])["authorized_until"] = time.Now().Add(900 * time.Millisecond).UTC().Format(time.RFC3339Nano)
				} else {
					time.Sleep(180 * time.Millisecond)
				}
				mode = ""
			}
			if strings.HasPrefix(mode, "renew-") {
				if request.Method == "service.lease.renew" {
					mode = strings.TrimPrefix(mode, "renew-")
				} else {
					mode = ""
				}
			}
			MutateLease(record, mode, broker.Fixture)
			if mode == "noncanonical" {
				raw := append(Encode(broker.Fixture.Test, map[string]any{"request_id": request.ID, "result": record}), '\n')
				var prefix [4]byte
				binary.BigEndian.PutUint32(prefix[:], uint32(len(raw)))
				if _, err := conn.Write(append(prefix[:], raw...)); err != nil {
					return
				}
				continue
			}
			result = record
		case "service.revocation.check":
			broker.Checks.Add(1)
			switch broker.CheckMode.Load().(string) {
			case "stall":
				_, _ = io.Copy(io.Discard, conn)
				return
			case "revoked":
				result = map[string]any{"verdict": "revoked", "revocation_sequence": int64(5)}
			case "regress":
				result = map[string]any{"verdict": "not_revoked", "revocation_sequence": int64(4)}
			case "advance":
				result = map[string]any{"verdict": "not_revoked", "revocation_sequence": int64(6)}
			case "zero":
				result = map[string]any{"verdict": "not_revoked", "revocation_sequence": int64(0)}
			case "slow":
				time.Sleep(100 * time.Millisecond)
				result = map[string]any{"verdict": "not_revoked", "revocation_sequence": int64(5)}
			case "null":
				result = map[string]any{"verdict": "not_revoked", "revocation_sequence": nil}
			default:
				result = map[string]any{"verdict": "not_revoked", "revocation_sequence": int64(5)}
			}
		case "account.hold":
			broker.Holds.Add(1)
			operation, digest := params["operation_id"].(string), Digest(request.Params)
			broker.mu.Lock()
			if broker.operation != "" && (operation != broker.operation || digest != broker.digest) {
				broker.mismatch = true
			}
			broker.operation, broker.digest = operation, digest
			broker.mu.Unlock()
			mode := broker.HoldMode.Load().(string)
			if mode == "lost" {
				return
			}
			hold := Clone(broker.Fixture.Test, broker.Fixture.Objects["swarma-broker-lab-hold/1"])
			hold["context"], hold["caller"] = Clone(broker.Fixture.Test, Object(authority["context"])), Clone(broker.Fixture.Test, Object(authority["worker"]))
			hold["operation_id"], hold["request_sha256"] = operation, digest
			switch mode {
			case "unknown":
				hold["result"] = "unknown"
			case "operation":
				hold["operation_id"] = strings.Repeat("f", 32)
			case "digest":
				hold["request_sha256"] = "sha256:" + strings.Repeat("f", 64)
			case "context":
				Object(hold["context"])["qualification_revision"] = "foreign"
			case "caller":
				Object(hold["caller"])["execution_id"] = "foreign"
			}
			result = hold
		default:
			return
		}
		if wire.Write(conn, map[string]any{"request_id": request.ID, "result": result}) != nil {
			return
		}
	}
}
func MutateLease(record map[string]any, mode string, fixture *Fixture) {
	bounds := Object(record["bounds"])
	switch mode {
	case "operation":
		record["request_id"] = strings.Repeat("f", 32)
	case "activation", "authority", "fence":
		record[mode+"_sha256"] = "sha256:" + strings.Repeat("f", 64)
	case "context":
		Object(record["context"])["qualification_revision"] = "foreign"
	case "gateway":
		Object(record["gateway"])["execution_id"] = "foreign"
	case "caller":
		Object(record["caller"])["execution_id"] = "foreign"
	case "floor":
		Object(record["manager_floor"])["sequence"] = int64(1)
	case "future":
		bounds["issued_at"] = time.Now().Add(time.Second).UTC().Format(time.RFC3339Nano)
	case "pinned-deadline":
		bounds["authorized_until"] = fixture.Deadline.Add(time.Second).UTC().Format(time.RFC3339Nano)
	case "extra":
		record["extra"] = true
	case "lifetime":
		bounds["lifetime_seconds"] = int64(9)
		bounds["authorized_until"] = time.Now().Add(time.Second).UTC().Format(time.RFC3339Nano)
	case "expired":
		bounds["issued_at"] = time.Now().Add(-2 * time.Second).UTC().Format(time.RFC3339Nano)
		bounds["authorized_until"] = time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano)
	case "interval":
		bounds["issued_at"] = time.Now().Add(-fixture.Lifetime * 2).UTC().Format(time.RFC3339Nano)
	case "zero":
		record["revocation_sequence"] = int64(0)
	case "regress":
		record["revocation_sequence"] = int64(4)
	case "advance":
		record["revocation_sequence"] = int64(6)
	case "lease-id":
		record["lease_id"] = "foreign"
	case "authority_until", "caller_until", "qualification_until", "time_until":
		bounds[mode] = time.Now().UTC().Format(time.RFC3339Nano)
	}
}
