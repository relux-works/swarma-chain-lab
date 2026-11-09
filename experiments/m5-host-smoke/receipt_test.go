package smoke

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func receiptFixture(stage, scenario string, p profile) (Request, Receipt) {
	checks, numbers, hashes := requirements(stage, p, scenario)
	q := Request{Version: 1, RunID: strings.Repeat("1", 64), Mode: p.mode, Scenario: scenario, Stage: stage, Sequence: 1, ConfigSHA256: strings.Repeat("2", 64), CreatedMS: 100, DeadlineMS: 200, Slot: p.slot, Checks: checks, Numbers: numbers, Hashes: hashes}
	r := Receipt{RequestSHA256: q.SHA256(), ObservedMS: 150, Checks: map[string]bool{}, Numbers: map[string]int64{}, Hashes: map[string]string{}}
	for _, k := range checks {
		r.Checks[k] = true
	}
	for k, v := range numbers {
		if v < 0 {
			v = 1
		}
		r.Numbers[k] = v
	}
	for k := range hashes {
		r.Hashes[k] = strings.Repeat("3", 64)
	}
	return q, r
}
func cloneReceipt(r Receipt) Receipt { var v Receipt; _ = json.Unmarshal(encode(r), &v); return v }
func wantCode(t *testing.T, e error, want string) {
	t.Helper()
	if e == nil || code(e) != want {
		t.Fatalf("want %s; got %v", want, e)
	}
}

// Every required operator assertion has a valid neighboring control and a
// planted false/missing observation. Counts include the extra-upstream-call
// plant; hashes and fresh bindings cannot be replaced by arbitrary text.
// This calibrates the checker, not the veracity of operator attestations.
func TestEveryReceiptGateRejectsItsPlant(t *testing.T) {
	for _, p := range []profile{host(), rehearsal(Config{NotBefore: 100, NotAfter: 310})} {
		for _, scenario := range []string{"expiry", "revoke"} {
			for _, stage := range []string{"preflight", "pregrant", "unconfirmed_payment", "issue", "running", "caps", "revoke", "close", "restart"} {
				t.Run(p.mode+"/"+scenario+"/"+stage, func(t *testing.T) {
					q, good := receiptFixture(stage, scenario, p)
					if e := ValidateReceipt(q, good, 120, 160); e != nil {
						t.Fatal("positive control", e)
					}
					for _, k := range q.Checks {
						t.Run(k, func(t *testing.T) {
							bad := cloneReceipt(good)
							bad.Checks[k] = false
							wantCode(t, ValidateReceipt(q, bad, 120, 160), "CHECK_"+k)
							delete(bad.Checks, k)
							wantCode(t, ValidateReceipt(q, bad, 120, 160), "RECEIPT_FIELDS")
						})
					}
					for k, w := range q.Numbers {
						t.Run(k, func(t *testing.T) {
							bad := cloneReceipt(good)
							if w >= 0 {
								bad.Numbers[k]++
							} else {
								bad.Numbers[k] = -9
							}
							wantCode(t, ValidateReceipt(q, bad, 120, 160), "NUMBER_"+k)
						})
					}
					for k := range q.Hashes {
						t.Run(k, func(t *testing.T) {
							bad := cloneReceipt(good)
							bad.Hashes[k] = "secret-canary-never-copy"
							wantCode(t, ValidateReceipt(q, bad, 120, 160), "HASH_"+k)
						})
					}
					bad := cloneReceipt(good)
					bad.Checks["extra"] = true
					wantCode(t, ValidateReceipt(q, bad, 120, 160), "RECEIPT_FIELDS")
				})
			}
		}
	}
}

// Replay across runs, scenarios, stages, slots, configs, sequence or deadline
// changes fails even if all claimed observations are positive.
func TestReceiptBindingAndTime(t *testing.T) {
	q, r := receiptFixture("caps", "expiry", host())
	for name, mutate := range map[string]func(*Request){
		"run": func(q *Request) { q.RunID = strings.Repeat("4", 64) }, "mode": func(q *Request) { q.Mode = "self-test" }, "scenario": func(q *Request) { q.Scenario = "revoke" }, "stage": func(q *Request) { q.Stage = "restart" }, "slot": func(q *Request) { q.Slot = "other" }, "config": func(q *Request) { q.ConfigSHA256 = strings.Repeat("5", 64) }, "sequence": func(q *Request) { q.Sequence++ }, "deadline": func(q *Request) { q.DeadlineMS++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := q
			mutate(&changed)
			wantCode(t, ValidateReceipt(changed, r, 120, 160), "RECEIPT_BINDING")
		})
	}
	for _, at := range []int64{99, 119, 161, 201} {
		bad := r
		bad.ObservedMS = at
		wantCode(t, ValidateReceipt(q, bad, 120, 160), "RECEIPT_TIME")
	}
	wantCode(t, ValidateReceipt(q, r, 120, 201), "RECEIPT_TIME")
}

// Unknown/duplicate/null/trailing/oversized input is rejected without echoing
// it. Valid fields retain their exact binding after serialization.
func TestStrictReceiptRedaction(t *testing.T) {
	_, r := receiptFixture("caps", "expiry", host())
	var parsed Receipt
	if e := Strict(encode(r), &parsed); e != nil {
		t.Fatal(e)
	}
	for _, raw := range []string{`{"request_sha256":"secret-canary","request_sha256":"x"}`, `{"password":"secret-canary"}`, `{"checks":null}`, string(encode(r)) + ` {}`, strings.Repeat("x", 256<<10+1)} {
		e := Strict([]byte(raw), &parsed)
		if e == nil || strings.Contains(e.Error(), "secret-canary") {
			t.Fatal("parser leaked or accepted invalid input")
		}
	}
}

// File intake refuses links, broad permissions and unknown/raw-log fields;
// failure packets contain only sanitized report/requests, never rejected bytes.
func TestFileBoundaryAndFailedPacket(t *testing.T) {
	root := filepath.Join(t.TempDir(), "packet")
	f, e := NewFiles(root)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	q, _ := receiptFixture("caps", "expiry", host())
	q.CreatedMS = time.Now().UnixMilli()
	q.DeadlineMS = time.Now().Add(time.Second).UnixMilli()
	canary := []byte(`{"password":"secret-canary"}`)
	if e = os.WriteFile(filepath.Join(root, "01-caps.incoming.json"), canary, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = f.Observe(context.Background(), q); e == nil {
		t.Fatal("raw-log receipt accepted")
	}
	if e = f.Finish(Report{Outcome: "FAIL", Failure: "JSON_SCHEMA"}); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"01-caps.request.json", "report.json", "SHA256SUMS"} {
		b, e := os.ReadFile(filepath.Join(root, name))
		if e != nil || strings.Contains(string(b), "secret-canary") {
			t.Fatal("failure evidence leak")
		}
	}
	if _, e = NewFiles(root); e == nil {
		t.Fatal("reused output accepted")
	}
	public := filepath.Join(root, "public")
	if e = os.WriteFile(public, []byte("{}"), 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = readFile(f.root, "public"); e == nil {
		t.Fatal("broad mode")
	}
	target := filepath.Join(root, "target")
	if e = os.WriteFile(target, []byte("{}"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(target, filepath.Join(root, "link")); e != nil {
		t.Fatal(e)
	}
	if _, e = readFile(f.root, "link"); e == nil {
		t.Fatal("symlink")
	}
	if e = os.Link(target, filepath.Join(root, "hard")); e != nil {
		t.Fatal(e)
	}
	if _, e = readFile(f.root, "target"); e == nil {
		t.Fatal("hardlink")
	}
}

// A missing receipt times out without inventing success; a valid receipt beside
// it produces the same selected projection and a checksummed packet.
func TestFileMissingAndPositive(t *testing.T) {
	for _, present := range []bool{false, true} {
		t.Run(map[bool]string{true: "valid", false: "missing"}[present], func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "packet")
			f, e := NewFiles(root)
			if e != nil {
				t.Fatal(e)
			}
			defer f.Close()
			q, r := receiptFixture("caps", "expiry", host())
			q.CreatedMS = time.Now().UnixMilli()
			q.DeadlineMS = time.Now().Add(time.Second).UnixMilli()
			r.RequestSHA256 = q.SHA256()
			r.ObservedMS = q.CreatedMS
			if present {
				if e = os.WriteFile(filepath.Join(root, "01-caps.incoming.json"), encode(r), 0600); e != nil {
					t.Fatal(e)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			_, e = f.Observe(ctx, q)
			if present {
				if e != nil {
					t.Fatal(e)
				}
			} else {
				wantCode(t, e, "RECEIPT_MISSING")
			}
		})
	}
}

// A named operator rejection retains its exact fixed gate in the report;
// unrecognized adapter errors cannot smuggle arbitrary text into evidence.
func TestOperatorFailureCodes(t *testing.T) {
	q, _ := receiptFixture("close", "expiry", host())
	wantCode(t, operatorFailure(q, refuse("CHECK_channel_cleared")), "OPERATOR_close_CHECK_channel_cleared")
	wantCode(t, operatorFailure(q, refuse("JSON_SCHEMA")), "OPERATOR_close_JSON_SCHEMA")
	wantCode(t, operatorFailure(q, refuse("secret-canary")), "OPERATOR_close")
}

// The Darwin adapter cannot claim a remote mirror or observed Starting
// transition. Both assertions remain required in the real host profile.
func TestHostOnlyObservationBoundary(t *testing.T) {
	for _, tc := range []struct{ stage, key string }{{"issue", "mirror_hash_index_equal"}, {"issue", "running_signer_consumed"}, {"running", "starting_then_started"}, {"revoke", "single_running_signer"}, {"preflight", "release_signature"}} {
		contains := func(p profile) bool {
			checks, _, _ := requirements(tc.stage, p, "revoke")
			for _, v := range checks {
				if v == tc.key {
					return true
				}
			}
			return false
		}
		if !contains(host()) || contains(rehearsal(Config{NotBefore: 100, NotAfter: 300})) {
			t.Fatal("host/self-test observation boundary", tc.key)
		}
	}
}

// A syntactically valid but different payload digest cannot accompany a positive
// executable claim. The request pins the approved artifact before handoff.
func TestObservedPayloadPin(t *testing.T) {
	for _, wrong := range []bool{false, true} {
		c, _, _ := publicFixture(t)
		r := runner{c: c, p: host(), seenRumors: -1, report: Report{RunID: strings.Repeat("1", 64), ConfigSHA256: strings.Repeat("2", 64)}}
		r.op = OperatorFunc(func(_ context.Context, q Request) (Receipt, error) {
			if q.Hashes["payload_binary"] != c.PayloadSHA256 {
				t.Fatal("payload pin missing")
			}
			got := Receipt{RequestSHA256: q.SHA256(), ObservedMS: time.Now().UnixMilli(), Checks: map[string]bool{}, Numbers: map[string]int64{}, Hashes: map[string]string{}}
			for _, k := range q.Checks {
				got.Checks[k] = true
			}
			for k, v := range q.Numbers {
				if v < 0 {
					v = 1000
				}
				got.Numbers[k] = v
			}
			for k, v := range q.Hashes {
				if v == "" {
					v = strings.Repeat("3", 64)
				}
				got.Hashes[k] = v
			}
			if wrong {
				got.Hashes["payload_binary"] = strings.Repeat("4", 64)
			}
			return got, nil
		})
		_, e := r.observe(context.Background(), "running", time.Now().Add(time.Second))
		if wrong {
			wantCode(t, e, "HASH_payload_binary")
		} else if e != nil {
			t.Fatal(e)
		}
	}
}

// Inventory intake binds exact bytes and payload pin. A different valid hash,
// missing/replaced host roles and free-form metadata cannot masquerade as
// approved input. Each required role is tested against a same-size wrong-key map.
func TestInventoryBindings(t *testing.T) {
	h := strings.Repeat("1", 64)
	v := Inventory{Source: strings.Repeat("1", 40), Tree: strings.Repeat("2", 40), Helper: h, StoragePolicySHA256: h, Binaries: map[string]string{}, Configs: map[string]string{}, Hosts: map[string]HostVersion{}}
	for _, role := range []string{"booking", "gateway", "store", "relay", "model", "wallet", "signer", "manager", "payload"} {
		v.Binaries[role] = h
		v.Configs[role] = h
	}
	for _, role := range []string{"signer", "gateway", "stations"} {
		v.Hosts[role] = HostVersion{"6.8.0", "255"}
	}
	if e := v.validate(); e != nil {
		t.Fatal(e)
	}
	for _, mode := range []string{"valid", "hash", "payload", "host", "metadata", "wrong_signer", "wrong_gateway", "wrong_stations"} {
		t.Run(mode, func(t *testing.T) {
			var copy Inventory
			_ = json.Unmarshal(encode(v), &copy)
			if mode == "host" {
				delete(copy.Hosts, "signer")
			}
			if mode == "metadata" {
				copy.Hosts["signer"] = HostVersion{"secret canary", "255"}
			}
			if role, wrong := strings.CutPrefix(mode, "wrong_"); wrong {
				copy.Hosts["node.example"] = copy.Hosts[role]
				delete(copy.Hosts, role)
			}
			root := t.TempDir()
			path := filepath.Join(root, "inventory.json")
			raw := encode(copy)
			if e := os.WriteFile(path, raw, 0600); e != nil {
				t.Fatal(e)
			}
			files, e := NewFiles(filepath.Join(root, "packet"))
			if e != nil {
				t.Fatal(e)
			}
			defer files.Close()
			want := hashBytes(raw)
			payload := h
			if mode == "hash" {
				want = strings.Repeat("3", 64)
			}
			if mode == "payload" {
				payload = strings.Repeat("4", 64)
			}
			e = files.AddInventory(path, want, payload)
			if mode == "valid" {
				if e != nil {
					t.Fatal(e)
				}
			} else {
				want := "INVENTORY_HOST"
				switch mode {
				case "hash":
					want = "INVENTORY_BINDING"
				case "payload":
					want = "INVENTORY_PAYLOAD"
				case "host":
					want = "INVENTORY_FIELDS"
				}
				wantCode(t, e, want)
				if _, e = os.Stat(filepath.Join(root, "packet", "inventory.json")); !os.IsNotExist(e) {
					t.Fatal("invalid inventory persisted")
				}
			}
		})
	}
}

func hashBytes(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }
