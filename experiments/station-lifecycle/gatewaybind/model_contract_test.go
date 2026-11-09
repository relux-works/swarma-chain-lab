package gatewaybind

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	proxy "github.com/relux-works/swarma-chain-lab/experiments/model-proxy"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/journal"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/station"
)

// Each signed cap must match in both directions before allocation or registry
// effects. The matching neighbor reaches real proxy Prepare with the signed caps.
func TestModelContractCapsBeforeAllocation(t *testing.T) {
	for i := 0; i < reflect.TypeOf(proxy.Caps{}).NumField(); i++ {
		for _, delta := range []int64{-1, 1} {
			t.Run(fmt.Sprintf("%s/%d", reflect.TypeOf(proxy.Caps{}).Field(i).Name, delta), func(t *testing.T) {
				f, r := modelFixture(t)
				signed := f.c.ModelCaps
				v := reflect.ValueOf(&f.d.cfg.ModelCaps).Elem().Field(i)
				v.SetUint(uint64(int64(v.Uint()) + delta))
				spec := station.SlotSpec{SlotID: f.id, BookingID: f.id, StationName: "id/fixture"}
				before, _ := f.c.Journal.Get(f.id)
				rawBefore, _ := json.Marshal(before)
				if _, e := f.d.Create(context.Background(), spec); e == nil || e.Error() != "MODEL_CAPS_MISMATCH" {
					t.Fatal("wrong refusal", e)
				}
				if _, e := f.d.broker.Lookup(f.id); e == nil {
					t.Fatal("allocated mismatched slot")
				}
				after, _ := f.c.Journal.Get(f.id)
				rawAfter, _ := json.Marshal(after)
				if !bytes.Equal(rawBefore, rawAfter) || r.prepare != 0 || r.activate != 0 {
					t.Fatal("refusal changed journal or registry")
				}
				f.d.cfg.ModelCaps = signed
				if _, e := f.d.Create(context.Background(), spec); e != nil {
					t.Fatal("valid neighbor", e)
				}
				state, e := r.service.Status(f.id)
				if e != nil || state.Binding.Caps != signed || r.prepare != 1 {
					t.Fatal("signed caps not prepared", e)
				}
			})
		}
	}
}

// Missing, changed, noncanonical contract bytes and mismatched presentation
// fields refuse before allocation. Kernel signatures remain outside this fixture.
func TestModelContractBindingRefusals(t *testing.T) {
	cases := map[string]func(*journal.Slot){
		"missing": func(s *journal.Slot) { s.ContractB64 = "" },
		"hash":    func(s *journal.Slot) { s.ContractSHA256 = strings.Repeat("a", 64) },
		"noncanonical": func(s *journal.Slot) {
			raw, _ := base64.StdEncoding.DecodeString(s.ContractB64)
			s.ContractB64 = base64.StdEncoding.EncodeToString(append(raw, '\n'))
		},
		"caps": func(s *journal.Slot) {
			raw, _ := base64.StdEncoding.DecodeString(s.ContractB64)
			s.ContractB64 = base64.StdEncoding.EncodeToString(bytes.Replace(raw, []byte(`"requests":10`), []byte(`"requests":11`), 1))
		},
		"grant-contract": func(s *journal.Slot) {
			raw, _ := base64.StdEncoding.DecodeString(s.CertificateB64)
			s.CertificateB64 = base64.StdEncoding.EncodeToString(bytes.Replace(raw, []byte(s.ContractSHA256), []byte(strings.Repeat("a", 64)), 1))
		},
		"grant-renter": func(s *journal.Slot) {
			raw, _ := base64.StdEncoding.DecodeString(s.CertificateB64)
			s.CertificateB64 = base64.StdEncoding.EncodeToString(bytes.Replace(raw, []byte(s.RenterPubKey), []byte(strings.Repeat("a", 64)), 1))
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f, r := modelFixture(t)
			s, _ := f.c.Journal.Get(f.id)
			original := *s
			mutate(s)
			writeModelJournalFixture(t, f, s)
			spec := station.SlotSpec{SlotID: f.id, BookingID: f.id, StationName: "id/fixture"}
			if _, e := f.d.Create(context.Background(), spec); e == nil || e.Error() != "MODEL_CONTRACT" {
				t.Fatal("wrong contract refusal", e)
			}
			if r.prepare != 0 || r.activate != 0 {
				t.Fatal("invalid contract reached registry")
			}
			if _, e := f.d.broker.Lookup(f.id); e == nil {
				t.Fatal("invalid contract allocated")
			}
			writeModelJournalFixture(t, f, &original)
			if _, e := f.d.Create(context.Background(), spec); e != nil {
				t.Fatal("valid neighbor", e)
			}
		})
	}
}

// Restart with a changed valid config must refuse activation of the old terms
// while still revoking the original binding and stopping its prepared slot.
func TestModelConfigChangeRefusesStartPreservesRevoke(t *testing.T) {
	f, r := modelFixture(t)
	spec := station.SlotSpec{SlotID: f.id, BookingID: f.id, StationName: "id/fixture"}
	st, e := f.d.Create(context.Background(), spec)
	if e != nil {
		t.Fatal(e)
	}
	original := f.c.ModelCaps
	f.c.ModelCaps.Requests++
	f.restart(t)
	s, _ := f.c.Journal.Get(f.id)
	info := station.SessionInfo{RenterPubKey: s.RenterPubKey, ContractSHA256: s.ContractSHA256, NotAfter: s.NotAfter}
	if e = f.d.StartSession(context.Background(), st, info); e == nil || e.Error() != "MODEL_CAPS_MISMATCH" {
		t.Fatal("changed config started old contract", e)
	}
	if r.activate != 0 || modelPhase(t, r, f.id) != "prepared" {
		t.Fatal("refusal activated")
	}
	stop := f.pump(t)
	defer stop()
	if e = f.d.End(context.Background(), st, "changed config cleanup"); e != nil {
		t.Fatal("old binding revoke blocked", e)
	}
	state, e := r.service.Status(f.id)
	if e != nil || state.Phase != "revoked" || state.Binding.Caps != original || r.revoke != 1 {
		t.Fatal("cleanup changed original binding", e)
	}
	f.host.mu.Lock()
	defer f.host.mu.Unlock()
	if f.host.starts != 0 || f.host.active {
		t.Fatal("refusal started host")
	}
}

// Fault injection writes only this test's isolated journal, then reloads it.
func writeModelJournalFixture(t *testing.T, f *fixture, s *journal.Slot) {
	t.Helper()
	f.d.Close()
	raw, e := json.Marshal(s)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(f.jdir, "slot-"+s.ID+".json"), raw, 0600); e != nil {
		t.Fatal(e)
	}
	f.restart(t)
}
