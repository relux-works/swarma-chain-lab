package wallet

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Production startup accepts properly provisioned local files with a distinct
// peer UID pin, and rejects key reuse, writable object roots and broad private
// file modes. No different-UID client or OS account is created by this fixture.
func TestCoreActionStartup(t *testing.T) {
	l := newCore(t)
	_, c := l.grant(Terms{Version: 1, Recipients: []string{testAddress(3)}, SpendCap: 1000000}, []string{"pay"}, 1000000)
	f := coreSocket(t, l, c)
	sc := f.service.config
	f.stop()
	run := filepath.Join(l.private, "runtime")
	if e := os.Mkdir(run, 0750); e != nil {
		t.Fatal(e)
	}
	run, e := filepath.EvalSymlinks(run)
	if e != nil {
		t.Fatal(e)
	}
	os.Chmod(run, 0750)
	os.Chown(run, os.Getuid(), os.Getgid())
	sc.Socket = filepath.Join(run, "w.sock")
	sc.PeerUID++
	key, _ := testKey(7)
	os.WriteFile(sc.ReceiptKeyFile, []byte(hex.EncodeToString(key.Serialize())), 0600)
	os.WriteFile(sc.WalletConfig, canonical(c), 0600)
	open := func() {
		t.Helper()
		s, e := OpenActionService(sc)
		if e != nil {
			t.Fatal("native startup neighbor", e)
		}
		s.Close()
	}
	open()
	granteeKey, _ := testKey(2)
	os.WriteFile(sc.ReceiptKeyFile, []byte(hex.EncodeToString(granteeKey.Serialize())), 0600)
	if s, e := OpenActionService(sc); e == nil {
		s.Close()
		t.Fatal("receipt/grantee key separation guard")
	} else if e.Error() != "SERVICE_KEY_SEPARATION" {
		t.Fatal(e)
	}
	os.WriteFile(sc.ReceiptKeyFile, []byte(hex.EncodeToString(key.Serialize())), 0600)
	os.Chmod(c.ObjectsDir, 0770)
	if s, e := OpenActionService(sc); e == nil {
		s.Close()
		t.Fatal("object directory custody guard")
	} else if e.Error() != "SERVICE_OBJECTS" {
		t.Fatal(e)
	}
	os.Chmod(c.ObjectsDir, 0700)
	os.Chmod(sc.WalletConfig, 0640)
	if s, e := OpenActionService(sc); e == nil {
		s.Close()
		t.Fatal("RPC configuration custody guard")
	} else if e.Error() != "CONFIG_PRIVATE_FILE" {
		t.Fatal(e)
	}
	os.Chmod(sc.WalletConfig, 0600)
	open()
}

// Persisted receipt/schema/config corruption refuses reopening without changing
// wallet state; the original signed terminal receipt survives a clean restart.
func TestCoreActionState(t *testing.T) {
	l := newCore(t)
	_, c := l.grant(Terms{Version: 1, Recipients: []string{testAddress(3)}, SpendCap: 1000000}, []string{"pay"}, 1000000)
	f := coreSocket(t, l, c)
	s := f.service
	r := actionFixture(t, "receive")
	got, receipt := socketRequest(t, s, r)
	expectAction(t, got, "executed", "ALLOCATED")
	f.stop()
	path := filepath.Join(s.config.StateDir, "service.json")
	original, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(filepath.Join(c.StateDir, "wallet.json"))
	addresses := string(l.rpc("agent", "getaddressesbylabel", ""))
	open := func() (*ActionService, error) {
		w, e := Open(c)
		if e != nil {
			return nil, e
		}
		key, _ := testKey(7)
		x, e := openActionService(s.config, w, key)
		if e != nil {
			w.Close()
		}
		return x, e
	}
	for name, change := range map[string]func(*serviceState){
		"binding":         func(x *serviceState) { x.Binding = strings.Repeat("a", 64) },
		"hash":            func(x *serviceState) { x.Entries[0].Hash = strings.Repeat("a", 64) },
		"phase":           func(x *serviceState) { x.Entries[0].Phase = "executed" },
		"missing-receipt": func(x *serviceState) { x.Entries[0].Receipt = nil },
		"signature":       func(x *serviceState) { x.Entries[0].Receipt.Signature = strings.Repeat("0", 128) },
		"duplicate-nonce": func(x *serviceState) { x.Entries = append(x.Entries, x.Entries[0]) },
		"peer":            func(x *serviceState) { x.Entries[0].Peer.UID++ },
	} {
		t.Run(name, func(t *testing.T) {
			var state serviceState
			json.Unmarshal(original, &state)
			change(&state)
			os.WriteFile(path, canonical(state), 0600)
			if x, e := open(); e == nil {
				x.Close()
				t.Fatal("journal corruption accepted", name)
			}
		})
	}
	os.WriteFile(path, original, 0600)
	os.Chmod(path, 0640)
	if x, e := open(); e == nil {
		x.Close()
		t.Fatal("journal private mode guard")
	}
	os.Chmod(path, 0600)
	x, e := open()
	if e != nil {
		t.Fatal("restart neighbor", e)
	}
	x.clock = func() int64 { return 2000 }
	stop := runExistingSocket(t, x)
	defer stop()
	_, replayed := socketRequest(t, x, r)
	if !bytes.Equal(receipt, replayed) {
		t.Fatal("restart terminal receipt changed")
	}
	after, _ := os.ReadFile(filepath.Join(c.StateDir, "wallet.json"))
	if !bytes.Equal(before, after) || addresses != string(l.rpc("agent", "getaddressesbylabel", "")) {
		t.Fatal("corrupt/restart caused effect")
	}
}

// Admission stops at the journal cap, preserving stored duplicate receipts.
// A write failure poisons the service before receive can allocate an address.
func TestCoreActionStateLimits(t *testing.T) {
	l := newCore(t)
	_, c := l.grant(Terms{Version: 1, Recipients: []string{testAddress(3)}, SpendCap: 1000000}, []string{"pay"}, 1000000)
	f := coreSocket(t, l, c)
	s := f.service
	r := actionFixture(t, "balance")
	var first []byte
	for i := 0; i < maxServiceEntries; i++ {
		r.Nonce = fmt.Sprintf("%032x", i)
		got, b := socketRequest(t, s, r)
		expectAction(t, got, "executed", "READ")
		if i == 0 {
			first = b
		}
	}
	r.Nonce = strings.Repeat("f", 32)
	got, _ := socketRequest(t, s, r)
	expectAction(t, got, "refused", "SERVICE_JOURNAL_LIMIT")
	r.Nonce = fmt.Sprintf("%032x", 0)
	_, b := socketRequest(t, s, r)
	if !bytes.Equal(first, b) {
		t.Fatal("full journal duplicate lost")
	}
	// An isolated second journal is necessary: a full one refuses before write.
	f.stop()
	other := filepath.Join(l.private, "service-write-failure")
	os.Mkdir(other, 0700)
	sc := s.config
	sc.StateDir = other
	w, e := Open(c)
	if e != nil {
		t.Fatal(e)
	}
	key, _ := testKey(7)
	x, e := openActionService(sc, w, key)
	if e != nil {
		w.Close()
		t.Fatal(e)
	}
	x.clock = func() int64 { return 500 }
	stop := runExistingSocket(t, x)
	defer stop()
	got, _ = socketRequest(t, x, actionFixture(t, "balance"))
	expectAction(t, got, "executed", "READ")
	addresses := string(l.rpc("agent", "getaddressesbylabel", ""))
	os.Chmod(filepath.Join(other, "service.json"), 0640)
	r = actionFixture(t, "receive")
	r.Nonce = strings.Repeat("b", 32)
	got, _ = socketRequest(t, x, r)
	expectAction(t, got, "refused", "SERVICE_JOURNAL_UNCERTAIN")
	r.Nonce = strings.Repeat("c", 32)
	got, _ = socketRequest(t, x, r)
	expectAction(t, got, "refused", "SERVICE_STATE_UNAVAILABLE")
	if addresses != string(l.rpc("agent", "getaddressesbylabel", "")) {
		t.Fatal("failed admission allocated address")
	}
}
