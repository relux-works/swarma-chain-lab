package wallet

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Oversize/zero/truncated frames refuse before decoding; one valid bounded
// frame round-trips exactly. A short writer is handled without silent truncation.
func TestActionFraming(t *testing.T) {
	body := []byte(`{"v":1}`)
	var b bytes.Buffer
	if e := writeActionFrame(&b, body); e != nil {
		t.Fatal(e)
	}
	valid := append([]byte{}, b.Bytes()...)
	got, e := readActionFrame(&b)
	if e != nil || !bytes.Equal(got, body) {
		t.Fatal("frame neighbor", e)
	}
	for name, raw := range map[string][]byte{"empty": {}, "short-header": {0, 0}, "zero": {0, 0, 0, 0}, "oversize": {0, 1, 0, 1}, "huge": {255, 255, 255, 255}, "short-body": valid[:len(valid)-1]} {
		t.Run(name, func(t *testing.T) {
			got, e := readActionFrame(bytes.NewReader(raw))
			if e == nil || got != nil {
				t.Fatal("frame bound guard")
			}
			if _, e := readActionFrame(bytes.NewReader(valid)); e != nil {
				t.Fatal("frame positive neighbor")
			}
		})
	}
	if e := writeActionFrame(io.Discard, make([]byte, MaxActionFrame+1)); e == nil {
		t.Fatal("outgoing frame bound")
	}
	max := make([]byte, MaxActionFrame)
	b.Reset()
	if e = writeActionFrame(&b, max); e != nil {
		t.Fatal(e)
	}
	if binary.BigEndian.Uint32(b.Bytes()[:4]) != MaxActionFrame {
		t.Fatal("frame endian")
	}
	if got, e = readActionFrame(&b); e != nil || len(got) != MaxActionFrame {
		t.Fatal("maximum frame")
	}
	oversize := make([]byte, 4+MaxActionFrame+1)
	binary.BigEndian.PutUint32(oversize[:4], MaxActionFrame+1)
	if got, e = readActionFrame(bytes.NewReader(oversize)); e == nil || got != nil {
		t.Fatal("frame bound guard")
	}
}

// Kernel-supplied peer credentials are inspected on a real local connection;
// this same-UID test does not prove cross-user filesystem custody.
func TestActionPeer(t *testing.T) {
	path := filepath.Join(privateDir(t), "s")
	l, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	result := make(chan PeerIdentity, 1)
	errs := make(chan error, 1)
	go func() {
		c, e := l.AcceptUnix()
		if e != nil {
			errs <- e
			return
		}
		defer c.Close()
		p, e := socketPeer(c)
		if e != nil {
			errs <- e
			return
		}
		result <- p
	}()
	c, e := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	p, e := socketPeer(c)
	if e != nil || p.UID != uint32(os.Getuid()) {
		t.Fatal("service peer credentials", e)
	}
	select {
	case p := <-result:
		if p.UID != uint32(os.Getuid()) {
			t.Fatal("client peer credentials")
		}
	case e := <-errs:
		t.Fatal(e)
	case <-time.After(time.Second):
		t.Fatal("peer timeout")
	}
}

// Private scalar files reject broadened permissions, aliases and invalid values;
// the valid known test scalar remains loadable. No live credential is touched.
func TestActionKeyFile(t *testing.T) {
	root := privateDir(t)
	path := filepath.Join(root, "key")
	key, _ := testKey(2)
	raw := []byte(hex.EncodeToString(key.Serialize()))
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := LoadActionKey(path); e != nil {
		t.Fatal("key neighbor", e)
	}
	if e := os.Chmod(path, 0640); e != nil {
		t.Fatal(e)
	}
	if _, e := LoadActionKey(path); e == nil {
		t.Fatal("private key mode guard")
	}
	os.Chmod(path, 0600)
	link := filepath.Join(root, "link")
	if e := os.Symlink(path, link); e != nil {
		t.Fatal(e)
	}
	if _, e := LoadActionKey(link); e == nil {
		t.Fatal("key symlink guard")
	}
	hard := filepath.Join(root, "hard")
	if e := os.Link(path, hard); e != nil {
		t.Fatal(e)
	}
	if _, e := LoadActionKey(path); e == nil {
		t.Fatal("key hardlink guard")
	}
	os.Remove(hard)
	for _, value := range []string{strings.Repeat("0", 64), strings.Repeat("f", 64), string(raw) + "\n"} {
		os.WriteFile(path, []byte(value), 0600)
		if _, e := LoadActionKey(path); e == nil {
			t.Fatal("key scalar guard")
		}
	}
	os.WriteFile(path, raw, 0600)
	if _, e := LoadActionKey(path); e != nil {
		t.Fatal("key restored neighbor", e)
	}
}

// Receipt authentication binds the service key, request and grantee. A valid
// receipt for another request or a modified result cannot become client success.
func TestActionReceiptBinding(t *testing.T) {
	key, pub := testKey(7)
	_, grantee := testKey(2)
	r := ActionReceipt{Version: 1, Service: WalletServiceID, Grantee: grantee, RequestHash: strings.Repeat("a", 64), Verdict: "executed", Reason: "EXECUTED", Effect: []byte(`{}`), Sequence: 1, ObservedHeight: 100}
	signed := signActionReceipt(r, key)
	raw := canonical(signed)
	if _, e := ParseActionReceipt(raw, pub, r.RequestHash, grantee); e != nil {
		t.Fatal("receipt neighbor", e)
	}
	for _, tc := range []struct{ key, hash, grantee string }{{pub, strings.Repeat("b", 64), grantee}, {pub, r.RequestHash, pub}, {grantee, r.RequestHash, grantee}} {
		if _, e := ParseActionReceipt(raw, tc.key, tc.hash, tc.grantee); e == nil {
			t.Fatal("receipt binding guard")
		}
	}
	signed.Receipt.Verdict = "refused"
	if _, e := ParseActionReceipt(canonical(signed), pub, r.RequestHash, grantee); e == nil {
		t.Fatal("receipt signature guard")
	}
}
