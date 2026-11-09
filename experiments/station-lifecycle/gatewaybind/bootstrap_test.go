package gatewaybind

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"relux.works/swarma-chain-lab/experiments/rental-gateway/station"
	lifecycle "relux.works/swarma-chain-lab/experiments/station-lifecycle"
)

// Payload decoders reject version/field/schema aliases before HMAC use; the
// canonical neighbor retains its booking identity and exact channel secret.
func TestBootstrapClosedSchema(t *testing.T) {
	b := PayloadBootstrap{V: 1, BookingID: strings.Repeat("a", 64), StationName: "id/fixture", ChannelSecret: lifecycle.Secret(strings.Repeat("x", 32))}
	raw, e := EncodeBootstrap(b)
	if e != nil {
		t.Fatal(e)
	}
	got, e := DecodeBootstrap(raw)
	if e != nil || got.BookingID != b.BookingID || !bytes.Equal(got.ChannelSecret, b.ChannelSecret) {
		t.Fatal("valid bootstrap", e)
	}
	for _, bad := range [][]byte{
		bytes.Replace(raw, []byte(`"v":1`), []byte(`"v":2`), 1),
		bytes.Replace(raw, []byte(`"v":1`), []byte(`"v":1,"v":1`), 1),
		bytes.Replace(raw, []byte(`"v":1`), []byte(`"v":1,"argv":[]`), 1),
		append(append([]byte(nil), raw...), '\n'),
		[]byte(strings.Repeat("x", 4097)),
		bytes.Replace(raw, []byte(`"id/fixture"`), []byte(`"../../operator"`), 1),
	} {
		if _, e = DecodeBootstrap(bad); e == nil || e.Error() != "PAYLOAD_BOOTSTRAP" {
			t.Fatal("invalid bootstrap accepted", e)
		}
	}
	if strings.Contains(fmt.Sprintf("%+v %#v", b, b), strings.Repeat("x", 32)) {
		t.Fatal("bootstrap formatting leaked secret")
	}
}

// Create retries across a gateway/broker restart preserve one credential and
// the exact opaque helper document; mutation of returned buffers changes neither.
func TestBootstrapDurableReplay(t *testing.T) {
	f := setup(t)
	spec := station.SlotSpec{SlotID: f.id, BookingID: f.id, StationName: "id/fixture"}
	st, e := f.d.Create(context.Background(), spec)
	if e != nil {
		t.Fatal(e)
	}
	v, e := f.d.broker.Lookup(f.id)
	if e != nil {
		t.Fatal(e)
	}
	secret := append([]byte(nil), st.ChannelSecret...)
	raw := append([]byte(nil), v.Bootstrap...)
	st.ChannelSecret[0] ^= 1
	v.Bootstrap[0] ^= 1
	f.restart(t)
	st, e = f.d.Create(context.Background(), spec)
	if e != nil {
		t.Fatal(e)
	}
	v, e = f.d.broker.Lookup(f.id)
	if e != nil || !bytes.Equal(secret, st.ChannelSecret) || !bytes.Equal(raw, v.Bootstrap) {
		t.Fatal("restart changed bootstrap or credential", e)
	}
}
