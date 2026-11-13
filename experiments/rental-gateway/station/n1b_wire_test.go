package station

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

type n1bTokenAdmin struct{ value TrackBToken }

func (a n1bTokenAdmin) Mint(context.Context, string) (TrackBToken, error) { return a.value, nil }
func (n1bTokenAdmin) Revoke(context.Context, string) error                { return nil }

// The original strict admin schema and private token-file bytes stay exact;
// failed decodes clear credentials, and normal destroy still removes the files.
func TestN1bTokenFileAndReplyBytes(t *testing.T) {
	for i := 0; i < 64; i++ {
		token := strings.Repeat("a", 62) + string("0123456789abcdef"[i%16]) + string("0123456789abcdef"[i/16])
		raw := []byte(`{"token":"` + token + `","status":"ok"}`)
		var reply trackBMintReply
		if decodeTrackBMintReply(raw, &reply) != nil || reply.Token.Reveal() != token || reply.Status != "ok" {
			t.Fatal("private mint reply bytes changed")
		}
		generic, e := json.Marshal(reply)
		if e != nil || bytes.Contains(generic, []byte(token)) {
			t.Fatal("mint reply entered generic output")
		}
		for _, bad := range [][]byte{
			bytes.Replace(raw, []byte(`"token":`), []byte(`"token":null,"ignored":`), 1),
			bytes.Replace(raw, []byte(`"token"`), []byte(`"Token"`), 1),
			bytes.Replace(raw, []byte(`"status":"ok"`), []byte(`"status":"ok","status":"bad"`), 1),
			bytes.Replace(raw, []byte(`"status":"ok"`), []byte(`"sta\u0074us":"ok"`), 1),
			[]byte(`{"token":123,"status":"ok"}`), []byte(`{"token":[],"status":"ok"}`),
		} {
			var old struct {
				Token  string `json:"token"`
				Status string `json:"status"`
			}
			if su.StrictInput(bad, &old) == nil {
				t.Fatal("private schema refusal control admitted")
			}
			if decodeTrackBMintReply(bad, &reply) == nil || !reply.Token.IsZero() {
				t.Fatal("private reply refusal retained credentials")
			}
		}
	}
	token := NewTrackBToken(strings.Repeat("e4", 32))
	d := &LocalTestDriver{Root: t.TempDir(), Tokens: n1bTokenAdmin{token}}
	st, e := d.Create(context.Background(), SlotSpec{SlotID: "private-file", BookingID: strings.Repeat("a", 64)})
	if e != nil {
		t.Fatal("private file fixture refused")
	}
	raw, e := os.ReadFile(filepath.Join(st.Home, TrackBTokenFile))
	if e != nil || string(raw) != token.Reveal()+"\n" {
		t.Fatal("private token-file bytes changed")
	}
	if _, e = d.Destroy(context.Background(), st); e != nil {
		t.Fatal("private file destroy refused")
	}
	if _, e = os.Stat(st.Home); !os.IsNotExist(e) {
		t.Fatal("destroy retained token file")
	}
}
