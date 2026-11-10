package signerservice

import (
	"context"
	"encoding/json"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The public/local admission guard rejects ambiguous keys before mutating the
// destination, including RawMessage subtrees. This does not exercise RPC effects.
func TestSJ1KeyAdmission(t *testing.T) {
	type wire struct {
		Grant json.RawMessage `json:"grant"`
		Note  string          `json:"note"`
	}
	valid := `{"grant":{"version":3},"note":"line\nvalue"}`
	cases := map[string]string{
		"left-valid":               `{"grant":{"version":3},"grant":{"version":2},"note":"x"}`,
		"right-valid":              `{"grant":{"version":2},"grant":{"version":3},"note":"x"}`,
		"escaped-duplicate":        `{"grant":{"version":3},"gr\u0061nt":{"version":2},"note":"x"}`,
		"escaped-single":           `{"gr\u0061nt":{"version":3},"note":"x"}`,
		"nested-left-valid":        `{"grant":{"version":3,"version":2},"note":"x"}`,
		"nested-right-valid":       `{"grant":{"version":2,"version":3},"note":"x"}`,
		"nested-escaped-duplicate": `{"grant":{"version":3,"vers\u0069on":2},"note":"x"}`,
		"nested-escaped-single":    `{"grant":{"vers\u0069on":3},"note":"x"}`,
		"array-escaped-single":     `{"grant":[{"vers\u0069on":3}],"note":"x"}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			out := wire{Grant: json.RawMessage(`{"retained":true}`), Note: "retained"}
			if err := strict([]byte(raw), &out); err == nil {
				t.Fatal("SJ1 ambiguous key admitted")
			}
			if string(out.Grant) != `{"retained":true}` || out.Note != "retained" {
				t.Fatal("SJ1 rejected input mutated destination")
			}
			raw = valid
			out = wire{}
			if err := strict([]byte(raw), &out); err != nil || string(out.Grant) != `{"version":3}` || out.Note != "line\nvalue" {
				t.Fatalf("valid neighbor: %v", err)
			}
		})
	}
}

type sj1Issuer struct {
	preflightIssuer
	calls int
}

func (s *sj1Issuer) Inspect(a, b []byte, now int64) (Intent, error) {
	s.calls++
	return s.preflightIssuer.Inspect(a, b, now)
}

// The embedded request is checked before issuer inspection, reservation or any
// external effect. The valid neighbor reaches the existing cap check; this does
// not claim issuance success (the real signed package is tested by rental).
func TestSJ1EmbeddedRequest(t *testing.T) {
	c := config(t)
	intent := Intent{BookingID: hash([]byte("book")), ContractSHA256: hash([]byte("contract")), BudgetSat: c.Caps.BudgetHour + 1, PaymentCoin: "nmc", PaymentNetwork: "regtest", PaymentGenesis: su.RegtestGenesis, PaymentTxID: hash([]byte("payment"))}
	issuer := &sj1Issuer{preflightIssuer: preflightIssuer{t, intent}}
	x, e := Open(c, issuer, noNode{t}, noBroadcast{t}, noStore{t})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(x.Close)
	snapshot := func() string {
		var out strings.Builder
		for _, name := range files(t, c.StateDir) {
			b, e := os.ReadFile(filepath.Join(c.StateDir, name))
			if e != nil {
				t.Fatal(e)
			}
			out.WriteString(name)
			out.Write(b)
		}
		return out.String()
	}
	before := snapshot()
	state := string(encode(x.state))
	good := `"booking_id":"` + intent.BookingID + `"`
	bad := `"booking_id":"invalid"`
	for _, field := range []string{good + `,` + bad, bad + `,` + good, good + `,"booking_\u0069d":"invalid"`, `"booking_\u0069d":"` + intent.BookingID + `"`} {
		item := Item{ID: hash([]byte("id")), Kind: "grant-issue", Request: `{` + field + `}`, Publication: `{}`}
		_, e := x.Process(context.Background(), encode(item), BookingSource, 500)
		wantError(t, e, "ISSUE_REQUEST")
		if issuer.calls != 0 || snapshot() != before || string(encode(x.state)) != state {
			t.Fatal("JSON refusal changed state or called issuer")
		}
	}
	item := Item{ID: hash([]byte("id")), Kind: "grant-issue", Request: `{` + good + `}`, Publication: `{}`}
	_, e = x.Process(context.Background(), encode(item), BookingSource, 500)
	wantError(t, e, "ISSUANCE_CAP")
	if issuer.calls != 1 || snapshot() != before || string(encode(x.state)) != state {
		t.Fatal("valid schema neighbor failed preflight invariant")
	}
}
