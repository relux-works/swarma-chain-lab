package deploy

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"math/rand/v2"
	"reflect"
	"strings"
	"testing"
)

// checkG2FieldParity compares both acceptance directions and sentinel priority.
// The frozen validator is the independent oracle, not the diagnostic rules.
func checkG2FieldParity(t testing.TB, p G2PayParameters) {
	t.Helper()
	want, got := ValidateG2PayParameters(p), validateG2PayFields(p)
	if (want == nil) != (got == nil) || (want != nil && !errors.Is(got, want)) {
		t.Fatalf("field validator differs from frozen validator: frozen=%v diagnostic=%v", want, got)
	}
	if got != nil {
		var field *FieldError
		if !errors.As(got, &field) || field.Path == "" || field.Path == "parameters" {
			t.Fatalf("semantic refusal lacks member path: %v", got)
		}
	}
	// Pin the canonical parser's acceptance to the same oracle too; its
	// pre-existing raw PLACEHOLDER refusal has priority over semantic checks.
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > 1<<16 {
		want = ErrPolicy
	} else if bytes.Contains(raw, []byte("PLACEHOLDER")) {
		want = ErrPlaceholder
	}
	parsed, err := ParseG2PayParameters(raw)
	if (want == nil) != (err == nil) || (want != nil && !errors.Is(err, want)) {
		t.Fatalf("canonical parser differs: frozen=%v parser=%v", want, err)
	}
	if err != nil && parsed != (G2PayParameters{}) {
		t.Fatal("refusal returned partial parameters")
	}
	if err == nil && parsed != p {
		t.Fatal("accepted parameters changed")
	}
}

func g2ScalarFields(v reflect.Value) []reflect.Value {
	var out []reflect.Value
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		if f.Kind() == reflect.Struct {
			out = append(out, g2ScalarFields(f)...)
		} else {
			out = append(out, f)
		}
	}
	return out
}

// Claim: the non-frozen per-field checks and unchanged frozen validator agree
// in both directions on every member's boundary corpus, paired violations,
// and deterministic mixed inputs. This includes accepted boundary neighbors;
// rejecting everything cannot pass. This is bounded differential evidence,
// supplemented by the fuzz target, not an exhaustive proof over all strings.
func TestG2PayFieldValidatorParity(t *testing.T) {
	stringsToTry := []string{
		"", "main", "regtest", mainGenesis, regtestGenesis,
		"CHANGE_ME", "@TXID@", "PLACEHOLDER", "root", "nobody", "swarma-walletx",
		"_agent-2", "1agent", "a.b", "Hot", "-hot", ".hot", "a/b", "../key",
		"/", "/srv/key", "/srv/../key", "/run", "/run/node", "/etc/swarma/node",
		"/var/lib/swarma-wallet", "/var/lib/swarma-walletx", "/srv/a b", "/srv/\x00key", "☃",
		g2KeyG, g2Key2G, g2KeyOff, strings.ToUpper(g2KeyG),
		strings.Repeat("0", 64), strings.Repeat("f", 64),
	}
	for _, n := range []int{30, 31, 32, 63, 64, 65, 1023, 1024, 1025, 4094, 4095, 4096} {
		stringsToTry = append(stringsToTry, strings.Repeat("a", n), "/"+strings.Repeat("a", n))
	}
	numbers := []int64{math.MinInt64, -1, 0, 1, 2, 5, 6, 7, 63, 64, 65, 99, 100, 101, 144, 145,
		545, 546, 547, 999, 1000, 1001, 3599, 3600, 3601, 65533, 65534, 65535, 65536,
		999999, 1000000, 1000001, 1<<20 - 1, 1 << 20, 1<<20 + 1,
		21000000*100000000 - 1, 21000000 * 100000000, 21000000*100000000 + 1, math.MaxInt32, math.MaxInt64 - 64, math.MaxInt64}
	base := g2Params()
	fieldCount := len(g2ScalarFields(reflect.ValueOf(&base).Elem()))
	for i := 0; i < fieldCount; i++ {
		p := g2Params()
		field := g2ScalarFields(reflect.ValueOf(&p).Elem())[i]
		switch field.Kind() {
		case reflect.String:
			for _, value := range stringsToTry {
				field.SetString(value)
				checkG2FieldParity(t, p)
			}
		case reflect.Bool:
			for _, value := range []bool{false, true} {
				field.SetBool(value)
				checkG2FieldParity(t, p)
			}
		case reflect.Int, reflect.Int64:
			for _, value := range numbers {
				field.SetInt(value)
				checkG2FieldParity(t, p)
			}
		case reflect.Uint16, reflect.Uint32:
			for _, value := range numbers {
				field.SetUint(uint64(value))
				checkG2FieldParity(t, p)
			}
		default:
			t.Fatal("uncovered field type", field.Kind())
		}
	}
	// Pairwise exceptional identity and relational constraints, including
	// domain-before-network sentinel priority and matching regtest pins.
	for _, network := range []string{"main", "regtest", "test"} {
		for _, genesis := range []string{mainGenesis, regtestGenesis, ""} {
			for _, domainOK := range []bool{true, false} {
				p := g2Params()
				p.Network, p.Genesis = network, genesis
				if !domainOK {
					p.ServiceUID = p.AgentUID
				}
				checkG2FieldParity(t, p)
			}
		}
	}
	for _, mutate := range []func(*G2PayParameters){
		func(p *G2PayParameters) { p.AgentKeyFile = p.NodeDataDir },
		func(p *G2PayParameters) { p.AgentSocketGID = p.OperatorGID },
		func(p *G2PayParameters) { p.ReceiptPubkey = p.Grantee },
		func(p *G2PayParameters) { p.G2.MaxTransferSat = p.G2.MaxDaySat },
		func(p *G2PayParameters) { p.G2.MaxDaySat = p.G2.MaxFloatSat + 1 },
		func(p *G2PayParameters) { p.G2.LowFloatSat = p.G2.MaxFloatSat },
		func(p *G2PayParameters) { p.G2.Canary.ValueSat = p.G2.MaxFloatSat + 1 },
		func(p *G2PayParameters) { p.G2.ConflictBlocksN = p.G2.ConfirmationsK - 1 },
		func(p *G2PayParameters) { p.G2.JournalSpendCapacity = p.G2.MaxDayCount + 63 },
		func(p *G2PayParameters) { p.G2.JournalSpendCapacity = p.G2.MaxDayCount + 64 },
	} {
		p := g2Params()
		mutate(&p)
		checkG2FieldParity(t, p)
	}
	rng := rand.New(rand.NewPCG(90, 3))
	for trial := 0; trial < 2048; trial++ {
		p := g2Params()
		fields := g2ScalarFields(reflect.ValueOf(&p).Elem())
		for n := 0; n < 1+trial%len(fields); n++ {
			field := fields[rng.IntN(len(fields))]
			switch field.Kind() {
			case reflect.String:
				field.SetString(stringsToTry[rng.IntN(len(stringsToTry))])
			case reflect.Bool:
				field.SetBool(rng.IntN(2) == 1)
			case reflect.Int, reflect.Int64:
				field.SetInt(numbers[rng.IntN(len(numbers))])
			case reflect.Uint16, reflect.Uint32:
				field.SetUint(rng.Uint64())
			}
		}
		checkG2FieldParity(t, p)
	}
	checkG2FieldParity(t, g2Params())
}

// Claim: fuzzed typed inputs preserve both acceptance directions, sentinel
// precedence and the no-partial-result contract against the frozen validator.
func FuzzG2PayFieldValidatorParity(f *testing.F) {
	for _, p := range []G2PayParameters{g2Params(), {}} {
		raw, err := json.Marshal(p)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1<<16 {
			return
		}
		var p G2PayParameters
		if json.Unmarshal(raw, &p) != nil {
			return
		}
		checkG2FieldParity(t, p)
	})
}
