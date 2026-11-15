package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
)

const vectorSHA256 = "67e45caabfa4599160e53bd95541db2b02ad8afdc21872776756881a85c97b4c"

type vector struct {
	ID          string `json:"id"`
	Claim       string `json:"claim"`
	Neighbour   string `json:"valid_neighbour"`
	Value       string `json:"value"`
	Pin         string `json:"pin"`
	SigningKey  string `json:"signing_public_key"`
	Script      string `json:"script_hex"`
	ConfirmedAt *int64 `json:"confirmed_at"`
	Height      int64  `json:"height"`
	Depth       int64  `json:"depth"`
	Created     struct {
		Operation string `json:"operation"`
		Name      string `json:"name"`
	} `json:"created"`
	Inputs []struct {
		Spent       string   `json:"spent_script_hex"`
		ConfirmedAt *int64   `json:"spent_confirmed_at"`
		Unlocking   string   `json:"unlocking_script_hex"`
		Witness     []string `json:"witness_hex"`
	} `json:"inputs"`
	Expect json.RawMessage `json:"expect"`
}

type vectors struct {
	Pins                   struct{ Valid, Invalid, Comparisons []vector }
	Scripts, Writers, Live []vector
	Walks                  []walkVector
	Parameters             struct {
		WitnessFrom int64 `json:"witness_rules_from_height_main_chain"`
	}
}

func loadVectors(t *testing.T) vectors {
	t.Helper()
	b, err := os.ReadFile("testdata/name-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", sha256.Sum256(b)) != vectorSHA256 {
		t.Fatal("vector source hash differs")
	}
	var v vectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	counts := []int{len(v.Pins.Valid), len(v.Pins.Invalid), len(v.Pins.Comparisons), len(v.Scripts), len(v.Writers), len(v.Live)}
	if fmt.Sprint(counts) != "[3 9 3 39 24 6]" {
		t.Fatalf("vector counts %v", counts)
	}
	return v
}

func octets(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func pin(t *testing.T, s string) Pin {
	t.Helper()
	p, err := ParsePin(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func height(h *int64) Height {
	if h == nil {
		return Height{}
	}
	return At(*h)
}

func chain(t *testing.T, from int64) Chain {
	t.Helper()
	c, err := NewChain(from)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// runVectors checks each refusal beside its declared passing neighbour; these are stated-input decisions, not chain validation.
func runVectors(t *testing.T, rows []vector, evaluate func(*testing.T, vector) any) {
	t.Helper()
	index := make(map[string]vector)
	for _, v := range rows {
		if _, exists := index[v.ID]; exists || v.ID == "" {
			t.Fatalf("duplicate or empty id %q", v.ID)
		}
		index[v.ID] = v
	}
	check := func(t *testing.T, v vector, emit bool) {
		t.Helper()
		got := evaluate(t, v)
		actual, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		var a, e any
		if err := json.Unmarshal(actual, &a); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(v.Expect, &e); err != nil {
			t.Fatal(err)
		}
		ea, _ := json.Marshal(e)
		aa, _ := json.Marshal(a)
		if string(aa) != string(ea) {
			t.Errorf("%s: got %s; want %s", v.ID, aa, ea)
		}
		if emit {
			b, _ := json.Marshal(map[string]any{"id": v.ID, "result": got})
			t.Logf("SECOND_READER %s", b)
		}
	}
	for _, v := range rows {
		t.Run(v.ID, func(t *testing.T) {
			t.Log(v.Claim)
			if v.Neighbour != "" {
				n, ok := index[v.Neighbour]
				if !ok || n.Neighbour != "" {
					t.Fatalf("invalid passing neighbour %q", v.Neighbour)
				}
				check(t, n, false)
			}
			check(t, v, true)
		})
	}
}

// TestV4OwnerPin proves the 15 published pin form, point and x-coordinate comparison cases; it grants no object authority.
func TestV4OwnerPin(t *testing.T) {
	v := loadVectors(t)
	rows := append(append(v.Pins.Valid, v.Pins.Invalid...), v.Pins.Comparisons...)
	runVectors(t, rows, func(t *testing.T, v vector) any {
		if v.SigningKey != "" {
			same, err := SameKeyAsSigning(pin(t, v.Pin), v.SigningKey)
			if err != nil {
				t.Fatal(err)
			}
			if same {
				return "same"
			}
			return "different"
		}
		p, err := ParsePin(v.Value)
		if err == nil {
			if !p.Valid() || p.String() != v.Value {
				t.Fatal("pin did not round trip")
			}
			return "pin"
		}
		var pe *PinError
		if !errors.As(err, &pe) || p.Valid() {
			t.Fatalf("unexpected pin refusal: %v", err)
		}
		return string(pe.Part)
	})
}

// TestV4NameScript proves all 39 exact-prefix/address readings and pushed octets; it does not reproduce a node's broader parser.
func TestV4NameScript(t *testing.T) {
	v := loadVectors(t)
	c := chain(t, v.Parameters.WitnessFrom)
	runVectors(t, v.Scripts, func(t *testing.T, v vector) any {
		r, ns := ReadOutput(octets(t, v.Script), pin(t, v.Pin), height(v.ConfirmedAt), c)
		out := map[string]any{"prefix": ns.Prefix.String(), "reading": r.String()}
		switch ns.Prefix {
		case PrefixUpdate, PrefixRegistration:
			out["name"], out["value"] = string(ns.Name), string(ns.Value)
			if ns.Prefix == PrefixRegistration {
				out["rand_hex"] = hex.EncodeToString(ns.Rand)
			}
		case PrefixReservation:
			out["hash_hex"] = hex.EncodeToString(ns.Hash)
		}
		if ns.Prefix != PrefixNone {
			out["address_script_hex"] = hex.EncodeToString(ns.AddressScript)
		}
		return out
	})
}

func writerInput(t *testing.T, v vector) (Operation, []Input) {
	t.Helper()
	op := map[string]Operation{"update": OpUpdate, "registration": OpRegistration}[v.Created.Operation]
	inputs := make([]Input, len(v.Inputs))
	for i, in := range v.Inputs {
		inputs[i] = Input{SpentScript: octets(t, in.Spent), SpentConfirmedAt: height(in.ConfirmedAt), Unlocking: octets(t, in.Unlocking)}
		for _, w := range in.Witness {
			inputs[i].Witness = append(inputs[i].Witness, octets(t, w))
		}
	}
	return op, inputs
}

// TestV4Writer proves all 24 writer decisions including witness/hash-type refusals; placeholder signatures are never cryptographically verified.
func TestV4Writer(t *testing.T) {
	v := loadVectors(t)
	c := chain(t, v.Parameters.WitnessFrom)
	runVectors(t, v.Writers, func(t *testing.T, v vector) any {
		op, inputs := writerInput(t, v)
		return CheckWriter(op, []byte(v.Created.Name), inputs, pin(t, v.Pin), c).String()
	})
}

// TestV4LiveName proves all six height decisions including exclusive expiry at h+D; the caller supplies the chain's depth at H.
func TestV4LiveName(t *testing.T) {
	v := loadVectors(t)
	runVectors(t, v.Live, func(t *testing.T, v vector) any {
		if v.ConfirmedAt == nil {
			t.Fatal("missing confirmation height")
		}
		l, err := CheckLive(*v.ConfirmedAt, v.Height, v.Depth)
		if err != nil {
			t.Fatal(err)
		}
		return l.String()
	})
}
