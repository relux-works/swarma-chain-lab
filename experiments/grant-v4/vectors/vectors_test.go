package vectors

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

// Regeneration exercises the lab APIs and checks all specified codes; any fixture byte drift fails.
func TestVectorsDrift(t *testing.T) {
	got, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		var a, b Set
		if json.Unmarshal(got, &a) == nil && json.Unmarshal(want, &b) == nil {
			for i, v := range a.Vectors {
				if i >= len(b.Vectors) || !reflect.DeepEqual(v, b.Vectors[i]) {
					t.Fatalf("vectors.json drift: first differing vector %s", v.ID)
				}
			}
			if len(b.Vectors) > len(a.Vectors) {
				t.Fatalf("vectors.json drift: extra vector %s", b.Vectors[len(a.Vectors)].ID)
			}
		}
		t.Fatal("vectors.json drift: metadata or formatting differs")
	}
}

func fixture(t *testing.T) Set {
	t.Helper()
	b, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	var s Set
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err = d.Decode(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

// No two cases may conceal a coverage gap behind the same operation and input.
// Every negative also points to an existing successful neighbour and names defects.
func TestUniqueInputsAndNegativeMetadata(t *testing.T) {
	s := fixture(t)
	seen := map[string]string{}
	byID := map[string]Vector{}
	for _, v := range s.Vectors {
		byID[v.ID] = v
	}
	for _, v := range s.Vectors {
		b, _ := json.Marshal(v.Input)
		k := v.Operation + string(b)
		if previous, ok := seen[k]; ok {
			t.Errorf("duplicate inputs: %s and %s", previous, v.ID)
		}
		seen[k] = v.ID
		if text(v.Output, "code") != "ok" {
			n, ok := byID[v.ValidNeighbour]
			if !ok || text(n.Output, "code") != "ok" || len(v.Defects) == 0 {
				t.Errorf("missing negative metadata: %s", v.ID)
			}
		}
	}
}

// Repairing only the earlier W7.4 defect must expose the later one in each of
// the ten pairs. This proves both defects survived, including readable shape.
func TestConsentPairsDiscriminateOrder(t *testing.T) {
	s := fixture(t)
	byID := map[string]Vector{}
	for _, v := range s.Vectors {
		byID[v.ID] = v
	}
	codes := map[string]string{"shape": "CONSENT_SHAPE", "binding": "CONSENT_BINDING", "key": "CONSENT_KEY", "signature": "CONSENT_SIGNATURE", "time": "CONSENT_TIME"}
	base := byID["consent-read-key"].Input
	count := 0
	for _, v := range s.Vectors {
		if !strings.HasPrefix(v.ID, "consent-") || !strings.Contains(v.ID, "-before-") {
			continue
		}
		parts := strings.Split(strings.TrimPrefix(v.ID, "consent-"), "-before-")
		early, late := parts[0], parts[1]
		if codes[early] == "" || codes[late] == "" {
			continue
		}
		count++
		in := clone(v.Input)
		ctx := in["context"].(object)
		valid := base["context"].(object)
		switch early {
		case "shape":
			in["raw_hex"] = base["raw_hex"]
			if late == "signature" {
				in["raw_hex"] = byID["consent-signature"].Input["raw_hex"]
			}
		case "binding":
			ctx["contract"] = valid["contract"]
		case "key":
			ctx["request_public_key"] = valid["request_public_key"]
		case "signature":
			in["raw_hex"] = base["raw_hex"]
		default:
			t.Fatalf("unexpected earlier stage %s", early)
		}
		if got := text(Evaluate("consent", in), "code"); got != codes[late] {
			t.Errorf("%s after repairing %s: got %s want %s", v.ID, early, got, codes[late])
		}
		if text(v.Output, "code") != codes[early] {
			t.Errorf("%s does not select earlier stage", v.ID)
		}
	}
	if count != 10 {
		t.Fatalf("got %d order pairs, want 10", count)
	}
}

// The memberless adapter must parse and verify actual signed input before the
// unsupported-type result; malformed octets and a broken signature cannot pass.
func TestMemberlessSignedInputsAreRead(t *testing.T) {
	for _, v := range fixture(t).Vectors {
		if v.Operation != "memberless_signed" {
			continue
		}
		t.Run(v.ID, func(t *testing.T) {
			if got := text(Evaluate(v.Operation, v.Input), "code"); got != "WIRE_TYPE" {
				t.Fatal(got)
			}
			in := clone(v.Input)
			in["raw_hex"] = "7b"
			if got := text(Evaluate(v.Operation, in), "code"); got != "WIRE_JSON" {
				t.Fatalf("unread malformed input: %s", got)
			}
			in = clone(v.Input)
			var env object
			if e := json.Unmarshal(unhex(text(in, "raw_hex")), &env); e != nil {
				t.Fatal(e)
			}
			env["signature"] = strings.Repeat("00", 64)
			in["raw_hex"] = hx(canonical(env, 2048))
			if got := text(Evaluate(v.Operation, in), "code"); got != "WIRE_SIGNATURE" {
				t.Fatalf("unverified signature: %s", got)
			}
		})
	}
}

// Only the three public fixture scalars are accepted; truncation cannot map an
// arbitrary integer into a test signing key. Valid controls still sign/verify.
func TestSignerPublicScalarsOnly(t *testing.T) {
	for _, n := range []int{-1, 0, 4, 256, 257} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			for _, f := range []func(){func() { key(n) }, func() { sign(n, [32]byte{}) }} {
				func() {
					defer func() {
						if recover() == nil {
							t.Error("non-test scalar accepted")
						}
					}()
					f()
				}()
			}
		})
	}
	for _, n := range []int{1, 2, 3} {
		if got := text(Evaluate("verify", object{"public_key": key(n), "digest": strings.Repeat("00", 32), "signature_hex": sign(n, [32]byte{})}), "code"); got != "ok" {
			t.Fatal(got)
		}
	}
}

// Fixed names follow input content, including malformed integer spellings;
// registry witness numbers are explicit upstream associations, never offsets.
func TestContentNamedIDs(t *testing.T) {
	expected := map[string]string{"": "empty", "00": "double-zero", "01": "leading-zero", "-1": "negative", "+1": "plus", "1.0": "fraction", "1e0": "exponent", " 1": "leading-space", "1 ": "trailing-space", "١": "nonascii"}
	count := 0
	for _, v := range fixture(t).Vectors {
		if v.Operation == "integer" && text(v.Output, "code") == "WIRE_INTEGER" && strings.HasPrefix(v.ID, "integer-grammar-") {
			want, ok := expected[text(v.Input, "value")]
			if !ok || v.ID != "integer-grammar-"+want {
				t.Errorf("content/id association drift: %s", v.ID)
			}
			count++
		}
	}
	if count != len(expected) {
		t.Fatalf("got %d named grammar inputs, want %d", count, len(expected))
	}
}
