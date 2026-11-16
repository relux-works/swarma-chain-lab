package identity

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const holderTestKey = "022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01"

func holderControl() []byte {
	return []byte(`{"schema":"swarma-holders-list/1","network":"main","owner":"id/example","seq":3,"holders":[{"name":"id/example-agent","key":"` + holderTestKey + `","seal":{"txid":"` + strings.Repeat("ab", 32) + `","vout":0}}]}`)
}
func holderTestPin(raw []byte) HolderPin {
	sum := sha256.Sum256(raw)
	return HolderPin{Seq: 3, SHA256: hex.EncodeToString(sum[:])}
}
func holderCode(err error) string {
	if err == nil {
		return "ok"
	}
	return err.Error()
}

// TestHoldersDocument proves H1/H2/H5/H6/H10/H53 refuse malformed or mismatched lists with exact codes beside a valid pinned list.
func TestHoldersDocument(t *testing.T) {
	base := holderControl()
	type test struct {
		name, code string
		raw        []byte
		pin        HolderPin
	}
	var cases []test
	add := func(name, before, after string) {
		raw := bytes.Replace(base, []byte(before), []byte(after), 1)
		if bytes.Equal(raw, base) {
			t.Fatal("ineffective test mutation", name)
		}
		cases = append(cases, test{name, "HOLDER_LIST_INVALID", raw, holderTestPin(raw)})
	}
	add("unlisted entry member", `"key":`, `"extra":1,"key":`)
	add("duplicate entry member", `"key":`, `"name":"id/other","key":`)
	add("duplicate list member", `"network":`, `"schema":"swarma-holders-list/1","network":`)
	add("duplicate seal member", `"vout":0`, `"txid":"`+strings.Repeat("cd", 32)+`","vout":0`)
	add("reordered seal", `"txid":"`+strings.Repeat("ab", 32)+`","vout":0`, `"vout":0,"txid":"`+strings.Repeat("ab", 32)+`"`)
	add("unlisted seal member", `"vout":0`, `"vout":0,"label":"x"`)
	add("missing seal vout", `,"vout":0`, ``)
	add("wrong schema", "swarma-holders-list/1", "swarma-device-list/1")
	add("unknown network", `"network":"main"`, `"network":"test"`)
	add("uppercase name", "id/example-agent", "id/Example-agent")
	add("wrong namespace", "id/example-agent", "d/example-agent")
	add("long name", "id/example-agent", "id/"+strings.Repeat("a", 253))
	add("wrong owner pin form", holderTestKey, holderTestKey[2:])
	add("wrong owner pin prefix", holderTestKey, "04"+holderTestKey[2:])
	add("off curve pin", holderTestKey, "02"+strings.Repeat("ff", 32))
	add("uppercase txid", strings.Repeat("ab", 32), strings.Repeat("AB", 32))
	add("short txid", strings.Repeat("ab", 32), strings.Repeat("ab", 31))
	add("whitespace", `,"network"`, `, "network"`)
	add("escaped string", "id/example-agent", `id/\u0065xample-agent`)
	add("non ASCII string", "id/example-agent", "id/examplé-agent")
	for _, seq := range []string{"0", "9007199254740992", "-1", "1.0", "1e2", "01", `"3"`} {
		add("seq "+seq, `"seq":3`, `"seq":`+seq)
	}
	for _, vout := range []string{"4294967296", "-1", "01", "1.0", `"0"`} {
		add("vout "+vout, `"vout":0`, `"vout":`+vout)
	}
	cases = append(cases,
		test{"trailing newline", "HOLDER_LIST_INVALID", append(bytes.Clone(base), '\n'), holderTestPin(append(bytes.Clone(base), '\n'))},
		test{"size before hash", "HOLDER_LIST_INVALID", bytes.Repeat([]byte{'x'}, MaxHoldersListBytes+1), holderTestPin(base)},
		test{"hash before invalid form", "HOLDER_LIST_MISMATCH", []byte(`{}`), holderTestPin(base)},
	)
	for _, binding := range []struct{ name, before, after string }{
		{"other owner", `"owner":"id/example"`, `"owner":"id/other"`},
		{"other network", `"network":"main"`, `"network":"regtest"`},
		{"other sequence", `"seq":3`, `"seq":4`},
	} {
		raw := bytes.Replace(base, []byte(binding.before), []byte(binding.after), 1)
		cases = append(cases, test{binding.name, "HOLDER_LIST_MISMATCH", raw, holderTestPin(raw)})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := VerifyHoldersList(base, holderTestPin(base), "main", "id/example"); err != nil {
				t.Fatal("positive control", err)
			}
			got, err := VerifyHoldersList(tc.raw, tc.pin, "main", "id/example")
			if got != nil || holderCode(err) != tc.code {
				t.Fatalf("got list=%v code=%s; want %s", got != nil, holderCode(err), tc.code)
			}
		})
	}
}

// TestHolderPins proves H8/H9 reject aliases, duplicates and noncompact pins without interpreting unrelated values.
func TestHolderPins(t *testing.T) {
	pin := holderTestPin(holderControl())
	body := string(compactR1(pin))
	base := `{"swarma-holders":` + body + `,"other":{"x":null}}`
	for _, raw := range []string{
		`{"Swarma-Holders":` + body + `}`,
		`{"\u0073warma-holders":` + body + `}`,
		`{"swarma-holderſ":` + body + `}`,
		`{"swarma-holders":` + body + `,"swarma-holders":` + body + `}`,
		`{"swarma-holders":` + body + `,"Swarma-Holders":` + body + `}`,
		strings.Replace(base, `"seq":3`, `"seq":"3"`, 1),
		strings.Replace(base, `"seq":3`, `"seq":0`, 1),
		strings.Replace(base, `"seq":3`, `"seq": 3`, 1),
		strings.Replace(base, body, `{"sha256":"`+pin.SHA256+`","seq":3}`, 1),
	} {
		t.Run(raw[:min(35, len(raw))], func(t *testing.T) {
			if p, err := ReadHolderPin([]byte(base)); err != nil || p == nil || *p != pin {
				t.Fatal("positive control", err)
			}
			if p, err := ReadHolderPin([]byte(raw)); p != nil || err != ErrHolderPinInvalid {
				t.Fatal("alias or malformed pin admitted", err)
			}
		})
	}
	if p, err := ReadHolderPin([]byte(`{"other":{"swarma-holders":` + body + `}}`)); err != nil || p != nil {
		t.Fatal("nested member selected a pin", err)
	}
}

// TestHoldersBoundsAndSets proves exact count/byte bounds, sorted unique names/seals, shared keys, and immutable entry access.
func TestHoldersBoundsAndSets(t *testing.T) {
	var list holdersDocument
	if json.Unmarshal(holderControl(), &list) != nil {
		t.Fatal("fixture")
	}
	entry := list.Holders[0]
	verify := func(raw []byte, want string) *HoldersList {
		t.Helper()
		result, err := VerifyHoldersList(raw, holderTestPin(raw), "main", "id/example")
		if holderCode(err) != want {
			t.Fatalf("got %v, want %s", err, want)
		}
		return result
	}
	for _, count := range []int{0, 1024, 1025} {
		list.Holders = []HolderEntry{}
		for i := range count {
			e := entry
			e.Name = fmt.Sprintf("id/agent-%04d", i)
			e.Seal.Vout = uint32(i)
			list.Holders = append(list.Holders, e)
		}
		want := "ok"
		if count == 1025 {
			// The 1024-entry positive immediately precedes this refusal.
			verify(compactR1(holdersDocument{list.Schema, list.Network, list.Owner, list.Seq, list.Holders[:1024]}), "ok")
			want = "HOLDER_LIST_INVALID"
		}
		verify(compactR1(list), want)
	}
	list.Holders = []HolderEntry{entry, entry}
	list.Holders[1].Name += "-b"
	list.Holders[1].Seal.Vout++
	valid := compactR1(list)
	for _, mutation := range []func(){
		func() { list.Holders[1].Name = list.Holders[0].Name },
		func() { list.Holders[1].Seal = list.Holders[0].Seal },
		func() { list.Holders[0], list.Holders[1] = list.Holders[1], list.Holders[0] },
	} {
		verify(valid, "ok")
		json.Unmarshal(valid, &list)
		mutation()
		verify(compactR1(list), "HOLDER_LIST_INVALID")
	}
	// A valid list of exactly 262144 bytes, without widening the count cap.
	list.Holders = nil
	for i := 0; ; i++ {
		e := entry
		e.Name = fmt.Sprintf("id/%04d-", i) + strings.Repeat("a", 200)
		e.Seal.Vout = uint32(i)
		list.Holders = append(list.Holders, e)
		raw := compactR1(list)
		if len(raw) > MaxHoldersListBytes {
			list.Holders = list.Holders[:len(list.Holders)-1]
			break
		}
	}
	for len(compactR1(list)) < MaxHoldersListBytes {
		for i := range list.Holders {
			if len(list.Holders[i].Name) < 255 {
				list.Holders[i].Name += "a"
				break
			}
		}
	}
	atBound := compactR1(list)
	verify(atBound, "ok")
	verify(append(bytes.Clone(atBound), ' '), "HOLDER_LIST_INVALID")
	h := verify(valid, "ok")
	out := h.Bytes()
	out[0] = 0
	e, ok := h.Entry(entry.Name)
	if !ok {
		t.Fatal("entry not found")
	}
	e.Key = "changed"
	if fresh, _ := h.Entry(entry.Name); fresh.Key != holderTestKey || bytes.Equal(out, h.Bytes()) {
		t.Fatal("mutable holders document")
	}
}

// TestInlineHolders053 proves all 28 inline outcomes (9 valid/19 refused) remain unchanged at the new document profile.
func TestInlineHolders053(t *testing.T) {
	var file struct {
		Values []struct {
			ID, Value string
			Neighbour string `json:"valid_neighbour"`
			Expect    struct{ Outcome string }
		}
	}
	r1Fixture(t, "holders-vectors.json", &file)
	byID := map[string]string{}
	for _, v := range file.Values {
		byID[v.ID] = v.Value
	}
	counts := map[string]int{}
	for _, v := range file.Values {
		t.Run(v.ID, func(t *testing.T) {
			if v.Expect.Outcome != "valid" {
				if _, err := ReadInlineHolders([]byte(byID[v.Neighbour])); err != nil {
					t.Fatal("positive control", err)
				}
			}
			_, err := ReadInlineHolders([]byte(v.Value))
			if (err == nil) != (v.Expect.Outcome == "valid") {
				t.Fatal("inline outcome changed", err)
			}
			counts[v.Expect.Outcome]++
		})
	}
	if len(file.Values) != 28 || counts["valid"] != 9 || counts["refused"] != 19 {
		t.Fatalf("counts: %v", counts)
	}
}
