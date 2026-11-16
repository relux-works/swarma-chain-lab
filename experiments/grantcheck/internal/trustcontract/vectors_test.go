package trustcontract

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

const vectorPath = "testdata/trust-vectors.json"

// vectorSHA256 pins the committed file. testdata/README.md states how it is
// copied verbatim from the upstream file.
const vectorSHA256 = "9c29cddd739d56c5d15f4663c3cc923c6ea016730fc62634bff4b4214bf27ff8"

type vectorFile struct {
	Schema   string `json:"schema"`
	LIP      string `json:"lip"`
	Note     string `json:"note"`
	TestKeys []struct {
		Name      string `json:"name"`
		Source    string `json:"source"`
		PublicKey string `json:"public_key"`
	} `json:"test_keys"`
	ValidContracts []struct {
		ID          string     `json:"id"`
		Claim       string     `json:"claim"`
		Contract    string     `json:"contract"`
		ContractHex string     `json:"contract_hex"`
		SHA256      string     `json:"sha256"`
		Scope       []string   `json:"v3_scope"`
		Budget      int64      `json:"v3_budget"`
		ConsentTags [][]string `json:"consent_tags"`
	} `json:"valid_contracts"`
	InvalidContracts []struct {
		ID       string `json:"id"`
		Claim    string `json:"claim"`
		Contract string `json:"contract"`
		Expect   string `json:"expect"`
	} `json:"invalid_contracts"`
	Bindings []struct {
		ID          string `json:"id"`
		Claim       string `json:"claim"`
		ContractRef string `json:"contract_ref"`
		Grant       Grant  `json:"grant"`
		Expect      string `json:"expect"`
	} `json:"bindings"`
	Envelopes      []json.RawMessage `json:"envelopes"` // kind-8185 admission is outside this module.
	EnvelopeGrants []struct {
		GrantID     string `json:"grant_id"`
		ContractRef string `json:"contract_ref"`
		Grant       Grant  `json:"grant"`
	} `json:"envelope_grants"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatal(err)
	}
	var file vectorFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		t.Fatal(err)
	}
	return file
}

func validContracts(t *testing.T, file vectorFile) map[string][]byte {
	t.Helper()
	contracts := map[string][]byte{}
	for _, v := range file.ValidContracts {
		if _, dup := contracts[v.ID]; dup || v.ID == "" {
			t.Fatalf("vector id %q is empty or repeated", v.ID)
		}
		contracts[v.ID] = []byte(v.Contract)
	}
	return contracts
}

// Claim: the committed vector file is the pinned one, and it holds every
// contract vector of LIP-0013: 4 valid, 32 invalid, 15 bindings and the 3
// grants of the envelope section. A changed, shortened or replaced file fails
// here, so no later test can pass on fewer vectors.
func TestVectorFilePinned(t *testing.T) {
	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := sha256Hex(raw); got != vectorSHA256 {
		t.Fatalf("vector file sha256 %s, want %s", got, vectorSHA256)
	}
	record, err := os.ReadFile(vectorPath + ".sha256")
	if err != nil {
		t.Fatal(err)
	}
	if fields := strings.Fields(string(record)); len(fields) != 2 || fields[0] != vectorSHA256 || fields[1] != "trust-vectors.json" {
		t.Fatalf("recorded sha256 line %q does not name the pinned file", record)
	}
	file := loadVectors(t)
	if file.Schema != "swarma-link-spec/lip-0013-vectors/1" || file.LIP != "LIP-0013" {
		t.Fatalf("schema %q of %q", file.Schema, file.LIP)
	}
	if len(file.ValidContracts) != 4 || len(file.InvalidContracts) != 32 || len(file.Bindings) != 15 || len(file.EnvelopeGrants) != 3 || len(file.Envelopes) != 26 {
		t.Fatalf("vector counts %d/%d/%d/%d, want 4/32/15/3", len(file.ValidContracts), len(file.InvalidContracts), len(file.Bindings), len(file.EnvelopeGrants))
	}
	for _, k := range file.TestKeys {
		if !isPubkey(k.PublicKey) {
			t.Fatalf("test key %s is no x-only key", k.Name)
		}
	}
}

// Claim: every valid LIP-0013 contract vector is accepted with its exact
// bytes: the hex equals the string, the profile /1 parser and the reader of
// both profiles accept, re-encoding gives the identical octets, and the
// SHA-256, the derived v3 scope, the budget and the consent tags are the
// published ones.
func TestLIP0013ValidContracts(t *testing.T) {
	file := loadVectors(t)
	for _, v := range file.ValidContracts {
		t.Run(v.ID, func(t *testing.T) {
			raw := []byte(v.Contract)
			if decoded, err := hex.DecodeString(v.ContractHex); err != nil || !bytes.Equal(decoded, raw) {
				t.Fatal("contract_hex is not the contract bytes")
			}
			c, code := ParseV1(raw)
			if code != "" {
				t.Fatalf("ParseV1 refused a valid contract: %s", code)
			}
			if !bytes.Equal(compact(c), raw) {
				t.Fatal("re-encoding does not give the exact bytes")
			}
			terms, code := Parse(raw)
			if code != "" || terms.Profile != ProfileV1 || terms.DelegateDepth != 0 || terms.ParentGrantID != "" || terms.Ordinal != 0 {
				t.Fatalf("Parse: code %q, terms %+v", code, terms)
			}
			if sha256Hex(raw) != v.SHA256 {
				t.Fatalf("sha256 %s, want %s", sha256Hex(raw), v.SHA256)
			}
			if v.Scope == nil || !slices.Equal(V3Scope(c.Actions), v.Scope) {
				t.Fatalf("derived scope %v, want %v", V3Scope(c.Actions), v.Scope)
			}
			if c.SpendBudget != v.Budget {
				t.Fatalf("budget %d, want %d", c.SpendBudget, v.Budget)
			}
			if !bytes.Equal(compact(ConsentTags(raw)), compact(v.ConsentTags)) {
				t.Fatal("consent tags differ from the published ones")
			}
		})
	}
}

// Claim: every invalid LIP-0013 contract vector is refused with its published
// section 2.3 code, by the profile /1 parser and by the reader of both
// profiles, and it never binds to a grant even when the grant commits to its
// exact bytes. An empty expectation is no pass. The valid controls are the
// vectors of TestLIP0013ValidContracts, each one defect away.
func TestLIP0013InvalidContracts(t *testing.T) {
	file := loadVectors(t)
	seen := map[string]bool{}
	for _, v := range file.InvalidContracts {
		t.Run(v.ID, func(t *testing.T) {
			if v.Expect == "" || seen[v.ID] {
				t.Fatal("vector has no expectation or a repeated id")
			}
			seen[v.ID] = true
			raw := []byte(v.Contract)
			if _, code := ParseV1(raw); code != v.Expect {
				t.Fatalf("ParseV1 gave %q, want %q", code, v.Expect)
			}
			if _, code := Parse(raw); code != v.Expect {
				t.Fatalf("Parse gave %q, want %q", code, v.Expect)
			}
			if _, code := Bind(raw, Grant{ContractSHA256: sha256Hex(raw), Scope: []string{}}); code != v.Expect {
				t.Fatalf("Bind gave %q, want %q", code, v.Expect)
			}
		})
	}
}

// Claim: every LIP-0013 binding vector gives its published section 2.5
// outcome: the four matching grants bind, and each of the eleven defects
// refuses with its code. The three grants of the envelope section, which the
// upstream checker binds at admission step 6d, bind as well.
func TestLIP0013Bindings(t *testing.T) {
	file := loadVectors(t)
	contracts := validContracts(t, file)
	for _, v := range file.Bindings {
		t.Run(v.ID, func(t *testing.T) {
			raw, ok := contracts[v.ContractRef]
			if !ok || v.Expect == "" {
				t.Fatal("vector names no valid contract or no expectation")
			}
			_, code := Bind(raw, v.Grant)
			if code == "" {
				code = "OK"
			}
			if code != v.Expect {
				t.Fatalf("Bind gave %q, want %q", code, v.Expect)
			}
		})
	}
	for _, v := range file.EnvelopeGrants {
		t.Run("envelope-grant-"+v.ContractRef, func(t *testing.T) {
			raw, ok := contracts[v.ContractRef]
			if !ok {
				t.Fatal("grant names no valid contract")
			}
			if terms, code := Bind(raw, v.Grant); code != "" || terms.Profile != ProfileV1 {
				t.Fatalf("Bind gave %q", code)
			}
		})
	}
}
