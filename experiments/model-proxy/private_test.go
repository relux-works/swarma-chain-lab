package modelproxy

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// Frozen f5dfaa70 schemas pin the private registrar and registry bytes.
type legacyCredential struct {
	Bearer   Secret   `json:"bearer"`
	Endpoint Endpoint `json:"endpoint"`
}
type legacyRecord struct {
	Binding  Binding      `json:"binding"`
	Bearer   Secret       `json:"bearer"`
	Phase    string       `json:"phase"`
	Exposure Counts       `json:"exposure"`
	Observed Usage        `json:"observed"`
	Pending  *reservation `json:"pending"`
}
type legacyLedger struct {
	Version int                     `json:"version"`
	Config  string                  `json:"config"`
	High    int64                   `json:"high"`
	Records map[string]legacyRecord `json:"records"`
}

// Equality preserves exact bearer/endpoint value semantics across separate
// allocations; changing either credential material or either pin must disagree.
func TestCredentialValueEquality(t *testing.T) {
	marker := Secret(strings.Repeat("A", 43))
	c := Credential{Bearer: NewBearer(marker), Endpoint: Endpoint{URL: "https://proxy.example", CertSHA256: strings.Repeat("b", 64)}}
	same := Credential{Bearer: NewBearer(marker), Endpoint: c.Endpoint}
	if !c.Equal(same) {
		t.Fatal("independent credential values compare unequal")
	}
	changed := same
	changed.Bearer = NewBearer(Secret(strings.Repeat("B", 43)))
	if c.Equal(changed) {
		t.Fatal("different bearer compares equal")
	}
	changed = same
	changed.Endpoint.URL = "https://other.example"
	if c.Equal(changed) {
		t.Fatal("different endpoint compares equal")
	}
	changed = same
	changed.Endpoint.CertSHA256 = strings.Repeat("c", 64)
	if c.Equal(changed) {
		t.Fatal("different certificate pin compares equal")
	}
}

// Explicit private encoders preserve old credential/record/ledger schemas;
// ordinary JSON encoding cannot expose any retained model bearer.
func TestModelPrivateWireCompatibility(t *testing.T) {
	marker := Secret(strings.Repeat("A", 43))
	ep := Endpoint{URL: "https://proxy.example", CertSHA256: strings.Repeat("b", 64)}
	credential := Credential{Bearer: NewBearer(marker), Endpoint: ep}
	r := record{Bearer: NewBearer(marker), Phase: "prepared"}
	state := ledger{Version: 1, Config: "fixture", High: 1, Records: map[string]record{"fixture": r}}
	for _, tc := range []struct{ current, legacy any }{
		{(*Credential)(nil), (*legacyCredential)(nil)},
		{credential, legacyCredential{Bearer: marker, Endpoint: ep}},
		{r, legacyRecord{Bearer: marker, Phase: "prepared"}},
		{state, legacyLedger{Version: 1, Config: "fixture", High: 1, Records: map[string]legacyRecord{"fixture": {Bearer: marker, Phase: "prepared"}}}},
	} {
		before, err := json.Marshal(tc.legacy)
		if err != nil || !bytes.Equal(before, privateCanonical(tc.current)) {
			t.Fatal("private model wire bytes changed")
		}
		public, err := json.Marshal(tc.current)
		if err != nil || bytes.Contains(public, []byte(marker)) {
			t.Fatal("retained model bearer disclosed by generic JSON")
		}
	}
}
