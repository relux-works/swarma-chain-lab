package lifecycle

import (
	"bytes"
	"encoding/json"
	"testing"
)

// Frozen f5dfaa70 schemas pin retained private bytes and protocol field order.
type legacySlot struct {
	Version       int    `json:"version"`
	ID            string `json:"slot"`
	GrantID       string `json:"grant_id"`
	NotBefore     int64  `json:"not_before"`
	NotAfter      int64  `json:"not_after"`
	PayloadID     string `json:"payload_id"`
	PayloadSHA256 string `json:"payload_sha256"`
	Bootstrap     Secret `json:"bootstrap"`
}
type legacyBrokerRecord struct {
	Key           string     `json:"key"`
	Credential    Secret     `json:"credential"`
	Slot          legacySlot `json:"slot"`
	BootstrapHash string     `json:"bootstrap_hash"`
	Binding       string     `json:"binding"`
	Desired       string     `json:"desired"`
	Result        Status     `json:"result"`
}
type legacyBrokerState struct {
	Version int                           `json:"version"`
	Config  string                        `json:"config"`
	High    int64                         `json:"high"`
	Records map[string]legacyBrokerRecord `json:"records"`
}
type legacyRecord struct {
	ID             string       `json:"id"`
	StartAttempted bool         `json:"start_attempted"`
	CreateFence    *CreateFence `json:"create_fence,omitempty"`
	Slot           *legacySlot  `json:"slot"`
	BootstrapHash  string       `json:"bootstrap_hash"`
	Binding        string       `json:"binding"`
	Phase          string       `json:"phase"`
	Reason         string       `json:"reason"`
}
type legacyState struct {
	Version int                     `json:"version"`
	Policy  string                  `json:"policy"`
	High    int64                   `json:"high"`
	Records map[string]legacyRecord `json:"records"`
}
type legacyCommand struct {
	Op      string     `json:"op"`
	Slot    legacySlot `json:"slot"`
	Binding string     `json:"binding"`
}
type legacyPollResponse struct {
	Version  int             `json:"version"`
	Commands []legacyCommand `json:"commands"`
}

// The private slot, broker/manager state and poll transport bytes stay exactly
// equal to their former schemas, including nil and empty collections.
func TestLifecyclePrivateWireCompatibility(t *testing.T) {
	raw := Secret(bytes.Repeat([]byte("x"), 32))
	s := Slot{Version: 1, ID: "1", Bootstrap: NewPrivateBytes(raw)}
	old := legacySlot{Version: 1, ID: "1", Bootstrap: raw}
	r := brokerRecord{Key: "fixture", Credential: NewPrivateBytes(raw), Slot: s}
	oldr := legacyBrokerRecord{Key: "fixture", Credential: raw, Slot: old}
	for _, tc := range []struct{ current, legacy any }{
		{(*Slot)(nil), (*legacySlot)(nil)},
		{s, old},
		{brokerState{Version: 1, Records: map[string]brokerRecord{"fixture": r}}, legacyBrokerState{Version: 1, Records: map[string]legacyBrokerRecord{"fixture": oldr}}},
		{state{Version: 1, Records: map[string]record{"fixture": {Slot: &s}}}, legacyState{Version: 1, Records: map[string]legacyRecord{"fixture": {Slot: &old}}}},
		{PollResponse{Version: 1, Commands: []Command{{Op: "start", Slot: s}}}, legacyPollResponse{Version: 1, Commands: []legacyCommand{{Op: "start", Slot: old}}}},
		{brokerState{Version: 1}, legacyBrokerState{Version: 1}},
		{PollResponse{Version: 1}, legacyPollResponse{Version: 1}},
	} {
		before, err := json.Marshal(tc.legacy)
		if err != nil || !bytes.Equal(before, privateCanonical(tc.current)) {
			t.Fatal("private lifecycle bytes changed")
		}
		public, err := json.Marshal(tc.current)
		if err != nil || bytes.Contains(public, []byte("eHh4eHh4")) {
			t.Fatal("retained lifecycle bytes disclosed by generic JSON")
		}
	}
}
