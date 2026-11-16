package chaingateway

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"testing"
)

// Helper-only corpus decoding. Expected outcomes come from the unchanged shared
// fixtures; the landed external-package harness retains its independent oracles.
type observation struct {
	Name             string              `json:"name"`
	Kind             string              `json:"kind"`
	Attempts         [][]map[string]any  `json:"attempts,omitempty"`
	Expected         map[string]any      `json:"expected,omitempty"`
	Requests         []map[string]any    `json:"requests,omitempty"`
	Responses        []map[string]any    `json:"responses,omitempty"`
	Accepted         bool                `json:"accepted,omitempty"`
	Snapshot         string              `json:"snapshot,omitempty"`
	Now              uint64              `json:"now,omitempty"`
	KnownTip         map[string]any      `json:"known_tip,omitempty"`
	Clock            bool                `json:"clock,omitempty"`
	Label            string              `json:"label,omitempty"`
	Config           map[string]any      `json:"config,omitempty"`
	Rounds           []collectionRound   `json:"rounds,omitempty"`
	History          []map[string]any    `json:"history,omitempty"`
	Decisions        []map[string]any    `json:"decisions,omitempty"`
	Confirmed        map[string]any      `json:"confirmed,omitempty"`
	Mempool          map[string]any      `json:"mempool,omitempty"`
	Claim            string              `json:"claim,omitempty"`
	Control          string              `json:"control,omitempty"`
	LiveTipSource    string              `json:"live_tip_source,omitempty"`
	LagSeconds       *uint64             `json:"lag_seconds,omitempty"`
	Enforceable      *bool               `json:"enforceable,omitempty"`
	ResponseWires    []string            `json:"response_wires,omitempty"`
	HistoryWires     []string            `json:"history_wires,omitempty"`
	SnapshotAttempts []snapshotAttempt   `json:"snapshot_attempts,omitempty"`
	Stage            string              `json:"stage,omitempty"`
	Renamed          *bool               `json:"renamed,omitempty"`
	Admission        *qualificationInput `json:"admission,omitempty"`
	Upstream         *upstreamInput      `json:"upstream,omitempty"`
	Reflection       *reflectionInput    `json:"reflection,omitempty"`
}

type collectionRound struct {
	Requests  []map[string]any `json:"requests"`
	Responses []map[string]any `json:"responses"`
}

type qualificationInput struct {
	Platform       string   `json:"platform"`
	EndpointProof  bool     `json:"endpoint_proof"`
	DumpProtected  bool     `json:"dump_protected"`
	NodeUID        uint32   `json:"node_uid"`
	ServerUID      uint32   `json:"server_uid"`
	AllowedUIDs    []uint32 `json:"allowed_uids"`
	WorkloadUIDs   []uint32 `json:"workload_uids"`
	Dedicated      bool     `json:"dedicated"`
	InitialUser    bool     `json:"initial_user"`
	InitialNetwork bool     `json:"initial_network"`
	LoopbackBind   bool     `json:"loopback_bind"`
	LoopbackAllow  bool     `json:"loopback_allow"`
}

type snapshotAttempt struct {
	Before      map[string]any   `json:"before,omitempty"`
	After       map[string]any   `json:"after,omitempty"`
	BeforeReply map[string]any   `json:"before_reply,omitempty"`
	AfterReply  map[string]any   `json:"after_reply,omitempty"`
	Requests    []map[string]any `json:"requests,omitempty"`
	Replies     []map[string]any `json:"replies,omitempty"`
	ReplyWires  []string         `json:"reply_wires,omitempty"`
	Bestblocks  []string         `json:"bestblocks,omitempty"`
	Failure     string           `json:"failure,omitempty"`
}

type reflectionInput struct {
	Mode   string `json:"mode"`
	User   string `json:"user"`
	Secret string `json:"secret"`
	Value  string `json:"value"`
}

func observations(t *testing.T) []observation {
	t.Helper()
	b, e := os.ReadFile("fixtures/observations.json")
	if e != nil {
		t.Fatal(e)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	d.UseNumber()
	var vs []observation
	if e = d.Decode(&vs); e != nil {
		t.Fatal(e)
	}
	if _, e = d.Token(); e != io.EOF {
		t.Fatal("trailing helper fixture data")
	}
	seen := map[string]bool{}
	for _, v := range vs {
		if v.Name == "" || seen[v.Name] {
			t.Fatal("missing or duplicate helper fixture")
		}
		seen[v.Name] = true
	}
	for _, v := range vs {
		if v.Control != "" && !seen[v.Control] {
			t.Fatal("missing helper fixture control")
		}
	}
	return vs
}
func wire(v any) []byte  { b, _ := json.Marshal(v); return b }
func same(a, b any) bool { return bytes.Equal(wire(a), wire(b)) }
