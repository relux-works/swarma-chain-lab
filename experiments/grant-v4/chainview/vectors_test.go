package chainview

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

const vectorSHA256 = "5f6b4c735b6e519c892518e0ade689f4055e211aa4693f2b6ca93858e756518c"

type nodeVector struct {
	Source  string           `json:"source_label"`
	Answers bool             `json:"answers"`
	Genesis string           `json:"genesis_hash"`
	IBD     bool             `json:"initial_block_download"`
	Headers int64            `json:"headers_above_tip"`
	Height  int64            `json:"tip_height"`
	Hash    string           `json:"tip_hash"`
	Chain   map[int64]string `json:"active_chain"`
}

func (n nodeVector) node() Node {
	return Node{SourceLabel: n.Source, Answers: n.Answers, GenesisHash: n.Genesis, InitialBlockDownload: n.IBD, HeadersAboveTip: n.Headers, Tip: Tip{n.Height, n.Hash}}
}

type vector struct {
	ID            string           `json:"id"`
	Claim         string           `json:"claim"`
	Expect        string           `json:"expect"`
	Neighbour     string           `json:"valid_neighbour"`
	Compound      bool             `json:"compound"`
	Control       string           `json:"control"`
	Rules         []string         `json:"rules"`
	PinnedGenesis string           `json:"pinned_genesis_hash"`
	Genesis       string           `json:"genesis_hash"`
	First         Tip              `json:"first_tip"`
	Last          Tip              `json:"last_tip"`
	EffectTip     *Tip             `json:"tip_before_effect"`
	TipHeight     int64            `json:"tip_height"`
	ActiveChain   map[int64]string `json:"active_chain"`
	BlockHeight   *int64           `json:"block_height"`
	BlockHash     string           `json:"block_hash"`
	Holds         bool             `json:"block_holds_transaction"`
	Lag           int64            `json:"lag"`
	Reading       nodeVector       `json:"reading_node"`
	Comparisons   []nodeVector     `json:"comparison_nodes"`
	S             int64            `json:"s"`
	Now           int64            `json:"now"`
	KeptMark      int64            `json:"kept_mark"`
	HeaderTime    int64            `json:"tip_header_time"`
	FirstSight    *int64           `json:"first_sight"`
	Class         ActionClass      `json:"class"`
	EffectNow     *int64           `json:"now_before_effect"`
	Start         ClockState       `json:"start"`
	End           ClockState       `json:"end"`
	Steps         []sequenceStep   `json:"steps"`
	K             int64            `json:"k"`
	RecentHash    string           `json:"committed_block_hash"`
	RecentHeight  *int64           `json:"committed_block_height"`
	AnchorHeight  int64            `json:"anchor_height"`
	WindowRecent  int64            `json:"recent_block_height"`
	NotBefore     int64            `json:"not_before_height"`
	NotAfter      int64            `json:"not_after_height"`
	Chain         string           `json:"chain"`
	SignedMinimum int64            `json:"signed_minimum"`
	OperatorFloor int64            `json:"operator_floor"`
	Evidence      struct {
		Chain  string `json:"chain"`
		Height *int64 `json:"block_height"`
	} `json:"evidence"`
	Findings []Code `json:"findings"`
}

type sequenceStep struct {
	Restart bool  `json:"restart"`
	Now     int64 `json:"now"`
	Tip     struct {
		Hash       string `json:"hash"`
		HeaderTime int64  `json:"header_time"`
	} `json:"tip"`
	Class   ActionClass `json:"class"`
	Finding Code        `json:"finding"`
	Expect  string      `json:"expect"`
}

type vectorFile struct {
	Schema     string `json:"schema"`
	Parameters struct {
		Pin   string `json:"pinned_genesis_hash"`
		S     int64  `json:"s_seconds"`
		Lag   int64  `json:"lag_blocks"`
		K     int64  `json:"k_blocks"`
		Money int64  `json:"cutoff_money_or_irreversible_seconds"`
		Other int64  `json:"cutoff_other_privileged_seconds"`
	} `json:"parameters"`
	Rules []struct {
		ID    string `json:"id"`
		State string `json:"state"`
	} `json:"rules"`
	Observations struct {
		Readings []vector `json:"readings"`
		Facts    []vector `json:"facts"`
	} `json:"observations"`
	Nodes     []vector `json:"nodes"`
	Clock     []vector `json:"clock"`
	Sequences []vector `json:"sequences"`
	Recent    struct {
		Blocks  []vector `json:"blocks"`
		Windows []vector `json:"windows"`
	} `json:"recent"`
	Depth []vector `json:"depth"`
	Order []vector `json:"order"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	data, err := os.ReadFile("testdata/observation-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(data)
	if hex.EncodeToString(hash[:]) != vectorSHA256 {
		t.Fatal("pinned vector bytes changed")
	}
	var f vectorFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	if f.Schema != "swarma-link-spec/lip-0022-vectors/1" || len(f.Rules) != 28 {
		t.Fatal("vector inventory changed")
	}
	return f
}

func (f vectorFile) parameters() Parameters {
	return Parameters{f.Parameters.Pin, f.Parameters.S, f.Parameters.Lag, f.Parameters.K, f.Parameters.Money, f.Parameters.Other}
}

type vectorResult struct {
	Verdict string      `json:"verdict,omitempty"`
	Steps   []string    `json:"steps,omitempty"`
	End     *ClockState `json:"end,omitempty"`
}

func verdict(code Code) string {
	if code == "" {
		return "ok"
	}
	return string(code)
}

func evaluateVector(t *testing.T, group string, v vector, p Parameters) vectorResult {
	t.Helper()
	var code Code
	switch group {
	case "readings":
		code = CheckObservation(v.PinnedGenesis, Observation{GenesisHash: v.Genesis, FirstTip: v.First, LastTip: v.Last, TipBeforeEffect: v.EffectTip})
	case "facts":
		if FactBelongs(v.TipHeight, v.ActiveChain, v.BlockHeight, v.BlockHash, v.Holds) {
			return vectorResult{Verdict: "belongs"}
		}
		return vectorResult{Verdict: "does not belong"}
	case "nodes":
		comparisons := make([]Node, len(v.Comparisons))
		for i, n := range v.Comparisons {
			comparisons[i] = n.node()
		}
		code = CheckHealth(p.PinnedGenesis, v.Lag, v.Reading.node(), comparisons, v.Reading.Chain)
	case "clock":
		p.SkewSeconds = v.S
		state := ClockState{KeptMark: v.KeptMark, FirstSights: map[string]int64{}}
		if v.FirstSight != nil {
			state.FirstSights["tip"] = *v.FirstSight
		}
		store, err := NewMemoryStore(state)
		if err != nil {
			t.Fatal(err)
		}
		clock, err := NewClock(p, store)
		if err != nil {
			t.Fatal(err)
		}
		code, err = clock.Observe(ClockInput{TipHash: "tip", Now: v.Now, HeaderTime: v.HeaderTime, Class: v.Class})
		if err != nil {
			t.Fatal(err)
		}
		if code == "" && v.EffectNow != nil {
			code, err = clock.Observe(ClockInput{TipHash: "tip", Now: *v.EffectNow, HeaderTime: v.HeaderTime, Class: v.Class})
			if err != nil {
				t.Fatal(err)
			}
		}
	case "sequences":
		memory := evaluateSequence(t, v, p, false)
		file := evaluateSequence(t, v, p, true)
		if !reflect.DeepEqual(memory, file) {
			t.Fatalf("store implementations disagree: memory=%+v file=%+v", memory, file)
		}
		return file
	case "blocks":
		code = CheckRecent(v.TipHeight, v.ActiveChain, v.RecentHeight, v.RecentHash, v.AnchorHeight, v.K)
	case "windows":
		if WindowAllows(v.WindowRecent, v.NotBefore, v.NotAfter, v.TipHeight) {
			return vectorResult{Verdict: "admit"}
		}
		return vectorResult{Verdict: "refuse"}
	case "depth":
		code = CheckDepth(v.Chain, v.Evidence.Chain, v.TipHeight, v.Evidence.Height, v.SignedMinimum, v.OperatorFloor)
	case "order":
		var err error
		code, err = FirstRefusal(v.Findings...)
		if err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("unhandled vector group", group)
	}
	return vectorResult{Verdict: verdict(code)}
}

func evaluateSequence(t *testing.T, v vector, p Parameters, fileBacked bool) vectorResult {
	t.Helper()
	p.SkewSeconds = v.S
	var store ClockStore
	var err error
	path := filepath.Join(t.TempDir(), "clock.json")
	if fileBacked {
		store, err = CreateFileStore(path, v.Start)
	} else {
		store, err = NewMemoryStore(v.Start)
	}
	if err != nil {
		t.Fatal(err)
	}
	clock, err := NewClock(p, store)
	if err != nil {
		t.Fatal(err)
	}
	result := vectorResult{Steps: []string{}}
	for i, step := range v.Steps {
		if step.Restart {
			if fileBacked {
				store, err = OpenFileStore(path)
				if err != nil {
					t.Fatal(err)
				}
			}
			clock, err = NewClock(p, store)
			if err != nil {
				t.Fatal(err)
			}
			result.Steps = append(result.Steps, "restart")
			continue
		}
		code, err := clock.Observe(ClockInput{TipHash: step.Tip.Hash, Now: step.Now, HeaderTime: step.Tip.HeaderTime, Class: step.Class, Findings: []Code{step.Finding}})
		if err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		result.Steps = append(result.Steps, verdict(code))
	}
	state, err := ReadClockState(store)
	if err != nil {
		t.Fatal(err)
	}
	result.End = &state
	return result
}

func expectedVector(v vector, group string) vectorResult {
	if group != "sequences" {
		return vectorResult{Verdict: v.Expect}
	}
	r := vectorResult{End: &v.End, Steps: []string{}}
	for _, s := range v.Steps {
		if s.Restart {
			r.Steps = append(r.Steps, "restart")
		} else {
			r.Steps = append(r.Steps, s.Expect)
		}
	}
	return r
}

// TestV4ObservationVectors checks all 97 pinned comparisons, paired neighbours
// and sequence end states in both stores; it does not qualify reads on a node.
func TestV4ObservationVectors(t *testing.T) {
	f := loadVectors(t)
	groups := []struct {
		name string
		rows []vector
	}{
		{"readings", f.Observations.Readings}, {"facts", f.Observations.Facts}, {"nodes", f.Nodes},
		{"clock", f.Clock}, {"sequences", f.Sequences}, {"blocks", f.Recent.Blocks},
		{"windows", f.Recent.Windows}, {"depth", f.Depth}, {"order", f.Order},
	}
	all := map[string]vector{}
	for _, g := range groups {
		for _, v := range g.rows {
			if _, exists := all[v.ID]; exists || v.ID == "" || v.Claim == "" {
				t.Fatal("missing or duplicate vector identity/claim", v.ID)
			}
			all[v.ID] = v
		}
	}
	if len(all) != 97 {
		t.Fatalf("got %d vectors, want 97", len(all))
	}
	results := map[string]vectorResult{}
	for _, g := range groups {
		for _, v := range g.rows {
			t.Run(v.ID, func(t *testing.T) {
				t.Log(v.Claim)
				if v.Neighbour != "" {
					n, ok := all[v.Neighbour]
					if !ok || !(n.Expect == "ok" || n.Expect == "belongs" || n.Expect == "admit") {
						t.Fatal("missing passing neighbour")
					}
					t.Run("beside-"+n.ID, func(t *testing.T) {
						got := evaluateVector(t, g.name, n, f.parameters())
						if !reflect.DeepEqual(got, expectedVector(n, g.name)) {
							t.Fatalf("neighbour: %+v", got)
						}
					})
				} else if g.name != "sequences" && !v.Compound && v.Expect != "ok" && v.Expect != "belongs" && v.Expect != "admit" {
					t.Fatal("refused vector has no neighbour")
				}
				if v.Control != "" {
					control, ok := all[v.Control]
					if !ok || len(control.Steps) == 0 {
						t.Fatal("missing sequence control")
					}
				}
				got := evaluateVector(t, g.name, v, f.parameters())
				results[v.ID] = got
				if want := expectedVector(v, g.name); !reflect.DeepEqual(got, want) {
					t.Errorf("got %+v, want %+v", got, want)
				}
			})
		}
	}
	if output := os.Getenv("CHAINVIEW_VECTOR_RESULTS"); output != "" {
		data, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(output, append(data, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
