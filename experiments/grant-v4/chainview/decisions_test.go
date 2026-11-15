package chainview

import (
	"math"
	"reflect"
	"testing"
)

func labParameters() Parameters { return Parameters{"genesis", 17, 3, 9, 100, 150} }
func height(h int64) *int64     { return &h }
func mustMemory(t *testing.T, state ClockState) *MemoryStore {
	t.Helper()
	s, err := NewMemoryStore(state)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func mustClock(t *testing.T, p Parameters, s ClockStore) *Clock {
	t.Helper()
	c, err := NewClock(p, s)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func mustState(t *testing.T, s ClockStore) ClockState {
	t.Helper()
	r, err := ReadClockState(s)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func wantCode(t *testing.T, got, want Code) {
	t.Helper()
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// TestV4DualTimeAndRisk proves each age independently stops at its supplied
// cutoff, including the default class; it does not classify real actions.
func TestV4DualTimeAndRisk(t *testing.T) {
	p := labParameters()
	for _, class := range []ActionClass{"", MoneyOrIrreversible, OtherPrivileged, "unknown"} {
		cutoff := p.MoneyAgeSeconds
		if class == OtherPrivileged {
			cutoff = p.OtherAgeSeconds
		}
		for _, delta := range []int64{-1, 0, 1} {
			age := cutoff + delta
			want := Code("")
			if delta >= 0 {
				want = TipAge
			}
			// Exercise the header alone and the seen age alone, with the other fresh.
			wantCode(t, CheckClock(p, 1000, 1000, 1000-age, 1000, class), want)
			wantCode(t, CheckClock(p, 1000, 1000, 1000+p.SkewSeconds, 1000-age, class), want)
		}
	}
	// Raising an explicit threshold changes the decision; no production default intervenes.
	p.MoneyAgeSeconds = 101
	wantCode(t, CheckClock(p, 1000, 1000, 900, 1000, MoneyOrIrreversible), "")
}

// TestV4ClockBoundaries proves skew and rollback triplets on nonproduction
// parameters, including the effect-clock reread; it does not assess UTC quality.
func TestV4ClockBoundaries(t *testing.T) {
	p := labParameters()
	for _, delta := range []int64{-1, 0, 1} {
		want := Code("")
		if delta > 0 {
			want = ObservationClock
		}
		wantCode(t, CheckClock(p, 1000, 1000, 1000+p.SkewSeconds+delta, 1000, ""), want)
		want = ""
		if delta < 0 {
			want = ObservationClock
		}
		wantCode(t, CheckClock(p, 1000+delta, 1000, 990, 990, ""), want)
	}
	s := mustMemory(t, ClockState{1000, map[string]int64{"tip": 1000}})
	c := mustClock(t, p, s)
	for _, now := range []int64{1099, 1100, 1101} {
		got, err := c.Observe(ClockInput{TipHash: "tip", Now: now, HeaderTime: 1000})
		if err != nil {
			t.Fatal(err)
		}
		want := Code("")
		if now >= 1100 {
			want = TipAge
		}
		wantCode(t, got, want)
	}
	if got := mustState(t, s).KeptMark; got != 1099 {
		t.Fatalf("refusal advanced mark: %d", got)
	}
}

// TestV4ClockRollback proves below-mark readings preserve the mark and all
// sightings, for known and new tips, while equal and higher readings pass.
func TestV4ClockRollback(t *testing.T) {
	initial := ClockState{1000, map[string]int64{"old": 990}}
	s := mustMemory(t, initial)
	c := mustClock(t, labParameters(), s)
	for _, hash := range []string{"old", "new"} {
		code, err := c.Observe(ClockInput{TipHash: hash, Now: 999, HeaderTime: 999})
		if err != nil {
			t.Fatal(err)
		}
		wantCode(t, code, ObservationClock)
		if got := mustState(t, s); !reflect.DeepEqual(got, initial) {
			t.Fatalf("rollback wrote state: %+v", got)
		}
	}
	for _, now := range []int64{1000, 1001} {
		code, err := c.Observe(ClockInput{TipHash: "new", Now: now, HeaderTime: 1000})
		if err != nil {
			t.Fatal(err)
		}
		wantCode(t, code, "")
	}
	if got := mustState(t, s); got.KeptMark != 1001 || got.FirstSights["new"] != 1000 {
		t.Fatal(got)
	}
}

// TestV4ObservationMovement proves a stated move-and-return is void and fact
// membership is tip-bounded; endpoint equality alone still misses hidden moves.
func TestV4ObservationMovement(t *testing.T) {
	tip := Tip{800, "tip"}
	o := Observation{GenesisHash: "genesis", FirstTip: tip, LastTip: tip}
	wantCode(t, CheckObservation("genesis", o), "")
	o.MovementObserved = true
	wantCode(t, CheckObservation("genesis", o), ObservationVoid)
	o.GenesisHash = "other"
	wantCode(t, CheckObservation("genesis", o), ObservationChain)
	o.GenesisHash = "genesis"
	o.MovementObserved = false
	effect := Tip{801, "next"}
	o.TipBeforeEffect = &effect
	wantCode(t, CheckObservation("genesis", o), ObservationVoid)
	chain := map[int64]string{799: "previous", 800: "tip", 801: "next"}
	for _, h := range []int64{799, 800, 801} {
		if got := FactBelongs(800, chain, &h, chain[h], true); got != (h <= 800) {
			t.Fatalf("height %d membership %t", h, got)
		}
	}
	if FactBelongs(800, chain, height(800), "orphan", true) || FactBelongs(800, chain, height(800), "tip", false) || FactBelongs(800, chain, nil, "tip", true) {
		t.Fatal("unproved fact belongs")
	}
}

// TestV4NodeSources proves two endpoint URLs under one source do not establish
// independence, and a healthy conflict cannot be outvoted or hidden by order.
func TestV4NodeSources(t *testing.T) {
	r := Node{SourceLabel: "source-a", Endpoint: "https://one.example.test", Answers: true, GenesisHash: "genesis", Tip: Tip{10, "tip"}}
	c := r
	c.Endpoint = "https://two.example.test"
	chain := map[int64]string{10: "tip", 9: "previous"}
	wantCode(t, CheckHealth("genesis", 1, r, []Node{c}, chain), NodeUnhealthy)
	c.SourceLabel = "source-b"
	wantCode(t, CheckHealth("genesis", 1, r, []Node{c}, chain), "")
	bad := r
	bad.Tip = Tip{11, "ahead"}
	for _, nodes := range [][]Node{{bad, c}, {c, bad}} {
		wantCode(t, CheckHealth("genesis", 1, r, nodes, chain), NodeDisagreement)
	}
	bad.InitialBlockDownload = true
	wantCode(t, CheckHealth("genesis", 1, r, []Node{bad, c}, chain), "")
}

// TestV4HealthBoundaries proves LAG-1/LAG/LAG+1 for known headers and comparison
// lag, on a stated branch; it does not validate node provisioning or peer sets.
func TestV4HealthBoundaries(t *testing.T) {
	r := Node{SourceLabel: "a", Answers: true, GenesisHash: "genesis", Tip: Tip{10, "tip"}}
	c := r
	c.SourceLabel = "b"
	chain := map[int64]string{6: "six", 7: "seven", 8: "eight", 10: "tip"}
	for _, n := range []int64{2, 3, 4} {
		x := r
		x.HeadersAboveTip = n
		want := Code("")
		if n > 3 {
			want = NodeUnhealthy
		}
		wantCode(t, CheckHealth("genesis", 3, x, []Node{c}, chain), want)
		x = c
		x.HeadersAboveTip = n
		wantCode(t, CheckHealth("genesis", 3, r, []Node{x}, chain), want)
		x = c
		x.Tip = Tip{10 - n, chain[10-n]}
		want = ""
		if n > 3 {
			want = NodeDisagreement
		}
		wantCode(t, CheckHealth("genesis", 3, r, []Node{x}, chain), want)
	}
}

// TestV4RecentBoundaries proves K and strict anchor-above-R triplets, orphan
// refusal and chain-relative recomputation; it assumes anchor membership proved.
func TestV4RecentBoundaries(t *testing.T) {
	chain := map[int64]string{100: "recent"}
	for _, distance := range []int64{-1, 0, 1, 8, 9, 10} {
		want := Code("")
		if distance <= 0 || distance > 9 {
			want = RecentBlockWindow
		}
		wantCode(t, CheckRecent(200, chain, height(100), "recent", 100+distance, 9), want)
	}
	wantCode(t, CheckRecent(200, chain, height(100), "orphan", 101, 9), RecentBlock)
	chain[100] = "replacement"
	wantCode(t, CheckRecent(200, chain, height(100), "recent", 101, 9), RecentBlock)
	chain[100] = "recent"
	wantCode(t, CheckRecent(200, chain, height(100), "recent", 101, 9), "")
	// Arithmetic stays bounded at the largest representable height.
	wantCode(t, CheckRecent(math.MaxInt64, map[int64]string{math.MaxInt64 - 1: "recent"}, height(math.MaxInt64-1), "recent", math.MaxInt64, 9), "")
}

// TestV4DepthMaximum proves both asymmetric minima, each threshold triplet,
// pending/cross-chain refusal and overflow-safe arithmetic on stated heights.
func TestV4DepthMaximum(t *testing.T) {
	for _, limits := range [][2]int64{{3, 6}, {6, 3}, {6, 6}} {
		for _, depth := range []int64{5, 6, 7} {
			want := Code("")
			if depth < 6 {
				want = Confirmations
			}
			wantCode(t, CheckDepth("chain", "chain", 100, height(101-depth), limits[0], limits[1]), want)
		}
	}
	wantCode(t, CheckDepth("chain", "chain", 100, nil, 1, 1), Confirmations)
	wantCode(t, CheckDepth("chain", "other", 100, height(0), 1, 1), Confirmations)
	wantCode(t, CheckDepth("chain", "chain", 100, height(101), 1, 1), Confirmations)
	wantCode(t, CheckDepth("chain", "chain", math.MaxInt64, height(0), math.MaxInt64, 1), "")
}

// TestV4WindowBoundaries proves half-open height bounds and no backdating at
// their neighbouring heights; it does not claim any wall-clock validity window.
func TestV4WindowBoundaries(t *testing.T) {
	for _, row := range []struct {
		r, b, e, h int64
		want       bool
	}{
		{50, 60, 70, 59, false}, {50, 60, 70, 60, true}, {50, 60, 70, 61, true},
		{50, 60, 70, 69, true}, {50, 60, 70, 70, false}, {50, 60, 70, 71, false},
		{50, 49, 70, 60, false}, {50, 50, 70, 60, true}, {50, 51, 70, 60, true},
		{50, 60, 59, 60, false}, {50, 60, 60, 60, false}, {50, 60, 61, 60, true},
	} {
		if got := WindowAllows(row.r, row.b, row.e, row.h); got != row.want {
			t.Fatalf("%+v got %t", row, got)
		}
	}
}

// TestV4FirstRefusal proves every pair selects the first profile code, in both
// input orders; this is not a total order over unrelated grant-rule findings.
func TestV4FirstRefusal(t *testing.T) {
	// This literal follows the draft table independently of the implementation array.
	order := []Code{ObservationChain, ObservationVoid, NodeUnhealthy, NodeDisagreement,
		ObservationClock, TipAge, RecentBlock, RecentBlockWindow, Confirmations}
	for i, upper := range order {
		for _, lower := range order[i+1:] {
			for _, pair := range [][]Code{{upper, lower}, {lower, upper}} {
				got, err := FirstRefusal(pair...)
				if err != nil {
					t.Fatal(err)
				}
				wantCode(t, got, upper)
			}
		}
	}
	if _, err := FirstRefusal("UNSPECIFIED"); err == nil {
		t.Fatal("unknown finding accepted")
	}
	got, err := FirstRefusal()
	if err != nil {
		t.Fatal(err)
	}
	wantCode(t, got, "")
}

// TestV4RefusalState proves first sightings persist despite each later refusal,
// while void/wrong-chain observations write nothing and existing sights stay.
func TestV4RefusalState(t *testing.T) {
	for _, finding := range refusalOrder {
		s := mustMemory(t, ClockState{900, map[string]int64{}})
		c := mustClock(t, labParameters(), s)
		got, err := c.Observe(ClockInput{TipHash: "tip", Now: 1000, HeaderTime: 2000, Findings: []Code{finding}})
		if err != nil {
			t.Fatal(err)
		}
		want := ObservationClock
		if finding == ObservationChain || finding == ObservationVoid || finding == NodeUnhealthy || finding == NodeDisagreement {
			want = finding
		}
		wantCode(t, got, want)
		state := mustState(t, s)
		if finding == ObservationChain || finding == ObservationVoid {
			if state.KeptMark != 900 || len(state.FirstSights) != 0 {
				t.Fatal(state)
			}
		} else if state.KeptMark != 1000 || state.FirstSights["tip"] != 1000 {
			t.Fatal(state)
		}
	}
}

// TestV4InvalidInputs proves missing parameters/store and malformed stated
// bounds fail closed, with no invented default policy or clock-state writes.
func TestV4InvalidInputs(t *testing.T) {
	s := mustMemory(t, ClockState{0, map[string]int64{}})
	for _, p := range []Parameters{{}, {PinnedGenesis: "genesis"}, {"genesis", -1, 0, 0, 1, 1}} {
		if _, err := NewClock(p, s); err == nil {
			t.Fatal("invalid parameters accepted")
		}
	}
	if _, err := NewClock(labParameters(), nil); err == nil {
		t.Fatal("missing store accepted")
	}
	c := mustClock(t, labParameters(), s)
	for _, in := range []ClockInput{{}, {TipHash: "x", Now: -1}, {TipHash: "x", Now: 1, Findings: []Code{"unknown"}}} {
		if _, err := c.Observe(in); err == nil {
			t.Fatal("invalid clock input accepted")
		}
		if got := mustState(t, s); got.KeptMark != 0 || len(got.FirstSights) != 0 {
			t.Fatal(got)
		}
	}
}

// TestV4IssuanceRecentTip proves B4.1 selects exactly a coherent healthy tip,
// with no selection on refusal or inconsistent inputs; no grant is encoded.
func TestV4IssuanceRecentTip(t *testing.T) {
	p := labParameters()
	r := Node{SourceLabel: "a", Answers: true, GenesisHash: p.PinnedGenesis, Tip: Tip{10, "tip"}}
	comparison := r
	comparison.SourceLabel = "b"
	chain := map[int64]string{9: "old", 10: "tip"}
	obs := Observation{GenesisHash: r.GenesisHash, FirstTip: r.Tip, LastTip: r.Tip}
	tip, code, err := RecentForIssuance(p, obs, r, []Node{comparison}, chain)
	if err != nil {
		t.Fatal(err)
	}
	wantCode(t, code, "")
	if tip != r.Tip {
		t.Fatal("selected an earlier block", tip)
	}
	for _, void := range []bool{false, true} {
		candidate := obs
		if void {
			candidate.MovementObserved = true
		}
		tip, code, err := RecentForIssuance(p, candidate, r, nil, chain)
		if err != nil {
			t.Fatal(err)
		}
		want := NodeUnhealthy
		if void {
			want = ObservationVoid
		}
		wantCode(t, code, want)
		if tip != (Tip{}) {
			t.Fatal("refusal returned a recent block", tip)
		}
	}
	other := r
	other.Tip = Tip{9, "old"}
	if tip, _, err := RecentForIssuance(p, obs, other, []Node{comparison}, chain); err == nil || tip != (Tip{}) {
		t.Fatal("mixed observation supplied a recent block")
	}
}
