package notarycheck

import "testing"

// fixtureNames is unexported and exists only in the offline vector/test path.
type fixtureName struct {
	Name         string `json:"name"`
	Registration Point  `json:"registration"`
	Value        string `json:"value"`
	Height       int64  `json:"height"`
	BlockHash    string `json:"blockhash"`
	Unreadable   bool   `json:"unreadable,omitempty"`
}
type fixtureNames []fixtureName

func (f fixtureNames) Lookup(name string, height int64, blockhash string) (NameObservation, error) {
	for _, n := range f {
		if n.Name == name && !n.Unreadable {
			return NameObservation{n.Registration, []byte(n.Value), n.Height, n.BlockHash}, nil
		}
	}
	return NameObservation{}, refuse("MVP_NAME_UNREADABLE")
}

// A valid two-owner offline fixture passes Check, but the running entry point
// rejects its injection and refuses MVP without the unwired node adapter.
// The strict default positive remains usable without any names input.
func TestRunningRejectsFixture(t *testing.T) {
	strict := readCorpus(t).Vectors[0].input()
	if strict.Names != nil {
		t.Fatal("strict control unexpectedly supplies names")
	}
	if _, e := CheckRunning(strict); e != nil {
		t.Fatalf("strict default needs no names: %v", e)
	}
	for _, v := range readCorpus(t).Vectors {
		if v.Name == "positive-mvp-issuer-owner" {
			in := v.input()
			if _, e := Check(in); e != nil {
				t.Fatal(e)
			}
			for _, withFixture := range []bool{true, false} {
				if !withFixture {
					in.Names = nil
				}
				r, e := CheckRunning(in)
				if e == nil || e.Error() != "MVP_CHAIN_READ_REQUIRED" || r.Digest != "" || len(r.Attestation) != 0 {
					t.Fatalf("running accepted fixture or missing node: %v", e)
				}
			}
			return
		}
	}
	t.Fatal("missing positive control")
}

// Lookup must receive each signed name and the same statement height/hash;
// accurate offline observations are the precondition, not inferred evidence.
type recordingNames struct {
	fixtureNames
	names     []string
	height    int64
	blockhash string
	bad       bool
}

func (r *recordingNames) Lookup(name string, height int64, blockhash string) (NameObservation, error) {
	r.names = append(r.names, name)
	if height != r.height || blockhash != r.blockhash {
		r.bad = true
	}
	return r.fixtureNames.Lookup(name, height, blockhash)
}
func TestLookupPinsStatementView(t *testing.T) {
	for _, v := range readCorpus(t).Vectors {
		if v.Name != "positive-mvp-issuer-owner" {
			continue
		}
		in := v.input()
		var st Statement
		var p Policy
		if !decode(in.Statement, &st, 8192) || !decode(in.Policy, &p, 8192) {
			t.Fatal("invalid control")
		}
		source := &recordingNames{fixtureNames: fixtureNames(v.Names), height: st.TipHeight, blockhash: st.TipHash}
		in.Names = source
		if _, e := Check(in); e != nil {
			t.Fatal(e)
		}
		if source.bad || len(source.names) != 2 || source.names[0] != p.ModeApprovals[0].Name || source.names[1] != p.ModeApprovals[1].Name {
			t.Fatal("lookup did not pin both signed identities to one view")
		}
		return
	}
	t.Fatal("missing positive control")
}
