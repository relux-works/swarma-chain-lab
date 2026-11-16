package trustcontract

import (
	"bytes"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

const lip0014SHA256 = "563d49574f3c2bd913316cd0b0a295987648f5c281d28a68b065bf96ef180f14"

type lip0014File struct {
	Contracts []struct {
		ID       string   `json:"id"`
		Contract string   `json:"contract"`
		Expected string   `json:"expected"`
		Bytes    int      `json:"bytes"`
		SHA256   string   `json:"sha256"`
		Scope    []string `json:"v3_scope"`
		Budget   int64    `json:"v3_budget"`
		Booking  string   `json:"consent_booking"`
	} `json:"contracts"`
	Pairs []struct {
		ID       string `json:"id"`
		Parent   string `json:"parent"`
		Child    string `json:"child"`
		Expected string `json:"expected"`
		Profile  string `json:"profile"`
	} `json:"pairs"`
}

func loadLIP0014(t *testing.T) lip0014File {
	t.Helper()
	raw, err := os.ReadFile("testdata/contract-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if sha256Hex(raw) != lip0014SHA256 {
		t.Fatal("LIP-0014 vector file differs from the pinned upstream bytes")
	}
	record, err := os.ReadFile("testdata/contract-vectors.json.sha256")
	if err != nil || string(record) != lip0014SHA256+"  contract-vectors.json\n" {
		t.Fatal("LIP-0014 SHA256 record differs")
	}
	var file lip0014File
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Contracts) != 151 || len(file.Pairs) != 39 {
		t.Fatal("LIP-0014 corpus shortened")
	}
	return file
}

// Claim: all 151 contract vectors give the exact section 3.1 first-rule
// result through the reader of both profiles, including the /2 copy. Valid
// documents preserve exact bytes and their published hash/scope/budget/tags.
// The 39 delegation pairs exercise section 8, outside this contract reader.
func TestLIP0014Contracts(t *testing.T) {
	file := loadLIP0014(t)
	for _, v := range file.Contracts {
		t.Run(v.ID, func(t *testing.T) {
			raw := []byte(v.Contract)
			if len(raw) != v.Bytes {
				t.Fatal("contract byte count differs")
			}
			terms, got := Parse(raw)
			if got == "" {
				got = "ok"
			}
			if got != v.Expected {
				t.Fatalf("LIP-0014 section 3.1: got %s, want %s", got, v.Expected)
			}
			if v.Expected != "ok" {
				return
			}
			if terms.Profile == ProfileV2 {
				c, _, code := ParseV2(raw)
				if code != "" || !bytes.Equal(canonical(c), raw) {
					t.Fatalf("/2 copy changed valid bytes: %s", code)
				}
			}
			if sha256Hex(raw) != v.SHA256 || !slices.Equal(V3Scope(terms.Actions), v.Scope) || terms.SpendBudget != v.Budget {
				t.Fatal("published derivation differs")
			}
			if tags := ConsentTags(raw); len(tags) != 4 || tags[2][1] != v.Booking {
				t.Fatal("booking derivation differs")
			}
		})
	}
}

// Claim: every pair is enumerated and its two documents are run through the
// copy. This reports parser outcomes only: section 8's parent/child verdict,
// especially the explicitly hypothetical spend profile, is NOT judged here.
func TestLIP0014PairDocuments(t *testing.T) {
	for _, v := range loadLIP0014(t).Pairs {
		t.Run(v.ID, func(t *testing.T) {
			_, parent := Parse([]byte(v.Parent))
			_, child := Parse([]byte(v.Child))
			t.Logf("section 8 pair verdict %s NOT JUDGED; document results parent=%q child=%q profile=%s", v.Expected, parent, child, v.Profile)
			// Non-spend pairs contain valid documents. Spend-profile pairs lift D12,
			// which this reader deliberately retains; do not bend their expectations.
			if !strings.Contains(v.Profile, "spend") && (parent != "" || child != "") {
				t.Fatalf("section 3.1 valid pair documents refused: parent=%s child=%s", parent, child)
			}
		})
	}
}
