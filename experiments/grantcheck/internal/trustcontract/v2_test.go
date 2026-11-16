package trustcontract

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Published BIP-340 test keys (vector indexes 0 and 1), never real keys.
const (
	testKey0 = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
	testKey1 = "dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659"
)

const depthZero = `{"depth":0,"actions":[],"budget":0,"slots":[],"notaries":[],"checkpoint":""}`

// rootV2 is a valid root of profile /2 without a right of re-delegation.
func rootV2() V2 {
	return V2{Profile: ProfileV2, Network: "main", LandlordName: "id/example-landlord", AgentName: "id/example-agent", GranteeKey: testKey0,
		Actions: []string{"instruct", "review"}, Repos: []string{}, NotBefore: 1794528000, NotAfter: 1797120000, Delegate: json.RawMessage(depthZero)}
}

// depthOne is a valid delegate of depth 1 for rootV2: one row, one notary.
func depthOne() string {
	return `{"depth":1,"actions":["instruct"],"budget":0,"slots":[{"executor":"id/example-worker","grantee":"` + testKey1 +
		`","cap":0,"notary":"id/example-notary"}],"notaries":[{"name":"id/example-notary","registration":{"txid":"` + strings.Repeat("d", 64) +
		`","vout":0},"owner":"02` + testKey0 + `"}],"checkpoint":"` + strings.Repeat("e", 64) + `"}`
}

// Claim: the reader of both profiles accepts a valid root of profile /2 at
// depth 0 with its exact bytes and reports depth 0, and it reports depth 1
// and a parent as what they are, so that a caller can refuse them. These are
// the valid controls of TestV2Refusals.
func TestV2Valid(t *testing.T) {
	root := compact(rootV2())
	terms, code := Parse(root)
	if code != "" || terms.Profile != ProfileV2 || terms.DelegateDepth != 0 || terms.ParentGrantID != "" || terms.Ordinal != 0 {
		t.Fatalf("root at depth 0: code %q, terms %+v", code, terms)
	}
	if c, _, code := ParseV2(root); code != "" || string(compact(c)) != string(root) {
		t.Fatalf("root does not re-encode to its exact bytes: %q", code)
	}
	delegating := rootV2()
	delegating.Delegate = json.RawMessage(depthOne())
	if terms, code = Parse(compact(delegating)); code != "" || terms.DelegateDepth != 1 {
		t.Fatalf("root at depth 1: code %q, depth %d", code, terms.DelegateDepth)
	}
	child := rootV2()
	child.ParentGrantID, child.Ordinal = strings.Repeat("a", 64), 1
	if terms, code = Parse(compact(child)); code != "" || terms.ParentGrantID == "" || terms.Ordinal != 1 || terms.DelegateDepth != 0 {
		t.Fatalf("child: code %q, terms %+v", code, terms)
	}
	text := rootV2()
	text.ScopeTextSHA256 = strings.Repeat("b", 64)
	if terms, code = Parse(compact(text)); code != "" || terms.ScopeTextSHA256 != text.ScopeTextSHA256 {
		t.Fatalf("root with a scope text hash: code %q", code)
	}
}

// Claim: the member set selects the rules and the profile string never does
// (LIP-0014 section 3.1), and rule 1 refuses every non-canonical spelling of
// a profile /2 document: whitespace, a trailing newline, trailing data, a
// repeated, unknown, missing, reordered or case-folded member. Each refused
// document is one edit away from the valid root of TestV2Valid.
func TestV2Refusals(t *testing.T) {
	root := string(compact(rootV2()))
	if _, code := Parse([]byte(root)); code != "" {
		t.Fatalf("control refused: %s", code)
	}
	edit := func(old, new string) string {
		t.Helper()
		if strings.Count(root, old) != 1 {
			t.Fatalf("edit %q does not apply exactly once", old)
		}
		return strings.Replace(root, old, new, 1)
	}
	v1 := V1{Profile: ProfileV2, Network: "main", LandlordName: "id/example-landlord", AgentName: "id/example-agent", GranteeKey: testKey0,
		Actions: []string{"instruct", "review"}, Repos: []string{}, NotBefore: 1794528000, NotAfter: 1797120000}
	for _, tc := range []struct{ name, doc, want string }{
		{"profile-1-string-with-fifteen-members", edit(`"profile":"swarma-trust-contract/2"`, `"profile":"swarma-trust-contract/1"`), "CONTRACT_PROFILE"},
		{"profile-2-string-with-eleven-members", string(compact(v1)), "CONTRACT_PROFILE"},
		{"unknown-profile-string", edit(`"profile":"swarma-trust-contract/2"`, `"profile":"swarma-trust-contract/3"`), "CONTRACT_PROFILE"},
		{"whitespace", edit(`"ordinal":0`, `"ordinal": 0`), "CONTRACT_ENCODING"},
		{"trailing-newline", root + "\n", "CONTRACT_ENCODING"},
		{"trailing-data", root + "{}", "CONTRACT_ENCODING"},
		{"repeated-member", edit(`"ordinal":0,`, `"ordinal":0,"ordinal":0,`), "CONTRACT_ENCODING"},
		{"unknown-member", edit(`"ordinal":0,`, `"ordinal":0,"extra":0,`), "CONTRACT_ENCODING"},
		{"missing-member", edit(`"ordinal":0,`, ``), "CONTRACT_ENCODING"},
		{"reordered-members", edit(`"parent_grant_id":"","ordinal":0,`, `"ordinal":0,"parent_grant_id":"",`), "CONTRACT_ENCODING"},
		{"case-folded-member", edit(`"ordinal":0`, `"Ordinal":0`), "CONTRACT_ENCODING"},
		{"whitespace-in-delegate", edit(`"depth":0`, `"depth": 0`), "CONTRACT_ENCODING"},
		{"unsorted-actions", edit(`"actions":["instruct","review"]`, `"actions":["review","instruct"]`), "CONTRACT_ACTIONS"},
		{"action-outside-the-set", edit(`"actions":["instruct","review"]`, `"actions":["instruct","publish"]`), "CONTRACT_ACTIONS"},
		{"parent-with-depth-1", strings.Replace(edit(`"parent_grant_id":"","ordinal":0`, `"parent_grant_id":"`+strings.Repeat("a", 64)+`","ordinal":1`), depthZero, depthOne(), 1), "CONTRACT_PARENT"},
		{"depth-2", edit(`"depth":0`, `"depth":2`), "CONTRACT_DELEGATE"},
		{"depth-0-with-actions", edit(`"depth":0,"actions":[]`, `"depth":0,"actions":["instruct"]`), "CONTRACT_DELEGATE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, code := Parse([]byte(tc.doc)); code != tc.want {
				t.Fatalf("Parse gave %q, want %q for %s", code, tc.want, tc.doc)
			}
		})
	}
}

func notaryFile(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "notary-checker", filepath.FromSlash(name)))
	if err != nil {
		t.Fatalf("this test reads the notary-checker module of the same checkout: %v", err)
	}
	return raw
}

// Claim: v2.go was copied from these exact notary-checker sources. When
// either file changes this test fails, and the copy must be read against the
// new source before the pins move. It proves that the sources did not move;
// TestNotaryCorpusAgrees is the evidence that the copy behaves like them.
func TestNotaryCopyMatchesSource(t *testing.T) {
	for name, want := range map[string]string{
		"contract.go": "d588697ea03b40bdc6d549ebb3b5d2ecd6064dabbb2a775aa9b1b2b66d93591d",
		"encoding.go": "304113dcf9070f2726f9779442669a9f4e0c071fb3212a383a3f6323f48982a1",
	} {
		if got := sha256Hex(notaryFile(t, name)); got != want {
			t.Errorf("notary-checker %s has sha256 %s, the copy was made from %s", name, got, want)
		}
	}
}

// Claim: on the notary's own committed corpus the copy decides every contract
// as the notary's ParseContract does, as far as the corpus states it. The
// notary's Check binds the parent contract and then the child contract before
// any later step, and a binding parses the contract after its hash. So for a
// vector whose expected outcome is a parse code, the parent gives that code,
// or the parent is valid and the child gives it; for a vector that passes
// both bindings, both contracts are valid; and for a vector that fails a
// binding after the parse, the parent is valid. Limit: vectors that stop
// before the bindings state nothing about their contracts and are not read.
func TestNotaryCorpusAgrees(t *testing.T) {
	var corpus struct {
		Vectors []struct {
			Name           string `json:"name"`
			Expected       string `json:"expected"`
			ParentContract string `json:"parent_contract"`
			ChildContract  string `json:"child_contract"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(notaryFile(t, "testdata/vectors.json"), &corpus); err != nil {
		t.Fatal(err)
	}
	parseCodes := map[string]bool{"CONTRACT_ENCODING": true, "CONTRACT_PROFILE": true, "CONTRACT_FIELD": true, "CONTRACT_ACTIONS": true, "CONTRACT_REPOS": true,
		"CONTRACT_BUDGET": true, "CONTRACT_NOTE": true, "CONTRACT_PARENT": true, "CONTRACT_DELEGATE": true, "DELEGATE_NO_NOTARY": true}
	bindCodes := map[string]bool{"CONTRACT_MISMATCH": true, "SCOPE_MISMATCH": true, "BUDGET_MISMATCH": true, "CONSENT_TAGS": true}
	refused, passed := 0, 0
	for _, v := range corpus.Vectors {
		_, _, parent := ParseV2([]byte(v.ParentContract))
		_, _, child := ParseV2([]byte(v.ChildContract))
		switch {
		case v.Expected == "AT_TIME" || v.Expected == "CONTRACT_HASH" || strings.HasPrefix(v.Expected, "GRANT_"):
		case parseCodes[v.Expected]:
			refused++
			if parent != v.Expected && (parent != "" || child != v.Expected) {
				t.Errorf("%s: want %s, the copy gave parent %q and child %q", v.Name, v.Expected, parent, child)
			}
		case bindCodes[v.Expected]:
			if parent != "" {
				t.Errorf("%s: the parent passed the notary's parser, the copy gave %q", v.Name, parent)
			}
		default:
			passed++
			if parent != "" || child != "" {
				t.Errorf("%s: both contracts passed the notary's parser, the copy gave parent %q and child %q", v.Name, parent, child)
			}
		}
	}
	if refused < 20 || passed < 50 {
		t.Fatalf("the corpus gave %d parse refusals and %d passing pairs, too few to compare", refused, passed)
	}
}
