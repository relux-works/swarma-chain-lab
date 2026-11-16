package grantcheck

// Offline fixtures for the trust profile. Every key is a public laboratory
// key (small scalars, or the published BIP-340 test key of scalar 3), never
// custody material. The backend of trustChecker is a routing stub: these
// fixtures test the checker's own gates before the kernel and are no evidence
// of chain qualification.
import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/relux-works/swarma-chain-lab/experiments/grantcheck/internal/trustcontract"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/kernel"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

const trustDepthZero = `{"depth":0,"actions":[],"budget":0,"slots":[],"notaries":[],"checkpoint":""}`

// trustDepthOne is a valid right of re-delegation for trustV2: one row and
// one notary.
func trustDepthOne() string {
	return `{"depth":1,"actions":["instruct"],"budget":0,"slots":[{"executor":"id/test-worker","grantee":"` + xonly(3) +
		`","cap":0,"notary":"id/test-notary"}],"notaries":[{"name":"id/test-notary","registration":{"txid":"` + strings.Repeat("d", 64) +
		`","vout":0},"owner":"02` + xonly(1) + `"}],"checkpoint":"` + strings.Repeat("e", 64) + `"}`
}

// trustV1 is a canonical profile /1 contract in the shape of the G1.0 grant:
// instruct and review, no repository, no budget. edit may change one member.
func trustV1(t *testing.T, network string, edit func(*trustcontract.V1)) []byte {
	t.Helper()
	c := trustcontract.V1{Profile: trustcontract.ProfileV1, Network: network, LandlordName: "id/test-landlord", AgentName: "id/test-agent",
		GranteeKey: xonly(2), Actions: []string{"instruct", "review"}, Repos: []string{}, NotBefore: 300, NotAfter: 1000}
	if edit != nil {
		edit(&c)
	}
	return jsonBytes(t, c)
}

// trustV2 is a canonical profile /2 root at depth 0 with the same terms.
func trustV2(t *testing.T, network string, edit func(*trustcontract.V2)) []byte {
	t.Helper()
	c := trustcontract.V2{Profile: trustcontract.ProfileV2, Network: network, LandlordName: "id/test-landlord", AgentName: "id/test-agent",
		GranteeKey: xonly(2), Actions: []string{"instruct", "review"}, Repos: []string{}, NotBefore: 300, NotAfter: 1000,
		Delegate: json.RawMessage(trustDepthZero)}
	if edit != nil {
		edit(&c)
	}
	return jsonBytes(t, c)
}

// replaceOnce edits contract bytes and fails when the edit does not apply
// exactly once, so no fixture silently equals its valid control.
func replaceOnce(t *testing.T, doc []byte, old, new string) []byte {
	t.Helper()
	if strings.Count(string(doc), old) != 1 {
		t.Fatalf("fixture edit %q does not apply exactly once", old)
	}
	return []byte(strings.Replace(string(doc), old, new, 1))
}

type trustGrantSpec struct {
	Network, Genesis string
	// Contract holds the exact bytes the grant commits to.
	Contract []byte
	// Like is a valid canonical contract from which the grant's names, window,
	// scope and budget are derived. Nil means Contract. A refused Contract
	// names its valid neighbour here, so the grant differs from a valid grant
	// in the contract bytes alone.
	Like []byte
	// Grantee is the scalar of the grantee's laboratory key; 0 means 2.
	Grantee byte
	// Edit changes the grant before the consent and both signatures are made.
	Edit func(*rental.Grant)
	// Tags changes the consent tags before the grantee signs the consent.
	Tags func([][]string)
	// Unvalidated signs the exact grant bytes without the issuer's own
	// validation, for a grant no issuer would produce.
	Unvalidated bool
}

// trustGrant builds a signed v3 presentation for a trust contract. The
// consent carries the tags of LIP-0013 section 2.4, the scope and the budget
// are the ones section 2.2 derives, and the issuer key is the laboratory key
// of scalar 1.
func trustGrant(t *testing.T, spec trustGrantSpec) Presentation {
	t.Helper()
	keyBytes := make([]byte, 32)
	keyBytes[31] = 1
	issuer, _ := btcec.PrivKeyFromBytes(keyBytes)
	keyBytes[31] = 2
	if spec.Grantee != 0 {
		keyBytes[31] = spec.Grantee
	}
	grantee, err := nostr.PrivKeyFromBytes(keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	like := spec.Like
	if like == nil {
		like = spec.Contract
	}
	terms, refusal := trustcontract.Parse(like)
	if refusal != "" {
		t.Fatalf("fixture contract is not valid: %s", refusal)
	}
	hash := rental.Hash(spec.Contract)
	g := rental.Grant{Version: 3, Network: spec.Network, Genesis: spec.Genesis, AgentName: terms.AgentName, LandlordName: terms.LandlordName,
		IssuerKey: xonly(1), GranteeKey: grantee.PubKeyHex(), ContractSHA256: hash, Scope: trustcontract.V3Scope(terms.Actions),
		NotBefore: terms.NotBefore, NotAfter: terms.NotAfter, Seal: rental.Point{TxID: strings.Repeat("d", 64)}}
	if terms.SpendBudget != 0 {
		budget := terms.SpendBudget
		g.Budget = &budget
	}
	if spec.Edit != nil {
		spec.Edit(&g)
	}
	tags := trustcontract.ConsentTags(spec.Contract)
	if spec.Tags != nil {
		spec.Tags(tags)
	}
	consent := signEvent(t, grantee, rental.Event{CreatedAt: 200, Kind: 8181, Tags: tags})
	g.Consent = rental.GrantConsent{ContractSHA256: g.ContractSHA256, ConsentEvent: consent, LandlordSig: signHash(t, issuer, g.ContractSHA256)}
	var raw []byte
	if spec.Unvalidated {
		digest := rental.Hash(append([]byte("swarma-grant-v3"), jsonBytes(t, g)...))
		raw = jsonBytes(t, rental.GrantPresentation{SignedGrant: rental.SignedGrant{Grant: g, Signature: signHash(t, issuer, digest)}, Issuance: rental.IssuanceProof{TxID: strings.Repeat("e", 64)}})
	} else {
		digest, err := g.SigningHash()
		if err != nil {
			t.Fatalf("fixture grant is not a valid v3 grant: %v", err)
		}
		raw, err = rental.PresentIssuedGrant(jsonBytes(t, rental.SignedGrant{Grant: g, Signature: signHash(t, issuer, digest)}), strings.Repeat("e", 64))
		if err != nil {
			t.Fatal(err)
		}
	}
	id, err := kernel.PresentationID(raw)
	if err != nil {
		t.Fatal(err)
	}
	return Presentation{GrantID: id, Bytes: raw}
}

// termsOf is a Config.Terms lookup that serves the given documents by their
// SHA-256 and nothing else.
func termsOf(docs ...[]byte) func(string) ([]byte, error) {
	return func(hash string) ([]byte, error) {
		for _, doc := range docs {
			if rental.Hash(doc) == hash {
				return doc, nil
			}
		}
		return nil, errors.New("terms unavailable")
	}
}

// trustConfig is unitConfig under the trust profile with an explicit network.
func trustConfig(t *testing.T, network, genesis string, docs ...[]byte) Config {
	t.Helper()
	config := unitConfig(t)
	config.ContractProfile = ContractProfileTrust
	config.Network, config.Genesis = network, genesis
	config.Terms = termsOf(docs...)
	return config
}

// stubLive installs the routing stub of unitChecker: it answers live for any
// proof, so a refusal in these tests is the checker's own.
func stubLive(t *testing.T, c *Checker) *kernel.Stub {
	t.Helper()
	b := &kernel.Stub{Handler: func(_ context.Context, raw []byte, agent, sender string, now int64) (kernel.Receipt, error) {
		g := proofGrant(t, raw)
		return kernel.Receipt{Verdict: "live", Reason: "LIVE", GrantID: g.ID(), AgentName: agent, LandlordName: g.Grant.LandlordName, Scope: g.Grant.Scope, CheckedAt: now}, nil
	}}
	c.backend = b
	return b
}

func trustChecker(t *testing.T, config Config) (*Checker, *kernel.Stub) {
	t.Helper()
	c, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	return c, stubLive(t, c)
}

// genesisOf names the genesis of a network for fixtures.
func genesisOf(network string) string {
	if network == "main" {
		return MainGenesis
	}
	return su.RegtestGenesis
}
