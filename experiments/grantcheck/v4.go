package grantcheck

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	bitcoinwire "github.com/btcsuite/btcd/wire"
	"github.com/relux-works/swarma-chain-lab/experiments/grant-v4/identity"
	v4wire "github.com/relux-works/swarma-chain-lab/experiments/grant-v4/wire"
)

var (
	ErrV4Unavailable = errors.New("CLASS_HISTORY_UNAVAILABLE")
	ErrV4Holder      = errors.New("CLASS_HOLDER")
	ErrV4SealNotLive = errors.New("HOLDER_SEAL_NOT_LIVE")
	ErrV4ListUnknown = errors.New("LIST_UNKNOWN")
	ErrV4Binding     = errors.New("binding_mismatch")
)

// V4Document is NOT a Verdict. It cannot authorize an effect, populate a v3
// proof cache, or become a live admission. Required is the document under the
// rules binding every reader. ProposalOutcome is the result of also judging
// the pending W11.10 proposals: "ok" or "GRANT_DELEGATE". Reporting both
// outcomes avoids choosing an owner policy for the four undetermined vectors.
type V4Document struct {
	Required        *v4wire.SignedGrant
	ProposalOutcome string
}

type V4DocumentContext struct {
	Parent    *v4wire.SignedGrant
	Reference *string
}

// VerifyV4Document is the configured offline v4 entry point. Dispatch is by
// configuration alone, never by payload sniffing. Its two reads share only
// immutable objects; neither admits anything or reads a clock.
func (c *Checker) VerifyV4Document(raw []byte, input V4DocumentContext) (*V4Document, error) {
	if c == nil || c.profile != ContractProfileV4 {
		return nil, v4wire.WireType
	}
	ctx := v4wire.GrantContext{Parent: input.Parent, Reference: input.Reference}
	g, err := v4wire.VerifyGrant(raw, ctx)
	if err != nil {
		return nil, err
	}
	bound := func(g *v4wire.SignedGrant) bool {
		var p struct{ Genesis string }
		return json.Unmarshal(g.Payload(), &p) == nil && p.Genesis == c.genesis
	}
	if !bound(g) || input.Parent != nil && !bound(input.Parent) {
		return nil, ErrV4Binding
	}
	ctx.JudgeProposals = true
	_, proposed := v4wire.VerifyGrant(raw, ctx)
	// A child's proposal interpretation includes its verified root parent.
	// The reader permits only one parent level; no attenuation is added here.
	if proposed == nil && input.Parent != nil {
		_, proposed = v4wire.VerifyGrant(input.Parent.Bytes(), v4wire.GrantContext{JudgeProposals: true})
	}
	outcome := "ok"
	if proposed != nil {
		if !errors.Is(proposed, v4wire.GrantDelegate) {
			return nil, proposed
		}
		outcome = v4wire.GrantDelegate.Error()
	}
	return &V4Document{Required: g, ProposalOutcome: outcome}, nil
}

// V4HeightWindowContains checks the half-open height window only, without an
// invented refusal code. LIP-0008 section 7.1 assigns none. All heights are
// independently read facts of one observation, never a clock measurement.
func V4HeightWindowContains(recent, first, end, tip uint64) bool {
	return recent <= v4wire.MaxNumber && end <= v4wire.MaxNumber && tip <= v4wire.MaxNumber && recent <= first && first < end && first <= tip && tip < end
}

// HolderTip names an observation. It is not a proof of chain membership.
type HolderTip struct {
	Hash   string
	Height uint64
}

// HolderSealRequest supplies the outpoint and the H46 pin-run anchor, not a
// presenter-chosen substitute for it. The future caller must derive that anchor
// from the confirmed landlord history at this same named tip.
type HolderSealRequest struct {
	Seal      identity.HolderOutpoint
	Tip       HolderTip
	PinAnchor HolderTip
}

// HolderSpender describes exact transaction octets and where the node sighted
// them. H47 additionally requires verifier-side script/signature validation;
// no caller-supplied validation boolean or transaction id substitutes for it.
type HolderSpender struct {
	Transaction []byte
	Tip         HolderTip
	Block       *HolderTip // nil means the node's mempool at Tip
}

// HolderSealView has exactly the read needed at H48 and the H44 recheck.
// H45/H46 require confirmed funding octets with output script, amount and
// block, a mempool-inclusive spend state, and every available spender.
// H28/H47 additionally require the watcher's spender/funding/sighting-tip
// evidence. H50 state-only/observe-grade answers are never enforcement data.
//
// There is NO production implementation or constructor for a useful
// HolderSealObservation in this offline profile. The opaque return prevents
// an external implementation from making an enforcement-grade claim by a
// status label. A fixture implementation exists only in tests. The future
// adapter must validate its provenance, observation consistency and H47 spends
// before constructing observations; it must not expose a public grade setter.
type HolderSealView interface {
	ReadHolderSeal(context.Context, HolderSealRequest) (HolderSealObservation, error)
}

// HolderSealObservation is deliberately opaque outside this package. Its zero
// value is unavailable, not a live seal. These fields describe the read seam,
// not a completed journal or an implementation of enforcement closures.
type HolderSealObservation struct {
	enforcementGrade bool
	tip              HolderTip
	funding          []byte
	fundingBlock     HolderTip
	unspent          bool
	spenders         []HolderSpender
	watcherFunding   []byte
	watcherSpenders  []HolderSpender
}

// VerifyV4HolderDocument checks the H8-H10/H53 documents and the selected
// name/owner pin. The seal seam deliberately fails closed without an internal
// enforcement-grade observation. Even a fixture success is NOT admission:
// H23/H38-H44 journals, name/history/writer proofs and effect rechecks are not
// supplied by this method. No closure, cache or journal is written here.
func (c *Checker) VerifyV4HolderDocument(ctx context.Context, landlordValue, list []byte, landlord, name, owner string, request HolderSealRequest) error {
	if c == nil || c.profile != ContractProfileV4 || ctx == nil || ctx.Err() != nil {
		return ErrV4Unavailable
	}
	pin, err := identity.ReadHolderPin(landlordValue)
	if err != nil {
		return err
	}
	if pin == nil {
		return ErrV4Holder
	}
	if list == nil {
		return ErrV4ListUnknown
	}
	holders, err := identity.VerifyHoldersList(list, *pin, c.network, landlord)
	if err != nil {
		return err
	}
	entry, exists := holders.Entry(name)
	if !exists || entry.Key != owner {
		return ErrV4Holder
	}
	// The entry's signed-by-hash seal, never the supplied request, selects the
	// read. A differing request is an unavailable context, not another seal.
	if entry.Seal != request.Seal || c.config.HolderSeals == nil {
		return ErrV4Unavailable
	}
	observation, err := c.config.HolderSeals.ReadHolderSeal(ctx, request)
	if err != nil || ctx.Err() != nil || !observation.enforcementGrade || observation.tip != request.Tip || !holderTipForm(request.Tip) || !holderTipForm(request.PinAnchor) || request.PinAnchor.Height > request.Tip.Height {
		return ErrV4Unavailable
	}
	if len(observation.funding) == 0 {
		return ErrV4Unavailable
	}
	if len(observation.funding) > 4000000 {
		return ErrV4Unavailable
	}
	reader := bytes.NewReader(observation.funding)
	var tx bitcoinwire.MsgTx
	if tx.Deserialize(reader) != nil || reader.Len() != 0 || tx.TxHash().String() != entry.Seal.TxID {
		return ErrV4Unavailable
	}
	if !holderTipForm(observation.fundingBlock) || observation.fundingBlock.Height > request.PinAnchor.Height || uint64(entry.Seal.Vout) >= uint64(len(tx.TxOut)) {
		return ErrV4SealNotLive
	}
	output := tx.TxOut[entry.Seal.Vout]
	key, err := identity.ParsePin(entry.Key)
	if err != nil {
		return ErrV4SealNotLive
	}
	hash := key.Hash160()
	script := append([]byte{0, 20}, hash[:]...)
	if output.Value < 0 || !bytes.Equal(output.PkScript, script) || !observation.unspent {
		return ErrV4SealNotLive
	}
	// Spenders/closures need H47 and durable H28 handling, not a boolean.
	// This profile does not implement them; contradictory or supplied evidence
	// is unavailable rather than ignored or reported as a revocation.
	if len(observation.spenders) != 0 || len(observation.watcherFunding) != 0 || len(observation.watcherSpenders) != 0 {
		return ErrV4Unavailable
	}
	return nil
}

func holderTipForm(tip HolderTip) bool {
	if tip.Height > v4wire.MaxNumber || len(tip.Hash) != 64 {
		return false
	}
	for _, b := range []byte(tip.Hash) {
		if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f') {
			return false
		}
	}
	return true
}
