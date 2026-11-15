package identity

import "bytes"

// StatedOutput is one output in a stated name-input chain, newest first.
// ID is an opaque output identifier, not a wire encoding. Readings are relative
// to StatedName.Owner. Available means the transaction was supplied; Height may
// still be known from current-output metadata when Available is false.
// Swarma is supplied member octets (nil means absent), never extracted here.
type StatedOutput struct {
	ID        string
	Height    Height
	Available bool
	Prefix    Prefix
	Name      []byte
	Reading   Reading
	Writer    Writer
	Swarma    []byte
	Nostr     NostrMember
}

// ReadStatedOutput reuses sections 2-4 on transaction octets. It establishes
// neither transaction validity nor links between operations. The caller supplies
// the ordered name-input chain and separately interpreted value members.
func ReadStatedOutput(id string, script []byte, at Height, inputs []Input, owner Pin, chain Chain) StatedOutput {
	r, ns := ReadOutput(script, owner, at, chain)
	op := OpNone
	if ns.Prefix == PrefixUpdate {
		op = OpUpdate
	} else if ns.Prefix == PrefixRegistration {
		op = OpRegistration
	}
	return StatedOutput{ID: id, Height: at, Available: true, Prefix: ns.Prefix,
		Name: ns.Name, Reading: r, Writer: CheckWriter(op, ns.Name, inputs, owner, chain)}
}

// CurrentStatus distinguishes an absent live output from an unavailable read.
type CurrentStatus uint8

const (
	CurrentUnknown CurrentStatus = iota
	CurrentOutput
	NoLiveOutput
)

// StatedName carries facts from ONE coherent observation, not presenter proof.
// Transactions means transaction reads are available. StepBound is an optional
// operator bound; nil is unlimited and zero permits no examinations. Every
// adjacent pair in Outputs states the name-input link; no RPC adapter is here.
// Depth is consensus expiration depth at the height being checked.
type StatedName struct {
	Name         []byte
	Owner        Pin
	Tip          Height
	Depth        int64
	Current      CurrentStatus
	Outputs      []StatedOutput
	Transactions bool
	StepBound    *uint64
}

func (s StatedName) valid() bool {
	_, known := s.Tip.Value()
	return len(s.Name) > 0 && s.Owner.Valid() && known && s.Depth > 0
}

func (s StatedName) live() (Liveness, bool) {
	if !s.valid() {
		return Expired, false
	}
	if s.Current == NoLiveOutput {
		return Expired, true
	}
	if s.Current != CurrentOutput || len(s.Outputs) == 0 {
		return Expired, false
	}
	h, known := s.Outputs[0].Height.Value()
	if !known {
		return Expired, false
	}
	l, err := CheckLive(h, s.Tip.h, s.Depth)
	return l, err == nil
}

type walked struct {
	outputs      []StatedOutput
	registration string
	complete     bool
}

// walk follows the stated links. An unsupported ADDRESS does not stop prefix
// traversal. An unsupported prefix, missing fact or exhausted bound does.
// stop is used only by consent, whose walk ends at the evidence output.
func walk(s StatedName, stop string) walked {
	var result walked
	if !s.valid() || s.Current != CurrentOutput || !s.Transactions {
		return result
	}
	seen := make(map[string]bool)
	last := s.Tip.h
	for i, out := range s.Outputs {
		if s.StepBound != nil && uint64(i) >= *s.StepBound {
			return result
		}
		h, known := out.Height.Value()
		if !out.Available || !known || h > last || out.ID == "" || seen[out.ID] ||
			!bytes.Equal(out.Name, s.Name) || (out.Prefix != PrefixUpdate && out.Prefix != PrefixRegistration) {
			return result
		}
		seen[out.ID], last = true, h
		result.outputs = append(result.outputs, out)
		if out.Prefix == PrefixRegistration {
			result.registration = out.ID
		}
		if out.ID == stop || out.Prefix == PrefixRegistration {
			result.complete = true
			return result
		}
	}
	return result
}

// HistoryRule is part of the predicate, not an interchangeable cache label.
type HistoryRule uint8

const (
	IssuerHistory HistoryRule = iota + 1
	NotaryHistory
)

// HistoryPredicate binds a registration and the start of its constrained
// stretch. From is R for an issuer and the checkpoint for a notary. Only issuer
// history compares Swarma; notary history also checks the current writer.
type HistoryPredicate struct {
	Rule         HistoryRule
	Registration string
	From         Height
	Swarma       []byte
}

func (p HistoryPredicate) valid(s StatedName) bool {
	h, known := p.From.Value()
	return s.valid() && known && h <= s.Tip.h && p.Registration != "" &&
		(p.Rule == IssuerHistory || p.Rule == NotaryHistory) && (p.Rule != IssuerHistory || p.Swarma != nil)
}

// HistoryCacheKey is a comparable, copied predicate identity, not a cache or
// authority. ChainThroughOutput must identify the validated active chain through
// CachedOutput; discard entries when a reorganisation touches their stretch.
// Admission must still recheck liveness at its own tip and consensus depth.
type HistoryCacheKey struct {
	rule                                                   HistoryRule
	name, registration, owner, swarma, chain, cachedOutput string
	from                                                   int64
}

// CacheKey includes R/checkpoint, rule, pin, member octets and chain identity.
// It cannot validate a caller's chain assertion and does not implement caching.
func (p HistoryPredicate) CacheKey(s StatedName, chainThroughOutput, cachedOutput string) (HistoryCacheKey, error) {
	if !p.valid(s) || chainThroughOutput == "" || cachedOutput == "" {
		return HistoryCacheKey{}, ErrHistoryPredicate
	}
	return HistoryCacheKey{rule: p.Rule, name: string(s.Name), registration: p.Registration,
		owner: s.Owner.String(), swarma: string(p.Swarma), from: p.From.h,
		chain: chainThroughOutput, cachedOutput: cachedOutput}, nil
}
