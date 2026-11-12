package rental

// PX1 stream S4 implementation (owner S4): the terms-v2 pay-grant issuance
// helper. Signatures are frozen in paygrant_v2_api.go; the format and the
// ceremony are described in PAYGRANT-V2.md.
//
// This file never reads, derives or holds a private key. Every signature comes
// from an external DigestSigner and is verified here before it is used. Any
// refusal returns a zero PayGrantV2Result: there is no partial grant.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// ErrPayGrantNotImplemented is the PX1 stub sentinel of this module; its text
// equals agent-wallet's ErrNotImplemented code. S4 no longer returns it; it
// stays exported because the freeze declared it.
var ErrPayGrantNotImplemented = errors.New("PX1_NOT_IMPLEMENTED")

// Terms v2 constants. They mirror agent-wallet (TermsV2Version,
// WalletServiceID, DayBasisUTCCalendar, RecipientMode*, MaxDayCountCap,
// MaxFee); rental cannot import agent-wallet, and the golden fixtures pin both.
const (
	payTermsVersion       = 2
	payTermsService       = "wallet.nmc"
	payTermsDayBasis      = "utc-calendar"
	payTermsModeAllow     = "allow"
	payTermsModeAny       = "any"
	payTermsMaxRecipients = 32
	payTermsMaxDayCount   = 1000
	payTermsMaxFeeSat     = int64(1000000) // agent-wallet MaxFee
	payGrantBookingDomain = "swarma-g2-pay-booking-v1"
	payGrantConsentKind   = 8181
	payGrantConsentTopic  = "swarma-rental-consent-v1"
	payGrantMessageV1     = 1
	payGrantExchangeLimit = 16384
)

// payGrantError keeps the visible error text a bounded code while letting
// callers inspect the cause (for example context.Canceled) with errors.Is.
type payGrantError struct {
	code  string
	cause error
}

func (e payGrantError) Error() string { return e.code }
func (e payGrantError) Unwrap() error { return e.cause }

func payGrantFail(code string, cause error) error { return payGrantError{code, cause} }

// payTermsAddress mirrors agent-wallet addressScriptForNetwork (wire.go) so
// that an allow-list this helper accepts is never refused by the executor's
// row 8 for a different reason. Only canonical P2PKH of the pinned network.
func payTermsAddress(address, network, genesis string) error {
	if !su.NetworkPinned(network, genesis) {
		return bad("NETWORK_PIN")
	}
	params := chaincfg.RegressionNetParams
	code := "ADDRESS_REGTEST"
	if network == "main" {
		params = chaincfg.MainNetParams
		params.PubKeyHashAddrID, params.ScriptHashAddrID, params.PrivateKeyID = 52, 13, 180
		params.Bech32HRPSegwit = "nc"
		code = "ADDRESS_MAIN"
	}
	a, e := btcutil.DecodeAddress(address, &params)
	if e != nil || !a.IsForNet(&params) || a.EncodeAddress() != address {
		return bad(code)
	}
	if _, ok := a.(*btcutil.AddressPubKeyHash); !ok {
		return bad("ADDRESS_P2PKH_ONLY")
	}
	return nil
}

// EncodePayTermsV2 applies wallet.ParseTermsV2 rows 3-10 without the executor
// pin (row 6) and without the grant budget (checked by ValidatePayGrantV2Input),
// in the frozen order, and returns the canonical compact bytes.
func EncodePayTermsV2(t PayTermsV2) ([]byte, error) {
	// Row 4.
	if t.Version != payTermsVersion || t.Service != payTermsService || t.DayBasis != payTermsDayBasis || !pubkey(t.ExecutorKey) {
		return nil, bad("CONTRACT_SCHEMA")
	}
	// Row 5: no service pin exists at issuance; the pair must be a pinned pair.
	if !su.NetworkPinned(t.Network, t.Genesis) {
		return nil, bad("TERMS_NETWORK")
	}
	// Row 7.
	switch {
	case t.Recipients == nil:
		return nil, bad("CONTRACT_SCHEMA")
	case t.RecipientMode == payTermsModeAllow:
		if len(t.Recipients) == 0 || len(t.Recipients) > payTermsMaxRecipients || !sort.StringsAreSorted(t.Recipients) {
			return nil, bad("CONTRACT_SCHEMA")
		}
	case t.RecipientMode == payTermsModeAny:
		if len(t.Recipients) != 0 {
			return nil, bad("CONTRACT_SCHEMA")
		}
	default:
		return nil, bad("CONTRACT_SCHEMA")
	}
	// Row 8.
	for _, r := range t.Recipients {
		if e := payTermsAddress(r, t.Network, t.Genesis); e != nil {
			return nil, e
		}
	}
	// Row 9: the list is sorted, so a duplicate is adjacent.
	for i := 1; i < len(t.Recipients); i++ {
		if t.Recipients[i] == t.Recipients[i-1] {
			return nil, bad("CONTRACT_RECIPIENTS")
		}
	}
	// Row 10. The grant budget bound is applied by ValidatePayGrantV2Input;
	// MaxMoney bounds every v3 budget, so it bounds spend_cap here.
	if !(0 < t.TransferCap && t.TransferCap <= t.DayCap && t.DayCap <= t.SpendCap && t.SpendCap <= MaxMoney) ||
		t.DayCountCap < 1 || t.DayCountCap > payTermsMaxDayCount || t.FeeCap < 1 || t.FeeCap > payTermsMaxFeeSat {
		return nil, bad("CONTRACT_BUDGET")
	}
	b, e := json.Marshal(t)
	if e != nil {
		return nil, bad("CONTRACT_SCHEMA")
	}
	return b, nil
}

// PayGrantBookingRef is SHA256("swarma-g2-pay-booking-v1" || terms bytes). A
// pay grant has no booking; this tag binds the consent to the terms instead.
func PayGrantBookingRef(terms []byte) string {
	return Hash(append([]byte(payGrantBookingDomain), terms...))
}

// ValidatePayGrantV2Input checks the ceremony input without any signer. The
// codes reuse the v3 grant codes where Grant.Validate would refuse the same
// field, so a passing input yields a Grant.Validate-valid grant.
func ValidatePayGrantV2Input(in PayGrantV2Input) error {
	if _, e := EncodePayTermsV2(in.Terms); e != nil {
		return e
	}
	if !su.NetworkPinned(in.Network, in.Genesis) || in.Network != in.Terms.Network || in.Genesis != in.Terms.Genesis {
		return bad("PAY_GRANT_NETWORK")
	}
	if !station(in.AgentName) || !station(in.LandlordName) || in.AgentName == in.LandlordName {
		return bad("GRANT_NAME")
	}
	if !pubkey(in.IssuerKey) || !pubkey(in.GranteeKey) {
		return bad("GRANT_KEY")
	}
	// Three custody roles, three keys: the landlord issues, Cedar requests,
	// agent-walletd signs receipts. A shared key would merge two roles.
	if in.IssuerKey == in.GranteeKey || in.GranteeKey == in.Terms.ExecutorKey || in.IssuerKey == in.Terms.ExecutorKey {
		return bad("PAY_GRANT_KEY_ROLES")
	}
	if !digest(in.Seal.TxID) {
		return bad("GRANT_HASH")
	}
	if in.NotBefore < 0 || in.NotAfter <= in.NotBefore || in.NotAfter > 253402300799 {
		return bad("GRANT_TIME")
	}
	if in.BudgetSat > MaxMoney {
		return bad("GRANT_BUDGET")
	}
	// LIP-0004: no budget is zero, and terms v2 need spend_cap <= budget.
	if in.BudgetSat < in.Terms.SpendCap {
		return bad("CONTRACT_BUDGET")
	}
	if in.ConsentCreatedAt < 1 || in.ConsentCreatedAt < in.NotBefore || in.ConsentCreatedAt >= in.NotAfter {
		return bad("PAY_GRANT_CONSENT_TIME")
	}
	if !digest(in.PrivacyNoticeSHA256) {
		return bad("PAY_GRANT_PRIVACY")
	}
	return nil
}

// payGrantConsentPayload is the unsigned NIP-01 consent event with its id,
// in NIP-01 member order and without "sig".
type payGrantConsentPayload struct {
	ID        string     `json:"id"`
	Pubkey    string     `json:"pubkey"`
	CreatedAt int64      `json:"created_at"`
	Kind      int        `json:"kind"`
	Tags      [][]string `json:"tags"`
	Content   string     `json:"content"`
}

// payGrantContractPayload is the countersign payload.
type payGrantContractPayload struct {
	ContractSHA256 string `json:"contract_sha256"`
}

func payGrantConsentTags(contract, booking, privacy string) [][]string {
	return [][]string{{"t", payGrantConsentTopic}, {"contract", contract}, {"booking", booking}, {"privacy", privacy}}
}

func payGrantEventID(pubkey string, createdAt int64, kind int, tags [][]string, content string) string {
	return Hash(eventBytes([]any{0, pubkey, createdAt, kind, tags, content}))
}

// payGrantSign asks one signer for one signature and accepts only an exact
// echo of the request plus a valid BIP-340 signature by the expected key. The
// signer receives copies, so it cannot rewrite the helper's terms or payload.
func payGrantSign(ctx context.Context, s DigestSigner, purpose, key, digestHex string, terms, payload []byte) (string, error) {
	if e := ctx.Err(); e != nil {
		return "", payGrantFail("PAY_GRANT_SIGNER", e)
	}
	req := PayGrantSigningRequest{Version: payGrantMessageV1, Purpose: purpose, SignerKey: key, Digest: digestHex, Terms: bytes.Clone(terms), Payload: bytes.Clone(payload)}
	resp, e := s.Sign(ctx, req)
	if e != nil {
		return "", payGrantFail("PAY_GRANT_SIGNER", e)
	}
	if resp.Version != payGrantMessageV1 || resp.Purpose != purpose || resp.SignerKey != key || resp.Digest != digestHex {
		return "", bad("PAY_GRANT_SIGNATURE_ECHO")
	}
	if !VerifySignature(key, digestHex, resp.Signature) {
		return "", bad("PAY_GRANT_SIGNATURE")
	}
	return resp.Signature, nil
}

// IssuePayGrantV2 runs the three external signatures in the frozen order
// (grantee consent, landlord contract countersign, landlord grant) and returns
// a ParseSignedGrant-valid result. Any refusal returns the zero result.
func IssuePayGrantV2(ctx context.Context, in PayGrantV2Input, grantee, landlord DigestSigner) (PayGrantV2Result, error) {
	var none PayGrantV2Result
	if e := ValidatePayGrantV2Input(in); e != nil {
		return none, e
	}
	// Both signers are bound before the first request leaves the helper, so a
	// wrong key never receives a payload to sign.
	if grantee == nil || landlord == nil || grantee.XOnlyKey() != in.GranteeKey || landlord.XOnlyKey() != in.IssuerKey {
		return none, bad("PAY_GRANT_SIGNER_KEY")
	}
	terms, e := EncodePayTermsV2(in.Terms)
	if e != nil {
		return none, e
	}
	contract := Hash(terms)

	// 1. Grantee: the NIP-01 id of Cedar's kind-8181 consent.
	tags := payGrantConsentTags(contract, PayGrantBookingRef(terms), in.PrivacyNoticeSHA256)
	event := Event{Pubkey: in.GranteeKey, CreatedAt: in.ConsentCreatedAt, Kind: payGrantConsentKind, Tags: tags, Content: ""}
	event.ID = payGrantEventID(event.Pubkey, event.CreatedAt, event.Kind, event.Tags, event.Content)
	consentPayload, e := json.Marshal(payGrantConsentPayload{event.ID, event.Pubkey, event.CreatedAt, event.Kind, event.Tags, event.Content})
	if e != nil {
		return none, bad("PAY_GRANT_ENCODING")
	}
	if event.Sig, e = payGrantSign(ctx, grantee, SignPurposeConsentEvent, in.GranteeKey, event.ID, terms, consentPayload); e != nil {
		return none, e
	}

	// 2. Landlord: the raw contract hash (GrantConsent.LandlordSig).
	contractPayload, e := json.Marshal(payGrantContractPayload{contract})
	if e != nil {
		return none, bad("PAY_GRANT_ENCODING")
	}
	countersign, e := payGrantSign(ctx, landlord, SignPurposeContract, in.IssuerKey, contract, terms, contractPayload)
	if e != nil {
		return none, e
	}

	// 3. Landlord: the domain-separated canonical grant.
	budget := in.BudgetSat
	g := Grant{Version: 3, Network: in.Network, Genesis: in.Genesis, AgentName: in.AgentName, LandlordName: in.LandlordName, IssuerKey: in.IssuerKey, GranteeKey: in.GranteeKey, ContractSHA256: contract, Scope: []string{"pay"}, NotBefore: in.NotBefore, NotAfter: in.NotAfter, Seal: in.Seal, Budget: &budget, Consent: GrantConsent{ContractSHA256: contract, ConsentEvent: event, LandlordSig: countersign}}
	unsigned, e := g.Canonical()
	if e != nil {
		return none, e
	}
	grantDigest := grantSigningDigest(unsigned)
	grantSig, e := payGrantSign(ctx, landlord, SignPurposeGrant, in.IssuerKey, grantDigest, terms, unsigned)
	if e != nil {
		return none, e
	}
	raw, e := json.Marshal(SignedGrant{Grant: g, Signature: grantSig})
	if e != nil {
		return none, bad("PAY_GRANT_ENCODING")
	}
	signed, e := ParseSignedGrant(raw)
	if e != nil {
		return none, e
	}
	commitment, e := IssuanceCommitment(signed)
	if e != nil {
		return none, e
	}
	return PayGrantV2Result{GrantID: signed.ID(), ContractSHA256: contract, Terms: terms, SignedGrant: raw, IssuanceCommitment: commitment}, nil
}

// VerifyPayGrantSigningRequest is the conforming-signer check (additive; not
// part of the frozen surface). A signer calls it before it shows the terms to
// the key holder. It recomputes the digest from Terms and Payload and refuses
// on any mismatch, so a conforming signer never signs a bare digest. It
// returns the parsed terms for display.
func VerifyPayGrantSigningRequest(req PayGrantSigningRequest) (PayTermsV2, error) {
	var t PayTermsV2
	if req.Version != payGrantMessageV1 {
		return t, bad("SIGNING_REQUEST_VERSION")
	}
	if !pubkey(req.SignerKey) || !digest(req.Digest) {
		return t, bad("SIGNING_REQUEST_KEY")
	}
	if canonical(req.Terms, &t) != nil {
		return PayTermsV2{}, bad("SIGNING_REQUEST_TERMS")
	}
	terms, e := EncodePayTermsV2(t)
	if e != nil || !bytes.Equal(terms, req.Terms) {
		return PayTermsV2{}, bad("SIGNING_REQUEST_TERMS")
	}
	contract := Hash(terms)
	var want string
	switch req.Purpose {
	case SignPurposeConsentEvent:
		var p payGrantConsentPayload
		if canonical(req.Payload, &p) != nil || p.Pubkey != req.SignerKey || p.CreatedAt < 1 || p.Kind != payGrantConsentKind || p.Content != "" || len(p.Tags) != 4 || len(p.Tags[3]) != 2 || !digest(p.Tags[3][1]) {
			return PayTermsV2{}, bad("SIGNING_REQUEST_PAYLOAD")
		}
		if !sameJSON(p.Tags, payGrantConsentTags(contract, PayGrantBookingRef(terms), p.Tags[3][1])) {
			return PayTermsV2{}, bad("SIGNING_REQUEST_PAYLOAD")
		}
		want = payGrantEventID(p.Pubkey, p.CreatedAt, p.Kind, p.Tags, p.Content)
		if p.ID != want {
			return PayTermsV2{}, bad("SIGNING_REQUEST_DIGEST")
		}
	case SignPurposeContract:
		var p payGrantContractPayload
		if canonical(req.Payload, &p) != nil || p.ContractSHA256 != contract {
			return PayTermsV2{}, bad("SIGNING_REQUEST_PAYLOAD")
		}
		want = contract
	case SignPurposeGrant:
		var g Grant
		if canonical(req.Payload, &g) != nil || g.Validate() != nil || g.ContractSHA256 != contract || g.IssuerKey != req.SignerKey || !sameJSON(g.Scope, []string{"pay"}) || g.Budget == nil || *g.Budget < t.SpendCap || g.Network != t.Network || g.Genesis != t.Genesis {
			return PayTermsV2{}, bad("SIGNING_REQUEST_PAYLOAD")
		}
		want = grantSigningDigest(req.Payload)
	default:
		return PayTermsV2{}, bad("SIGNING_REQUEST_PURPOSE")
	}
	if req.Digest != want {
		return PayTermsV2{}, bad("SIGNING_REQUEST_DIGEST")
	}
	return t, nil
}

// fileExchangeSigner is the offline transport to a signer on another machine
// (Ivan's Mac). It holds no key; it moves request and signature files.
type fileExchangeSigner struct {
	outbox, inbox, key string
	poll               time.Duration
}

// NewFileExchangeSigner returns the offline file-exchange signer. A request
// is written atomically to outbox/<purpose>-<digest>.request.json (0600); the
// answer is read from inbox/<purpose>-<digest>.signature.json, polling every
// poll (1 s when poll <= 0) until ctx ends.
func NewFileExchangeSigner(outbox, inbox, key string, poll time.Duration) DigestSigner {
	if poll <= 0 {
		poll = time.Second
	}
	return &fileExchangeSigner{outbox: outbox, inbox: inbox, key: key, poll: poll}
}

func (s *fileExchangeSigner) XOnlyKey() string { return s.key }

func (s *fileExchangeSigner) Sign(ctx context.Context, req PayGrantSigningRequest) (PayGrantSignature, error) {
	var none PayGrantSignature
	if req.SignerKey != s.key {
		return none, bad("PAY_GRANT_SIGNER_KEY")
	}
	switch req.Purpose {
	case SignPurposeConsentEvent, SignPurposeContract, SignPurposeGrant:
	default:
		return none, bad("SIGNING_REQUEST_PURPOSE")
	}
	// The digest is part of a file name: only 64 lowercase hex may pass.
	if !digest(req.Digest) {
		return none, bad("SIGNING_REQUEST_KEY")
	}
	body, e := json.Marshal(req)
	if e != nil || len(body) > payGrantExchangeLimit {
		return none, bad("SIGNING_REQUEST_ENCODING")
	}
	name := req.Purpose + "-" + req.Digest
	if e = writeExchangeRequest(filepath.Join(s.outbox, name+".request.json"), body); e != nil {
		return none, e
	}
	answer := filepath.Join(s.inbox, name+".signature.json")
	tick := time.NewTicker(s.poll)
	defer tick.Stop()
	for {
		raw, e := readExchangeSignature(answer)
		if e != nil {
			return none, e
		}
		if raw != nil {
			var sig PayGrantSignature
			if canonical(raw, &sig) != nil {
				return none, bad("SIGNATURE_FILE_ENCODING")
			}
			return sig, nil
		}
		select {
		case <-ctx.Done():
			return none, payGrantFail("SIGNATURE_WAIT", ctx.Err())
		case <-tick.C:
		}
	}
}

// writeExchangeRequest publishes the request by rename, so the remote side
// never reads a partial file. An existing request is accepted only if it holds
// the same bytes (a re-run after an interruption).
func writeExchangeRequest(path string, body []byte) error {
	if old, e := os.ReadFile(path); e == nil {
		if !bytes.Equal(old, body) {
			return bad("SIGNING_REQUEST_CONFLICT")
		}
		return nil
	} else if !errors.Is(e, fs.ErrNotExist) {
		return payGrantFail("SIGNING_REQUEST_WRITE", e)
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".paygrant-request-*")
	if e != nil {
		return payGrantFail("SIGNING_REQUEST_WRITE", e)
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if e = f.Chmod(0600); e == nil {
		if _, e = f.Write(body); e == nil {
			e = f.Sync()
		}
	}
	if ce := f.Close(); e == nil {
		e = ce
	}
	if e != nil {
		return payGrantFail("SIGNING_REQUEST_WRITE", e)
	}
	if e = os.Rename(tmp, path); e != nil {
		return payGrantFail("SIGNING_REQUEST_WRITE", e)
	}
	ok = true
	return nil
}

// readExchangeSignature returns nil, nil while the answer is absent. A
// symlink, a non-regular file or an oversized file is refused, never followed.
func readExchangeSignature(path string) ([]byte, error) {
	info, e := os.Lstat(path)
	if errors.Is(e, fs.ErrNotExist) {
		return nil, nil
	}
	if e != nil {
		return nil, payGrantFail("SIGNATURE_FILE", e)
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > payGrantExchangeLimit {
		return nil, bad("SIGNATURE_FILE")
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		return nil, payGrantFail("SIGNATURE_FILE", e)
	}
	return raw, nil
}
