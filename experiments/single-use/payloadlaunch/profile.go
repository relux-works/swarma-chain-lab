// Package payloadlaunch defines DK5b's canonical installed launch contracts.
// It constructs bytes and argv only; it never reads files, provisions a slot,
// launches a process, trusts an environment variable or establishes root custody.
package payloadlaunch

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"path"
	"slices"
	"strconv"
	"strings"
)

const (
	Version          uint64 = 1
	ProfileID               = "dk5b-v1"
	EnvelopeRoot            = "/var/lib/swarma-slotd-demo-payload"
	AnchorRoot              = "/etc/swarma/payload-anchors"
	MaxProfileBytes         = 4096
	MaxManifestBytes        = 16384
	MaxAnchorBytes          = 2048
)

type Code string

func (c Code) Error() string { return string(c) }

const (
	ErrMissing     Code = "PAYLOAD_LAUNCH_MISSING"
	ErrUnsupported Code = "PAYLOAD_LAUNCH_UNSUPPORTED"
	ErrCorrupt     Code = "PAYLOAD_LAUNCH_CORRUPT"
	ErrBinding     Code = "PAYLOAD_LAUNCH_BINDING"
)

// File's presence is proved by the caller's custody-checked read. I/O failures
// are not absence. Existing zero-byte files have Present=true and are corrupt.
type File struct {
	Present bool
	Bytes   []byte
}

// Profile is root-policy input, never a create-request option. A provisioner
// supplies its approved static release and literal operator settings.
type Profile struct {
	Version             uint64 `json:"v"`
	Kind                string `json:"kind"`
	Executable          string `json:"executable"`
	ExecutableSHA256    string `json:"executable_sha256"`
	StaticReleaseSHA256 string `json:"static_release_sha256"`
	Gateway             string `json:"gateway"`
	GatewayCertSHA256   string `json:"gateway_cert_sha256"`
	Dialect             string `json:"dialect"`
	Model               string `json:"model"`
	MaxTokens           uint64 `json:"max_tokens"`
}

type Paths struct {
	Envelope, Inputs, Bootstrap, CA, ModelConfig, Journal           string
	StaticManifest, StaticSignature, StaticAnchor, Anchor, Manifest string
}

func hexOK(s string, size int) bool {
	if len(s) != size {
		return false
	}
	b, e := hex.DecodeString(s)
	return e == nil && hex.EncodeToString(b) == s
}
func canonical(v any) []byte { b, _ := json.Marshal(v); return append(b, '\n') }
func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func presence(f File) error {
	if !f.Present {
		if len(f.Bytes) != 0 {
			return ErrCorrupt
		}
		return ErrMissing
	}
	return nil
}
func decode(f File, limit int, out any) error {
	if e := presence(f); e != nil {
		return e
	}
	if len(f.Bytes) == 0 || len(f.Bytes) > limit || json.Unmarshal(f.Bytes, out) != nil || !bytes.Equal(f.Bytes, canonical(out)) {
		return ErrCorrupt
	}
	return nil
}
func uidOK(uid uint32) bool { return uid != 0 && uid != 65534 && uid != ^uint32(0) }

// SlotUID mirrors slotd v0's full 0..9999 allocation range, including exclusion
// of nobody and the uint32 sentinel; it does not allocate an OS account.
func SlotUID(base, slot uint32) (uint32, error) {
	if base == 0 || slot > 9999 || uint64(base)+9999 >= uint64(^uint32(0)) || (base <= 65534 && uint64(base)+9999 >= 65534) {
		return 0, ErrCorrupt
	}
	return base + slot, nil
}

// PathsFor derives the only accepted per-UID namespace. Custody, physical
// ancestry and mount visibility still require descriptor-based runtime checks.
func PathsFor(uid uint32) (Paths, error) {
	if !uidOK(uid) {
		return Paths{}, ErrCorrupt
	}
	u := strconv.FormatUint(uint64(uid), 10)
	p, a := EnvelopeRoot+"/"+u, AnchorRoot+"/"+u
	return Paths{Envelope: p, Inputs: p + "/inputs", Bootstrap: p + "/inputs/bootstrap", CA: p + "/inputs/ca.pem", ModelConfig: p + "/inputs/model.json", Journal: p + "/journal", StaticManifest: p + "/static/manifest.json", StaticSignature: p + "/static/manifest.sig", StaticAnchor: a + "/10-install.conf", Anchor: a + "/20-slot.conf", Manifest: p + "/inputs/slot.json"}, nil
}
func cleanExecutable(s string) bool {
	if !path.IsAbs(s) || path.Clean(s) != s || s == "/" || s == EnvelopeRoot || strings.HasPrefix(s, EnvelopeRoot+"/") || s == AnchorRoot || strings.HasPrefix(s, AnchorRoot+"/") || len(s) > 4096 {
		return false
	}
	for _, r := range s {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/._-", r) {
			return false
		}
	}
	return true
}
func validProfile(p Profile) error {
	if p.Version == 0 || p.Kind != "station-payload" || !cleanExecutable(p.Executable) || !hexOK(p.ExecutableSHA256, 64) || !hexOK(p.StaticReleaseSHA256, 64) || !hexOK(p.GatewayCertSHA256, 64) || (p.Dialect != "messages" && p.Dialect != "responses") || len(p.Model) == 0 || len(p.Model) > 128 || p.MaxTokens == 0 {
		return ErrCorrupt
	}
	for _, r := range p.Model {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:/@+-", r) {
			return ErrCorrupt
		}
	}
	a, e := netip.ParseAddrPort(p.Gateway)
	if e != nil || a.String() != p.Gateway || a.Port() == 0 || a.Addr().Zone() != "" || a.Addr().Is4In6() || a.Addr().IsUnspecified() || a.Addr().IsMulticast() {
		return ErrCorrupt
	}
	if len(canonical(p)) > MaxProfileBytes {
		return ErrCorrupt
	}
	if p.Version != Version {
		return ErrUnsupported
	}
	return nil
}
func EncodeProfile(p Profile) ([]byte, error) {
	if e := validProfile(p); e != nil {
		return nil, e
	}
	b := canonical(p)
	if len(b) > MaxProfileBytes {
		return nil, ErrCorrupt
	}
	return b, nil
}
func DecodeProfile(f File) (Profile, error) {
	var p Profile
	if e := decode(f, MaxProfileBytes, &p); e != nil {
		return Profile{}, e
	}
	if e := validProfile(p); e != nil {
		return Profile{}, e
	}
	return p, nil
}

// Argv emits exactly the installed profile's literals. All values come from a
// validated manifest derived from root policy/receipts; no generic caller argv,
// executable override, shell, environment expansion or default is accepted.
func Argv(m Manifest) ([]string, error) {
	if e := validManifest(m); e != nil {
		return nil, e
	}
	p := m.Profile
	return []string{p.Executable, "-slot-profile", ProfileID, "-bootstrap", m.Bootstrap.Path, "-ca", m.CA.Path, "-model-config", m.ModelConfig.Path, "-journal-dir", m.Journal.Path, "-gateway", p.Gateway, "-gateway-pin", p.GatewayCertSHA256, "-dialect", p.Dialect, "-model", p.Model, "-max-tokens", strconv.FormatUint(p.MaxTokens, 10)}, nil
}

// ValidateArgv checks the complete observed vector, including argv[0], without
// parsing away duplicates, order or unknown options. It proves no execution.
func ValidateArgv(m Manifest, actual []string) error {
	expected, e := Argv(m)
	if e != nil {
		return e
	}
	if !slices.Equal(actual, expected) {
		return ErrBinding
	}
	return nil
}

// CheckProfile compares the admitted manifest to current trusted root policy.
// A creation receipt alone must not silently authorize obsolete launch policy.
func CheckProfile(m Manifest, current Profile) error {
	if e := validProfile(current); e != nil {
		return e
	}
	if e := validManifest(m); e != nil {
		return e
	}
	if m.Profile != current {
		return ErrBinding
	}
	return nil
}
