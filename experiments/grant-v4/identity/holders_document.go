package identity

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"
)

const MaxHoldersListBytes = 262144

// ReadInlineHolders reads the transition form of LIP-0010 section 10.9 at
// version 0.1.53. Its strict ordering/uniqueness matches the existing draft
// reader, not the intentionally weaker 0.1.51 stated-fact profile. It reads
// no journal form mark and therefore does not decide whether migration allows
// this document at an admission.
func ReadInlineHolders(raw []byte) (R1Value, error) {
	return ReadR1Value(R1DraftLab, raw)
}

var (
	ErrHolderPinInvalid   = errors.New("HOLDER_PIN_INVALID")
	ErrHolderListInvalid  = errors.New("HOLDER_LIST_INVALID")
	ErrHolderListMismatch = errors.New("HOLDER_LIST_MISMATCH")
)

// HolderPin is only a document-level hash/version pin (LIP-0010 H8-H10).
// Reading it establishes no confirmed name output, rollback floor or journal.
type HolderPin struct {
	Seq    uint64 `json:"seq"`
	SHA256 string `json:"sha256"`
}

type HolderOutpoint struct {
	TxID string `json:"txid"`
	Vout uint32 `json:"vout"`
}

type HolderEntry struct {
	Name string         `json:"name"`
	Key  string         `json:"key"`
	Seal HolderOutpoint `json:"seal"`
}

type holdersDocument struct {
	Schema  string        `json:"schema"`
	Network string        `json:"network"`
	Owner   string        `json:"owner"`
	Seq     uint64        `json:"seq"`
	Holders []HolderEntry `json:"holders"`
}

// HoldersList is an immutable document under a hash pin, never a liveness
// assertion. Its entries are meaningful only after all admission reads.
type HoldersList struct {
	raw     []byte
	entries []HolderEntry
}

func (h *HoldersList) Bytes() []byte { return bytes.Clone(h.raw) }
func (h *HoldersList) Entry(name string) (HolderEntry, bool) {
	for _, e := range h.entries {
		if e.Name == name {
			return e, true
		}
	}
	return HolderEntry{}, false
}

func holderName(name string) bool {
	if !strings.HasPrefix(name, "id/") || len(name) < 4 || len(name) > 255 {
		return false
	}
	for _, c := range []byte(name[3:]) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}
func holderHash(s string) bool { return len(s) == 64 && isLowerHex(s) }

// holderObject retains the written spelling of member names. JSON decoding
// alone cannot tell the exact name from an escaped alias (H9). Duplicate
// decoded names are explicitly rejected, at each inspected object depth.
func holderObject(raw []byte) ([]string, []string, []json.RawMessage, error) {
	if len(raw) == 0 || raw[0] != '{' || !utf8.Valid(raw) {
		return nil, nil, nil, ErrHolderListInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if _, err := d.Token(); err != nil {
		return nil, nil, nil, err
	}
	var names, written []string
	var values []json.RawMessage
	seen := map[string]bool{}
	for d.More() {
		start := int(d.InputOffset())
		token, err := d.Token()
		name, ok := token.(string)
		if err != nil || !ok || seen[name] {
			return nil, nil, nil, ErrHolderListInvalid
		}
		seen[name] = true
		span := bytes.TrimLeft(raw[start:int(d.InputOffset())], ", \t\r\n")
		names = append(names, name)
		written = append(written, string(span))
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return nil, nil, nil, err
		}
		values = append(values, value)
	}
	if _, err := d.Token(); err != nil || d.InputOffset() != int64(len(raw)) {
		return nil, nil, nil, ErrHolderListInvalid
	}
	return names, written, values, nil
}

// ReadHolderPin reads H8/H9 only. A nil pin without error means the exact
// member is absent: H7 lists no name. Other top-level values are uninterpreted.
func ReadHolderPin(raw []byte) (*HolderPin, error) {
	if len(raw) > 520 {
		return nil, ErrHolderPinInvalid
	}
	// Top-level unrelated duplicate names do not select a holders pin. The
	// existing name-value reader separately applies its own binding rules.
	d := json.NewDecoder(bytes.NewReader(raw))
	if len(raw) == 0 || raw[0] != '{' || !utf8.Valid(raw) {
		return nil, ErrHolderPinInvalid
	}
	if _, err := d.Token(); err != nil {
		return nil, ErrHolderPinInvalid
	}
	var pinRaw []byte
	for d.More() {
		start := int(d.InputOffset())
		token, err := d.Token()
		name, ok := token.(string)
		if err != nil || !ok {
			return nil, ErrHolderPinInvalid
		}
		span := bytes.TrimLeft(raw[start:int(d.InputOffset())], ", \t\r\n")
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, ErrHolderPinInvalid
		}
		if strings.EqualFold(name, "swarma-holders") {
			if name != "swarma-holders" || string(span) != `"swarma-holders"` || pinRaw != nil {
				return nil, ErrHolderPinInvalid
			}
			pinRaw = value
		}
	}
	if _, err := d.Token(); err != nil || d.InputOffset() != int64(len(raw)) {
		return nil, ErrHolderPinInvalid
	}
	if pinRaw == nil {
		return nil, nil
	}
	if !holderNames(pinRaw, "seq", "sha256") {
		return nil, ErrHolderPinInvalid
	}
	var pin HolderPin
	if json.Unmarshal(pinRaw, &pin) != nil || pin.Seq == 0 || pin.Seq > 9007199254740991 || !holderHash(pin.SHA256) || !bytes.Equal(pinRaw, compactR1(pin)) {
		return nil, ErrHolderPinInvalid
	}
	return &pin, nil
}
func holderNames(raw []byte, expected ...string) bool {
	names, _, _, err := holderObject(raw)
	if err != nil || len(names) != len(expected) {
		return false
	}
	for i := range names {
		if names[i] != expected[i] {
			return false
		}
	}
	return true
}

// VerifyHoldersList applies H53 exactly: byte bound, hash, whole list form,
// then binding. It neither reads a seal nor takes a list into a holder journal.
// The pin and landlord/network context MUST come from independently read
// configuration/name facts, not from the supplied list.
func VerifyHoldersList(raw []byte, pin HolderPin, network, landlord string) (*HoldersList, error) {
	if len(raw) > MaxHoldersListBytes {
		return nil, ErrHolderListInvalid
	}
	hash := sha256.Sum256(raw)
	if hex.EncodeToString(hash[:]) != pin.SHA256 {
		return nil, ErrHolderListMismatch
	}
	var list holdersDocument
	if !holderNames(raw, "schema", "network", "owner", "seq", "holders") || json.Unmarshal(raw, &list) != nil || !bytes.Equal(raw, compactR1(list)) || list.Schema != "swarma-holders-list/1" || list.Network != "main" && list.Network != "regtest" || !holderName(list.Owner) || list.Seq == 0 || list.Seq > 9007199254740991 || list.Holders == nil || len(list.Holders) > 1024 {
		return nil, ErrHolderListInvalid
	}
	_, _, members, _ := holderObject(raw)
	var entries []json.RawMessage
	if json.Unmarshal(members[4], &entries) != nil {
		return nil, ErrHolderListInvalid
	}
	seals := map[HolderOutpoint]bool{}
	for i, e := range list.Holders {
		if !holderNames(entries[i], "name", "key", "seal") || !holderName(e.Name) || !holderHash(e.Seal.TxID) || i > 0 && list.Holders[i-1].Name >= e.Name || seals[e.Seal] {
			return nil, ErrHolderListInvalid
		}
		if _, err := ParsePin(e.Key); err != nil {
			return nil, ErrHolderListInvalid
		}
		_, _, values, _ := holderObject(entries[i])
		if !holderNames(values[2], "txid", "vout") {
			return nil, ErrHolderListInvalid
		}
		seals[e.Seal] = true
	}
	if list.Seq != pin.Seq || list.Owner != landlord || list.Network != network {
		return nil, ErrHolderListMismatch
	}
	return &HoldersList{raw: bytes.Clone(raw), entries: list.Holders}, nil
}
