package journal

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// This frozen raw schema is test-only and was copied from f5dfaa70. It must not
// acquire logging methods or track future changes to the production Slot type.
type legacySlot struct {
	ID             string   `json:"id"`
	StationName    string   `json:"station_name"`
	RenterPubKey   string   `json:"renter_pubkey"` // 64 lower hex, grantee key
	CertificateB64 string   `json:"certificate_b64"`
	BookingID      string   `json:"booking_id,omitempty"` // M3 booking id (Track B key)
	ContractSHA256 string   `json:"contract_sha256"`
	ContractB64    string   `json:"contract_b64,omitempty"` // exact consent-bound bytes; retained for model revocation
	NotBefore      int64    `json:"not_before"`
	NotAfter       int64    `json:"not_after"` // half-open: [NotBefore, NotAfter)
	Started        bool     `json:"started"`
	Starting       bool     `json:"starting,omitempty"` // retained on failed start until destruction
	SeenRumorIDs   []string `json:"seen_rumor_ids"`
	Refusals       int      `json:"refusals"`
	Ended          bool     `json:"ended"`
	EndReason      string   `json:"end_reason,omitempty"`
	Destroyed      bool     `json:"destroyed"`
	// ChannelSecretHex is the per-slot stationlink credential key
	// (64 lower hex = 32 bytes). Journal files are 0600 in a 0700
	// dir on the gateway host only. Cleared durably at slot end.
	ChannelSecretHex string `json:"channel_secret_hex,omitempty"`
	// TokenSHA256 is the hash of the per-slot Track B token (the
	// token itself lives only in the station home).
	TokenSHA256 string `json:"token_sha256,omitempty"`
	// StationHome/User locate the created station for Destroy after
	// a gateway restart (no PID is ever persisted).
	StationHome string `json:"station_home,omitempty"`
	StationUser string `json:"station_user,omitempty"`
	// Operations are the durable closer-operation records.
	Operations []OpRecord `json:"operations,omitempty"`
	Deliveries []Delivery `json:"deliveries,omitempty"`

	seen map[string]bool `json:"-"`
}

// Old raw-slot bytes survive private encoding, disk persistence and restart;
// generic encoding redacts, and ending the slot removes its credential.
func TestJournalPrivateWireCompatibility(t *testing.T) {
	channel := bytes.Repeat([]byte("x"), 32)
	marker := hex.EncodeToString(channel)
	before, err := json.Marshal(legacySlot{ID: "fixture", RenterPubKey: "renter", ChannelSecretHex: marker})
	if err != nil {
		t.Fatal("legacy journal fixture refused")
	}
	var slot Slot
	if json.Unmarshal(before, &slot) != nil || slot.ChannelSecretHex.Reveal() != marker {
		t.Fatal("legacy journal credential unavailable")
	}
	after, err := EncodePrivateSlot(&slot)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("private journal bytes changed")
	}
	public, err := json.Marshal(slot)
	if err != nil || bytes.Contains(public, []byte(marker)) {
		t.Fatal("journal credential disclosed by generic JSON")
	}
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil || store.Put(&slot) != nil {
		t.Fatal("private journal persistence refused")
	}
	disk, err := os.ReadFile(filepath.Join(dir, "slot-fixture.json"))
	if err != nil || !bytes.Equal(disk, before) {
		t.Fatal("persisted journal bytes changed")
	}
	store, err = Open(dir)
	if err != nil {
		t.Fatal("private journal restart refused")
	}
	got, ok := store.Get("fixture")
	if !ok || got.ChannelSecretHex.Reveal() != marker {
		t.Fatal("private journal restart lost credential")
	}
	if store.MarkEnded("fixture", "fixture") != nil {
		t.Fatal("journal end refused")
	}
	store, err = Open(dir)
	if err != nil {
		t.Fatal("ended journal restart refused")
	}
	got, ok = store.Get("fixture")
	if !ok || !got.Ended || !got.ChannelSecretHex.IsZero() {
		t.Fatal("ended journal retained credential")
	}
}
