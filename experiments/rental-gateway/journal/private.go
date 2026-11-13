package journal

import "encoding/json"

// slotPrivate is used only by the explicit private persistence encoder.
type slotPrivate struct {
	ID               string          `json:"id"`
	StationName      string          `json:"station_name"`
	RenterPubKey     string          `json:"renter_pubkey"`
	CertificateB64   string          `json:"certificate_b64"`
	BookingID        string          `json:"booking_id,omitempty"`
	ContractSHA256   string          `json:"contract_sha256"`
	ContractB64      string          `json:"contract_b64,omitempty"`
	NotBefore        int64           `json:"not_before"`
	NotAfter         int64           `json:"not_after"`
	Started          bool            `json:"started"`
	Starting         bool            `json:"starting,omitempty"`
	SeenRumorIDs     []string        `json:"seen_rumor_ids"`
	Refusals         int             `json:"refusals"`
	Ended            bool            `json:"ended"`
	EndReason        string          `json:"end_reason,omitempty"`
	Destroyed        bool            `json:"destroyed"`
	ChannelSecretHex string          `json:"channel_secret_hex,omitempty"`
	TokenSHA256      string          `json:"token_sha256,omitempty"`
	StationHome      string          `json:"station_home,omitempty"`
	StationUser      string          `json:"station_user,omitempty"`
	Operations       []OpRecord      `json:"operations,omitempty"`
	Deliveries       []Delivery      `json:"deliveries,omitempty"`
	seen             map[string]bool `json:"-"`
}

func slotPrivateValue(s Slot) slotPrivate {
	return slotPrivate{
		ID:               s.ID,
		StationName:      s.StationName,
		RenterPubKey:     s.RenterPubKey,
		CertificateB64:   s.CertificateB64,
		BookingID:        s.BookingID,
		ContractSHA256:   s.ContractSHA256,
		ContractB64:      s.ContractB64,
		NotBefore:        s.NotBefore,
		NotAfter:         s.NotAfter,
		Started:          s.Started,
		Starting:         s.Starting,
		SeenRumorIDs:     s.SeenRumorIDs,
		Refusals:         s.Refusals,
		Ended:            s.Ended,
		EndReason:        s.EndReason,
		Destroyed:        s.Destroyed,
		ChannelSecretHex: s.ChannelSecretHex.Reveal(),
		TokenSHA256:      s.TokenSHA256,
		StationHome:      s.StationHome,
		StationUser:      s.StationUser,
		Operations:       s.Operations,
		Deliveries:       s.Deliveries,
		seen:             s.seen,
	}
}

// EncodePrivateSlot preserves private journal bytes; generic JSON stays redacted.
func EncodePrivateSlot(s *Slot) ([]byte, error) { return json.Marshal(slotPrivateValue(*s)) }
