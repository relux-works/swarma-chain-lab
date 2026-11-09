package rental

import "net/url"

// NostrNames is the root-only N1 subset allowed in K1 authority values.
// Arbitrary social local-parts belong to the separate discovery package.
type NostrNames struct {
	Root string `json:"_"`
}
type NostrDescriptor struct {
	Names  NostrNames          `json:"names"`
	Relays map[string][]string `json:"relays,omitempty"`
}

func validateNostr(d *NostrDescriptor) error {
	if d == nil {
		return nil
	}
	if !pubkey(d.Names.Root) {
		return bad("NOSTR_KEY")
	}
	if d.Relays == nil {
		return nil
	}
	if len(d.Relays) != 1 {
		return bad("NOSTR_RELAYS")
	}
	relays, ok := d.Relays[d.Names.Root]
	if !ok || len(relays) == 0 {
		return bad("NOSTR_RELAYS")
	}
	seen := map[string]bool{}
	for _, raw := range relays {
		u, e := url.Parse(raw)
		if e != nil || !u.IsAbs() || (u.Scheme != "ws" && u.Scheme != "wss") || u.Hostname() == "" || u.User != nil || u.Fragment != "" || seen[raw] {
			return bad("NOSTR_RELAY_URL")
		}
		seen[raw] = true
	}
	return nil
}
