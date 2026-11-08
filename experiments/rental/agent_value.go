package rental

import "encoding/json"

// AgentKeys is the exact LIP-0003 name value payload. Ownership of the name
// remains with its separate cold owner; these are public hot-key identities.
type AgentKeys struct {
	Nostr string `json:"nostr"`
	Grant string `json:"grant"`
}

type agentNameValue struct {
	Swarma struct {
		Agent AgentKeys `json:"agent"`
	} `json:"swarma"`
}

// AgentValue emits the single admitted field spelling and compact ordering.
func AgentValue(keys AgentKeys) (string, error) {
	if !pubkey(keys.Nostr) || !pubkey(keys.Grant) {
		return "", bad("AGENT_NAME_KEY")
	}
	var value agentNameValue
	value.Swarma.Agent = keys
	raw, err := json.Marshal(value)
	return string(raw), err
}

// ParseAgentValue rejects extra/missing/alias fields, duplicate keys, escapes,
// whitespace and ordering variants before returning mathematical public keys.
func ParseAgentValue(raw string) (AgentKeys, error) {
	var value agentNameValue
	if len(raw) > 520 || canonical([]byte(raw), &value) != nil {
		return AgentKeys{}, bad("AGENT_NAME_VALUE")
	}
	keys := value.Swarma.Agent
	if !pubkey(keys.Nostr) || !pubkey(keys.Grant) {
		return AgentKeys{}, bad("AGENT_NAME_KEY")
	}
	return keys, nil
}
