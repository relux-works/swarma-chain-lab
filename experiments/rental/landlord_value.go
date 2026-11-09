package rental

import "encoding/json"

type AgentBinding struct {
	Nostr    string `json:"nostr"`
	Landlord string `json:"landlord"`
}
type LandlordBinding struct {
	Grant string `json:"grant"`
}
type agentBindingValue struct {
	Nostr  *NostrDescriptor `json:"nostr,omitempty"`
	Swarma struct {
		Agent AgentBinding `json:"agent"`
	} `json:"swarma"`
}
type landlordBindingValue struct {
	Nostr  *NostrDescriptor `json:"nostr,omitempty"`
	Swarma struct {
		Landlord LandlordBinding `json:"landlord"`
	} `json:"swarma"`
}

func AgentBindingValue(binding AgentBinding) (string, error) { return agentValue(binding, nil) }
func CombinedAgentBindingValue(binding AgentBinding, descriptor NostrDescriptor) (string, error) {
	return agentValue(binding, &descriptor)
}
func agentValue(binding AgentBinding, descriptor *NostrDescriptor) (string, error) {
	if !pubkey(binding.Nostr) || !station(binding.Landlord) {
		return "", bad("AGENT_BINDING")
	}
	if e := validateNostr(descriptor); e != nil {
		return "", e
	}
	if descriptor != nil && descriptor.Names.Root != binding.Nostr {
		return "", bad("AGENT_NOSTR_MISMATCH")
	}
	var v agentBindingValue
	v.Nostr = descriptor
	v.Swarma.Agent = binding
	b, e := json.Marshal(v)
	if e != nil {
		return "", e
	}
	if len(b) > 520 {
		return "", bad("AGENT_BINDING_VALUE")
	}
	return string(b), nil
}
func ParseAgentBinding(raw string) (AgentBinding, error) {
	b, _, e := ParseAgentIdentity(raw)
	return b, e
}

// ParseAgentIdentity exposes optional discovery metadata without changing the
// authority binding. Every caller shares the same strict validation path.
func ParseAgentIdentity(raw string) (AgentBinding, *NostrDescriptor, error) {
	var v agentBindingValue
	if len(raw) > 520 || canonical([]byte(raw), &v) != nil {
		return AgentBinding{}, nil, bad("AGENT_BINDING_VALUE")
	}
	b := v.Swarma.Agent
	if !pubkey(b.Nostr) || !station(b.Landlord) {
		return AgentBinding{}, nil, bad("AGENT_BINDING")
	}
	if e := validateNostr(v.Nostr); e != nil {
		return AgentBinding{}, nil, e
	}
	if v.Nostr != nil && v.Nostr.Names.Root != b.Nostr {
		return AgentBinding{}, nil, bad("AGENT_NOSTR_MISMATCH")
	}
	return b, v.Nostr, nil
}
func LandlordValue(binding LandlordBinding) (string, error) { return landlordValue(binding, nil) }
func CombinedLandlordValue(binding LandlordBinding, descriptor NostrDescriptor) (string, error) {
	return landlordValue(binding, &descriptor)
}
func landlordValue(binding LandlordBinding, descriptor *NostrDescriptor) (string, error) {
	if !pubkey(binding.Grant) {
		return "", bad("LANDLORD_KEY")
	}
	if e := validateNostr(descriptor); e != nil {
		return "", e
	}
	var v landlordBindingValue
	v.Nostr = descriptor
	v.Swarma.Landlord = binding
	b, e := json.Marshal(v)
	if e != nil {
		return "", e
	}
	if len(b) > 520 {
		return "", bad("LANDLORD_VALUE")
	}
	return string(b), nil
}
func ParseLandlordValue(raw string) (LandlordBinding, error) {
	b, _, e := ParseLandlordIdentity(raw)
	return b, e
}

// The social identity is independent of the landlord's grant-signing key.
func ParseLandlordIdentity(raw string) (LandlordBinding, *NostrDescriptor, error) {
	var v landlordBindingValue
	if len(raw) > 520 || canonical([]byte(raw), &v) != nil {
		return LandlordBinding{}, nil, bad("LANDLORD_VALUE")
	}
	b := v.Swarma.Landlord
	if !pubkey(b.Grant) {
		return LandlordBinding{}, nil, bad("LANDLORD_KEY")
	}
	if e := validateNostr(v.Nostr); e != nil {
		return LandlordBinding{}, nil, e
	}
	return b, v.Nostr, nil
}
