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
	Swarma struct {
		Agent AgentBinding `json:"agent"`
	} `json:"swarma"`
}
type landlordBindingValue struct {
	Swarma struct {
		Landlord LandlordBinding `json:"landlord"`
	} `json:"swarma"`
}

func AgentBindingValue(binding AgentBinding) (string, error) {
	if !pubkey(binding.Nostr) || !station(binding.Landlord) {
		return "", bad("AGENT_BINDING")
	}
	var v agentBindingValue
	v.Swarma.Agent = binding
	b, e := json.Marshal(v)
	return string(b), e
}
func ParseAgentBinding(raw string) (AgentBinding, error) {
	var v agentBindingValue
	if len(raw) > 520 || canonical([]byte(raw), &v) != nil {
		return AgentBinding{}, bad("AGENT_BINDING_VALUE")
	}
	b := v.Swarma.Agent
	if !pubkey(b.Nostr) || !station(b.Landlord) {
		return AgentBinding{}, bad("AGENT_BINDING")
	}
	return b, nil
}
func LandlordValue(binding LandlordBinding) (string, error) {
	if !pubkey(binding.Grant) {
		return "", bad("LANDLORD_KEY")
	}
	var v landlordBindingValue
	v.Swarma.Landlord = binding
	b, e := json.Marshal(v)
	return string(b), e
}
func ParseLandlordValue(raw string) (LandlordBinding, error) {
	var v landlordBindingValue
	if len(raw) > 520 || canonical([]byte(raw), &v) != nil {
		return LandlordBinding{}, bad("LANDLORD_VALUE")
	}
	b := v.Swarma.Landlord
	if !pubkey(b.Grant) {
		return LandlordBinding{}, bad("LANDLORD_KEY")
	}
	return b, nil
}
