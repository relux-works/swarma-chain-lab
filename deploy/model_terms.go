package deploy

import "encoding/json"

// This independent deployment projection matches the signed booking field order.
// Browser-visible contract integers must be exactly representable by JavaScript.
type modelCaps struct {
	InputTokens            uint64 `json:"input_tokens"`
	OutputTokens           uint64 `json:"output_tokens"`
	Requests               uint64 `json:"requests"`
	MaxTokens              uint64 `json:"max_tokens"`
	CostNanoUSD            uint64 `json:"cost_nano_usd"`
	DefaultMaxOutputTokens uint64 `json:"default_max_output_tokens"`
}

func (c modelCaps) valid() bool {
	for _, n := range []uint64{c.InputTokens, c.OutputTokens, c.Requests, c.MaxTokens, c.CostNanoUSD, c.DefaultMaxOutputTokens} {
		if n == 0 || n > (1<<53)-1 {
			return false
		}
	}
	return c.DefaultMaxOutputTokens <= c.MaxTokens && c.MaxTokens <= c.OutputTokens
}

type bookingTemplate struct {
	Version        int        `json:"version"`
	ID             string     `json:"id"`
	ProfileID      string     `json:"profile_id"`
	ProfileVersion string     `json:"profile_version"`
	ProfileSHA256  string     `json:"profile_sha256"`
	Allowed        []string   `json:"allowed"`
	Forbidden      []string   `json:"forbidden"`
	BudgetSat      int64      `json:"budget_sat"`
	ModelCaps      *modelCaps `json:"model_caps,omitempty"`
}

func templateCapsMatch(t bookingTemplate, c *modelCaps) bool {
	if t.Version == 1 {
		return t.ModelCaps == nil && c == nil
	}
	return t.Version == 2 && t.ModelCaps != nil && c != nil && t.ModelCaps.valid() && c.valid() && *t.ModelCaps == *c
}

// CompareModelTerms checks public cross-document bindings only. Individual
// service validation remains mandatory: this does not replace native startup,
// read credentials, contact providers, or establish host/runtime qualification.
func CompareModelTerms(bookingRaw, profile, gatewayRaw, modelRaw, pairRaw []byte) error {
	for _, raw := range [][]byte{bookingRaw, gatewayRaw, modelRaw, pairRaw} {
		if e := ValidatePublicJSON(raw); e != nil {
			return e
		}
	}
	if len(profile) == 0 || len(profile) > 1<<20 {
		return ErrPolicy
	}
	var b struct {
		Version int `json:"service_version"`
		Config  struct {
			Template       json.RawMessage `json:"template"`
			TemplateSHA256 string          `json:"template_sha256"`
			ModelCaps      *modelCaps      `json:"model_caps"`
		} `json:"config"`
	}
	var g struct {
		ModelProxy *gatewayModelProxy `json:"model_proxy"`
		Exchange   struct {
			TemplateSHA256 string `json:"template_sha256"`
			ProfileSHA256  string `json:"profile_sha256"`
		} `json:"exchange"`
	}
	var t bookingTemplate
	if json.Unmarshal(bookingRaw, &b) != nil || json.Unmarshal(gatewayRaw, &g) != nil || b.Version != 2 || serviceDecode(b.Config.Template, &t, false) != nil || t.Version != 2 || !templateCapsMatch(t, b.Config.ModelCaps) || g.ModelProxy == nil {
		return ErrPolicy
	}
	encoded, e := json.Marshal(t)
	if e != nil || digest(encoded) != b.Config.TemplateSHA256 || g.Exchange.TemplateSHA256 != b.Config.TemplateSHA256 || digest(profile) != t.ProfileSHA256 || g.Exchange.ProfileSHA256 != t.ProfileSHA256 || g.ModelProxy.Caps != *t.ModelCaps {
		return ErrPolicy
	}
	if e := validatePayloadInputs([][]byte{pairRaw, modelRaw}); e != nil {
		return e
	}
	var pair payloadPair
	var model modelConfig
	if json.Unmarshal(pairRaw, &pair) != nil || json.Unmarshal(modelRaw, &model) != nil {
		return ErrPolicy
	}
	if pair.MaxTokens > t.ModelCaps.MaxTokens || t.ModelCaps.DefaultMaxOutputTokens > model.Models[pair.Model].ContextTokens || pair.Endpoint != g.ModelProxy.Origin || pair.CertSHA256 != g.ModelProxy.CertSHA256 {
		return ErrPolicy
	}
	return nil
}
