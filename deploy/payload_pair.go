package deploy

// payloadPair describes the pinned operator argv and the expected public model
// endpoint. It contains no private bootstrap or credential values. The same
// values are checked by station-payload.NewPinned before any network activity.
type payloadPair struct {
	Dialect    string `json:"dialect"`
	Model      string `json:"model"`
	MaxTokens  uint64 `json:"max_tokens"`
	Endpoint   string `json:"model_endpoint"`
	CertSHA256 string `json:"model_cert_sha256"`
}

func validatePayloadInputs(inputs [][]byte) error {
	if len(inputs) != 2 {
		return ErrPolicy
	}
	for _, raw := range inputs {
		if ValidatePublicJSON(raw) != nil {
			return ErrPolicy
		}
	}
	var p payloadPair
	var c modelConfig
	if serviceDecode(inputs[0], &p, true) != nil || serviceDecode(inputs[1], &c, true) != nil || validateModel(inputs[1], c.Listen) != nil {
		return ErrPolicy
	}
	m, ok := c.Models[p.Model]
	if !ok || p.MaxTokens == 0 || p.MaxTokens > m.ContextTokens || p.Endpoint != c.Endpoint.URL || p.CertSHA256 != c.Endpoint.CertSHA256 {
		return ErrPolicy
	}
	want := "messages"
	if _, ok := c.ModelProfiles[p.Model]; ok {
		want = "responses"
	}
	if p.Dialect != want {
		return ErrPolicy
	}
	return nil
}
