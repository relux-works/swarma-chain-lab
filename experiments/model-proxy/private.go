package modelproxy

type credentialPrivate struct {
	Bearer   Secret   `json:"bearer"`
	Endpoint Endpoint `json:"endpoint"`
}

func credentialPrivateValue(s Credential) credentialPrivate {
	return credentialPrivate{
		Bearer:   s.Bearer.Reveal(),
		Endpoint: s.Endpoint,
	}
}

type recordPrivate struct {
	Binding  Binding      `json:"binding"`
	Bearer   Secret       `json:"bearer"`
	Phase    string       `json:"phase"`
	Exposure Counts       `json:"exposure"`
	Observed Usage        `json:"observed"`
	Pending  *reservation `json:"pending"`
}

func recordPrivateValue(s record) recordPrivate {
	return recordPrivate{
		Binding:  s.Binding,
		Bearer:   s.Bearer.Reveal(),
		Phase:    s.Phase,
		Exposure: s.Exposure,
		Observed: s.Observed,
		Pending:  s.Pending,
	}
}

type ledgerPrivate struct {
	Version int                      `json:"version"`
	Config  string                   `json:"config"`
	High    int64                    `json:"high"`
	Records map[string]recordPrivate `json:"records"`
}

func ledgerPrivateValue(s ledger) ledgerPrivate {
	return ledgerPrivate{
		Version: s.Version,
		Config:  s.Config,
		High:    s.High,
		Records: privateRecords(s.Records),
	}
}
func privateRecords(in map[string]record) map[string]recordPrivate {
	if in == nil {
		return nil
	}
	out := make(map[string]recordPrivate, len(in))
	for k, v := range in {
		out[k] = recordPrivateValue(v)
	}
	return out
}

type adminResponsePrivate struct {
	V          int                `json:"v"`
	OK         bool               `json:"ok"`
	Binding    Binding            `json:"binding"`
	Credential *credentialPrivate `json:"credential,omitempty"`
	Error      string             `json:"error,omitempty"`
}

func adminResponsePrivateValue(s adminResponse) adminResponsePrivate {
	return adminResponsePrivate{
		V:          s.V,
		OK:         s.OK,
		Binding:    s.Binding,
		Credential: privateCredentialPointer(s.Credential),
		Error:      s.Error,
	}
}
func privateCredentialPointer(in *Credential) *credentialPrivate {
	if in == nil {
		return nil
	}
	out := credentialPrivateValue(*in)
	return &out
}

// privateValue is invoked only by the explicit private wire/persistence codec.
func privateValue(v any) any {
	switch s := v.(type) {
	case Credential:
		return credentialPrivateValue(s)
	case *Credential:
		if s == nil {
			return nil
		}
		return credentialPrivateValue(*s)
	case record:
		return recordPrivateValue(s)
	case *record:
		if s == nil {
			return nil
		}
		return recordPrivateValue(*s)
	case ledger:
		return ledgerPrivateValue(s)
	case *ledger:
		if s == nil {
			return nil
		}
		return ledgerPrivateValue(*s)
	case adminResponse:
		return adminResponsePrivateValue(s)
	case *adminResponse:
		if s == nil {
			return nil
		}
		return adminResponsePrivateValue(*s)
	default:
		return v
	}
}
