package lifecycle

type slotPrivate struct {
	Version       int    `json:"version"`
	ID            string `json:"slot"`
	GrantID       string `json:"grant_id"`
	NotBefore     int64  `json:"not_before"`
	NotAfter      int64  `json:"not_after"`
	PayloadID     string `json:"payload_id"`
	PayloadSHA256 string `json:"payload_sha256"`
	Bootstrap     Secret `json:"bootstrap"`
}

func slotPrivateValue(s Slot) slotPrivate {
	return slotPrivate{
		Version:       s.Version,
		ID:            s.ID,
		GrantID:       s.GrantID,
		NotBefore:     s.NotBefore,
		NotAfter:      s.NotAfter,
		PayloadID:     s.PayloadID,
		PayloadSHA256: s.PayloadSHA256,
		Bootstrap:     s.Bootstrap.Reveal(),
	}
}

type brokerRecordPrivate struct {
	Key           string      `json:"key"`
	Credential    Secret      `json:"credential"`
	Slot          slotPrivate `json:"slot"`
	BootstrapHash string      `json:"bootstrap_hash"`
	Binding       string      `json:"binding"`
	Desired       string      `json:"desired"`
	Result        Status      `json:"result"`
}

func brokerRecordPrivateValue(s brokerRecord) brokerRecordPrivate {
	return brokerRecordPrivate{
		Key:           s.Key,
		Credential:    s.Credential.Reveal(),
		Slot:          slotPrivateValue(s.Slot),
		BootstrapHash: s.BootstrapHash,
		Binding:       s.Binding,
		Desired:       s.Desired,
		Result:        s.Result,
	}
}

type brokerStatePrivate struct {
	Version int                            `json:"version"`
	Config  string                         `json:"config"`
	High    int64                          `json:"high"`
	Records map[string]brokerRecordPrivate `json:"records"`
}

func brokerStatePrivateValue(s brokerState) brokerStatePrivate {
	return brokerStatePrivate{
		Version: s.Version,
		Config:  s.Config,
		High:    s.High,
		Records: privateBrokerRecords(s.Records),
	}
}
func privateBrokerRecords(in map[string]brokerRecord) map[string]brokerRecordPrivate {
	if in == nil {
		return nil
	}
	out := make(map[string]brokerRecordPrivate, len(in))
	for k, v := range in {
		out[k] = brokerRecordPrivateValue(v)
	}
	return out
}

type recordPrivate struct {
	ID             string       `json:"id"`
	StartAttempted bool         `json:"start_attempted"`
	CreateFence    *CreateFence `json:"create_fence,omitempty"`
	Slot           *slotPrivate `json:"slot"`
	BootstrapHash  string       `json:"bootstrap_hash"`
	Binding        string       `json:"binding"`
	Phase          string       `json:"phase"`
	Reason         string       `json:"reason"`
}

func recordPrivateValue(s record) recordPrivate {
	return recordPrivate{
		ID:             s.ID,
		StartAttempted: s.StartAttempted,
		CreateFence:    s.CreateFence,
		Slot:           privateSlotPointer(s.Slot),
		BootstrapHash:  s.BootstrapHash,
		Binding:        s.Binding,
		Phase:          s.Phase,
		Reason:         s.Reason,
	}
}

type statePrivate struct {
	Version int                      `json:"version"`
	Policy  string                   `json:"policy"`
	High    int64                    `json:"high"`
	Records map[string]recordPrivate `json:"records"`
}

func statePrivateValue(s state) statePrivate {
	return statePrivate{
		Version: s.Version,
		Policy:  s.Policy,
		High:    s.High,
		Records: privateManagerRecords(s.Records),
	}
}
func privateManagerRecords(in map[string]record) map[string]recordPrivate {
	if in == nil {
		return nil
	}
	out := make(map[string]recordPrivate, len(in))
	for k, v := range in {
		out[k] = recordPrivateValue(v)
	}
	return out
}
func privateSlotPointer(in *Slot) *slotPrivate {
	if in == nil {
		return nil
	}
	out := slotPrivateValue(*in)
	return &out
}

type commandPrivate struct {
	Op      string      `json:"op"`
	Slot    slotPrivate `json:"slot"`
	Binding string      `json:"binding"`
}

func commandPrivateValue(s Command) commandPrivate {
	return commandPrivate{
		Op:      s.Op,
		Slot:    slotPrivateValue(s.Slot),
		Binding: s.Binding,
	}
}

type pollResponsePrivate struct {
	Version  int              `json:"version"`
	Commands []commandPrivate `json:"commands"`
}

func pollResponsePrivateValue(s PollResponse) pollResponsePrivate {
	return pollResponsePrivate{
		Version:  s.Version,
		Commands: privateCommands(s.Commands),
	}
}
func privateCommands(in []Command) []commandPrivate {
	if in == nil {
		return nil
	}
	out := make([]commandPrivate, len(in))
	for k, v := range in {
		out[k] = commandPrivateValue(v)
	}
	return out
}

// privateValue maps only the private protocol/state types to wire DTOs.
func privateValue(v any) any {
	switch s := v.(type) {
	case map[string]brokerRecord:
		return privateBrokerRecords(s)
	case *map[string]brokerRecord:
		if s == nil {
			return nil
		}
		return privateBrokerRecords(*s)
	case Slot:
		return slotPrivateValue(s)
	case *Slot:
		if s == nil {
			return nil
		}
		return slotPrivateValue(*s)
	case brokerRecord:
		return brokerRecordPrivateValue(s)
	case *brokerRecord:
		if s == nil {
			return nil
		}
		return brokerRecordPrivateValue(*s)
	case brokerState:
		return brokerStatePrivateValue(s)
	case *brokerState:
		if s == nil {
			return nil
		}
		return brokerStatePrivateValue(*s)
	case record:
		return recordPrivateValue(s)
	case *record:
		if s == nil {
			return nil
		}
		return recordPrivateValue(*s)
	case state:
		return statePrivateValue(s)
	case *state:
		if s == nil {
			return nil
		}
		return statePrivateValue(*s)
	case Command:
		return commandPrivateValue(s)
	case *Command:
		if s == nil {
			return nil
		}
		return commandPrivateValue(*s)
	case PollResponse:
		return pollResponsePrivateValue(s)
	case *PollResponse:
		if s == nil {
			return nil
		}
		return pollResponsePrivateValue(*s)
	default:
		return v
	}
}
