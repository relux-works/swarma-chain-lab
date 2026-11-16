package rehearsal

import (
	"encoding/json"
	pc "github.com/relux-works/swarma-chain-lab/experiments/payment-chain"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
	"github.com/relux-works/swarma-chain-lab/experiments/station-lifecycle/slotd"
)

// privateRouteFixture is a test-only legacy config writer. Generic Route JSON
// intentionally redacts; genuine private fixture files need their original
// credentials. Never use this projection in logging or production output.
func privateRouteFixture(value any) any {
	type legacy struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	switch r := value.(type) {
	case su.Route:
		return legacy{r.Host, r.Port, r.Username, r.Password.RevealForBasicAuth()}
	case pc.Route:
		return legacy{r.Host, r.Port, r.Username, r.Password.RevealForBasicAuth()}
	default:
		return value
	}
}

func privateRouteFixtureJSON(value any) []byte {
	raw, err := json.Marshal(privateRouteFixture(value))
	if err != nil {
		panic("private route fixture refused")
	}
	return raw
}

// The fake private helper compares the original request wire, not public JSON.
func privateRequestFixtureJSON(q slotd.Request) []byte {
	type public slotd.Request
	if q.Bootstrap == nil {
		b, _ := json.Marshal(public(q))
		return b
	}
	bootstrap := q.Bootstrap.RevealForRequest()
	q.Bootstrap = nil
	raw, _ := json.Marshal(public(q))
	secret, _ := json.Marshal(bootstrap)
	raw = append(raw[:len(raw)-1], []byte(`,"bootstrap":`)...)
	raw = append(raw, secret...)
	return append(raw, '}')
}
