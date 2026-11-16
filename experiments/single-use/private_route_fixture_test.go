package singleuse

import (
	"encoding/json"
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
	case Route:
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
