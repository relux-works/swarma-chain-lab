//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	proxy "github.com/relux-works/swarma-chain-lab/experiments/model-proxy"
)

// The production selection function reads only the selected origin. Invalid
// mode/recipient combinations refuse before any protected file read or dial.
func TestManagedCredentialOrigin(t *testing.T) {
	fixture := startBroker(t)
	raw, _ := json.Marshal(fixture.config)
	for _, scenario := range []string{"default", "development", "managed", "development-broker", "default-broker", "missing-broker", "upstream", "profiles", "broker-read-failure"} {
		t.Run(scenario, func(t *testing.T) {
			config := proxy.GatewayFileConfig{Mode: proxy.ModeManaged}
			config.Upstream = proxy.ManagedUpstream
			config.APIKeyFile = "ambient-key"
			path := "broker-mapping"
			wantRead := ""
			valid := false
			switch scenario {
			case "default", "development":
				config.Mode, path, wantRead, valid = "", "", config.APIKeyFile, true
				if scenario == "development" {
					config.Mode = proxy.ModeDevelopment
				}
			case "managed":
				wantRead, valid = path, true
			case "development-broker":
				config.Mode = proxy.ModeDevelopment
			case "default-broker":
				config.Mode = ""
			case "missing-broker":
				path = ""
			case "upstream":
				config.Upstream = "https://other-recipient.example/v1/messages"
			case "profiles":
				config.ModelProfiles = map[string]proxy.ModelProfile{"model": {}}
			case "broker-read-failure":
				wantRead = path
			}
			reads := 0
			read := func(name string, limit int64) ([]byte, error) {
				reads++
				if name != wantRead {
					t.Error("unexpected origin read")
				}
				if scenario == "broker-read-failure" {
					return nil, errors.New("fixture private failure")
				}
				if name == "ambient-key" {
					if limit != 4096 {
						t.Error("development read limit changed")
					}
					return []byte("fixture-development-key"), nil
				}
				return raw, nil
			}
			key, source, closeSource, err := credentialOrigin(context.Background(), config, path, read)
			if closeSource != nil {
				defer closeSource()
			}
			if !valid {
				if err == nil || err.Error() != "CREDENTIAL_SOURCE" || key != nil || source != nil {
					t.Fatal("invalid credential origin admitted")
				}
			} else if err != nil || closeSource == nil {
				t.Fatal("valid credential origin refused")
			} else if scenario == "managed" {
				if len(key) != 0 || source == nil {
					t.Fatal("managed origin used ambient key")
				}
			} else if string(key) != "fixture-development-key" || source != nil {
				t.Fatal("default origin behaviour changed")
			}
			wantReads := 0
			if wantRead != "" {
				wantReads = 1
			}
			if reads != wantReads {
				t.Fatal("credential origin read before refusal")
			}
		})
	}
}
