//go:build linux

package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// Claim: a healthy broker can serve the first acquisition after retiring its
// pre-use socket; an unavailable broker still refuses without material, then recovers.
func TestManagedIdleBeforeFirstUse(t *testing.T) {
	for _, scenario := range []string{"control", "idle", "unavailable"} {
		t.Run(scenario, func(t *testing.T) {
			fixture := startBroker(t)
			fixture.mu.Lock()
			fixture.idle = time.Second
			fixture.mu.Unlock()
			raw, _ := json.Marshal(fixture.config)
			holder, err := openManagedHolder(context.Background(), raw)
			if err != nil {
				t.Fatal("holder startup control refused")
			}
			defer holder.close()
			if scenario != "control" {
				time.Sleep(1500 * time.Millisecond)
			}
			if scenario == "unavailable" {
				fixture.mu.Lock()
				fixture.refusal = "role_not_permitted"
				fixture.mu.Unlock()
			}
			_, material, _, err := holder.CredentialValue(context.Background())
			if scenario == "unavailable" {
				if err == nil || len(material) != 0 {
					t.Fatal("startup recovery bypassed unavailable authority")
				}
				fixture.mu.Lock()
				fixture.refusal = ""
				fixture.mu.Unlock()
				eventuallyManaged(t, func() bool {
					_, recovered, _, err := holder.CredentialValue(context.Background())
					defer clear(recovered)
					return err == nil && len(recovered) > 0
				})
			} else if err != nil || len(material) == 0 {
				t.Fatal("first valid request after startup idle refused")
			}
			clear(material)
		})
	}
}
