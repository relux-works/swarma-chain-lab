package lifecycle

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Legacy canonical terminal state admits both null and empty byte strings; reopening must preserve that acceptance.
func TestReviewLegacyTerminalByteEncodings(t *testing.T) {
	for _, field := range []string{"nil-control", "credential", "bootstrap", "both"} {
		t.Run(field, func(t *testing.T) {
			now := int64(100)
			broker, config := brokerFixture(t, &now)
			key := hash([]byte("review-terminal"))
			slot, err := broker.Allocate(key, hash([]byte("review-grant")), 90, 200)
			if err != nil {
				t.Fatal("allocation fixture refused")
			}
			if err = broker.SetStop(key); err != nil {
				t.Fatal("stop fixture refused")
			}
			poll, err := broker.Poll(PollRequest{Version: 1, Results: []Status{}})
			if err != nil || len(poll.Commands) != 1 {
				t.Fatal("stop command fixture refused")
			}
			_, err = broker.Poll(PollRequest{Version: 1, Results: []Status{{SlotID: slot.ID, Binding: poll.Commands[0].Binding, Phase: "stopped", NotAfter: slot.NotAfter}}})
			if err != nil {
				t.Fatal("terminal transition refused")
			}
			if err = broker.Close(); err != nil {
				t.Fatal("fixture close failed")
			}
			path := filepath.Join(config.StateDir, "broker.json")
			wire, err := os.ReadFile(path)
			if err != nil {
				t.Fatal("terminal read failed")
			}
			for _, name := range []string{"credential", "bootstrap"} {
				if field == name || field == "both" {
					target := []byte(`"` + name + `":null`)
					if bytes.Count(wire, target) != 1 {
						t.Fatal("terminal mutation anchor missing")
					}
					wire = bytes.Replace(wire, target, []byte(`"`+name+`":""`), 1)
				}
			}
			if err = os.WriteFile(path, wire, 0600); err != nil {
				t.Fatal("legacy fixture write failed")
			}
			reopened, err := NewBroker(config)
			if err != nil {
				if err.Error() != "BROKER_STATE" {
					t.Fatal("unexpected broker recovery error")
				}
				t.Fatal("legacy canonical empty-byte terminal state refused (BROKER_STATE)")
			}
			defer reopened.Close()
			if _, err = reopened.Credential(key); err == nil {
				t.Fatal("terminal credential revived")
			}
		})
	}
}

// Manager recovery must retain the same legacy canonical empty-byte acceptance as broker recovery.
func TestReviewLegacyManagerTerminalByteEncodings(t *testing.T) {
	for _, empty := range []bool{false, true} {
		name := "nil-control"
		if empty {
			name = "empty-bootstrap"
		}
		t.Run(name, func(t *testing.T) {
			manager, config, _, _, slot := managerFixture(t)
			if _, err := manager.Start(context.Background(), slot); err != nil {
				t.Fatal("manager start fixture refused")
			}
			if _, err := manager.Stop(context.Background(), slot.ID); err != nil {
				t.Fatal("manager stop fixture refused")
			}
			if err := manager.Close(); err != nil {
				t.Fatal("manager close failed")
			}
			path := filepath.Join(config.StateDir, "state.json")
			wire, err := os.ReadFile(path)
			if err != nil {
				t.Fatal("manager terminal read failed")
			}
			if empty {
				target := []byte(`"bootstrap":null`)
				if bytes.Count(wire, target) != 1 {
					t.Fatal("manager mutation anchor missing")
				}
				wire = bytes.Replace(wire, target, []byte(`"bootstrap":""`), 1)
			}
			if err = os.WriteFile(path, wire, 0600); err != nil {
				t.Fatal("legacy manager fixture write failed")
			}
			reopened, err := New(config)
			if err != nil {
				if err.Error() != "STATE_BINDING" {
					t.Fatal("unexpected manager recovery error")
				}
				t.Fatal("legacy canonical empty-byte manager state refused (STATE_BINDING)")
			}
			defer reopened.Close()
		})
	}
}
