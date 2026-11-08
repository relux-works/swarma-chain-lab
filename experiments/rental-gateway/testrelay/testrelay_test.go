package testrelay_test

import (
	"context"
	"testing"
	"time"

	"relux.works/swarma-chain-lab/experiments/rental-gateway/gateway"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/nostr"
	"relux.works/swarma-chain-lab/experiments/rental-gateway/testrelay"
)

// TestRelayVerifiesSignatures proves Publish awaits relay OK
// (accepted vs rejected), and the test relay stores valid
// signed gift wraps and rejects tampered events like a real relay
// (the gateway later refuses them again at unwrap: defence in depth).
func TestRelayVerifiesSignatures(t *testing.T) {
	relay, err := testrelay.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	sender, _ := nostr.GeneratePrivKey()
	recipient, _ := nostr.GeneratePrivKey()
	wrap, _, err := nostr.WrapDM(sender, recipient.PubKeyHex(), "via relay", nil, 1500)
	if err != nil {
		t.Fatal(err)
	}
	client := &gateway.RelayClient{URL: relay.URL}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Publish(ctx, wrap); err != nil {
		t.Fatal(err)
	}
	// Tampered event: content flipped after signing. Publish now
	// awaits the relay OK (RM2 M7), so the rejection is the error.
	bad := *wrap
	bad.Content = "x" + bad.Content[1:]
	if err := client.Publish(ctx, &bad); err == nil {
		t.Fatal("tampered event publish accepted by relay")
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		evs := relay.Events()
		for _, ev := range evs {
			if ev.ID == bad.ID && ev.Content == bad.Content {
				t.Fatal("tampered event stored by relay")
			}
		}
		if len(evs) >= 1 && evs[0].ID == wrap.ID {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("valid event not stored; stored=%v", evs)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
