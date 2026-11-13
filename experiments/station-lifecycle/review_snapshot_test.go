package lifecycle

import (
	"bytes"
	"testing"
)

// The exact snapshot used by refusal tests must distinguish credential-only authority changes.
func TestReviewAuthoritySnapshotDistinguishesCredentials(t *testing.T) {
	now := int64(100)
	broker, _ := brokerFixture(t, &now)
	key := hash([]byte("review-authority"))
	if _, err := broker.Allocate(key, hash([]byte("review-grant")), 90, 200); err != nil {
		t.Fatal("allocation fixture refused")
	}
	original, err := broker.Credential(key)
	if err != nil {
		t.Fatal("credential positive control refused")
	}
	snapshot := privateCanonical(broker.state.Records)
	changed := append(Secret(nil), original...)
	changed[0] ^= 1
	record := broker.state.Records[key]
	record.Credential = NewPrivateBytes(changed)
	broker.state.Records[key] = record
	observed, err := broker.Credential(key)
	if err != nil || bytes.Equal(original, observed) {
		t.Fatal("credential-change control was not applied")
	}
	if bytes.Equal(snapshot, privateCanonical(broker.state.Records)) {
		t.Fatal("authority snapshot hides a credential-only mutation")
	}
}

// A rejected public Poll must not change the credential exposed by the public accessor.
func TestReviewRejectedPollPreservesCredential(t *testing.T) {
	now := int64(100)
	broker, _ := brokerFixture(t, &now)
	key := hash([]byte("review-authority"))
	slot, err := broker.Allocate(key, hash([]byte("review-grant")), 90, 200)
	if err != nil {
		t.Fatal("allocation fixture refused")
	}
	before, err := broker.Credential(key)
	if err != nil {
		t.Fatal("credential positive control refused")
	}
	_, err = broker.Poll(PollRequest{Version: 1, Results: []Status{{SlotID: slot.ID, Phase: "running", Binding: hash([]byte("foreign")), NotAfter: 200}}})
	if err == nil || err.Error() != "POLL_BINDING" {
		t.Fatal("wrong-binding refusal changed")
	}
	after, err := broker.Credential(key)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("rejected Poll changed credential authority")
	}
}
