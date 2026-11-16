package vectors

import (
	"bytes"
	"os"
	"testing"
)

// Regeneration exercises the lab APIs and checks all specified codes; any fixture byte drift fails.
func TestVectorsDrift(t *testing.T) {
	got, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("vectors.json drift: regenerate and independently check before accepting")
	}
}
