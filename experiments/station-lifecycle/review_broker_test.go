package lifecycle

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// A retained broker credential must not be recoverable from numeric diagnostics.
func TestReviewBrokerCredentialOutput(t *testing.T) {
	secret := Secret(bytes.Repeat([]byte("x"), 32))
	record := brokerRecord{Credential: NewPrivateBytes(secret)}
	needle := strings.Trim(fmt.Sprint([]byte(secret)), "[]")
	for _, format := range []string{"%p", "%d"} {
		if strings.Contains(fmt.Sprintf(format, record), needle) {
			t.Fatal("broker credential recoverable from numeric formatted bytes")
		}
	}
}
