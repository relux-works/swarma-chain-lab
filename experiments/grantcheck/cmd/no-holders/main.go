// Command no-holders checks an operator-supplied landlord VALUE offline.
package main

import (
	"encoding/json"
	"fmt"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	"io"
	"os"
)

// check accepts raw value JSON or the JSON string returned in name_show.value.
// It neither opens configuration nor constructs any node/RPC client.
func check(raw []byte) string {
	var text string
	if json.Unmarshal(raw, &text) == nil {
		raw = []byte(text)
	}
	var value struct {
		Swarma struct {
			Landlord map[string]json.RawMessage `json:"landlord"`
		} `json:"swarma"`
	}
	if json.Unmarshal(raw, &value) != nil {
		return "REFUSE INVALID_VALUE"
	}
	if _, present := value.Swarma.Landlord["holders"]; present {
		return "REFUSE HOLDERS_PRESENT"
	}
	if _, err := rental.ParseLandlordValue(string(raw)); err != nil {
		return "REFUSE INVALID_LEGACY_VALUE"
	}
	return "LEGACY-OK"
}
func run(in io.Reader, out io.Writer) int {
	raw, err := io.ReadAll(io.LimitReader(in, 1048577))
	result := "REFUSE INPUT"
	if err == nil && len(raw) <= 1048576 {
		result = check(raw)
	}
	fmt.Fprintln(out, result)
	if result == "LEGACY-OK" {
		return 0
	}
	return 1
}
func main() { os.Exit(run(os.Stdin, os.Stdout)) }
