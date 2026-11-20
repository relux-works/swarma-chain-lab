//go:build linux && gateway_lab

package service

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"math/big"
	"regexp"
	"strconv"
	"strings"

	"github.com/relux-works/swarma-chain-lab/experiments/model-proxy/service/internal/wire"
)

//go:embed testdata/lab-v0-c0e/surfaces.json
var labAttemptSurfaces []byte

//go:embed testdata/lab-v0-c0e/model-price.json
var labAttemptPrice []byte

//go:embed testdata/lab-v0-c0e/index.json
var labAttemptIndex []byte

//go:embed testdata/lab-v0-c0e/client.json
var labAttemptClient []byte

const labAttemptGroupFormat = "swarma-broker-lab-attempt-group/1"
const labAttemptLedgerFormat = "swarma-broker-lab-attempt-ledger/1"
const labSafeInteger int64 = 9007199254740991

var labAttemptRules = func() labGrammar {
	var rules labGrammar
	if json.Unmarshal(labAttemptSurfaces, &rules) != nil {
		panic("invalid lab attempt contract")
	}
	return rules
}()

func labAttemptRecord(raw []byte, format string) (map[string]any, error) {
	object, err := wire.Parse(raw)
	if err != nil {
		return nil, ErrFrame
	}
	for _, shape := range labAttemptRules.Surfaces {
		if shape.Format == format {
			if !labPayloadValid(raw, shape.MaxBytes) || labAttemptFields(object, shape) != nil {
				return nil, ErrFrame
			}
			return object, nil
		}
	}
	return nil, ErrFrame
}
func labAttemptFields(object map[string]any, shape labShape) error {
	if len(object) != len(shape.Fields) {
		return ErrFrame
	}
	for name, kind := range shape.Fields {
		if labAttemptValue(object[name], kind) != nil {
			return ErrFrame
		}
	}
	return nil
}
func labAttemptValue(value any, kind string) error {
	if value == nil {
		return ErrFrame
	}
	if strings.HasPrefix(kind, "[]") {
		values, ok := value.([]any)
		if !ok || len(values) > 256 {
			return ErrFrame
		}
		for _, child := range values {
			if labAttemptValue(child, kind[2:]) != nil {
				return ErrFrame
			}
		}
		return nil
	}
	if strings.HasPrefix(kind, "@") {
		object, ok := value.(map[string]any)
		shape, found := labAttemptRules.Structures[kind[1:]]
		if !ok || !found {
			return ErrFrame
		}
		return labAttemptFields(object, shape)
	}
	switch kind {
	case "invocation-count", "output-tokens", "wall-ms":
		number, ok := value.(int64)
		limit := int64(256)
		if kind == "output-tokens" {
			limit = 128000
		}
		if kind == "wall-ms" {
			limit = 900000
		}
		if !ok || number < 1 || number > limit {
			return ErrFrame
		}
		return nil
	case "usd":
		if _, err := labMicroUSD(value); err != nil {
			return err
		}
		return nil
	case "native-id":
		text, ok := value.(string)
		if !ok || !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`).MatchString(text) {
			return ErrFrame
		}
		return nil
	case "native-executor":
		text, ok := value.(string)
		if !ok || !regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`).MatchString(text) {
			return ErrFrame
		}
		return nil
	}
	return labValue(value, kind)
}
func labMicroUSD(value any) (int64, error) {
	text, ok := value.(string)
	if !ok {
		return 0, ErrFrame
	}
	parts := strings.Split(text, ".")
	if len(parts) != 2 || len(parts[0]) < 1 || len(parts[0]) > 10 || len(parts[1]) != 6 || len(parts[0]) > 1 && parts[0][0] == '0' {
		return 0, ErrFrame
	}
	for _, digit := range parts[0] + parts[1] {
		if digit < '0' || digit > '9' {
			return 0, ErrFrame
		}
	}
	number, err := strconv.ParseInt(parts[0]+parts[1], 10, 64)
	if err != nil || number <= 0 || number > labSafeInteger {
		return 0, ErrFrame
	}
	return number, nil
}
func labUSD(value int64) string {
	return strconv.FormatInt(value/1000000, 10) + "." + strconv.FormatInt(1000000+value%1000000, 10)[1:]
}
func labAttemptEncode(value any) []byte {
	raw, err := wire.Encode(value)
	if err != nil {
		return nil
	}
	return raw
}
func labAttemptHash(value any) string { return labDigest(labAttemptEncode(value)) }
func labApprovalTarget(object map[string]any, member, domain string) string {
	record := map[string]any{}
	for name, value := range object {
		if name != member {
			record[name] = value
		}
	}
	return labAttemptHash(map[string]any{"domain": domain, "record": record})
}
func labUsageZero() map[string]any {
	result := map[string]any{}
	for name := range labAttemptRules.Structures["GatewayUsage"].Fields {
		result[name] = int64(0)
	}
	return result
}

var labUsageUnavailable = labAttemptHash(map[string]any{"domain": "swarma-broker-lab-usage-unavailable/1"})

func labPriceCharge(price, usage map[string]any) (int64, error) {
	if labAttemptFields(usage, labAttemptRules.Structures["GatewayUsage"]) != nil {
		return 0, ErrUnknown
	}
	input, output := usage["input_tokens"].(int64), usage["output_tokens"].(int64)
	write5, write1, read := usage["cache_creation_5m_input_tokens"].(int64), usage["cache_creation_1h_input_tokens"].(int64), usage["cache_read_input_tokens"].(int64)
	if input > 1000000 || write5 > 1000000 || write1 > 1000000 || read > 1000000 || input+write5+write1+read > 1000000 || write5+write1 != usage["cache_creation_input_tokens"] || output > price["output_token_ceiling"].(int64) {
		return 0, ErrUnknown
	}
	rates := labObject(price["rates"])
	counters := map[string]int64{"input_usd_per_million": input, "output_usd_per_million": output, "cache_write_5m_usd_per_million": write5, "cache_write_1h_usd_per_million": write1, "cache_read_usd_per_million": read}
	total := new(big.Int)
	for name, count := range counters {
		rate, err := labMicroUSD(rates[name])
		if err != nil {
			return 0, ErrUnknown
		}
		total.Add(total, new(big.Int).Mul(big.NewInt(count), big.NewInt(rate)))
	}
	total.Add(total, big.NewInt(999999))
	total.Quo(total, big.NewInt(1000000))
	if !total.IsInt64() || total.Int64() > labSafeInteger {
		return 0, ErrUnknown
	}
	return total.Int64(), nil
}
func labWorstReservation(price map[string]any, output int64) (int64, error) {
	if !bytes.Equal(labAttemptEncode(price), labAttemptPrice) || output != 128000 {
		return 0, ErrUnknown
	}
	rates := labObject(price["rates"])
	highest := int64(0)
	category := ""
	for _, name := range []string{"input_usd_per_million", "cache_write_5m_usd_per_million", "cache_write_1h_usd_per_million", "cache_read_usd_per_million"} {
		rate, err := labMicroUSD(rates[name])
		if err != nil {
			return 0, err
		}
		if rate > highest {
			highest, category = rate, name
		}
	}
	usage := labUsageZero()
	usage["output_tokens"] = output
	switch category {
	case "input_usd_per_million":
		usage["input_tokens"] = int64(1000000)
	case "cache_write_5m_usd_per_million":
		usage["cache_creation_input_tokens"], usage["cache_creation_5m_input_tokens"] = int64(1000000), int64(1000000)
	case "cache_write_1h_usd_per_million":
		usage["cache_creation_input_tokens"], usage["cache_creation_1h_input_tokens"] = int64(1000000), int64(1000000)
	case "cache_read_usd_per_million":
		usage["cache_read_input_tokens"] = int64(1000000)
	}
	return labPriceCharge(price, usage)
}
