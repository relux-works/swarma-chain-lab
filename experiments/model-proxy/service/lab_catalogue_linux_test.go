//go:build linux && gateway_lab

package service

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/model-proxy/service/internal/wire"
)

func labCandidate(value any) []byte {
	raw, err := wire.Encode(value)
	if err != nil {
		raw, _ = json.Marshal(value)
	}
	return raw
}

// TestLabFrozenRecordCatalogue proves each instantiated C0 grammar node and closed member is checked by the runtime reader, not a test-only reader.
func TestLabFrozenRecordCatalogue(test *testing.T) {
	fixtures := labFixtures(test)
	for format, control := range fixtures {
		test.Run(format, func(test *testing.T) {
			var shape labShape
			for _, candidate := range labRules.Surfaces {
				if candidate.Format == format {
					shape = candidate
				}
			}
			baseline := labBytes(test, control)
			check := func(candidate map[string]any, admit bool, name string) {
				test.Helper()
				if _, err := labRecord(baseline, format); err != nil {
					test.Fatal("valid control", err)
				}
				_, err := labRecord(labCandidate(candidate), format)
				if (err == nil) != admit {
					test.Fatalf("catalogue %s admission=%t", name, err == nil)
				}
			}
			var visit func(map[string]any, labShape)
			visit = func(object map[string]any, shape labShape) {
				for name, kind := range shape.Fields {
					saved := object[name]
					delete(object, name)
					check(control, false, "missing-"+name)
					object[name] = saved
					for _, label := range literalMutations(name) {
						changed := label.Value.(string)
						if changed == name {
							continue
						}
						if _, exists := object[changed]; exists {
							continue
						}
						delete(object, name)
						object[changed] = saved
						check(control, false, "label-"+name+"-"+label.Name)
						delete(object, changed)
						object[name] = saved
						object[changed] = saved
						check(control, false, "extra-label-"+name+"-"+label.Name)
						delete(object, changed)
					}
					object[name+"́"] = saved
					check(control, false, "combining-label")
					delete(object, name+"́")
					fullwidth := strings.Map(func(char rune) rune {
						if char >= 33 && char <= 126 {
							return char + 0xfee0
						}
						return char
					}, name)
					object[fullwidth] = saved
					check(control, false, "fullwidth-label")
					delete(object, fullwidth)
					for _, mutation := range wrongTypes(saved) {
						object[name] = mutation.Value
						check(control, false, "wrong-type-"+name)
						object[name] = saved
					}
					switch {
					case strings.HasPrefix(kind, "@"):
						visit(labObject(saved), labRules.Structures[kind[1:]])
					case strings.HasPrefix(kind, "[]"):
						array := saved.([]any)
						element := kind[2:]
						if strings.HasPrefix(element, "@") {
							for _, item := range array {
								visit(labObject(item), labRules.Structures[element[1:]])
							}
						}
						if len(array) > 0 {
							for _, count := range []int{0, 1, 255, 256, 257} {
								expanded := make([]any, count)
								for index := range expanded {
									expanded[index] = array[0]
								}
								object[name] = expanded
								check(control, count <= 256, "array-bound")
								object[name] = saved
							}
						}
					default:
						for _, mutation := range scalarMutations(kind) {
							object[name] = mutation.Value
							check(control, mutation.Admit, name+"-"+mutation.Name)
							object[name] = saved
						}
					}
				}
			}
			visit(control, shape)
			raw := labBytes(test, control)
			if _, err := labRecord(append(raw, '\n'), format); err == nil {
				test.Fatal("noncanonical newline")
			}
			duplicate := append([]byte(`{"format":"`+format+`",`), raw[1:]...)
			if _, err := labRecord(duplicate, format); err == nil {
				test.Fatal("duplicate root member")
			}
		})
	}
}

// TestLabHeaderCatalogue proves ASCII case controls while every inserted/substituted byte rejects nonaliases of the frozen header names.
func TestLabHeaderCatalogue(test *testing.T) {
	fixture := labWireCases(test)[0]
	for _, header := range fixture.Request.Headers {
		original := header[0]
		for _, label := range literalMutations(original) {
			name := label.Value.(string)
			request := labRequest(fixture)
			delete(request.Header, original)
			request.Header[name] = []string{header[1]}
			expected := asciiHeaderCaseEqual(name, original)
			if labShapeValid(request) != expected {
				test.Fatalf("header literal %s", label.Name)
			}
		}
		for offset := 0; offset <= len(original); offset++ {
			for value := 0; value <= 255; value++ {
				for _, name := range []string{original[:offset] + string([]byte{byte(value)}) + original[offset:], func() string {
					if offset == len(original) {
						return original
					}
					return original[:offset] + string([]byte{byte(value)}) + original[offset+1:]
				}()} {
					request := labRequest(fixture)
					delete(request.Header, original)
					request.Header[name] = []string{header[1]}
					expected := asciiHeaderCaseEqual(name, original)
					if labShapeValid(request) != expected {
						test.Fatalf("header byte %d position %d", value, offset)
					}
				}
			}
		}
	}
}

// TestLabProductionCrossReadLease proves each dialect accepts its own material shape and refuses the other without broadening production.
func TestLabProductionCrossReadLease(test *testing.T) {
	_, pins := labPinRecords(test)
	operation := strings.Repeat("b", 32)
	record := labLeaseResult(test, pins, operation)
	raw := labBytes(test, record)
	if _, err := labRecord(raw, "anthropic-api-key-lab/1"); err != nil {
		test.Fatal(err)
	}
	var production leaseResult
	if wire.Decode(raw, &production) == nil {
		test.Fatal("production accepted lab material")
	}
	production = leaseResult{ID: "production-lease", Account: "lab/anthropic", Harness: "claude_code", Kind: "claude-oauth-token", Until: time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano), Renewable: true}
	production.Payload.Kind = "claude-oauth-token"
	production.Payload.Value = labMaterial
	client := &Client{cfg: Config{MaxLifetime: 900 * time.Second}, leases: map[*Lease]bool{}}
	own, err := client.accept(&production, Caller{Account: "lab/anthropic"}, time.Now(), 0)
	if err != nil {
		test.Fatal("production valid control", err)
	}
	defer own.close()
	if _, err := labRecord(labBytes(test, production), "anthropic-api-key-lab/1"); err == nil {
		test.Fatal("lab accepted production material")
	}
}

// TestLabBuildTagIsolation proves untagged package selection excludes every lab source beside the tagged graph's admitted files.
func TestLabBuildTagIsolation(test *testing.T) {
	for _, tag := range []bool{false, true} {
		args := []string{"list", "-json"}
		if overlay := os.Getenv("LAB_TEST_OVERLAY"); overlay != "" {
			args = append(args, "-overlay", overlay)
		}
		if tag {
			args = append(args, "-tags", "gateway_lab")
		}
		args = append(args, ".")
		command := exec.Command("go", args...)
		raw, err := command.Output()
		if err != nil {
			test.Fatal("go list failed")
		}
		var listing struct{ GoFiles []string }
		if json.Unmarshal(raw, &listing) != nil {
			test.Fatal("go list JSON")
		}
		included := slices.Contains(listing.GoFiles, "lab_source_linux.go")
		if included != tag {
			test.Fatal("lab source selected outside its build tag")
		}
	}
}

// TestLabLeaseExpiredRenewal proves a live lease renews but an ended lease cannot be restored by a later-looking reply.
func TestLabLeaseExpiredRenewal(test *testing.T) {
	_, pins := labPinRecords(test)
	pins.lifetime = time.Second
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	source := &LabSource{&labSourceState{pins: pins, ctx: ctx, client: &Client{leases: map[*Lease]bool{}}}}
	operation := strings.Repeat("b", 32)
	if err := source.accept(labBytes(test, labLeaseResult(test, pins, operation)), operation, time.Now(), ""); err != nil {
		test.Fatal(err)
	}
	next := strings.Repeat("c", 32)
	reply := labLeaseResult(test, pins, next)
	if err := source.accept(labBytes(test, reply), next, time.Now(), source.lease.id); err != nil {
		test.Fatal("live renewal control", err)
	}
	source.lease.close()
	third := strings.Repeat("d", 32)
	if err := source.accept(labBytes(test, labLeaseResult(test, pins, third)), third, time.Now(), source.lease.id); err == nil {
		test.Fatal("ended lease resurrected")
	}
}

// TestLabSSEIncremental proves a complete safe SSE event flushes before upstream EOF and a split full needle remains held.
func TestLabSSEIncremental(test *testing.T) {
	reader, writer := io.Pipe()
	test.Cleanup(func() { reader.Close(); writer.Close() })
	recorder := &labFlushRecorder{ResponseRecorder: httptest.NewRecorder(), flushed: make(chan struct{}, 1)}
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { done <- labStream(ctx, recorder, reader, [][]byte{[]byte(labMaterial)}, func() {}) }()
	writer.Write([]byte("data: {}\n\n"))
	select {
	case <-recorder.flushed:
	case <-time.After(200 * time.Millisecond):
		test.Fatal("SSE buffered until EOF")
	}
	writer.Close()
	if err := <-done; err != nil {
		test.Fatal(err)
	}
	if !bytes.Equal(recorder.Body.Bytes(), []byte("data: {}\n\n")) {
		test.Fatal("SSE bytes changed")
	}
}

type labFlushRecorder struct {
	*httptest.ResponseRecorder
	flushed chan struct{}
}

func (recorder *labFlushRecorder) Flush() {
	recorder.ResponseRecorder.Flush()
	select {
	case recorder.flushed <- struct{}{}:
	default:
	}
}

// TestLabPayloadBoundaries proves bounded preflight accepts its exact ceiling and refuses zero/one-over; at-limit padding is not a valid record claim.
func TestLabPayloadBoundaries(test *testing.T) {
	for _, maximum := range []int{16384, 65536, 262144} {
		if !labPayloadValid(make([]byte, maximum), maximum) || labPayloadValid(nil, maximum) || labPayloadValid(make([]byte, maximum+1), maximum) {
			test.Fatal("payload preflight boundary")
		}
	}
}

// TestLabNumberLexemes proves C0 integer spelling operators refuse alongside their canonical range controls, independently of HTTP JSON.
func TestLabNumberLexemes(test *testing.T) {
	bounds := map[string][2]int64{"uint": {0, 9007199254740991}, "positive": {1, 9007199254740991}, "root": {0, 0}, "lifetime": {1, 900}, "alignment": {0, 2}, "exit": {0, 255}, "poll": {250, 250}, "capture-timeout": {300, 300}}
	for kind, bound := range bounds {
		for _, number := range []int64{0, 1, bound[0], bound[1]} {
			text := strconv.FormatInt(number, 10)
			cases := map[string]string{"leading-zero": "0" + text, "redundant-zero": "00" + text, "positive-sign": "+" + text, "negative-sign": "-" + text, "fraction": text + ".0", "fraction-two-zeroes": text + ".00", "fraction-nonzero": text + ".5"}
			for _, marker := range []string{"e", "E"} {
				for _, sign := range []string{"", "+", "-"} {
					for _, exponent := range []string{"0", "00", "1"} {
						cases[marker+sign+exponent] = text + marker + sign + exponent
					}
				}
			}
			for name, lexeme := range cases {
				controlNumber := number
				if number < bound[0] || number > bound[1] {
					controlNumber = bound[0]
				}
				valid, err := wire.Parse([]byte(`{"number":` + strconv.FormatInt(controlNumber, 10) + `}`))
				if err != nil || labValue(valid["number"], kind) != nil {
					test.Fatal("canonical integer control")
				}
				changed, err := wire.Parse([]byte(`{"number":` + lexeme + `}`))
				if err == nil && (name != "negative-sign" || labValue(changed["number"], kind) == nil) {
					test.Fatalf("%s numeric spelling admitted: %s", kind, lexeme)
				}
			}
		}
	}
}

// TestLabCanonicalCatalogue proves every served record rejects C0 equivalent-value byte alternatives beside its byte-exact control.
func TestLabCanonicalCatalogue(test *testing.T) {
	for format, fixture := range labFixtures(test) {
		control := labBytes(test, fixture)
		if _, err := labRecord(control, format); err != nil {
			test.Fatal("valid record")
		}
		cases := [][]byte{append([]byte{' '}, control...), append(bytes.Clone(control), ' '), append(bytes.Clone(control), '\n'), append([]byte{'{', ' '}, control[1:]...), bytes.Replace(control, []byte(`"format"`), []byte(`"\u0066ormat"`), 1)}
		for _, changed := range cases {
			var decoded any
			if json.Unmarshal(changed, &decoded) != nil || !labEqual(labCandidate(decoded), labCandidate(fixture)) {
				test.Fatal("byte control changed decoded value")
			}
			if _, err := labRecord(changed, format); err == nil {
				test.Fatal("noncanonical alias admitted")
			}
		}
	}
}
