package service

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	check "github.com/relux-works/swarma-chain-lab/experiments/notary-checker"
	"github.com/relux-works/swarma-chain-lab/experiments/notary-checker/internal/diagnosticcheck"
)

// Claim: storage has exactly one unexported **PrivateKey field. Constructor,
// nil/zero reads and clearing retain the existing key object and its lifecycle.
func TestSigningKeyStorage(t *testing.T) {
	shape := reflect.TypeOf(signingKey{})
	if shape.NumField() != 1 || shape.Field(0).Type != reflect.TypeOf((**btcec.PrivateKey)(nil)) || shape.Field(0).IsExported() {
		t.Fatal("signing key storage must be one unexported **PrivateKey field")
	}
	field, ok := reflect.TypeOf(Service{}).FieldByName("key")
	if !ok || field.Type != reflect.TypeOf((*signingKey)(nil)) || field.IsExported() {
		t.Fatal("Service must retain its key through the private holder")
	}
	defer func() {
		if recover() != nil {
			t.Error("signing key accessor panicked")
		}
	}()
	var absent *signingKey
	if absent.privateKey() != nil || (&signingKey{}).privateKey() != nil || newSigningKey(nil).privateKey() != nil {
		t.Fatal("nil/zero key accessor changed")
	}
	absent.Zero()
	(&signingKey{}).Zero()
	raw := sha256.Sum256([]byte("synthetic-storage-key"))
	key, _ := btcec.PrivKeyFromBytes(raw[:])
	holder := newSigningKey(key)
	if holder.privateKey() != key || !bytes.Equal(holder.privateKey().Serialize(), raw[:]) {
		t.Fatal("constructor changed key")
	}
	holder.Zero()
	if !key.Key.IsZero() {
		t.Fatal("holder did not clear original key")
	}
}

// Claim: fmt's bad-verb restart exposes a plain *PrivateKey's limbs, while
// the exact **PrivateKey storage prints an address through the same path.
func TestSigningKeyBadVerbStorage(t *testing.T) {
	raw := sha256.Sum256([]byte("synthetic-bad-verb-key"))
	key, _ := btcec.PrivKeyFromBytes(raw[:])
	d := diagnosticcheck.NewDetector(raw[:], true)
	verb := "%s"
	plain := fmt.Sprintf(verb, &struct{ key *btcec.PrivateKey }{key})
	if !d.Leaks(plain) {
		t.Fatal("plain *struct control did not expose scalar limbs")
	}
	holder := newSigningKey(key)
	out := fmt.Sprintf(verb, &Service{key: holder})
	if d.Leaks(out) || !strings.Contains(out, "0x") {
		t.Fatal("double-pointer storage did not contain the bad-verb restart to an address")
	}
}

func serviceDiagnosticForms(t *testing.T) ([]diagnosticcheck.Form, []byte, []diagnosticcheck.Form) {
	t.Helper()
	raw := sha256.Sum256([]byte("synthetic-service-signing-key"))
	key, _ := btcec.PrivKeyFromBytes(raw[:])
	holder := newSigningKey(key)
	path := filepath.Join(t.TempDir(), "credential")
	if os.WriteFile(path, []byte("synthetic-user:synthetic-diagnostic-password"), 0600) != nil {
		t.Fatal("credential fixture")
	}
	n, err := check.NewNodeNameReader("http://127.0.0.1:1", path)
	if err != nil {
		t.Fatal("reader fixture")
	}
	s := &Service{key: holder, node: n}
	// Reflective value copies exercise fmt's value path without copying locks
	// in ordinary Go assignments. The fixture never serves concurrent work.
	value := reflect.ValueOf(s).Elem().Interface()
	pp := &s
	var nilService *Service
	var nilHolder *signingKey
	forms := []diagnosticcheck.Form{
		{Name: "service/pointer", Value: s}, {Name: "service/value", Value: value}, {Name: "service/double-pointer", Value: pp},
		{Name: "holder/value", Value: *holder}, {Name: "holder/pointer", Value: holder},
		{Name: "zero/holder", Value: signingKey{}}, {Name: "zero/holder-pointer", Value: &signingKey{}}, {Name: "nil/holder", Value: nilHolder},
		{Name: "zero/service", Value: reflect.ValueOf(&Service{}).Elem().Interface()}, {Name: "nil/service", Value: nilService},
		{Name: "wrap/service-unexported-pointer", Value: struct{ s *Service }{s}},
		{Name: "wrap/service-unexported-value", Value: struct{ s Service }{Service{key: holder, node: n}}},
		{Name: "wrap/service-unexported-double-pointer", Value: struct{ s **Service }{pp}},
		{Name: "wrap/service-exported-pointer", Value: struct{ S *Service }{s}},
		{Name: "wrap/service-exported-value", Value: struct{ S Service }{Service{key: holder, node: n}}},
		{Name: "wrap/holder-unexported-value", Value: struct{ k signingKey }{*holder}},
		{Name: "wrap/holder-unexported-pointer", Value: struct{ k *signingKey }{holder}},
		{Name: "wrap/handler-interface", Value: struct{ h interface{ Close() } }{s}},
		{Name: "wrap/any-interface", Value: struct{ a any }{value}},
		{Name: "wrap/nested", Value: struct {
			o struct{ i struct{ s *Service } }
		}{struct{ i struct{ s *Service } }{struct{ s *Service }{s}}}},
		{Name: "array/service", Value: [1]*Service{s}}, {Name: "array/holder", Value: [1]signingKey{*holder}},
		{Name: "slice/service", Value: []*Service{s}}, {Name: "slice/any", Value: []any{value, holder}},
		{Name: "map/service-pointer", Value: map[string]*Service{"a": s}},
		{Name: "map/service-value", Value: map[string]any{"a": value}},
		{Name: "map/service-key", Value: map[*Service]int{s: 1}}, {Name: "map/holder-key", Value: map[signingKey]int{*holder: 1}},
		{Name: "reflect/service", Value: reflect.ValueOf(s).Elem()},
		{Name: "reflect/key-field", Value: reflect.ValueOf(s).Elem().FieldByName("key")},
		{Name: "reflect/holder", Value: reflect.ValueOf(holder).Elem()},
		{Name: "reflect/storage", Value: reflect.ValueOf(holder).Elem().Field(0)},
		{Name: "holder/double-pointer", Value: &holder},
		{Name: "array/service-value", Value: [1]any{value}},
		{Name: "interface/service", Value: any(s)}, {Name: "interface/service-value", Value: any(value)},
	}
	controls := []diagnosticcheck.Form{
		{Name: "plain-key", Value: &struct{ key *btcec.PrivateKey }{key}},
		{Name: "plain-inline-key", Value: struct{ key btcec.PrivateKey }{*key}},
		{Name: "plain-bytes", Value: struct{ key []byte }{raw[:]}},
	}
	return forms, raw[:], controls
}

// Claim: the real Service, value copies, wrappers, interfaces, reflection,
// arrays and maps expose no key through the full 43-sink battery. Plain
// *struct/inline keys and bytes calibrate the same detector and sinks.
func TestSigningKeyServiceContainer(t *testing.T) {
	forms, raw, controls := serviceDiagnosticForms(t)
	diagnosticcheck.Check(t, forms, controls, diagnosticcheck.NewDetector(raw, true))
}

// Claim: the same real Service forms also keep its RPC password contained.
func TestRPCPasswordServiceDiagnostics(t *testing.T) {
	forms, _, _ := serviceDiagnosticForms(t)
	raw := []byte("synthetic-diagnostic-password")
	controls := []diagnosticcheck.Form{{Name: "plain-password", Value: struct{ p *[]byte }{&raw}}}
	diagnosticcheck.Check(t, forms, controls, diagnosticcheck.NewDetector(raw, false))
}

// Claim: actual runtime panic printing is safe for every listed Service form.
func TestSigningKeyDiagnosticPanic(t *testing.T) {
	forms, raw, _ := serviceDiagnosticForms(t)
	diagnosticcheck.PanicCheck(t, "TestSigningKeyDiagnosticPanic", forms, diagnosticcheck.NewDetector(raw, true))
}

// Claim: every existing positive-vector digest produces the exact signature
// and public key captured from the unmodified base's loaded signing closure.
// This checks service bytes, separately from the independent Python fixture
// signatures (which use a different nonce convention). Existing refusal tests
// still exercise the admission path unchanged.
func TestSigningKeyVectors(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/service-signatures.json")
	if err != nil {
		t.Fatal(err)
	}
	var pinned struct {
		Base    string
		Vectors []struct{ Name, Digest, Signature, Public string }
	}
	if json.Unmarshal(raw, &pinned) != nil || pinned.Base != "22cdfd7c0ba132510c4d0baf8094714bb272c309" {
		t.Fatal("signature baseline")
	}
	raw, err = os.ReadFile("../../testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var data struct {
		Vectors []struct {
			Name     string `json:"name"`
			Expected string `json:"expected"`
			Result   struct {
				Digest string `json:"digest"`
			} `json:"result"`
		}
	}
	if json.Unmarshal(raw, &data) != nil {
		t.Fatal("vector corpus")
	}
	count := 0
	for _, v := range data.Vectors {
		if v.Expected != "ATTEST" {
			continue
		}
		t.Run(v.Name, func(t *testing.T) {
			var signature, public string
			for _, p := range pinned.Vectors {
				if p.Name == v.Name && p.Digest == v.Result.Digest {
					signature, public = p.Signature, p.Public
				}
			}
			if signature == "" || public == "" {
				t.Fatal("positive vector missing from baseline")
			}
			s, _, _ := setup(t)
			keyBytes := make([]byte, 32)
			keyBytes[31] = 4
			s.Close()
			put(t, s.config.KeyFile, append([]byte(keyHeader), keyBytes...))
			path := filepath.Join(t.TempDir(), "config")
			put(t, path, encode(t, s.config))
			loaded, err := Load(path)
			if err != nil {
				t.Fatal("fixed fixture key refused")
			}
			t.Cleanup(loaded.Close)
			if loaded.public != public || hex.EncodeToString(schnorr.SerializePubKey(loaded.key.privateKey().PubKey())) != public {
				t.Fatal("public key bytes changed")
			}
			digest, err := hex.DecodeString(v.Result.Digest)
			if err != nil {
				t.Fatal("fixture digest")
			}
			got, err := loaded.sign(digest)
			if err != nil || got != signature {
				t.Fatal("signature bytes changed")
			}
		})
		count++
	}
	if count != 15 || count != len(pinned.Vectors) {
		t.Fatal("positive signature vector coverage changed")
	}
	t.Logf("byte-identical signature/public-key vectors=%d", count)
}
