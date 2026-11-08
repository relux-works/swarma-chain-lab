package singleuse

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"relux.works/swarma-chain-lab/experiments/sealwatch"
)

type Anchor struct {
	TxID   string `json:"txid"`
	Block  string `json:"block"`
	Height int64  `json:"height"`
	Vout   uint32 `json:"vout"`
}
type Policy struct {
	Network            string          `json:"network"`
	Genesis            string          `json:"genesis"`
	Seal               Point           `json:"seal"`
	SealScript         string          `json:"seal_script"`
	IssuerKey          string          `json:"issuer_key"`
	GranteeKey         string          `json:"grantee_key"`
	Anchor             Anchor          `json:"anchor"`
	OwnerName          string          `json:"owner_name"`
	OwnerPaymentScript string          `json:"owner_payment_script"`
	OwnerSPKI          string          `json:"owner_spki"`
	RequesterSPKI      string          `json:"requester_spki"`
	CertificateHash    string          `json:"certificate_sha256"`
	Enrollment         json.RawMessage `json:"enrollment"`
	VerifierPath       string          `json:"verifier_path"`
	VerifierHash       string          `json:"verifier_sha256"`
	StateDir           string          `json:"state_dir"`
}

// StrictInput rejects unknown names and spelling aliases in local typed inputs.
// Arbitrary JSON is allowed only at explicit RawMessage boundaries, checked by
// their dedicated parser (the pinned public verifier for enrollment).
func StrictInput(raw []byte, out any) error {
	if e := sealwatch.DecodeJSON(raw, out); e != nil {
		return e
	}
	var check func([]byte, reflect.Type) error
	check = func(b []byte, t reflect.Type) error {
		if t == reflect.TypeFor[json.RawMessage]() {
			return nil
		}
		if t.Kind() == reflect.Pointer {
			return check(b, t.Elem())
		}
		if t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
			var items []json.RawMessage
			if json.Unmarshal(b, &items) != nil || items == nil {
				return fail("INPUT_ARRAY")
			}
			for _, item := range items {
				if e := check(item, t.Elem()); e != nil {
					return e
				}
			}
			return nil
		}
		if t.Kind() != reflect.Struct {
			return nil
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(b, &fields) != nil || fields == nil {
			return fail("INPUT_OBJECT")
		}
		known := map[string]reflect.Type{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			name := strings.Split(f.Tag.Get("json"), ",")[0]
			if name == "" {
				name = f.Name
			}
			if name != "-" {
				known[name] = f.Type
			}
		}
		for name, v := range fields {
			typ, ok := known[name]
			if !ok || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
				return fail("INPUT_FIELD")
			}
			if e := check(v, typ); e != nil {
				return e
			}
		}
		return nil
	}
	return check(raw, reflect.TypeOf(out))
}
func PublicFile(path string, limit int64) ([]byte, error) {
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() < 1 || info.Size() > limit {
		return nil, fail("PUBLIC_FILE")
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, fail("PUBLIC_FILE")
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm()&0022 != 0 {
		return nil, fail("PUBLIC_FILE")
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(b)) > limit {
		return nil, fail("PUBLIC_FILE")
	}
	return b, nil
}
func (p Policy) validate(cert, req []byte) error {
	if !NetworkPinned(p.Network, p.Genesis) || !digestHex(p.Seal.TxID) || !digestHex(p.Anchor.TxID) || !digestHex(p.Anchor.Block) || p.Anchor.Height < 1 || !digestHex(p.CertificateHash) || Hash(cert) != p.CertificateHash || len(cert) == 0 || len(cert) > 98304 || len(req) == 0 || len(req) > 12288 {
		return fail("POLICY_BINDING")
	}
	_, script, e := SealScript(p.IssuerKey, p.GranteeKey)
	if e != nil {
		return e
	}
	if hex.EncodeToString(script) != p.SealScript {
		return fail("SEAL_SCRIPT_PIN")
	}
	payment, e := hex.DecodeString(p.OwnerPaymentScript)
	if e != nil || len(payment) == 0 || len(payment) > 10000 || hex.EncodeToString(payment) != p.OwnerPaymentScript {
		return fail("OWNER_SCRIPT")
	}
	if len(p.OwnerName) == 0 || len(p.OwnerName) > 255 || len(p.OwnerSPKI) == 0 || len(p.RequesterSPKI) == 0 || p.OwnerSPKI == p.RequesterSPKI || len(p.Enrollment) > 8192 || !filepath.IsAbs(p.StateDir) || filepath.Clean(p.StateDir) != p.StateDir || !filepath.IsAbs(p.VerifierPath) || !digestHex(p.VerifierHash) {
		return fail("POLICY_INPUT")
	}
	for _, s := range []string{p.OwnerName} {
		for _, c := range []byte(s) {
			if c < 32 || c > 126 {
				return fail("ASCII_NAME")
			}
		}
	}
	return nil
}

type limitedBuffer struct {
	bytes.Buffer
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if len(p) > b.max-b.Len() {
		return 0, fail("VERIFIER_OUTPUT_BOUND")
	}
	return b.Buffer.Write(p)
}

func verifyRequest(ctx context.Context, p Policy, cert, req []byte, at time.Time) error {
	binary, e := PublicFile(p.VerifierPath, 64<<20)
	if e != nil || Hash(binary) != p.VerifierHash {
		return fail("VERIFIER_PIN")
	}
	var config map[string]json.RawMessage
	if e = sealwatch.DecodeJSON(p.Enrollment, &config); e != nil || config == nil {
		return fail("ENROLLMENT")
	}
	var owner, requester, mxid string
	if e = sealwatch.ProjectJSON(p.Enrollment, map[string]any{"owner_spki": &owner, "requester_spki": &requester, "owner_mxid": &mxid}, nil); e != nil || owner != p.OwnerSPKI || requester != p.RequesterSPKI || mxid == "" {
		return fail("ENROLLMENT_PINS")
	}
	dir, e := os.MkdirTemp(p.StateDir, "verify-")
	if e != nil {
		return fail("VERIFIER_WORKDIR")
	}
	defer os.RemoveAll(dir)
	config["state_dir"], _ = json.Marshal(filepath.Join(dir, "ABSENT-STATE"))
	config["gh_path"], _ = json.Marshal(filepath.Join(dir, "ABSENT-PROVIDER"))
	cfg, _ := json.Marshal(config)
	for name, b := range map[string][]byte{"config.json": cfg, "certificate.json": cert, "request.json": req} {
		if e = os.WriteFile(filepath.Join(dir, name), b, 0600); e != nil {
			return fail("VERIFIER_INPUT")
		}
	}
	cmd := exec.CommandContext(ctx, p.VerifierPath, "grants", "verify", "--config", filepath.Join(dir, "config.json"), "--certificate", filepath.Join(dir, "certificate.json"), "--request", filepath.Join(dir, "request.json"), "--at", at.UTC().Format(time.RFC3339), "--owner-mxid", mxid)
	cmd.Dir = dir
	cmd.Env = []string{"HOME=" + dir, "TMPDIR=" + dir, "PATH=/nonexistent", "MAC_KEYVAULT_SKIP_KEYCHAIN=1"}
	out := &limitedBuffer{max: 8192}
	diag := &limitedBuffer{max: 8192}
	cmd.Stdout = out
	cmd.Stderr = diag
	if cmd.Run() != nil {
		return fail("REQUEST_VERIFICATION")
	}
	var verdict, certID, requestID, action string
	var validAt, expiresAt time.Time
	var target struct{ Organization, Name, Visibility string }
	if e = sealwatch.ProjectJSON(out.Bytes(), map[string]any{"verdict": &verdict, "certificate_id": &certID, "request_id": &requestID, "action": &action, "valid_at": &validAt, "expires_at": &expiresAt, "target": &target}, nil); e != nil || verdict != "accepted" || certID == "" || requestID == "" || action != "repository.create" || target.Organization != "relux-works" || target.Name != "matrix-grants-poc-261031" || target.Visibility != "private" || !validAt.Equal(at) || !expiresAt.After(at) {
		return fail("VERIFIER_FACTS")
	}
	return nil
}
