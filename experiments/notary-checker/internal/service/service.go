// Package service wraps the pinned checker with host key custody, bounded HTTP
// and a concrete regtest node reader. Deployment and transaction funding remain
// operator obligations; this service never broadcasts a transaction.
package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	check "github.com/relux-works/swarma-chain-lab/experiments/notary-checker"
	"github.com/relux-works/swarma-chain-lab/experiments/notary-checker/internal/operatorfile"
)

type Limits struct {
	RequestBytes      int64 `json:"request_bytes"`
	RequestsPerSecond int   `json:"requests_per_second"`
	Burst             int   `json:"burst"`
	TimeoutMS         int   `json:"timeout_ms"`
	Concurrent        int   `json:"concurrent"`
}
type Config struct {
	Listen               string `json:"listen"`
	KeyFile              string `json:"key_file"`
	RPCEndpoint          string `json:"rpc_endpoint"`
	RPCCredentialFile    string `json:"rpc_credential_file"`
	DeploymentPolicyFile string `json:"deployment_policy_file"`
	Limits               Limits `json:"limits"`
}
type Request struct {
	Parent          json.RawMessage `json:"parent"`
	Child           json.RawMessage `json:"child"`
	ParentContract  json.RawMessage `json:"parent_contract"`
	ChildContract   json.RawMessage `json:"child_contract"`
	Request         json.RawMessage `json:"request"`
	PolicyReference string          `json:"policy_reference"`
	Statement       json.RawMessage `json:"statement"`
	ParentText      string          `json:"parent_text,omitempty"`
	ChildText       string          `json:"child_text,omitempty"`
}
type Response struct {
	Decision          string          `json:"decision"`
	SignedAttestation json.RawMessage `json:"signed_attestation,omitempty"`
	AnchorFrame       string          `json:"anchor_frame,omitempty"`
}
type Service struct {
	lifecycle    sync.Mutex
	closing      bool
	active       sync.WaitGroup
	closeOnce    sync.Once
	config       Config
	key          *btcec.PrivateKey
	public       string
	policy       []byte
	reference    string
	policyObject check.Policy
	node         *check.NodeNameReader
	sign         func([]byte) (string, error)
	now          func() time.Time
	slots        chan struct{}
	mu           sync.Mutex
	tokens       float64
	updated      time.Time
}

func readBounded(path string, max int64) ([]byte, error) {
	return operatorfile.Read(path, max)
}
func Load(path string) (*Service, error) {
	raw, e := readBounded(path, 16384)
	if e != nil {
		return nil, errors.New("CONFIG")
	}
	var c Config
	if Strict(raw, &c) != nil || !validConfig(c) {
		return nil, errors.New("CONFIG")
	}
	policy, e := readBounded(c.DeploymentPolicyFile, 8192)
	if e != nil {
		return nil, errors.New("POLICY_FILE")
	}
	var p check.Policy
	if Strict(policy, &p) != nil {
		return nil, errors.New("POLICY_FILE")
	}
	k, e := loadKey(c.KeyFile)
	if e != nil {
		return nil, e
	}
	node, e := check.NewNodeNameReader(c.RPCEndpoint, c.RPCCredentialFile)
	if e != nil {
		k.Zero()
		return nil, e
	}
	h := sha256.Sum256(policy)
	s := &Service{config: c, key: k, public: hex.EncodeToString(schnorr.SerializePubKey(k.PubKey())), policy: policy, reference: hex.EncodeToString(h[:]), policyObject: p, node: node, now: time.Now, slots: make(chan struct{}, c.Limits.Concurrent), tokens: float64(c.Limits.Burst), updated: time.Now()}
	s.sign = func(digest []byte) (string, error) {
		sig, e := schnorr.Sign(s.key, digest)
		if e != nil {
			return "", errors.New("SIGNING_FAILED")
		}
		return hex.EncodeToString(sig.Serialize()), nil
	}
	return s, nil
}
func validConfig(c Config) bool {
	host, port, e := net.SplitHostPort(c.Listen)
	ip := net.ParseIP(host)
	l := c.Limits
	return e == nil && ip != nil && ip.IsLoopback() && port != "" && c.KeyFile != "" && c.RPCEndpoint != "" && c.RPCCredentialFile != "" && c.DeploymentPolicyFile != "" && l.RequestBytes >= 1024 && l.RequestBytes <= 1048576 && l.RequestsPerSecond >= 1 && l.RequestsPerSecond <= 100 && l.Burst >= 1 && l.Burst <= 100 && l.TimeoutMS >= 10 && l.TimeoutMS <= 30000 && l.Concurrent >= 1 && l.Concurrent <= 32
}

// Close prevents new work, drains existing handlers, then clears the key.
func (s *Service) Close() {
	s.closeOnce.Do(func() {
		s.lifecycle.Lock()
		s.closing = true
		s.lifecycle.Unlock()
		s.active.Wait()
		if s.key != nil {
			s.key.Zero()
		}
	})
}
func (s *Service) allowed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	elapsed := now.Sub(s.updated).Seconds()
	if elapsed > 0 {
		s.tokens += elapsed * float64(s.config.Limits.RequestsPerSecond)
		s.updated = now
	}
	if s.tokens > float64(s.config.Limits.Burst) {
		s.tokens = float64(s.config.Limits.Burst)
	}
	if s.tokens < 1 {
		return false
	}
	s.tokens--
	return true
}
func write(w http.ResponseWriter, status int, r Response) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(r)
}
func refused(w http.ResponseWriter, status int, code string) {
	write(w, status, Response{Decision: code})
}
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.lifecycle.Lock()
	if s.closing {
		s.lifecycle.Unlock()
		refused(w, 503, "SHUTDOWN")
		return
	}
	s.active.Add(1)
	s.lifecycle.Unlock()
	defer s.active.Done()
	if r.URL.Path != "/v1/attest" || r.URL.RawQuery != "" {
		refused(w, 404, "ENDPOINT")
		return
	}
	if r.Method != "POST" {
		refused(w, 405, "METHOD")
		return
	}
	if !s.allowed() {
		refused(w, 429, "RATE_LIMIT")
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		refused(w, 503, "BUSY")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(s.config.Limits.TimeoutMS)*time.Millisecond)
	defer cancel()
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, s.config.Limits.RequestBytes))
	if e != nil {
		var size *http.MaxBytesError
		if errors.As(e, &size) {
			refused(w, 413, "REQUEST_TOO_LARGE")
		} else {
			refused(w, 400, "REQUEST_READ")
		}
		return
	}
	var req Request
	if Strict(raw, &req) != nil {
		refused(w, 400, "REQUEST_INVALID")
		return
	}
	result, e := s.attest(ctx, req)
	if e != nil {
		code := "SERVICE_FAILURE"
		var named check.Refusal
		if errors.As(e, &named) {
			code = string(named)
		}
		refused(w, 422, code)
		return
	}
	write(w, 200, result)
}
func (s *Service) attest(ctx context.Context, req Request) (Response, error) {
	fail := func(code string) (Response, error) { return Response{}, check.Refusal(code) }
	if req.PolicyReference != s.reference {
		return fail("POLICY_REFERENCE")
	}
	var statement check.Statement
	if Strict(req.Statement, &statement) != nil {
		return fail("STATEMENT_FIELD")
	}
	node := s.node.WithContext(ctx)
	notary, e := node.Lookup(s.policyObject.NotaryName, statement.TipHeight, statement.TipHash)
	if e != nil {
		return Response{}, e
	}
	in := check.Input{Parent: req.Parent, Child: req.Child, ParentContract: req.ParentContract, ChildContract: req.ChildContract, Request: req.Request, Policy: s.policy, NotaryValue: notary.Value, Statement: req.Statement, ParentText: []byte(req.ParentText), ChildText: []byte(req.ChildText), At: s.now().Unix()}
	result, err := check.CheckRunningWithNode(in, node)
	if err != nil {
		return Response{}, err
	}
	var a check.Attestation
	if json.Unmarshal(result.Attestation, &a) != nil {
		return fail("ATTESTATION_BINDING")
	}
	if a.Network != "regtest" {
		return fail("NODE_NETWORK")
	}
	if a.NotaryKey != s.public {
		return fail("NOTARY_KEY_MISMATCH")
	}
	var contract check.Contract
	var delegate check.Delegate
	if json.Unmarshal(req.ParentContract, &contract) != nil || json.Unmarshal(contract.Delegate, &delegate) != nil {
		return fail("ATTESTATION_BINDING")
	}
	found := false
	for _, n := range delegate.Notaries {
		if n.Name == a.NotaryName && n.Registration == notary.Registration {
			found = true
		}
	}
	if !found {
		return fail("NOTARY_REGISTRATION_MISMATCH")
	}
	if e = node.View(statement.TipHeight, statement.TipHash); e != nil {
		return Response{}, e
	}
	if ctx.Err() != nil {
		return fail("REQUEST_TIMEOUT")
	}
	digest, e := hex.DecodeString(result.Digest)
	if e != nil {
		return fail("ATTESTATION_BINDING")
	}
	sig, e := s.sign(digest)
	if e != nil {
		return fail("SIGNING_FAILED")
	}
	envelope, id, e := check.SignedAttestation(result, sig)
	if e != nil {
		return Response{}, e
	}
	anchor, e := check.AnchorScript(id, a.ChildGrantID, a.ParentGrantID)
	if e != nil {
		return Response{}, e
	}
	if ctx.Err() != nil {
		return fail("REQUEST_TIMEOUT")
	}
	return Response{Decision: "ATTEST", SignedAttestation: envelope, AnchorFrame: hex.EncodeToString(anchor)}, nil
}

// Run opens only the configured listener. Read deadlines include slow bodies;
// the request context bounds all RPC calls and is checked before signing.
func (s *Service) Run(ctx context.Context) error {
	listener, e := net.Listen("tcp", s.config.Listen)
	if e != nil {
		return errors.New("LISTEN")
	}
	return s.runListener(ctx, listener)
}
func (s *Service) runListener(ctx context.Context, listener net.Listener) error {
	timeout := time.Duration(s.config.Limits.TimeoutMS) * time.Millisecond
	server := &http.Server{Handler: s, ReadHeaderTimeout: timeout, ReadTimeout: timeout, WriteTimeout: timeout + time.Second, IdleTimeout: timeout, MaxHeaderBytes: 8192, ErrorLog: log.New(io.Discard, "", 0)}
	exited := make(chan struct{})
	defer close(exited)
	go func() {
		select {
		case <-ctx.Done():
			_ = server.Close()
		case <-exited:
		}
	}()
	e := server.Serve(listener)
	if e == http.ErrServerClosed {
		return nil
	}
	return errors.New("SERVER")
}
