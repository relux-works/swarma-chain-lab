// Command rt-grant-fixture provisions a throwaway standing grant on a private
// loopback regtest node. It is rehearsal tooling, never a release component.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	rental "github.com/relux-works/swarma-chain-lab/experiments/rental"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

const agentName = "id/rt-agent"
const landlordName = "id/rt-landlord"
const sealSat int64 = 1000000

type options struct {
	host, cookie, wallet, out, agent, landlord, executor, recipient string
	port                                                            int
	allowance, fee                                                  int64
	validFor                                                        time.Duration
}

// Only fixed diagnostics cross the process boundary: RPC bodies, credentials,
// filesystem errors and private keys must never become command output.
func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rt-grant-fixture", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var o options
	fs.StringVar(&o.host, "rpc-host", "127.0.0.1", "numeric loopback RPC host")
	fs.IntVar(&o.port, "rpc-port", 0, "private regtest RPC port")
	fs.StringVar(&o.cookie, "rpc-cookie", "", "private node cookie file")
	fs.StringVar(&o.wallet, "wallet", "", "existing throwaway funding/name wallet (native witness capable)")
	fs.StringVar(&o.out, "out-dir", "", "new private output directory; must not exist")
	fs.StringVar(&o.agent, "agent-name", agentName, "fixed rehearsal agent name")
	fs.StringVar(&o.landlord, "landlord-name", landlordName, "fixed rehearsal landlord name")
	fs.StringVar(&o.executor, "executor-key", "", "installed wallet receipt public key (x-only hex)")
	fs.StringVar(&o.recipient, "recipient", "", "allow-listed regtest P2PKH recipient")
	fs.Int64Var(&o.allowance, "allowance-sat", 20000, "payment principal; budget adds the fee reserve")
	fs.Int64Var(&o.fee, "fee-limit-sat", 30000, "fee reserve and per-payment fee cap")
	fs.DurationVar(&o.validFor, "valid-for", 24*time.Hour, "grant lifetime (maximum 24h)")
	fail := func(code string) int { fmt.Fprintln(stderr, "rt-grant-fixture: "+code); return 1 }
	if fs.Parse(args) != nil || fs.NArg() != 0 {
		return fail("ARGUMENTS")
	}
	if err := o.validate(); err != nil {
		return fail(err.Error())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	id, err := provision(ctx, o)
	if err != nil {
		return fail(err.Error())
	}
	fmt.Fprintln(stdout, "RT_GRANT_ID "+id)
	return 0
}

func (o options) terms() rental.PayTermsV2 {
	return rental.PayTermsV2{Version: 2, Service: "wallet.nmc", ExecutorKey: o.executor,
		Network: "regtest", Genesis: su.RegtestGenesis, RecipientMode: "allow", Recipients: []string{o.recipient},
		SpendCap: o.allowance + o.fee, TransferCap: o.allowance + o.fee, DayCap: o.allowance + o.fee,
		DayCountCap: 10, FeeCap: o.fee, DayBasis: "utc-calendar"}
}
func (o options) validate() error {
	ip, err := netip.ParseAddr(o.host)
	if err != nil || !ip.IsLoopback() || ip.Zone() != "" {
		return errors.New("LOOPBACK_REQUIRED")
	}
	if o.port < 1 || o.port > 65535 || o.cookie == "" || o.wallet == "" || strings.ContainsAny(o.wallet, "/\\?#%") || o.out == "" {
		return errors.New("ARGUMENTS")
	}
	if o.agent != agentName || o.landlord != landlordName {
		return errors.New("FIXED_NAMES_REQUIRED")
	}
	if _, err := os.Lstat(o.out); !os.IsNotExist(err) {
		return errors.New("OUT_DIR_EXISTS_OR_UNAVAILABLE")
	}
	if o.allowance < 20000 || o.allowance > rental.MaxMoney || o.fee < 1 || o.fee > rental.MaxMoney-o.allowance || o.validFor < time.Minute || o.validFor > 24*time.Hour {
		return errors.New("PARAMETERS")
	}
	if _, err := rental.EncodePayTermsV2(o.terms()); err != nil {
		return errors.New("TERMS")
	}
	return nil
}

type rpcError struct {
	Code int `json:"code"`
}

func (e *rpcError) Error() string { return "RPC_REFUSED" }

type rpcClient struct {
	client               *http.Client
	base, cookie, wallet string
}

func newRPC(o options) (*rpcClient, error) {
	f, err := os.Open(o.cookie)
	if err != nil {
		return nil, errors.New("COOKIE")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("COOKIE")
	}
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	cookie := strings.TrimSpace(string(b))
	if err != nil || len(b) > 4096 || !strings.Contains(cookie, ":") || strings.ContainsAny(cookie, "\r\n") {
		return nil, errors.New("COOKIE")
	}
	// No environment proxy, DNS, redirects or alternate transport can move the
	// credential-bearing request off the numeric loopback endpoint.
	tr := &http.Transport{DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext}
	c := &http.Client{Transport: tr, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &rpcClient{c, "http://" + net.JoinHostPort(o.host, strconv.Itoa(o.port)), cookie, o.wallet}, nil
}
func (r *rpcClient) call(ctx context.Context, wallet bool, method string, out any, args ...any) error {
	if args == nil {
		args = []any{}
	}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "1.0", "id": "rt", "method": method, "params": args})
	endpoint := r.base
	if wallet {
		endpoint += "/wallet/" + url.PathEscape(r.wallet)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return errors.New("RPC_TRANSPORT")
	}
	user, password, _ := strings.Cut(r.cookie, ":")
	req.SetBasicAuth(user, password)
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return errors.New("RPC_TRANSPORT")
	}
	defer resp.Body.Close()
	var v struct {
		Result json.RawMessage `json:"result"`
		Error  *rpcError       `json:"error"`
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil || json.Unmarshal(b, &v) != nil {
		return errors.New("RPC_RESPONSE")
	}
	if v.Error != nil {
		return v.Error
	}
	if resp.StatusCode != http.StatusOK || len(v.Result) == 0 {
		return errors.New("RPC_RESPONSE")
	}
	if out != nil && json.Unmarshal(v.Result, out) != nil {
		return errors.New("RPC_RESULT")
	}
	return nil
}
func (r *rpcClient) regtest(ctx context.Context) error {
	var info struct {
		Chain string `json:"chain"`
	}
	if err := r.call(ctx, false, "getblockchaininfo", &info); err != nil {
		return err
	}
	if info.Chain != "regtest" {
		return errors.New("REGTEST_REQUIRED")
	}
	// Core's getblockchaininfo has no genesis member; getblockhash(0) pins it.
	var genesis string
	if err := r.call(ctx, false, "getblockhash", &genesis, 0); err != nil {
		return err
	}
	if genesis != su.RegtestGenesis {
		return errors.New("REGTEST_GENESIS_REQUIRED")
	}
	return nil
}

type fixtureSigner struct{ key *btcec.PrivateKey }

func (s fixtureSigner) XOnlyKey() string {
	return hex.EncodeToString(schnorr.SerializePubKey(s.key.PubKey()))
}
func (s fixtureSigner) Sign(_ context.Context, req rental.PayGrantSigningRequest) (rental.PayGrantSignature, error) {
	if _, err := rental.VerifyPayGrantSigningRequest(req); err != nil || req.SignerKey != s.XOnlyKey() {
		return rental.PayGrantSignature{}, errors.New("SIGN_REQUEST")
	}
	b, _ := hex.DecodeString(req.Digest)
	sig, err := schnorr.Sign(s.key, b)
	if err != nil {
		return rental.PayGrantSignature{}, errors.New("SIGN")
	}
	return rental.PayGrantSignature{Version: 1, Purpose: req.Purpose, SignerKey: req.SignerKey, Digest: req.Digest, Signature: hex.EncodeToString(sig.Serialize())}, nil
}
func writePrivate(dir, name string, b []byte) error {
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("OUTPUT_CREATE")
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return errors.New("OUTPUT_WRITE")
	}
	return nil
}
func makeKey(dir, name string) (fixtureSigner, error) {
	k, err := btcec.NewPrivateKey()
	if err != nil {
		return fixtureSigner{}, errors.New("KEY_GENERATION")
	}
	// Normalize the issuer too: GrantSealScript uses the even-y compressed key.
	if k.PubKey().SerializeCompressed()[0] == 3 {
		k.Key.Negate()
	}
	s := fixtureSigner{k}
	if err = writePrivate(dir, name, []byte(hex.EncodeToString(k.Serialize())+"\n")); err != nil {
		return fixtureSigner{}, err
	}
	return s, nil
}

type fixture struct {
	Version             int             `json:"version"`
	Network             string          `json:"network"`
	Genesis             string          `json:"genesis"`
	GrantID             string          `json:"grant_id"`
	ContractSHA256      string          `json:"contract_sha256"`
	IssuerKey           string          `json:"issuer_key"`
	GranteeKey          string          `json:"grantee_key"`
	ExecutorKey         string          `json:"executor_key"`
	Seal                rental.Point    `json:"seal"`
	AgentName           string          `json:"agent_name"`
	LandlordName        string          `json:"landlord_name"`
	SealScript          string          `json:"seal_script"`
	ConstructionProfile string          `json:"construction_profile"`
	AllowanceSat        int64           `json:"allowance_sat"`
	FeeLimitSat         int64           `json:"fee_limit_sat"`
	BudgetSat           int64           `json:"budget_sat"`
	NotBefore           int64           `json:"not_before"`
	NotAfter            int64           `json:"not_after"`
	Terms               json.RawMessage `json:"terms"`
	Presentation        json.RawMessage `json:"presentation"`
}

func provision(ctx context.Context, o options) (string, error) {
	r, err := newRPC(o)
	if err != nil {
		return "", err
	}
	defer r.client.CloseIdleConnections()
	if err = r.regtest(ctx); err != nil {
		return "", err
	}
	// Check BOTH names before creating keys or making any write RPC. A rerun is
	// never a name takeover or renewal, even when these fixed names have expired.
	for _, name := range []string{agentName, landlordName} {
		err = r.call(ctx, false, "name_show", nil, name)
		var re *rpcError
		if !errors.As(err, &re) || re.Code != -4 {
			return "", errors.New("FRESH_NAMES_REQUIRED")
		}
	}
	if err = os.Mkdir(o.out, 0700); err != nil {
		return "", errors.New("OUT_DIR_EXISTS_OR_UNAVAILABLE")
	}
	// On failure retain private partial state for operator inspection; never
	// retry automatically after an on-chain effect or erase its custody keys.
	issuer, err := makeKey(o.out, "issuer.key")
	if err != nil {
		return "", err
	}
	grantee, err := makeKey(o.out, "grantee.key")
	if err != nil {
		return "", err
	}
	var miner string
	if err = r.call(ctx, true, "getnewaddress", &miner, "", "bech32"); err != nil {
		return "", err
	}
	mine := func(n int) error { return r.call(ctx, false, "generatetoaddress", nil, n, miner) }
	// Mature fresh native-witness funding even if the supplied wallet was empty.
	if err = mine(101); err != nil {
		return "", err
	}
	av, _ := rental.AgentBindingValue(rental.AgentBinding{Nostr: grantee.XOnlyKey(), Landlord: landlordName})
	lv, _ := rental.LandlordValue(rental.LandlordBinding{Grant: issuer.XOnlyKey()})
	names := []struct {
		name, value string
		reservation []string
	}{{name: agentName, value: av}, {name: landlordName, value: lv}}
	for i := range names {
		if err = r.call(ctx, true, "name_new", &names[i].reservation, names[i].name); err != nil {
			return "", err
		}
		if len(names[i].reservation) != 2 {
			return "", errors.New("NAME_RESERVATION")
		}
	}
	if err = mine(12); err != nil {
		return "", err
	}
	for _, n := range names {
		if err = r.call(ctx, true, "name_firstupdate", nil, n.name, n.reservation[1], n.reservation[0], n.value); err != nil {
			return "", err
		}
	}
	if err = mine(1); err != nil {
		return "", err
	}
	script, _ := rental.GrantSealScript(issuer.XOnlyKey())
	pub, _ := schnorr.ParsePubKey(mustHex(issuer.XOnlyKey()))
	address, _ := btcutil.NewAddressPubKeyHash(btcutil.Hash160(pub.SerializeCompressed()), &chaincfg.RegressionNetParams)
	sealID, err := r.transaction(ctx, []map[string]any{{address.EncodeAddress(): su.Coins(sealSat)}})
	if err != nil {
		return "", err
	}
	if err = mine(1); err != nil {
		return "", err
	}
	var view su.TransactionView
	if err = r.call(ctx, false, "getrawtransaction", &view, sealID, true); err != nil {
		return "", err
	}
	var seal rental.Point
	for _, out := range view.Vout {
		if out.Script.Hex == script && int64(out.Value) == sealSat {
			seal = rental.Point{TxID: sealID, Vout: out.N}
		}
	}
	if seal.TxID == "" {
		return "", errors.New("SEAL_ABSENT")
	}
	var locked bool
	if err = r.call(ctx, true, "lockunspent", &locked, false, []rental.Point{seal}); err != nil {
		return "", err
	}
	if !locked {
		return "", errors.New("SEAL_LOCK")
	}
	now := time.Now().Unix()
	in := rental.PayGrantV2Input{Network: "regtest", Genesis: su.RegtestGenesis, AgentName: agentName, LandlordName: landlordName,
		IssuerKey: issuer.XOnlyKey(), GranteeKey: grantee.XOnlyKey(), NotBefore: now - 60, NotAfter: now + int64(o.validFor/time.Second),
		Seal: seal, BudgetSat: o.allowance + o.fee, Terms: o.terms(), ConsentCreatedAt: now, PrivacyNoticeSHA256: rental.Hash([]byte("regtest-only-rehearsal"))}
	issued, err := rental.IssuePayGrantV2(ctx, in, grantee, issuer)
	if err != nil {
		return "", errors.New("GRANT_ISSUANCE")
	}
	// Same issuance commitment/fund/sign/broadcast recipe as coreLab.issueProof.
	txid, err := r.transaction(ctx, []map[string]any{{"data": issued.IssuanceCommitment}})
	if err != nil {
		return "", err
	}
	if err = mine(1); err != nil {
		return "", err
	}
	presentation, err := rental.PresentIssuedGrant(issued.SignedGrant, txid)
	if err != nil {
		return "", errors.New("GRANT_PRESENTATION")
	}
	f := fixture{1, "regtest", su.RegtestGenesis, issued.GrantID, issued.ContractSHA256, issuer.XOnlyKey(), grantee.XOnlyKey(), o.executor, seal, agentName, landlordName, script, su.WitnessProfile, o.allowance, o.fee, in.BudgetSat, in.NotBefore, in.NotAfter, issued.Terms, presentation}
	b, _ := json.Marshal(f)
	if err = writePrivate(o.out, "fixture.json", append(b, '\n')); err != nil {
		return "", err
	}
	// Hash-addressed objects are ready to copy into the installed objects dir.
	if err = writePrivate(o.out, issued.GrantID+".json", presentation); err != nil {
		return "", err
	}
	if err = writePrivate(o.out, issued.ContractSHA256+".json", issued.Terms); err != nil {
		return "", err
	}
	return issued.GrantID, nil
}
func mustHex(s string) []byte { b, _ := hex.DecodeString(s); return b }

func (r *rpcClient) transaction(ctx context.Context, outputs []map[string]any) (string, error) {
	var coins []struct {
		TxID      string      `json:"txid"`
		Vout      uint32      `json:"vout"`
		Script    string      `json:"scriptPubKey"`
		Amount    json.Number `json:"amount"`
		Spendable bool        `json:"spendable"`
		Safe      bool        `json:"safe"`
	}
	if err := r.call(ctx, true, "listunspent", &coins, 1); err != nil {
		return "", err
	}
	var input *rental.Point
	for _, c := range coins {
		amount, err := su.ParseCoins(c.Amount.String())
		if err == nil && amount >= sealSat+100000 && c.Spendable && c.Safe && su.NativeP2WPKH(mustHex(c.Script)) {
			input = &rental.Point{TxID: c.TxID, Vout: c.Vout}
			break
		}
	}
	if input == nil {
		return "", errors.New("WITNESS_FUNDING_REQUIRED")
	}
	var raw, change string
	if err := r.call(ctx, false, "createrawtransaction", &raw, []rental.Point{*input}, outputs); err != nil {
		return "", err
	}
	if err := r.call(ctx, true, "getnewaddress", &change, "", "bech32"); err != nil {
		return "", err
	}
	var funded struct {
		Hex string `json:"hex"`
	}
	if err := r.call(ctx, true, "fundrawtransaction", &funded, raw, map[string]any{"add_inputs": false, "changeAddress": change, "fee_rate": 200}); err != nil {
		return "", err
	}
	var signed struct {
		Hex      string `json:"hex"`
		Complete bool   `json:"complete"`
	}
	if err := r.call(ctx, true, "signrawtransactionwithwallet", &signed, funded.Hex); err != nil {
		return "", err
	}
	if !signed.Complete {
		return "", errors.New("TRANSACTION_SIGN")
	}
	var txid string
	if err := r.call(ctx, false, "sendrawtransaction", &txid, signed.Hex); err != nil {
		return "", err
	}
	return txid, nil
}
