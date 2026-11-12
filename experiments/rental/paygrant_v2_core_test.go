package rental

// Owner S4. Genuine Namecoin Core regtest evidence for the terms-v2 pay grant:
// a grant issued by IssuePayGrantV2 through external signers is planned by the
// existing MakeGrantIssuancePlan, broadcast, confirmed, and then admitted by
// the unchanged v3 kernel (rental.Check) with scope ["pay"] and its budget.

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

// payGrantCorePins accepts the existing repository Core pin pair and the
// official Namecoin Core 28.0 x86_64-linux-gnu release pair (archive SHA-256
// 6f12031926f0999b8507e073648cc2b4488d452531301a2244a562a92f2f7860, the
// executable pin recorded in experiments/fullnode-trusts/README.md).
var payGrantCorePins = map[string]string{
	"86b85483da23c83f7de134a5bf28bad8e3c6a8dbfe2af71a5e889a7b1547787f": "5cccdfe19aef6b427373c200bda72d4dd66b5be2c5f93b7e8b08b9d6a81fdd4d",
	"dc7430676e445af3992430e036f7c1a17bea44f757e9cf25b69205e39625f2f7": "318b6c881c8071abbafd984550172369c3498b4c65c389797350f2d458f085b1",
}

// newPayGrantCore is newCore with the release pin pair above; the node set-up
// is otherwise identical (same coreLab, same configuration, same station).
func newPayGrantCore(t *testing.T) *coreLab {
	t.Helper()
	if os.Getenv("M1_REGTEST") != "1" {
		t.Skip("requires explicit genuine Core M1_REGTEST=1")
	}
	root := os.Getenv("M1_RUN_ROOT")
	if !filepath.IsAbs(root) {
		t.Fatal("absolute M1_RUN_ROOT required")
	}
	if e := os.Mkdir(root, 0700); e != nil {
		t.Fatal(e)
	}
	l := &coreLab{t: t, root: root, private: filepath.Join(root, "private"), public: filepath.Join(root, "public"), daemon: os.Getenv("M1_CORE_DAEMON"), cli: os.Getenv("M1_CORE_CLI"), station: "id/swarma-station-test"}
	for _, d := range []string{l.private, l.public} {
		if e := os.Mkdir(d, 0700); e != nil {
			t.Fatal(e)
		}
	}
	daemon, e1 := os.ReadFile(l.daemon)
	cli, e2 := os.ReadFile(l.cli)
	if e1 != nil || e2 != nil || payGrantCorePins[Hash(daemon)] == "" || payGrantCorePins[Hash(daemon)] != Hash(cli) {
		t.Fatal("Core binary pin")
	}
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	random := make([]byte, 32)
	if _, e = rand.Read(random); e != nil {
		t.Fatal(e)
	}
	password := hex.EncodeToString(random)
	salt := hex.EncodeToString(random[:8])
	mac := hmac.New(sha256.New, []byte(salt))
	mac.Write([]byte(password))
	l.route = su.Route{Host: "127.0.0.1", Port: port, Username: "w3-observer", Password: password}
	l.observer, e = su.NewRPC(l.route)
	if e != nil {
		t.Fatal(e)
	}
	l.conf = filepath.Join(l.private, "namecoin.conf")
	cfg := fmt.Sprintf("server=1\ndeprecatedrpc=create_bdb\nlisten=0\ndnsseed=0\ndiscover=0\nnetworkactive=0\ntxindex=1\npersistmempool=0\nfallbackfee=0.002\nacceptnonstdtxn=1\nnameencoding=ascii\nvalueencoding=ascii\nrpcwhitelistdefault=0\nrpcauth=w3-observer:%s$%x\nrpcwhitelist=w3-observer:getblockchaininfo,getblockhash,getblockheader,getrawtransaction,gettxout,name_show,getrawmempool,getblock\n[regtest]\nrpcbind=127.0.0.1\nrpcallowip=127.0.0.1\nrpcport=%d\n", salt, mac.Sum(nil), port)
	if e = os.WriteFile(l.conf, []byte(cfg), 0600); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { l.stop(); l.save("commands.json", l.rows) })
	l.start()
	l.rpc("", "createwallet", "issuer", false, false, "", false, false)
	l.address = text(t, l.rpc("issuer", "getnewaddress", "", "legacy"))
	l.script = text(t, object(t, l.rpc("issuer", "getaddressinfo", l.address))["scriptPubKey"])
	l.mine(101)
	var reservation []string
	if e = json.Unmarshal(l.rpc("issuer", "name_new", l.station), &reservation); e != nil {
		t.Fatal(e)
	}
	l.mine(12)
	l.rpc("issuer", "name_firstupdate", l.station, reservation[1], reservation[0], "{}", map[string]string{"destAddress": l.address})
	l.mine(1)
	return l
}

// Claim (genuine Core 28 regtest): a pay grant issued by IssuePayGrantV2 with
// terms v2 over two regtest P2PKH wallet addresses is accepted by the
// existing MakeGrantIssuancePlan; while its issuance is unconfirmed the v3
// kernel says pending ISSUANCE_UNCONFIRMED (negative neighbour); once mined it
// is LIVE with scope ["pay"] and the issued budget at a time days after the
// one-hour booking cap; another sender is refused GRANTEE_MISMATCH; and a
// seal spend closes it (SEAL_SPENT), so the landlord revoke path applies.
// Limit: in-memory signers stand in for the Mac Keychain key and Cedar's key.
func TestCorePayGrantV2Issuance(t *testing.T) {
	l := newPayGrantCore(t)
	l.grantIdentity()
	seal := l.witnessPool(1, true)
	p := l.policy("paygrant-v2")
	p.ConstructionProfile = "W"
	p.AgentName = l.station
	p.LandlordName = labLandlord
	p.SealScript, _ = GrantSealScript(p.IssuerPubkey)
	p.FundingScript = testFundingScript()

	recipients := []string{text(t, l.rpc("issuer", "getnewaddress", "", "legacy")), text(t, l.rpc("issuer", "getnewaddress", "", "legacy"))}
	sort.Strings(recipients)
	terms := px1PayTermsAllow()
	terms.Network, terms.Genesis, terms.Recipients = "regtest", su.RegtestGenesis, recipients
	_, issuer := testKey(1)
	_, grantee := testKey(2)
	const notBefore = int64(100)
	in := PayGrantV2Input{Network: "regtest", Genesis: su.RegtestGenesis, AgentName: l.station, LandlordName: labLandlord, IssuerKey: issuer, GranteeKey: grantee, NotBefore: notBefore, NotAfter: notBefore + 30*86400, Seal: seal, BudgetSat: 500000, Terms: terms, ConsentCreatedAt: notBefore + 10, PrivacyNoticeSHA256: Hash([]byte("g2-privacy-notice"))}
	log := &px1SignLog{}
	g, ll := px1Signers(log)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r, e := IssuePayGrantV2(ctx, in, g, ll)
	if e != nil || len(log.calls) != 3 {
		t.Fatal("issue", e, log.calls)
	}
	l.save("paygrant-v2-result.json", r)
	l.save("paygrant-v2-terms.json", json.RawMessage(r.Terms))

	proof := l.grantProof(p, r.SignedGrant, false)
	signed, _ := ParseSignedGrant(r.SignedGrant)
	at := notBefore + 3*86400 // past any 3600 s booking window
	l.checkGrant("paygrant-unconfirmed", p, signed.Grant, proof, at, "pending", "ISSUANCE_UNCONFIRMED", false)
	l.mine(1)
	live := l.checkGrant("paygrant-live", p, signed.Grant, proof, at, "live", "LIVE", false)
	if live.GrantID != r.GrantID || !reflect.DeepEqual(live.Scope, []string{"pay"}) || live.BudgetSat != in.BudgetSat {
		t.Fatalf("live receipt %+v", live)
	}
	_, outsider := testKey(4)
	if rr := Check(context.Background(), l.observer, p, proof, p.AgentName, outsider, at); rr.Verdict != "refused" || rr.Reason != "GRANTEE_MISMATCH" {
		t.Fatalf("outsider %+v", rr)
	}
	l.revokeDetached(seal, false)
	l.checkGrant("paygrant-revoked", p, signed.Grant, proof, at, "refused", "SEAL_SPENT", true)
	l.save("paygrant-v2-core-result.json", map[string]any{"status": "PASS", "grant_id": r.GrantID, "contract_sha256": r.ContractSHA256, "issuance_commitment": r.IssuanceCommitment, "signer_calls": log.calls})
}
