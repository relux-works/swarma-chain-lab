package wallet

import (
	"bytes"
	"context"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

func mainAddress(t *testing.T) string {
	t.Helper()
	p := chaincfg.MainNetParams
	p.PubKeyHashAddrID = 52
	a, err := btcutil.NewAddressPubKeyHash(make([]byte, 20), &p)
	if err != nil {
		t.Fatal(err)
	}
	return a.EncodeAddress()
}

// Main requests use the same signed wire/hash while the local service pins
// select their address network. Legacy entrypoints, reciprocal address swaps,
// wrong genesis and name actions refuse before any wallet or RPC effect.
func TestMainActionNetwork(t *testing.T) {
	r := actionFixture(t, "spend")
	r.Params = canonical(SpendParams{To: mainAddress(t), Amount: 100000, FeeLimit: 200000})
	key, _ := testKey(2)
	raw, err := SignActionForNetwork(r, key, nil, "main", su.MainGenesis)
	if err != nil {
		t.Fatal(err)
	}
	v, err := ParseActionForNetwork(raw, WalletServiceID, "main", su.MainGenesis)
	if err != nil || !bytes.Equal(v.RequestBytes, canonical(r)) || v.Hash != Hash(canonical(r)) {
		t.Fatal(v, err)
	}
	if _, err = ParseAction(raw, WalletServiceID); err == nil || err.Error() != "ADDRESS_REGTEST" {
		t.Fatal("legacy accepted main", err)
	}
	if _, err = ParseActionForNetwork(raw, WalletServiceID, "main", su.RegtestGenesis); err == nil || err.Error() != "NETWORK_PIN" {
		t.Fatal("mixed genesis", err)
	}
	r.Params = canonical(SpendParams{To: testAddress(3), Amount: 100000, FeeLimit: 200000})
	if _, err = SignActionForNetwork(r, key, nil, "main", su.MainGenesis); err == nil || err.Error() != "ADDRESS_MAIN" {
		t.Fatal("regtest recipient on main", err)
	}
	r.Action = "names.register"
	if _, err = SignActionForNetwork(r, key, nil, "main", su.MainGenesis); err == nil || err.Error() != "ACTION_UNSUPPORTED" {
		t.Fatal("main names", err)
	}
	c := Config{Network: "main", Genesis: su.MainGenesis}
	if w, err := Open(c); err == nil || err.Error() != "CONFIG_REGTEST_ONLY" || w != nil {
		t.Fatal("legacy main wallet", err)
	}
	w := &Wallet{config: c}
	if got := w.Execute(context.Background(), nil, nil, nil, ""); got.Reason != "LEGACY_REGTEST_ONLY" {
		t.Fatal(got)
	}
	if got := w.executeAuthenticated(context.Background(), nil, nil, Request{Action: "names.register"}, "", 0, nil, "", nil); got.Reason != "MAIN_ACTION_UNSUPPORTED" {
		t.Fatal(got)
	}
}

// Signed oneoff grants bind main recipients and the trusted authority network;
// a correct issuer signature cannot transport a grant into a regtest authority.
func TestMainOneoffNetwork(t *testing.T) {
	_, issuer := testKey(1)
	_, grantee := testKey(2)
	g := OneoffGrant{Version: 1, Network: "main", Genesis: su.MainGenesis, Agent: "id/main-agent", Landlord: "id/main-landlord", Issuer: issuer, Grantee: grantee, Address: mainAddress(t), Amount: 100000, FeeLimit: 200000, NotBefore: 100, NotAfter: 200, Seal: su.Point{TxID: Hash([]byte("seal"))}}
	raw := canonical(OneoffEnvelope{g, signDigest(t, OneoffDigest(g), 1)})
	a := CombinedAuthority{Agent: g.Agent, Landlord: g.Landlord}
	a.Kernel.Policy.Network, a.Kernel.Policy.Genesis = "main", su.MainGenesis
	if got, err := a.Parse(raw); err != nil || got.Budget != 300000 {
		t.Fatal(got, err)
	}
	a.Kernel.Policy.Network, a.Kernel.Policy.Genesis = "regtest", su.RegtestGenesis
	if _, err := a.Parse(raw); err == nil || err.Error() != "ONEOFF_POLICY" {
		t.Fatal("main oneoff crossed network", err)
	}
}
