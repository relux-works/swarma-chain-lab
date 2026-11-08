package sealwatch

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

type projectionRPC struct {
	inner  *fixture
	change func(string, []any, []byte) []byte
	hits   int
}

func (p *projectionRPC) Call(ctx context.Context, method string, args ...any) (io.ReadCloser, error) {
	body, err := p.inner.Call(ctx, method, args...)
	if err != nil {
		return body, err
	}
	raw, err := io.ReadAll(body)
	body.Close()
	if err != nil {
		return nil, err
	}
	// Baseline test structs omit these tags. The control wire fixture always
	// spells Core block members officially, independently of production tags.
	if method == "getblock" {
		raw = bytes.ReplaceAll(raw, []byte(`"Hash":`), []byte(`"hash":`))
		raw = bytes.ReplaceAll(raw, []byte(`"Height":`), []byte(`"height":`))
		raw = bytes.ReplaceAll(raw, []byte(`"Tx":`), []byte(`"tx":`))
	}
	if p.change != nil {
		changed := p.change(method, args, raw)
		if !bytes.Equal(raw, changed) {
			p.hits++
		}
		raw = changed
	}
	return io.NopCloser(bytes.NewReader(raw)), nil
}

func watchProjectionMutation(t *testing.T, raw []byte, field, mode string, occurrence int) []byte {
	t.Helper()
	tag := `"` + field + `":`
	i := -len(tag)
	for j := 0; j <= occurrence; j++ {
		next := bytes.Index(raw[i+len(tag):], []byte(tag))
		if next < 0 {
			t.Fatal("missing fixture field", field, occurrence)
		}
		i += len(tag) + next
	}
	d := json.NewDecoder(bytes.NewReader(raw[i+len(tag):]))
	var value json.RawMessage
	if err := d.Decode(&value); err != nil {
		t.Fatal(err)
	}
	end := i + len(tag) + int(d.InputOffset())
	alias := `"` + strings.ToUpper(field) + `":` + string(value)
	official := tag + string(value)
	var replacement string
	switch mode {
	case "alias":
		replacement = alias
	case "alias-last":
		replacement = tag + `null,` + alias
	case "official-last":
		replacement = alias + `,` + tag + `null`
	case "duplicate":
		replacement = official + `,` + official
	default:
		t.Fatal("unknown mutation")
	}
	return []byte(string(raw[:i]) + replacement + string(raw[end:]))
}

// Official Core spellings retain all three causal verdicts. Every aliased,
// conflicting or duplicate field below must produce UNKNOWN/malformed, with
// no positive seal proof, no confirmed-spend claim and no command authority.
// This probes real Watch calls, not agreement between two decoders.
func TestW7WatchExactProjection(t *testing.T) {
	type target struct {
		name, method, field, scenario string
		occurrence                    int
	}
	var targets []target
	for _, field := range []string{"chain", "blocks", "headers", "bestblockhash", "initialblockdownload"} {
		targets = append(targets, target{"tip/" + field, "getblockchaininfo", field, "unspent", 0})
	}
	for _, field := range []string{"bestblock", "confirmations", "scriptPubKey", "hex"} {
		targets = append(targets, target{"utxo/" + field, "gettxout", field, "unspent", 0})
	}
	for _, field := range []string{"txid", "blockhash", "confirmations", "vout", "n", "scriptPubKey", "hex"} {
		targets = append(targets, target{"anchor/" + field, "getrawtransaction", field, "unspent", 0})
	}
	for _, field := range []string{"txid", "vin", "vout"} {
		targets = append(targets, target{"mempool/" + field, "getrawtransaction", field, "mempool", 0})
	}
	targets = append(targets, target{"mempool/input-txid", "getrawtransaction", "txid", "mempool", 1})
	for _, field := range []string{"hash", "height", "tx", "coinbase"} {
		targets = append(targets, target{"block/" + field, "getblock", field, "block", 0})
	}
	for _, tc := range targets {
		for _, mode := range []string{"official", "alias", "alias-last", "official-last", "duplicate"} {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				f, b, l := setup()
				want := Unspent
				switch tc.scenario {
				case "mempool":
					f.pool = []tx{normalTx(digest(400), b.Seal)}
					want = Suspend
				case "block":
					f.addBlock(normalTx(digest(400), b.Seal))
					want = FinalRevoked
				}
				p := &projectionRPC{inner: f}
				if mode != "official" {
					p.change = func(method string, args []any, raw []byte) []byte {
						if method != tc.method {
							return raw
						}
						if method == "getrawtransaction" && tc.scenario == "mempool" && args[0] == b.Anchor.TxID {
							return raw
						}
						return watchProjectionMutation(t, raw, tc.field, mode, tc.occurrence)
					}
				}
				v := New(p).Watch(context.Background(), b, l)
				if mode == "official" {
					if v.State != want {
						t.Fatalf("official %s: %+v", want, v)
					}
				} else {
					if p.hits == 0 {
						t.Fatal("control mutation not applied")
					}
					if v.State != Unknown || v.Reason != "RPC_UNAVAILABLE_OR_MALFORMED" || v.SealChainOK || v.SpendBlock != "" {
						t.Fatalf("ambiguous reply not refused: %+v", v)
					}
				}
				if v.PrivilegedCommandsAllowed {
					t.Fatal("unexpected effect authority")
				}
			})
		}
	}
}

// Strings/arrays have no field aliases: preserve their existing strict shapes,
// including duplicate mempool-id rejection, alongside an official empty pool.
func TestW7ScalarAndMempoolProjection(t *testing.T) {
	for _, tc := range []struct{ method, raw, reason string }{
		{"getrawmempool", `{"txid":"` + digest(400) + `"}`, "RPC_UNAVAILABLE_OR_MALFORMED"},
		{"getrawmempool", `[{"txid":"` + digest(400) + `"}]`, "RPC_UNAVAILABLE_OR_MALFORMED"},
		{"getrawmempool", `["` + digest(400) + `","` + digest(400) + `"]`, "MEMPOOL_SCHEMA"},
		{"getblockhash", `{"hash":"` + digest(10) + `"}`, "RPC_UNAVAILABLE_OR_MALFORMED"},
	} {
		t.Run(tc.method+tc.raw, func(t *testing.T) {
			f, b, l := setup()
			f.pool = []tx{normalTx(digest(400), Point{digest(123), 2})}
			p := &projectionRPC{inner: f}
			if v := New(p).Watch(context.Background(), b, l); v.State != Unspent {
				t.Fatal(v)
			}
			f.substitute[tc.method] = tc.raw
			v := New(p).Watch(context.Background(), b, l)
			if v.State != Unknown || v.Reason != tc.reason || v.SealChainOK || v.PrivilegedCommandsAllowed {
				t.Fatal(v)
			}
		})
	}
}

// Lowercasing is not Unicode simple folding: long-s and s are fold-equal.
// Reject duplicates in otherwise ignored extension objects too; ordinary
// unknown Core extension fields remain compatible with UNSPENT.
func TestW7FoldDuplicates(t *testing.T) {
	for _, extra := range []string{`"extra":{"s":1,"ſ":2}`, `"extra":{"k":1,"K":2}`, `"extra":{"a":1,"A":2}`} {
		f, b, l := setup()
		p := &projectionRPC{inner: f, change: func(m string, _ []any, raw []byte) []byte {
			if m == "getblockchaininfo" {
				return append([]byte(`{`+extra+`,`), raw[1:]...)
			}
			return raw
		}}
		v := New(p).Watch(context.Background(), b, l)
		if v.State != Unknown || v.Reason != "RPC_UNAVAILABLE_OR_MALFORMED" || v.SealChainOK {
			t.Errorf("fold duplicate %s: %+v", extra, v)
		}
	}
	f, b, l := setup()
	p := &projectionRPC{inner: f, change: func(m string, _ []any, raw []byte) []byte {
		if m == "getblockchaininfo" {
			return append([]byte(`{"extra":{"s":1,"different":2},`), raw[1:]...)
		}
		return raw
	}}
	if v := New(p).Watch(context.Background(), b, l); v.State != Unspent {
		t.Fatal("official extension", v)
	}
}
