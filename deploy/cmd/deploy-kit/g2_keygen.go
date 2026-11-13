package main

// g2-keygen: the station-side generator of the two G2 private scalar files,
// the agent's action key (agent_key_file) and the executor's receipt key
// (/etc/swarma/wallet/receipt.key). It runs as root on the station; the
// scalar never leaves the new file: it is not printed, logged or returned,
// and the buffers that held it are cleared after the write.

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/relux-works/swarma-chain-lab/deploy"
)

// errG2KeygenRandom refuses when the random source failed, or gave no
// acceptable scalar in g2KeygenAttempts draws. Nothing is written then.
var errG2KeygenRandom = errors.New("deploy-kit: g2-keygen found no acceptable random scalar")

// g2KeygenAttempts bounds the resampling loop. With crypto/rand a draw is
// refused with probability about 2^-127 (scalar 0, >= n, or one of the 2056
// trivial scalars), so the bound only stops a broken source.
const g2KeygenAttempts = 64

// g2TrivialScalarMax and g2TrivialBIP340Secrets are the trivial-key rule.
// deploy-kit g2-funded-preflight applies the same rule to the parameters'
// grantee and receipt_pubkey (x(k*G) for 1 <= k <= 1024, and the keys of
// BIP-340 test vectors #0-#3); the two lists must stay equal, and
// TestG2KeygenTrivialRuleList pins this one to those published values.
const g2TrivialScalarMax = 1024

// g2TrivialBIP340Secrets are the "secret key" column of rows index 0..3 of
// https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
var g2TrivialBIP340Secrets = [4]string{
	"0000000000000000000000000000000000000000000000000000000000000003",
	"b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef",
	"c90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b14e5c9",
	"0b432b2677937381aef05bb02a66ecd012773062cf3fa2549e44f58ed2401710",
}

// g2KeyXOnly returns the lowercase-hex x-only public key x(k*G).
func g2KeyXOnly(k *secp256k1.ModNScalar) string {
	var p secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(k, &p)
	p.ToAffine()
	return hex.EncodeToString(p.X.Bytes()[:])
}

// g2TrivialXOnly is the set of refused x-only keys. An x-only key does not
// carry the sign of y, so a key in the set also refuses n-k.
var g2TrivialXOnly = sync.OnceValue(func() map[string]bool {
	set := make(map[string]bool, g2TrivialScalarMax+len(g2TrivialBIP340Secrets))
	var k secp256k1.ModNScalar
	for i := uint32(1); i <= g2TrivialScalarMax; i++ {
		set[g2KeyXOnly(k.SetInt(i))] = true
	}
	for i, s := range g2TrivialBIP340Secrets {
		b, e := hex.DecodeString(s)
		if e != nil || len(b) != 32 || k.SetByteSlice(b) || k.IsZero() {
			panic("g2-keygen: invalid BIP-340 vector secret " + strconv.Itoa(i))
		}
		set[g2KeyXOnly(&k)] = true
	}
	return set
})

// g2NewScalar draws 32 bytes from rnd until they are a valid secp256k1
// scalar (not 0, below n) whose x-only key is not trivial. It returns the
// scalar as exactly 64 lowercase hex characters, the format of agent-wallet
// LoadActionKey and loadReceiptKey (service_config.go parseActionKey), and
// its x-only key. The caller clears the returned buffer.
func g2NewScalar(rnd io.Reader) (*[64]byte, string, error) {
	var raw [32]byte
	defer clear(raw[:])
	var k secp256k1.ModNScalar
	defer k.Zero()
	for range g2KeygenAttempts {
		if _, e := io.ReadFull(rnd, raw[:]); e != nil {
			return nil, "", errG2KeygenRandom
		}
		if k.SetByteSlice(raw[:]) || k.IsZero() {
			continue
		}
		x := g2KeyXOnly(&k)
		if g2TrivialXOnly()[x] {
			continue
		}
		out := new([64]byte)
		hex.Encode(out[:], raw[:])
		return out, x, nil
	}
	return nil, "", errG2KeygenRandom
}

// g2NewSecretFile creates path exclusively with exactly mode and writes data
// to it, then syncs the file and its directory. path must be absolute and
// clean; its parent must be an existing directory reached without any
// symlink. An existing path (a dangling symlink included) is refused before
// anything is written. The file is created with mode and set to mode on the
// open descriptor before any byte is written (umask can only narrow it), so
// it is never readable more widely than mode. On a failure after creation
// the new file is removed.
func g2NewSecretFile(path string, data []byte, mode os.FileMode) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return deploy.ErrInput
	}
	dir := filepath.Dir(path)
	info, e := os.Lstat(dir)
	if e != nil || !info.IsDir() {
		return deploy.ErrInput
	}
	if resolved, e := filepath.EvalSymlinks(dir); e != nil || resolved != dir {
		return deploy.ErrInput
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, mode)
	if e != nil {
		return deploy.ErrInput
	}
	fail := func() error {
		f.Close()
		os.Remove(path)
		return deploy.ErrPolicy
	}
	if f.Chmod(mode) != nil {
		return fail()
	}
	opened, e := f.Stat()
	if e != nil || !opened.Mode().IsRegular() || opened.Mode().Perm() != mode || opened.Size() != 0 {
		return fail()
	}
	if linked, e := os.Lstat(path); e != nil || !os.SameFile(opened, linked) {
		return fail()
	}
	if n, e := f.Write(data); e != nil || n != len(data) {
		return fail()
	}
	if f.Sync() != nil {
		return fail()
	}
	if f.Close() != nil {
		os.Remove(path)
		return deploy.ErrPolicy
	}
	d, e := os.Open(dir)
	if e != nil {
		os.Remove(path)
		return deploy.ErrPolicy
	}
	syncErr := d.Sync()
	if d.Close() != nil || syncErr != nil {
		os.Remove(path)
		return deploy.ErrPolicy
	}
	return nil
}

// g2Keygen writes a new random secp256k1 private scalar to -out and prints
// only its x-only public key:
//
//	deploy-kit g2-keygen -out FILE [-mode 0600|0640]
//
// FILE is created exclusively (g2NewSecretFile) and holds exactly 64
// lowercase hex characters, no newline. -mode is 0600 (default; the agent
// action key, which agent-wallet LoadActionKey reads only as an owner-only
// file) or 0640 (the receipt key, installed root:swarma-wallet 0640). The
// owner and group stay root's; the chown is the operator's step. A trivial
// scalar (g2TrivialXOnly) is never written: it is drawn again. Stdout is the
// single line "G2_KEY_XONLY <64 hex>".
func g2Keygen(args []string, out io.Writer) error { return g2KeygenFrom(args, out, rand.Reader) }

// g2KeygenFrom is g2Keygen with the random source as a parameter (the test
// seam); production passes crypto/rand.
func g2KeygenFrom(args []string, out io.Writer, rnd io.Reader) error {
	f := flag.NewFlagSet("g2-keygen", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	path := f.String("out", "", "new absolute key file")
	modeFlag := f.String("mode", "0600", "file mode: 0600 or 0640")
	if f.Parse(args) != nil || f.NArg() != 0 {
		return deploy.ErrInput
	}
	var mode os.FileMode
	switch *modeFlag {
	case "0600":
		mode = 0600
	case "0640":
		mode = 0640
	default:
		return deploy.ErrInput
	}
	if !filepath.IsAbs(*path) || filepath.Clean(*path) != *path {
		return deploy.ErrInput
	}
	if _, e := os.Lstat(*path); !errors.Is(e, os.ErrNotExist) {
		return deploy.ErrInput
	}
	scalar, xonly, e := g2NewScalar(rnd)
	if e != nil {
		return e
	}
	e = g2NewSecretFile(*path, scalar[:], mode)
	clear(scalar[:])
	if e != nil {
		return e
	}
	_, e = fmt.Fprintln(out, "G2_KEY_XONLY "+xonly)
	return e
}
