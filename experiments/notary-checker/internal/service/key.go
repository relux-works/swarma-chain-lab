package service

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"syscall"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

var keyError = errors.New("KEY_FILE")

const keyHeader = "notary-key-v1\n"

// Keygen creates a host-generated key exclusively. Only its x-only public key
// is returned. There is no secret import/export command or secret diagnostic.
func Keygen(path string) (string, error) {
	k, err := btcec.NewPrivateKey()
	if err != nil {
		return "", keyError
	}
	defer k.Zero()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", keyError
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	raw := append([]byte(keyHeader), k.Serialize()...)
	defer clear(raw)
	if err = f.Chmod(0600); err != nil {
		return "", keyError
	}
	if _, err = f.Write(raw); err != nil {
		return "", keyError
	}
	if f.Sync() != nil {
		return "", keyError
	}
	if f.Close() != nil {
		return "", keyError
	}
	ok = true
	return hex.EncodeToString(schnorr.SerializePubKey(k.PubKey())), nil
}

func privateFile(path string, max int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, keyError
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 {
		return nil, keyError
	}
	if s, ok := st.Sys().(*syscall.Stat_t); !ok || s.Uid != uint32(os.Getuid()) {
		return nil, keyError
	}
	// Open nonblocking so a FIFO reaches fstat; restore blocking reads only
	// after the descriptor is verified as an owner-only regular file.
	if e := syscall.SetNonblock(int(f.Fd()), false); e != nil {
		return nil, keyError
	}
	raw, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(raw)) > max {
		clear(raw)
		return nil, keyError
	}
	return raw, nil
}
func loadKey(path string) (*btcec.PrivateKey, error) {
	raw, err := privateFile(path, int64(len(keyHeader)+32))
	if err != nil {
		return nil, keyError
	}
	defer clear(raw)
	if len(raw) != len(keyHeader)+32 || !bytes.Equal(raw[:len(keyHeader)], []byte(keyHeader)) {
		return nil, keyError
	}
	secret := raw[len(keyHeader):]
	var scalar btcec.ModNScalar
	if scalar.SetByteSlice(secret) || scalar.IsZero() {
		return nil, keyError
	}
	scalar.Zero()
	k, _ := btcec.PrivKeyFromBytes(secret)
	return k, nil
}
