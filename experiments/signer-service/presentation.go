package signerservice

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
	rental "github.com/relux-works/swarma-chain-lab/experiments/rental"
	su "github.com/relux-works/swarma-chain-lab/experiments/single-use"
)

func presentationRoot(path string) error {
	actual, e := filepath.EvalSymlinks(path)
	if e != nil || actual != path || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fail("PRESENTATION_ROOT")
	}
	st, e := os.Lstat(path)
	if e != nil || !publicOwner(st, true) {
		return fail("PRESENTATION_ROOT")
	}
	return nil
}
func publicOwner(st os.FileInfo, directory bool) bool {
	v, ok := st.Sys().(*syscall.Stat_t)
	if !ok || int(v.Uid) != os.Getuid() || st.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return false
	}
	if directory {
		return st.IsDir() && st.Mode().Perm() == 0755
	}
	return st.Mode().IsRegular() && st.Mode().Perm() == 0644 && v.Nlink == 1
}

// readRecord already binds RawTx to the exact signed plan and grant commitment.
// Re-observe those exact bytes on the active chain before exposing a proof. This
// is publication finality (one confirmation), not a live-grant authorization.
func (x *Engine) publishConfirmed(ctx context.Context, op operation, r record) error {
	o := su.NewReadObservation(ctx, x.node)
	defer o.Close()
	p := x.cfg.Policy.Policy
	if e := o.Start(p.Network, p.Genesis); e != nil {
		return e
	}
	v, _, e := o.PaymentTransaction(r.TxID)
	if e != nil {
		return e
	}
	if v.Hex != r.RawTx {
		return fail("PRESENTATION_TX_BINDING")
	}
	if v.Block == "" || v.Confirmations < 1 {
		return fail("PRESENTATION_UNCONFIRMED")
	}
	if _, e = o.Confirmed(v); e != nil {
		return e
	}
	if e = o.Stable(); e != nil {
		return e
	}
	return publishPresentation(ctx, x.cfg.PresentationDir, op.Intent.BookingID, r.Presentation)
}

// Atomic no-replace rename publishes a fully synced file. A retry verifies exact
// existing bytes and fsyncs again, covering uncertain directory-fsync outcomes.
// All leaf operations are relative to the validated held directory descriptor.
func publishPresentation(ctx context.Context, path, id string, raw []byte) error {
	if ctx.Err() != nil {
		return fail("CANCELED")
	}
	parsed, e := rental.ParseGrantPresentation(raw)
	if !digest(id) || len(raw) > 16384 || e != nil || parsed.SignedGrant.Grant.Consent.ConsentEvent.Tags[2][1] != id {
		return fail("PRESENTATION_ENCODING")
	}
	if e = presentationRoot(path); e != nil {
		return e
	}
	expected, e := os.Lstat(path)
	if e != nil {
		return fail("PRESENTATION_ROOT")
	}
	dir, e := os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return fail("PRESENTATION_ROOT")
	}
	defer dir.Close()
	st, e := dir.Stat()
	if e != nil || !publicOwner(st, true) || !os.SameFile(expected, st) {
		return fail("PRESENTATION_ROOT")
	}
	fd := int(dir.Fd())
	name := id + ".json"
	existing := func() (bool, error) {
		n, e := unix.Openat(fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if errors.Is(e, os.ErrNotExist) {
			return false, nil
		}
		if e != nil {
			return false, fail("PRESENTATION_FILE")
		}
		f := os.NewFile(uintptr(n), name)
		defer f.Close()
		st, e := f.Stat()
		if e != nil || !publicOwner(st, false) || st.Size() != int64(len(raw)) {
			return false, fail("PRESENTATION_CONFLICT")
		}
		b, e := io.ReadAll(io.LimitReader(f, 16385))
		if e != nil || !bytes.Equal(b, raw) {
			return false, fail("PRESENTATION_CONFLICT")
		}
		if ctx.Err() != nil {
			return false, fail("CANCELED")
		}
		if f.Sync() != nil || dir.Sync() != nil {
			return false, fail("PRESENTATION_FSYNC")
		}
		return true, nil
	}
	if ok, e := existing(); e != nil || ok {
		return e
	}
	var salt [16]byte
	if _, e = rand.Read(salt[:]); e != nil {
		return fail("PRESENTATION_WRITE")
	}
	tmp := ".presentation-" + hex.EncodeToString(salt[:])
	n, e := unix.Openat(fd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW, 0600)
	if e != nil {
		return fail("PRESENTATION_WRITE")
	}
	f := os.NewFile(uintptr(n), tmp)
	defer unix.Unlinkat(fd, tmp, 0)
	_, e = f.Write(raw)
	if e == nil {
		e = f.Chmod(0644)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil || ce != nil {
		return fail("PRESENTATION_FSYNC")
	}
	if ctx.Err() != nil {
		return fail("CANCELED")
	}
	e = renamePresentation(fd, tmp, name)
	if errors.Is(e, os.ErrExist) {
		if ok, e := existing(); e != nil || ok {
			return e
		}
		return fail("PRESENTATION_COMMIT")
	}
	if e != nil {
		return fail("PRESENTATION_COMMIT")
	}
	if dir.Sync() != nil {
		return fail("PRESENTATION_FSYNC")
	}
	return nil
}
