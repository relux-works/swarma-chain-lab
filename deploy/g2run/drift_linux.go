//go:build linux

package g2run

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// DriftIdentity includes atime, unlike the ledger identity. Reads use pread on a
// single O_NOATIME descriptor, never a fallback that could alter this evidence.
type DriftIdentity struct {
	Dev, Ino               uint64
	Mode, UID, GID         uint32
	Size, AtimeNS, MtimeNS int64
	SHA256                 string
}

func (id DriftIdentity) wire() []any {
	return []any{id.Dev, id.Ino, id.Mode, id.UID, id.GID, id.Size, id.AtimeNS, id.MtimeNS, id.SHA256}
}
func driftIdentity(f *os.File, st unix.Stat_t) (DriftIdentity, error) {
	h := sha256.New()
	n, e := io.Copy(h, io.NewSectionReader(f, 0, 1<<63-1))
	if e != nil {
		return DriftIdentity{}, e
	}
	if n != st.Size {
		return DriftIdentity{}, errors.New("DRIFT_SIZE_CHANGED")
	}
	var after unix.Stat_t
	if e = unix.Fstat(int(f.Fd()), &after); e != nil {
		return DriftIdentity{}, e
	}
	if after.Atim != st.Atim {
		return DriftIdentity{}, errors.New("DRIFT_ATIME_MOVED")
	}
	if after.Dev != st.Dev || after.Ino != st.Ino || after.Size != st.Size || after.Mtim != st.Mtim || after.Ctim != st.Ctim {
		return DriftIdentity{}, errors.New("DRIFT_CHANGED_WHILE_HASHING")
	}
	return DriftIdentity{st.Dev, st.Ino, st.Mode & 07777, st.Uid, st.Gid, st.Size, st.Atim.Nano(), st.Mtim.Nano(), hex.EncodeToString(h.Sum(nil))}, nil
}
func (fs PortFS) openDrift(p string, flags int) (*os.File, unix.Stat_t, error) {
	var st unix.Stat_t
	f, e := fs.open(p, flags|unix.O_NOATIME, false)
	if e != nil {
		return nil, st, e
	}
	if e = unix.Fstat(int(f.Fd()), &st); e == nil {
		e = fs.samePath(p, &st)
	}
	if e != nil {
		f.Close()
		return nil, st, e
	}
	return f, st, nil
}

// ReadDriftIdentity is g2-drift identity; it preserves nanosecond atime.
func ReadDriftIdentity(fs PortFS, p string) (DriftIdentity, error) {
	f, st, e := fs.openDrift(p, unix.O_RDONLY)
	if e != nil {
		return DriftIdentity{}, e
	}
	defer f.Close()
	id, e := driftIdentity(f, st)
	if e == nil {
		e = fs.samePath(p, &st)
	}
	return id, e
}

// FlipDrift saves recoverable state before changing byte zero on the same inode.
func FlipDrift(fs PortFS, p, state string) error {
	if p == state {
		return errors.New("DRIFT_STATE_IS_TARGET")
	}
	f, st, e := fs.openDrift(p, unix.O_RDWR)
	if e != nil {
		return e
	}
	defer f.Close()
	if st.Size < 1 {
		return errors.New("DRIFT_EMPTY")
	}
	id, e := driftIdentity(f, st)
	if e != nil {
		return e
	}
	var first [1]byte
	if _, e = f.ReadAt(first[:], 0); e != nil {
		return e
	}
	raw, e := json.Marshal(struct {
		Byte     string `json:"byte"`
		Identity []any  `json:"identity"`
	}{hex.EncodeToString(first[:]), id.wire()})
	if e != nil {
		return e
	}
	if e = fs.writeAtomic(state, raw, 0600); e != nil {
		return e
	}
	if e = fs.samePath(p, &st); e != nil {
		return e
	}
	first[0] ^= 1
	if n, e := f.WriteAt(first[:], 0); e != nil {
		return e
	} else if n != 1 {
		return errors.New("DRIFT_SHORT_WRITE")
	}
	return f.Sync()
}
func decodeDriftState(raw []byte) (byte, DriftIdentity, error) {
	fail := func() (byte, DriftIdentity, error) { return 0, DriftIdentity{}, errors.New("DRIFT_STATE_SCHEMA") }
	var wire struct {
		Byte     string `json:"byte"`
		Identity []any  `json:"identity"`
	}
	if decodePortJSON(raw, &wire) != nil || !portHex(wire.Byte, 2) || len(wire.Identity) != 9 {
		return fail()
	}
	w := wire.Identity
	nums := make([]uint64, 6)
	for i := 0; i < 6; i++ {
		max := uint64(1<<63 - 1)
		if i < 2 {
			max = ^uint64(0)
		}
		n, ok := portUint(w[i], max)
		if !ok {
			return fail()
		}
		nums[i] = n
	}
	if nums[2] > 07777 || nums[3] >= 1<<32-1 || nums[4] >= 1<<32-1 || nums[5] < 1 {
		return fail()
	}
	atime, ok := portInt(w[6])
	if !ok {
		return fail()
	}
	mtime, ok := portInt(w[7])
	if !ok {
		return fail()
	}
	sha, ok := w[8].(string)
	if !ok || !portHex(sha, 64) {
		return fail()
	}
	b, _ := hex.DecodeString(wire.Byte)
	return b[0], DriftIdentity{nums[0], nums[1], uint32(nums[2]), uint32(nums[3]), uint32(nums[4]), int64(nums[5]), atime, mtime, sha}, nil
}

// RestoreDrift refuses malformed state or a replaced inode before any write,
// restores exact timestamps on the pinned descriptor, checks the whole identity,
// and removes only the observed state inode after successful readback.
func RestoreDrift(fs PortFS, p, state string) error {
	sf, sst, e := fs.openDrift(state, unix.O_RDONLY)
	if e != nil {
		return e
	}
	defer sf.Close()
	raw, e := io.ReadAll(io.LimitReader(sf, 4097))
	if e != nil || len(raw) > 4096 {
		return errors.New("DRIFT_STATE_READ")
	}
	first, want, e := decodeDriftState(raw)
	if e != nil {
		return e
	}
	f, st, e := fs.openDrift(p, unix.O_RDWR)
	if e != nil {
		return e
	}
	defer f.Close()
	if st.Dev != want.Dev || st.Ino != want.Ino {
		return errors.New("DRIFT_INODE")
	}
	if n, e := f.WriteAt([]byte{first}, 0); e != nil {
		return e
	} else if n != 1 {
		return errors.New("DRIFT_SHORT_WRITE")
	}
	if e = f.Sync(); e != nil {
		return e
	}
	times := []unix.Timespec{unix.NsecToTimespec(want.AtimeNS), unix.NsecToTimespec(want.MtimeNS)}
	if e = unix.UtimesNanoAt(int(f.Fd()), "", times, unix.AT_EMPTY_PATH); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = unix.Fstat(int(f.Fd()), &st); e != nil {
		return e
	}
	got, e := driftIdentity(f, st)
	if e != nil {
		return e
	}
	if got != want {
		return errors.New("DRIFT_IDENTITY_AFTER_RESTORE")
	}
	if e = fs.samePath(p, &st); e != nil {
		return e
	}
	return fs.removeSame(state, &sst)
}
