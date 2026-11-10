package payloadlaunch

import "time"

type FilePin struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// Directory identifies a receipt-backed journal root, not arbitrary contents.
// Device zero is representable; inode and Linux mount ID must be nonzero.
type Directory struct {
	Device  uint64 `json:"device"`
	Inode   uint64 `json:"inode"`
	MountID uint64 `json:"mount_id"`
}
type Journal struct {
	Version   uint64    `json:"v"`
	Path      string    `json:"path"`
	Directory Directory `json:"directory"`
}

// Manifest carries no raw channel/model credentials or release signing key.
// Its bootstrap hash covers the exact private bytes; static pins must also pass
// DK5's independently signed static set, not merely this root-custodied codec.
type Manifest struct {
	Version              uint64  `json:"v"`
	Slot                 uint32  `json:"slot"`
	UID                  uint32  `json:"uid"`
	GID                  uint32  `json:"gid"`
	Generation           string  `json:"generation"`
	BookingID            string  `json:"booking_id"`
	NotAfter             string  `json:"not_after"`
	Profile              Profile `json:"profile"`
	StaticManifestSHA256 string  `json:"static_manifest_sha256"`
	Bootstrap            FilePin `json:"bootstrap"`
	CA                   FilePin `json:"ca"`
	ModelConfig          FilePin `json:"model_config"`
	Journal              Journal `json:"journal"`
}

type Anchor struct {
	Version          uint64 `json:"v"`
	Slot             uint32 `json:"slot"`
	UID              uint32 `json:"uid"`
	GID              uint32 `json:"gid"`
	Generation       string `json:"generation"`
	ExecutableSHA256 string `json:"executable_sha256"`
	ManifestPath     string `json:"manifest_path"`
	ManifestSHA256   string `json:"manifest_sha256"`
}

// Receipt is independently persisted root state, never reconstructed from the
// candidate being checked. It pins every manifest byte plus identity and the
// existing slotd bootstrap/executable/deadline binding and journal directory.
type Receipt struct {
	Slot, UID, GID                                                          uint32
	Generation, ManifestSHA256, BootstrapSHA256, ExecutableSHA256, NotAfter string
	JournalDirectory                                                        Directory
}

func allocationOK(slot, uid, gid uint32) bool {
	if uid <= slot || uid != gid {
		return false
	}
	actual, e := SlotUID(uid-slot, slot)
	return e == nil && actual == uid
}
func deadlineOK(s string) bool {
	t, e := time.Parse(time.RFC3339, s)
	return e == nil && t.UTC().Format(time.RFC3339) == s && t.Nanosecond() == 0
}
func validManifest(m Manifest) error {
	if m.Version == 0 || !allocationOK(m.Slot, m.UID, m.GID) || !hexOK(m.Generation, 32) || !hexOK(m.BookingID, 64) || !deadlineOK(m.NotAfter) || !hexOK(m.StaticManifestSHA256, 64) {
		return ErrCorrupt
	}
	p, _ := PathsFor(m.UID)
	if m.Bootstrap.Path != p.Bootstrap || m.CA.Path != p.CA || m.ModelConfig.Path != p.ModelConfig || m.Journal.Path != p.Journal || !hexOK(m.Bootstrap.SHA256, 64) || !hexOK(m.CA.SHA256, 64) || !hexOK(m.ModelConfig.SHA256, 64) || m.Journal.Version == 0 || m.Journal.Directory.Inode == 0 || m.Journal.Directory.MountID == 0 {
		return ErrCorrupt
	}
	if e := validProfile(m.Profile); e != nil {
		return e
	}
	if m.Version != Version || m.Journal.Version != 1 {
		return ErrUnsupported
	}
	return nil
}
func validAnchor(a Anchor) error {
	if a.Version == 0 || !allocationOK(a.Slot, a.UID, a.GID) || !hexOK(a.Generation, 32) || !hexOK(a.ExecutableSHA256, 64) || !hexOK(a.ManifestSHA256, 64) {
		return ErrCorrupt
	}
	p, _ := PathsFor(a.UID)
	if a.ManifestPath != p.Manifest {
		return ErrCorrupt
	}
	if a.Version != Version {
		return ErrUnsupported
	}
	return nil
}
func EncodeManifest(m Manifest) ([]byte, error) {
	if e := validManifest(m); e != nil {
		return nil, e
	}
	b := canonical(m)
	if len(b) > MaxManifestBytes {
		return nil, ErrCorrupt
	}
	return b, nil
}
func DecodeManifest(f File) (Manifest, error) {
	var m Manifest
	if e := decode(f, MaxManifestBytes, &m); e != nil {
		return Manifest{}, e
	}
	if e := validManifest(m); e != nil {
		return Manifest{}, e
	}
	return m, nil
}
func DecodeAnchor(f File) (Anchor, error) {
	var a Anchor
	if e := decode(f, MaxAnchorBytes, &a); e != nil {
		return Anchor{}, e
	}
	if e := validAnchor(a); e != nil {
		return Anchor{}, e
	}
	return a, nil
}

// EncodeSet makes the manifest then the anchor pinning its exact bytes. This
// prepares no runtime state and grants no authority to a caller-created pair.
func EncodeSet(m Manifest) (manifest, anchor []byte, err error) {
	manifest, err = EncodeManifest(m)
	if err != nil {
		return nil, nil, err
	}
	p, _ := PathsFor(m.UID)
	a := Anchor{Version, m.Slot, m.UID, m.GID, m.Generation, m.Profile.ExecutableSHA256, p.Manifest, digest(manifest)}
	return manifest, canonical(a), nil
}

// ValidateSet requires custody-checked anchor bytes from the fixed path derived
// from the actual process UID. A self-consistent untrusted pair is not authority.
// The caller must prove path/metadata/namespace custody before reading bytes.
func ValidateSet(anchor, manifest File, uid, gid uint32) (Manifest, error) {
	if !uidOK(uid) || gid != uid {
		return Manifest{}, ErrBinding
	}
	for _, f := range []File{anchor, manifest} {
		if !f.Present && len(f.Bytes) != 0 {
			return Manifest{}, ErrCorrupt
		}
	}
	if !anchor.Present || !manifest.Present {
		return Manifest{}, ErrMissing
	}
	a, e := DecodeAnchor(anchor)
	if e != nil {
		return Manifest{}, e
	}
	if a.UID != uid || a.GID != gid {
		return Manifest{}, ErrBinding
	}
	if len(manifest.Bytes) == 0 || len(manifest.Bytes) > MaxManifestBytes {
		return Manifest{}, ErrCorrupt
	}
	if digest(manifest.Bytes) != a.ManifestSHA256 {
		return Manifest{}, ErrBinding
	}
	m, e := DecodeManifest(manifest)
	if e != nil {
		return Manifest{}, e
	}
	if a.Slot != m.Slot || a.UID != m.UID || a.GID != m.GID || a.Generation != m.Generation || a.ExecutableSHA256 != m.Profile.ExecutableSHA256 {
		return Manifest{}, ErrBinding
	}
	return m, nil
}

// CheckReceipt is slotd's additional check against its existing protected
// creation record. All failures return a zero result, never a partial admission.
func CheckReceipt(manifest File, r Receipt) (Manifest, error) {
	if !allocationOK(r.Slot, r.UID, r.GID) || !hexOK(r.Generation, 32) || !hexOK(r.ManifestSHA256, 64) || !hexOK(r.BootstrapSHA256, 64) || !hexOK(r.ExecutableSHA256, 64) || !deadlineOK(r.NotAfter) || r.JournalDirectory.Inode == 0 || r.JournalDirectory.MountID == 0 {
		return Manifest{}, ErrCorrupt
	}
	m, e := DecodeManifest(manifest)
	if e != nil {
		return Manifest{}, e
	}
	if digest(manifest.Bytes) != r.ManifestSHA256 || m.Slot != r.Slot || m.UID != r.UID || m.GID != r.GID || m.Generation != r.Generation || m.Bootstrap.SHA256 != r.BootstrapSHA256 || m.Profile.ExecutableSHA256 != r.ExecutableSHA256 || m.NotAfter != r.NotAfter || m.Journal.Directory != r.JournalDirectory {
		return Manifest{}, ErrBinding
	}
	return m, nil
}
