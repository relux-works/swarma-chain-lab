package configguard

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
)

// Anchor is rendered by the install owner into an immutable root-owned drop-in.
// It contains public pins only; the manifest/signature live in a private0750 dir.
type Anchor struct{ Manifest, Signature, Digest, Release, Algorithm, PublicKey string }

var anchorNames = []string{"MANIFEST", "SIGNATURE", "SHA256", "RELEASE_SHA256", "ALGORITHM", "PUBLIC_KEY"}

func (a Anchor) values() []string {
	return []string{a.Manifest, a.Signature, a.Digest, a.Release, a.Algorithm, a.PublicKey}
}
func (a Anchor) valid() bool {
	if !validPath(a.Manifest) || !validPath(a.Signature) || a.Manifest == a.Signature || filepath.Dir(a.Manifest) != filepath.Dir(a.Signature) || !digestOK(a.Digest) || !digestOK(a.Release) || len(a.PublicKey) < 1 || len(a.PublicKey) > 22000 {
		return false
	}
	if a.Algorithm != "ed25519" && a.Algorithm != "rsa-pss-sha256" {
		return false
	}
	for _, v := range a.values() {
		if strings.ContainsAny(v, "\"\\\x00\r\n\t %$") {
			return false
		}
	}
	return true
}

// RenderDropIn emits a closed systemd subset: no shell, specifiers or expansion.
// Callers must use an independently approved digest/key; this does not seal files.
func RenderDropIn(a Anchor) ([]byte, error) {
	if !a.valid() {
		return nil, fail("DK5_ANCHOR_SCHEMA")
	}
	if _, e := parsePublicKey(a.Algorithm, a.PublicKey); e != nil {
		return nil, e
	}
	var b strings.Builder
	b.WriteString("[Service]\n")
	for i, v := range a.values() {
		fmt.Fprintf(&b, "Environment=\"SWARMA_INSTALL_%s=%s\"\n", anchorNames[i], v)
	}
	return []byte(b.String()), nil
}
func parseAnchor(raw []byte) (Anchor, error) {
	var a Anchor
	lines := strings.Split(string(raw), "\n")
	if len(lines) != 8 || lines[0] != "[Service]" || lines[7] != "" {
		return a, fail("DK5_ANCHOR_SCHEMA")
	}
	values := []*string{&a.Manifest, &a.Signature, &a.Digest, &a.Release, &a.Algorithm, &a.PublicKey}
	for i, p := range values {
		prefix := "Environment=\"SWARMA_INSTALL_" + anchorNames[i] + "="
		line := lines[i+1]
		if !strings.HasPrefix(line, prefix) || !strings.HasSuffix(line, "\"") {
			return Anchor{}, fail("DK5_ANCHOR_SCHEMA")
		}
		*p = strings.TrimSuffix(strings.TrimPrefix(line, prefix), "\"")
	}
	if !a.valid() {
		return Anchor{}, fail("DK5_ANCHOR_SCHEMA")
	}
	return a, nil
}

// OpenSignedSet reads pins from a preselected root-owned file, never process
// environment. Manifest and signature are0644 under private0750 ancestry; the
// daemon config files themselves remain0640. Root compromise is out of scope.
func OpenSignedSet(anchorPath, service string, r Reader) (*Set, error) {
	raw, e := r.read(anchorPath, 32768, 0644, 0755, 0)
	if e != nil {
		return nil, fail("DK5_ANCHOR_FILE")
	}
	a, e := parseAnchor(raw)
	if e != nil {
		return nil, e
	}
	manifest, e := r.read(a.Manifest, 1<<20, 0644, 0750, uint32(r.GID))
	if e != nil {
		return nil, fail("DK5_MANIFEST_READ")
	}
	defer clear(manifest)
	if digest(manifest) != a.Digest {
		return nil, fail("DK5_MANIFEST_HASH")
	}
	signature, e := r.read(a.Signature, 32768, 0644, 0750, uint32(r.GID))
	if e != nil {
		return nil, fail("DK5_SIGNATURE_FILE")
	}
	if e = verifySignature(manifest, signature, a.Algorithm, a.PublicKey); e != nil {
		return nil, e
	}
	return openManifest(manifest, a.Manifest, a.Release, service, r)
}

// Only package tests replace these dependencies. No environment/config option
// changes anchor selection, NSS lookup or native identity in a daemon.
var installedSource = struct {
	reader         func() Reader
	group          func(string) (*user.Group, error)
	units, payload string
}{Native, user.LookupGroup, "/etc/systemd/system", "/etc/swarma/payload-anchors"}

func serviceBinding(service string) (string, Reader, error) {
	r := installedSource.reader()
	if r.EUID <= 0 {
		return "", r, fail("DK5_SERVICE_IDENTITY")
	}
	switch service {
	case "issuer", "gateway", "model", "booking", "store", "relay", "wallet", "stations":
		g, e := installedSource.group("swarma-" + service)
		if e != nil {
			return "", r, fail("DK5_SERVICE_GROUP")
		}
		gid, e := strconv.Atoi(g.Gid)
		if e != nil || gid <= 0 {
			return "", r, fail("DK5_SERVICE_GROUP")
		}
		r.GID = gid
		return filepath.Join(installedSource.units, "swarma-"+service+".service.d", "10-install.conf"), r, nil
	case "payload":
		// Static per-slot assets get an exclusive slot anchor. Dynamic bootstrap and
		// slotd launch enforcement are DK5b; no shared readable payload group.
		return filepath.Join(installedSource.payload, strconv.Itoa(r.EUID), "10-install.conf"), r, nil
	default:
		return "", r, fail("DK5_SERVICE_IDENTITY")
	}
}
func ServiceSet(service string) (*Set, error) {
	p, r, e := serviceBinding(service)
	if e != nil {
		return nil, e
	}
	return OpenSignedSet(p, service, r)
}
func ReadService(service, path string, limit int64) ([]byte, error) {
	s, e := ServiceSet(service)
	if e != nil {
		return nil, e
	}
	return s.Read(path, limit)
}

// CheckMain handles only the explicit systemd preflight mode, before ordinary
// argument parsing. An error exits before any service constructor can run.
func CheckMain(service string) {
	if len(os.Args) != 2 || os.Args[1] != "--check-installed" {
		return
	}
	if _, e := ServiceSet(service); e != nil {
		fmt.Fprintln(os.Stderr, e.Error())
		os.Exit(1)
	}
	os.Exit(0)
}
