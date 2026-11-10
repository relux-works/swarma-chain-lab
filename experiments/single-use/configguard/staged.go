package configguard

// StagedSet contains custody-checked bytes, not staging filesystem paths.
// Files is keyed by the intended final absolute names. The caller owns all
// slices/maps and must not change them concurrently with validation.
type StagedSet struct {
	Anchor    []byte
	Manifest  []byte
	Signature []byte
	Files     map[string][]byte
}

// StagedPolicy is independently trusted provisioning policy, never reconstructed
// from candidate bytes. Paths is the exact sorted list of final config names;
// ManifestPath and SignaturePath name the final signed-set metadata.
type StagedPolicy struct {
	ManifestPath, SignaturePath, ReleaseSHA256, Service string
	GID                                                 int
	Paths                                               []string
}

// ValidateStagedSet verifies a signed static set before final-path installation.
// It performs no filesystem access, mutates no input, and returns no authority
// object or bytes. Root custody/metadata and atomic installation remain caller
// obligations; success does not waive OpenSignedSet at installed admission.
func ValidateStagedSet(s StagedSet, p StagedPolicy) error {
	if p.Service == "" || p.GID <= 0 {
		return fail("DK5_SERVICE_IDENTITY")
	}
	if !digestOK(p.ReleaseSHA256) {
		return fail("DK5_MANIFEST_ANCHOR")
	}
	if !validPath(p.ManifestPath) || !validPath(p.SignaturePath) || p.ManifestPath == p.SignaturePath {
		return fail("DK5_PATH")
	}
	if len(p.Paths) < 1 || len(p.Paths) > 256 {
		return fail("DK5_MANIFEST_PATH")
	}
	previous := ""
	for _, path := range p.Paths {
		if !validPath(path) || path <= previous || path == p.ManifestPath || path == p.SignaturePath {
			return fail("DK5_MANIFEST_PATH")
		}
		previous = path
	}
	if len(s.Anchor) < 1 || len(s.Anchor) > 32768 {
		return fail("DK5_ANCHOR_FILE")
	}
	a, e := parseAnchor(s.Anchor)
	if e != nil {
		return e
	}
	if a.Manifest != p.ManifestPath || a.Signature != p.SignaturePath || a.Release != p.ReleaseSHA256 {
		return fail("DK5_MANIFEST_BINDING")
	}
	if len(s.Manifest) < 1 || len(s.Manifest) > 1<<20 {
		return fail("DK5_MANIFEST_READ")
	}
	if digest(s.Manifest) != a.Digest {
		return fail("DK5_MANIFEST_HASH")
	}
	if len(s.Signature) < 1 || len(s.Signature) > 32768 {
		return fail("DK5_SIGNATURE_FILE")
	}
	if e := verifySignature(s.Manifest, s.Signature, a.Algorithm, a.PublicKey); e != nil {
		return e
	}
	m, e := decodeManifest(s.Manifest, a.Manifest, p.ReleaseSHA256, p.Service, p.GID)
	if e != nil {
		return e
	}
	if len(m.Files) != len(p.Paths) {
		return fail("DK5_MANIFEST_BINDING")
	}
	allowed := make(map[string]bool, len(p.Paths))
	for i, entry := range m.Files {
		if entry.Path != p.Paths[i] {
			return fail("DK5_MANIFEST_BINDING")
		}
		allowed[entry.Path] = true
	}
	for path := range s.Files {
		if !allowed[path] {
			return fail("DK5_UNLISTED_PATH")
		}
	}
	for _, entry := range m.Files {
		raw, ok := s.Files[entry.Path]
		if !ok {
			return fail("DK5_FILE_OPEN")
		}
		if len(raw) < 1 || len(raw) > 16<<20 {
			return fail("DK5_FILE_SIZE")
		}
		if digest(raw) != entry.SHA256 {
			return fail("DK5_CONTENT_HASH")
		}
	}
	return nil
}
