package payloadlaunch_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	c "github.com/relux-works/swarma-chain-lab/experiments/single-use/payloadlaunch"
)

const bootstrapHash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

func file(b []byte) c.File { return c.File{Present: true, Bytes: b} }
func hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func raw(t testing.TB, v any) []byte {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return append(b, '\n')
}
func fixture(t testing.TB, name string) []byte {
	t.Helper()
	b, e := os.ReadFile("testdata/" + name + "-v1.json")
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func profile() c.Profile {
	return c.Profile{Version: 1, Kind: "station-payload", Executable: "/usr/libexec/swarma-station-payload", ExecutableSHA256: strings.Repeat("1", 64), StaticReleaseSHA256: strings.Repeat("2", 64), Gateway: "192.0.2.1:9443", GatewayCertSHA256: strings.Repeat("5", 64), Dialect: "responses", Model: "fixture-model", MaxTokens: 128}
}
func manifest() c.Manifest {
	const p = "/var/lib/swarma-slotd-demo-payload/200017"
	return c.Manifest{Version: 1, Slot: 17, UID: 200017, GID: 200017, Generation: "00112233445566778899aabbccddeeff", BookingID: strings.Repeat("7", 64), NotAfter: "2026-11-10T12:00:00Z", Profile: profile(), StaticManifestSHA256: strings.Repeat("3", 64), Bootstrap: c.FilePin{Path: p + "/inputs/bootstrap", SHA256: bootstrapHash}, CA: c.FilePin{Path: p + "/inputs/ca.pem", SHA256: strings.Repeat("4", 64)}, ModelConfig: c.FilePin{Path: p + "/inputs/model.json", SHA256: strings.Repeat("6", 64)}, Journal: c.Journal{Version: 1, Path: p + "/journal", Directory: c.Directory{Device: 2049, Inode: 12345, MountID: 42}}}
}
func receipt(m c.Manifest, b []byte) c.Receipt {
	return c.Receipt{Slot: m.Slot, UID: m.UID, GID: m.GID, Generation: m.Generation, ManifestSHA256: hash(b), BootstrapSHA256: m.Bootstrap.SHA256, ExecutableSHA256: m.Profile.ExecutableSHA256, NotAfter: m.NotAfter, JournalDirectory: m.Journal.Directory}
}

// Literal structs, fixture bytes and precomputed hashes independently pin the
// documented schemas and argv. These synthetic vectors grant no host authority.
func TestGoldenContracts(t *testing.T) {
	hashes := map[string]string{"profile": "ad3ab71c7fbbc02f0c94bb4462e3d65e13ba03d3dd33c2bb21fde8c3a2a448bd", "manifest": "12142db8f6c6caa00e2356aa79df94753cd1308f6ceb1f6a9329254bb5e6bf02", "anchor": "117ccc3760b5ef98c1cfb484de7c62813aa424a0bc467f731ac5ebeeb9097c31", "argv": "11d5932acb358280a85f299c0deba9e3bdda67f34e0e749f3a43282e6552d78c"}
	for name, want := range hashes {
		if hash(fixture(t, name)) != want {
			t.Fatal("golden hash changed", name)
		}
	}
	p, e := c.EncodeProfile(profile())
	if e != nil || !bytes.Equal(p, fixture(t, "profile")) {
		t.Fatal("profile bytes", e)
	}
	gotP, e := c.DecodeProfile(file(p))
	if e != nil || gotP != profile() {
		t.Fatal("profile decode", e)
	}
	m := manifest()
	mb, ab, e := c.EncodeSet(m)
	if e != nil || !bytes.Equal(mb, fixture(t, "manifest")) || !bytes.Equal(ab, fixture(t, "anchor")) {
		t.Fatal("set bytes", e)
	}
	got, e := c.ValidateSet(file(ab), file(mb), m.UID, m.GID)
	if e != nil || got != m {
		t.Fatal("valid set", e)
	}
	got, e = c.CheckReceipt(file(mb), receipt(m, mb))
	if e != nil || got != m {
		t.Fatal("valid receipt", e)
	}
	args, e := c.Argv(m)
	if e != nil || !bytes.Equal(raw(t, args), fixture(t, "argv")) {
		t.Fatal("exact argv", e)
	}
	if len(args) != 21 || args[1] != "-slot-profile" || args[2] != "dk5b-v1" || args[20] != "128" {
		t.Fatal("launch profile changed")
	}
	args[0] = "changed"
	again, e := c.Argv(m)
	if e != nil || again[0] != m.Profile.Executable {
		t.Fatal("shared argv output")
	}
	paths, e := c.PathsFor(m.UID)
	if e != nil || paths.Anchor != "/etc/swarma/payload-anchors/200017/20-slot.conf" || paths.StaticAnchor != "/etc/swarma/payload-anchors/200017/10-install.conf" || paths.Manifest != "/var/lib/swarma-slotd-demo-payload/200017/inputs/slot.json" || paths.StaticSignature != "/var/lib/swarma-slotd-demo-payload/200017/static/manifest.sig" {
		t.Fatal("derived paths", e)
	}
}

// Pure profile validation rejects unsafe/ambiguous policy values before argv;
// messages/Responses, IPv4/IPv6 and explicit positive budgets remain supported.
func TestProfileRefusals(t *testing.T) {
	cases := []struct {
		name   string
		change func(*c.Profile)
		want   error
	}{
		{"version0", func(p *c.Profile) { p.Version = 0 }, c.ErrCorrupt}, {"version2", func(p *c.Profile) { p.Version = 2 }, c.ErrUnsupported},
		{"kind", func(p *c.Profile) { p.Kind = "shell" }, c.ErrCorrupt}, {"relative executable", func(p *c.Profile) { p.Executable = "payload" }, c.ErrCorrupt},
		{"traversal", func(p *c.Profile) { p.Executable = "/usr/libexec/../payload" }, c.ErrCorrupt}, {"root executable", func(p *c.Profile) { p.Executable = "/" }, c.ErrCorrupt},
		{"managed executable", func(p *c.Profile) { p.Executable = c.EnvelopeRoot + "/200017/payload" }, c.ErrCorrupt}, {"anchor executable", func(p *c.Profile) { p.Executable = c.AnchorRoot + "/payload" }, c.ErrCorrupt},
		{"shell characters", func(p *c.Profile) { p.Executable = "/usr/bin/payload;id" }, c.ErrCorrupt}, {"specifier", func(p *c.Profile) { p.Executable = "/usr/bin/%u" }, c.ErrCorrupt},
		{"executable size", func(p *c.Profile) { p.Executable = "/" + strings.Repeat("a", 4096) }, c.ErrCorrupt}, {"profile size", func(p *c.Profile) { p.Executable = "/" + strings.Repeat("a", 4000) }, c.ErrCorrupt},
		{"executable digest", func(p *c.Profile) { p.ExecutableSHA256 = "" }, c.ErrCorrupt}, {"release digest", func(p *c.Profile) { p.StaticReleaseSHA256 = strings.Repeat("g", 64) }, c.ErrCorrupt},
		{"certificate digest", func(p *c.Profile) { p.GatewayCertSHA256 = strings.Repeat("A", 64) }, c.ErrCorrupt},
		{"host name", func(p *c.Profile) { p.Gateway = "example.invalid:9443" }, c.ErrCorrupt}, {"zero port", func(p *c.Profile) { p.Gateway = "192.0.2.1:0" }, c.ErrCorrupt},
		{"port overflow", func(p *c.Profile) { p.Gateway = "192.0.2.1:65536" }, c.ErrCorrupt}, {"noncanonical port", func(p *c.Profile) { p.Gateway = "192.0.2.1:09443" }, c.ErrCorrupt},
		{"unspecified", func(p *c.Profile) { p.Gateway = "0.0.0.0:9443" }, c.ErrCorrupt}, {"multicast", func(p *c.Profile) { p.Gateway = "[ff02::1]:9443" }, c.ErrCorrupt},
		{"mapped ipv6", func(p *c.Profile) { p.Gateway = "[::ffff:192.0.2.1]:9443" }, c.ErrCorrupt}, {"zone", func(p *c.Profile) { p.Gateway = "[fe80::1%eth0]:9443" }, c.ErrCorrupt},
		{"dialect missing", func(p *c.Profile) { p.Dialect = "" }, c.ErrCorrupt}, {"dialect unknown", func(p *c.Profile) { p.Dialect = "chat" }, c.ErrCorrupt},
		{"model missing", func(p *c.Profile) { p.Model = "" }, c.ErrCorrupt}, {"model too long", func(p *c.Profile) { p.Model = strings.Repeat("a", 129) }, c.ErrCorrupt},
		{"model expansion", func(p *c.Profile) { p.Model = "${MODEL}" }, c.ErrCorrupt}, {"zero budget", func(p *c.Profile) { p.MaxTokens = 0 }, c.ErrCorrupt},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := profile()
			tc.change(&p)
			before := p
			b, e := c.EncodeProfile(p)
			if e != tc.want || b != nil {
				t.Fatal("encode refusal", e)
			}
			decoded, e := c.DecodeProfile(file(raw(t, p)))
			if e != tc.want || decoded != (c.Profile{}) {
				t.Fatal("decode refusal", e)
			}
			m := manifest()
			m.Profile = p
			args, e := c.Argv(m)
			if e != tc.want || args != nil {
				t.Fatal("argv refusal", e)
			}
			if p != before {
				t.Fatal("policy mutated")
			}
			if _, e = c.EncodeProfile(profile()); e != nil {
				t.Fatal("valid neighbor", e)
			}
		})
	}
	for _, dialect := range []string{"messages", "responses"} {
		p := profile()
		p.Dialect = dialect
		p.Gateway = "[2001:db8::1]:65535"
		p.Model = "vendor/model-1.2:latest"
		p.MaxTokens = ^uint64(0)
		if _, e := c.EncodeProfile(p); e != nil {
			t.Fatal("explicit valid neighbor", e)
		}
	}
}

// Structural/path/version violations have specific refusals and zero outputs;
// a valid neighboring manifest/argv still works. No custody or clock is simulated.
func TestManifestRefusals(t *testing.T) {
	cases := []struct {
		name   string
		change func(*c.Manifest)
		want   error
	}{
		{"version0", func(m *c.Manifest) { m.Version = 0 }, c.ErrCorrupt}, {"version2", func(m *c.Manifest) { m.Version = 2 }, c.ErrUnsupported},
		{"slot bound", func(m *c.Manifest) { m.Slot = 10000 }, c.ErrCorrupt}, {"UID zero", func(m *c.Manifest) { m.UID = 0; m.GID = 0 }, c.ErrCorrupt},
		{"GID shared", func(m *c.Manifest) { m.GID++ }, c.ErrCorrupt}, {"base zero", func(m *c.Manifest) { m.UID = m.Slot; m.GID = m.UID }, c.ErrCorrupt},
		{"nobody range", func(m *c.Manifest) { m.UID = 65534; m.GID = m.UID }, c.ErrCorrupt},
		{"generation", func(m *c.Manifest) { m.Generation = "" }, c.ErrCorrupt}, {"booking", func(m *c.Manifest) { m.BookingID = "" }, c.ErrCorrupt},
		{"deadline offset", func(m *c.Manifest) { m.NotAfter = "2026-11-10T12:00:00+00:00" }, c.ErrCorrupt},
		{"deadline fractional", func(m *c.Manifest) { m.NotAfter = "2026-11-10T12:00:00.001Z" }, c.ErrCorrupt},
		{"static manifest", func(m *c.Manifest) { m.StaticManifestSHA256 = "" }, c.ErrCorrupt},
		{"bootstrap path", func(m *c.Manifest) { m.Bootstrap.Path = "/tmp/bootstrap" }, c.ErrCorrupt}, {"CA path", func(m *c.Manifest) { m.CA.Path = m.Bootstrap.Path }, c.ErrCorrupt},
		{"model path", func(m *c.Manifest) { m.ModelConfig.Path += "/../model.json" }, c.ErrCorrupt}, {"journal path", func(m *c.Manifest) { m.Journal.Path = "journal" }, c.ErrCorrupt},
		{"bootstrap digest", func(m *c.Manifest) { m.Bootstrap.SHA256 = "" }, c.ErrCorrupt}, {"CA digest", func(m *c.Manifest) { m.CA.SHA256 = "" }, c.ErrCorrupt}, {"model digest", func(m *c.Manifest) { m.ModelConfig.SHA256 = "" }, c.ErrCorrupt},
		{"journal version0", func(m *c.Manifest) { m.Journal.Version = 0 }, c.ErrCorrupt}, {"journal version2", func(m *c.Manifest) { m.Journal.Version = 2 }, c.ErrUnsupported},
		{"journal inode", func(m *c.Manifest) { m.Journal.Directory.Inode = 0 }, c.ErrCorrupt}, {"journal mount", func(m *c.Manifest) { m.Journal.Directory.MountID = 0 }, c.ErrCorrupt},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := manifest()
			tc.change(&m)
			before := m
			b, a, e := c.EncodeSet(m)
			if e != tc.want || b != nil || a != nil {
				t.Fatal("set refusal", e)
			}
			got, e := c.DecodeManifest(file(raw(t, m)))
			if e != tc.want || got != (c.Manifest{}) {
				t.Fatal("decode refusal", e)
			}
			args, e := c.Argv(m)
			if e != tc.want || args != nil {
				t.Fatal("argv refusal", e)
			}
			if m != before {
				t.Fatal("manifest mutated")
			}
			if _, _, e = c.EncodeSet(manifest()); e != nil {
				t.Fatal("valid neighbor", e)
			}
		})
	}
	m := manifest()
	m.Journal.Directory.Device = 0
	m.NotAfter = "2000-01-01T00:00:00Z"
	if _, _, e := c.EncodeSet(m); e != nil {
		t.Fatal("codec must not claim clock/mount observation", e)
	}
}

// Canonicality rejects duplicate/unknown/case aliases and alternate encodings;
// each decoder preserves bytes and returns no partial object on failure.
func TestCanonicalRecords(t *testing.T) {
	for _, name := range []string{"profile", "manifest", "anchor"} {
		t.Run(name, func(t *testing.T) {
			good := fixture(t, name)
			decode := func(f c.File) (any, error) {
				switch name {
				case "profile":
					return c.DecodeProfile(f)
				case "manifest":
					return c.DecodeManifest(f)
				default:
					return c.DecodeAnchor(f)
				}
			}
			zero := any(c.Profile{})
			limit := c.MaxProfileBytes
			if name == "manifest" {
				zero = c.Manifest{}
				limit = c.MaxManifestBytes
			}
			if name == "anchor" {
				zero = c.Anchor{}
				limit = c.MaxAnchorBytes
			}
			mutate := func(from, to string) []byte {
				b := bytes.Replace(good, []byte(from), []byte(to), 1)
				if bytes.Equal(b, good) {
					t.Fatal("plant not applied")
				}
				return b
			}
			cases := []struct {
				name string
				f    c.File
				want error
			}{
				{"absent", c.File{}, c.ErrMissing}, {"absent with bytes", c.File{Bytes: good}, c.ErrCorrupt}, {"empty", file(nil), c.ErrCorrupt},
				{"missing LF", file(good[:len(good)-1]), c.ErrCorrupt}, {"extra LF", file(append(bytes.Clone(good), '\n')), c.ErrCorrupt},
				{"unknown", file(mutate("{", "{\"extra\":true,")), c.ErrCorrupt}, {"duplicate", file(mutate("{", "{\"v\":1,")), c.ErrCorrupt},
				{"case alias", file(mutate(`"v":1`, `"V":1`)), c.ErrCorrupt}, {"float version", file(mutate(`"v":1`, `"v":1.0`)), c.ErrCorrupt},
				{"unsupported", file(mutate(`"v":1`, `"v":2`)), c.ErrUnsupported}, {"missing version", file(mutate(`"v":1,`, ``)), c.ErrCorrupt},
				{"legacy or empty object", file([]byte("{}\n")), c.ErrCorrupt}, {"null", file([]byte("null\n")), c.ErrCorrupt},
				{"oversize", file(bytes.Repeat([]byte(" "), limit+1)), c.ErrCorrupt}, {"second object", file(append(bytes.Clone(good), good...)), c.ErrCorrupt},
			}
			for _, tc := range cases {
				t.Run(tc.name, func(t *testing.T) {
					before := bytes.Clone(tc.f.Bytes)
					got, e := decode(tc.f)
					if e != tc.want || !reflect.DeepEqual(got, zero) {
						t.Fatal("refusal mismatch", e)
					}
					if !bytes.Equal(before, tc.f.Bytes) {
						t.Fatal("bytes changed")
					}
					if _, e = decode(file(good)); e != nil {
						t.Fatal("valid neighbor", e)
					}
				})
			}
		})
	}
}

// A valid root anchor is necessary but slotd must ALSO match its independent
// current receipt. Self-consistent replacement pairs cannot update that receipt.
func TestSetBindings(t *testing.T) {
	m := manifest()
	mb, ab, e := c.EncodeSet(m)
	if e != nil {
		t.Fatal(e)
	}
	check := func(t *testing.T, a, b c.File, uid, gid uint32, want error) {
		t.Helper()
		beforeA, beforeB := bytes.Clone(a.Bytes), bytes.Clone(b.Bytes)
		got, e := c.ValidateSet(a, b, uid, gid)
		if e != want || got != (c.Manifest{}) {
			t.Fatalf("got %v, want %v; partial=%v", e, want, got != (c.Manifest{}))
		}
		if !bytes.Equal(a.Bytes, beforeA) || !bytes.Equal(b.Bytes, beforeB) {
			t.Fatal("refusal mutated bytes")
		}
		if _, e = c.ValidateSet(file(ab), file(mb), m.UID, m.GID); e != nil {
			t.Fatal("valid neighbor", e)
		}
	}
	t.Run("manifest digest", func(t *testing.T) {
		other := m
		other.Profile.MaxTokens++
		check(t, file(ab), file(raw(t, other)), m.UID, m.GID, c.ErrBinding)
	})
	t.Run("runtime UID", func(t *testing.T) { check(t, file(ab), file(mb), m.UID+1, m.GID+1, c.ErrBinding) })
	t.Run("runtime group", func(t *testing.T) { check(t, file(ab), file(mb), m.UID, m.GID+1, c.ErrBinding) })
	t.Run("runtime root", func(t *testing.T) { check(t, file(ab), file(mb), 0, 0, c.ErrBinding) })
	t.Run("missing", func(t *testing.T) {
		check(t, c.File{}, file(mb), m.UID, m.GID, c.ErrMissing)
		check(t, file(ab), c.File{}, m.UID, m.GID, c.ErrMissing)
	})
	t.Run("inconsistent absence", func(t *testing.T) { check(t, c.File{Bytes: ab}, file(mb), m.UID, m.GID, c.ErrCorrupt) })
	t.Run("empty manifest", func(t *testing.T) { check(t, file(ab), file(nil), m.UID, m.GID, c.ErrCorrupt) })
	t.Run("oversize manifest", func(t *testing.T) {
		check(t, file(ab), file(bytes.Repeat([]byte(" "), c.MaxManifestBytes+1)), m.UID, m.GID, c.ErrCorrupt)
	})
	for _, field := range []string{"slot", "generation", "executable", "path", "gid", "version0", "version2"} {
		t.Run("anchor "+field, func(t *testing.T) {
			a, e := c.DecodeAnchor(file(ab))
			if e != nil {
				t.Fatal(e)
			}
			want := error(c.ErrBinding)
			switch field {
			case "slot":
				a.Slot++
			case "generation":
				a.Generation = strings.Repeat("f", 32)
			case "executable":
				a.ExecutableSHA256 = strings.Repeat("f", 64)
			case "path":
				a.ManifestPath = "/tmp/slot.json"
				want = c.ErrCorrupt
			case "gid":
				a.GID++
				want = c.ErrCorrupt
			case "version0":
				a.Version = 0
				want = c.ErrCorrupt
			case "version2":
				a.Version = 2
				want = c.ErrUnsupported
			}
			check(t, file(raw(t, a)), file(mb), m.UID, m.GID, want)
		})
	}
	t.Run("hash matches malformed manifest", func(t *testing.T) {
		a, _ := c.DecodeAnchor(file(ab))
		bad := append(bytes.Clone(mb), ' ')
		a.ManifestSHA256 = hash(bad)
		check(t, file(raw(t, a)), file(bad), m.UID, m.GID, c.ErrCorrupt)
	})
	t.Run("hash matches unsupported manifest", func(t *testing.T) {
		a, _ := c.DecodeAnchor(file(ab))
		other := m
		other.Version = 2
		bad := raw(t, other)
		a.ManifestSHA256 = hash(bad)
		check(t, file(raw(t, a)), file(bad), m.UID, m.GID, c.ErrUnsupported)
	})
	r := receipt(m, mb)
	for _, field := range []string{"slot", "uid", "generation", "digest", "bootstrap", "executable", "deadline", "device", "inode", "mount", "invalid"} {
		t.Run("receipt "+field, func(t *testing.T) {
			bad := r
			want := error(c.ErrBinding)
			switch field {
			case "slot":
				bad.Slot++
			case "uid":
				bad.UID++
				bad.GID++
			case "generation":
				bad.Generation = strings.Repeat("f", 32)
			case "digest":
				bad.ManifestSHA256 = strings.Repeat("f", 64)
			case "bootstrap":
				bad.BootstrapSHA256 = strings.Repeat("f", 64)
			case "executable":
				bad.ExecutableSHA256 = strings.Repeat("f", 64)
			case "deadline":
				bad.NotAfter = "2026-11-10T13:00:00Z"
			case "device":
				bad.JournalDirectory.Device++
			case "inode":
				bad.JournalDirectory.Inode++
			case "mount":
				bad.JournalDirectory.MountID++
			case "invalid":
				bad.Generation = ""
				want = c.ErrCorrupt
			}
			got, e := c.CheckReceipt(file(mb), bad)
			if e != want || got != (c.Manifest{}) {
				t.Fatal("receipt refused incorrectly", e)
			}
			if _, e = c.CheckReceipt(file(mb), r); e != nil {
				t.Fatal("valid receipt neighbor", e)
			}
		})
	}
	other := m
	other.Generation = strings.Repeat("f", 32)
	newM, newA, e := c.EncodeSet(other)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = c.ValidateSet(file(newA), file(newM), m.UID, m.GID); e != nil {
		t.Fatal("new root-custodied pair is byte-valid", e)
	}
	if got, e := c.CheckReceipt(file(newM), r); e != c.ErrBinding || got != (c.Manifest{}) {
		t.Fatal("replacement pair overwrote receipt authority", e)
	}
}

// Allocation bounds match the declared slotd policy range, and public error
// strings are stable. Paths are lexical derivation, never filesystem proof.
func TestAllocationAndCodes(t *testing.T) {
	for _, x := range [][2]uint32{{0, 0}, {1, 10000}, {60000, 0}, {65534, 0}, {^uint32(0) - 9999, 0}} {
		if uid, e := c.SlotUID(x[0], x[1]); e != c.ErrCorrupt || uid != 0 {
			t.Fatal("bad allocation", x, e)
		}
	}
	for _, x := range [][2]uint32{{1, 0}, {200000, 9999}, {65535, 17}, {^uint32(0) - 10000, 9999}} {
		if uid, e := c.SlotUID(x[0], x[1]); e != nil || uid != x[0]+x[1] {
			t.Fatal("valid allocation", x, e)
		}
	}
	for _, uid := range []uint32{0, 65534, ^uint32(0)} {
		if p, e := c.PathsFor(uid); e != c.ErrCorrupt || p != (c.Paths{}) {
			t.Fatal("invalid path UID", e)
		}
	}
	for code, want := range map[c.Code]string{c.ErrMissing: "PAYLOAD_LAUNCH_MISSING", c.ErrUnsupported: "PAYLOAD_LAUNCH_UNSUPPORTED", c.ErrCorrupt: "PAYLOAD_LAUNCH_CORRUPT", c.ErrBinding: "PAYLOAD_LAUNCH_BINDING"} {
		if code.Error() != want {
			t.Fatal("code changed")
		}
	}
}

// A fixed independently pinned golden anchor admits only the exact manifest
// bytes. This oracle tests digest enforcement without a second implementation.
func FuzzGoldenAnchor(f *testing.F) {
	a, m := fixture(f, "anchor"), fixture(f, "manifest")
	f.Add(m)
	f.Add([]byte("{}\n"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		before := bytes.Clone(b)
		_, e := c.ValidateSet(file(a), file(b), 200017, 200017)
		if (e == nil) != bytes.Equal(b, m) {
			t.Fatal("golden anchor admitted different bytes")
		}
		if !bytes.Equal(before, b) {
			t.Fatal("input changed")
		}
	})
}

// Exact argv comparison refuses alternate spelling, reordering, duplicates,
// injected caller options and changed literals, without mutating caller slices.
func TestObservedArgvAndPolicy(t *testing.T) {
	m := manifest()
	var golden []string
	if json.Unmarshal(fixture(t, "argv"), &golden) != nil {
		t.Fatal("golden argv")
	}
	if c.ValidateArgv(m, golden) != nil || c.CheckProfile(m, profile()) != nil {
		t.Fatal("positive launch")
	}
	cases := map[string][]string{"missing": nil, "extra caller flag": append(append([]string{}, golden...), "-caller-option"), "duplicate": append(append([]string{}, golden...), "-model", "other")}
	for i := range golden {
		v := append([]string{}, golden...)
		v[i] += "x"
		cases["element "+string(rune('A'+i))] = v
	}
	reordered := append([]string{}, golden...)
	reordered[3], reordered[5] = reordered[5], reordered[3]
	reordered[4], reordered[6] = reordered[6], reordered[4]
	cases["reordered pairs"] = reordered
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			before := append([]string{}, args...)
			if c.ValidateArgv(m, args) != c.ErrBinding {
				t.Fatal("changed argv accepted")
			}
			if len(args) != len(before) {
				t.Fatal("argv mutated")
			}
			for i := range args {
				if args[i] != before[i] {
					t.Fatal("argv mutated")
				}
			}
			if c.ValidateArgv(m, golden) != nil {
				t.Fatal("positive neighbor")
			}
		})
	}
	current := profile()
	current.MaxTokens++
	if c.CheckProfile(m, current) != c.ErrBinding {
		t.Fatal("changed root policy accepted")
	}
	current.Model = ""
	if c.CheckProfile(m, current) != c.ErrCorrupt {
		t.Fatal("invalid root policy accepted")
	}
	m.Journal.Path = ""
	if c.ValidateArgv(m, golden) != c.ErrCorrupt || c.CheckProfile(m, profile()) != c.ErrCorrupt {
		t.Fatal("invalid manifest accepted")
	}
}
