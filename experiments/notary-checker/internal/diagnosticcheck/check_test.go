package diagnosticcheck

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// Claim: each required rendering is detected; addresses and redaction are
// accepted. This calibrates the instrument independently of holder behavior.
func TestDetectorRenderings(t *testing.T) {
	raw := []byte("0123456789abcdef0123456789abcdef")
	d := NewDetector(raw, true)
	var words [8]uint32
	for i := range words {
		words[i] = binary.BigEndian.Uint32(raw[28-4*i : 32-4*i])
	}
	for _, tc := range []struct{ name, out string }{
		{"plaintext", string(raw)}, {"raw-byte", fmt.Sprintf("%s", raw)},
		{"hex", hex.EncodeToString(raw)}, {"uppercase-hex", strings.ToUpper(hex.EncodeToString(raw))},
		{"decimal-byte", fmt.Sprint(raw)}, {"byte-literal", fmt.Sprintf("%#v", raw)},
		{"limbs", fmt.Sprint(words)}, {"limb-literal", fmt.Sprintf("%#v", words)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !d.Leaks(tc.out) {
				t.Fatal("detector missed synthetic control")
			}
		})
	}
	for _, safe := range []string{"[REDACTED]", "0xc00001c080", "&{0xc00001c080}", "<nil>"} {
		if d.Leaks(safe) {
			t.Fatal("detector rejected address/redaction control")
		}
	}
}

// Claim: each scalar limb remains detectable under every battery verb that
// exposes its numeric value, including bad-verb restarts and width padding.
// Quoted invalid runes become U+FFFD; pointer-only output carries no limb.
func TestDetectorScalarFormats(t *testing.T) {
	raw := sha256.Sum256([]byte("synthetic-service-signing-key"))
	d := NewDetector(raw[:], true)
	for i := 0; i < 8; i++ {
		word := binary.BigEndian.Uint32(raw[28-4*i : 32-4*i])
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%X", "%d", "%t", "%U", "%e", "%b", "%o", "%O", "%w", "%!", "%z", "%10.3s", "%#s"} {
			t.Run(fmt.Sprintf("limb-%d/%s", i, verb), func(t *testing.T) {
				// The unexported field exercises fmt's element rendering path.
				out := fmt.Sprintf(verb, &struct{ limb uint32 }{word})
				if !d.Leaks(out) {
					t.Fatal("detector missed scalar element rendering")
				}
			})
		}
		// A longer decimal token containing a limb is not that limb.
		if d.Leaks("9" + strconv.FormatUint(uint64(word), 10) + "9") {
			t.Fatal("decimal digit boundary ignored")
		}
	}
}

// Claim: eight-byte scalar windows detect partial plaintext/hex/base64 output,
// while unrelated and seven-byte-only controls remain accepted.
func TestDetectorWindows(t *testing.T) {
	raw := []byte("01234567abcdefghIJKLMNOPqrstuvwx")
	d := NewDetector(raw, true)
	for i := 0; i+8 <= len(raw); i++ {
		w := raw[i : i+8]
		for _, out := range []string{string(w), hex.EncodeToString(w), base64.StdEncoding.EncodeToString(w), base64.RawStdEncoding.EncodeToString(w)} {
			if !d.Leaks("prefix:" + out + ":suffix") {
				t.Fatal("detector missed eight-byte window")
			}
		}
	}
	for _, safe := range []string{"[REDACTED]", "0xc00001c080", string(raw[:7]), hex.EncodeToString(raw[:7]), base64.StdEncoding.EncodeToString(raw[:7])} {
		if d.Leaks(safe) {
			t.Fatal("detector rejected non-window control")
		}
	}
}

// Claim: each calibration control must leak independently, regardless of
// ordering; a leaking neighbor cannot mask a silent or absent control.
func TestDiagnosticCalibrationControls(t *testing.T) {
	if mode := os.Getenv("DIAGNOSTIC_CALIBRATION"); mode != "" {
		raw := []byte("synthetic-calibration-password")
		leaking := Form{Name: "leaking", Value: struct{ password string }{string(raw)}}
		silent := Form{Name: "silent", Value: "[REDACTED]"}
		controls := []Form{leaking, leaking}
		switch mode {
		case "first":
			controls[0] = silent
		case "last":
			controls[1] = silent
		case "empty":
			controls = nil
		}
		Check(t, []Form{{Name: "safe", Value: "[REDACTED]"}}, controls, NewDetector(raw, false))
		return
	}
	for _, mode := range []string{"valid", "first", "last", "empty"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestDiagnosticCalibrationControls$", "-test.count=1")
			cmd.Env = append(os.Environ(), "DIAGNOSTIC_CALIBRATION="+mode)
			out, err := cmd.CombinedOutput()
			if cmd.Process != nil {
				t.Logf("calibration child PID=%d", cmd.Process.Pid)
			}
			if mode == "valid" {
				if err != nil {
					t.Fatal("valid calibration rejected")
				}
				return
			}
			want := "plain diagnostic control silent did not leak"
			if mode == "empty" {
				want = "plain diagnostic controls missing"
			}
			if err == nil || !strings.Contains(string(out), want) || strings.Contains(string(out), "panic:") {
				t.Fatal("calibration did not reject the intended silent control")
			}
		})
	}
}
