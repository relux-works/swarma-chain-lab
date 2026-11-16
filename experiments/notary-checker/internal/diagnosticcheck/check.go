// Package diagnosticcheck supplies synthetic-secret probes used only by tests.
// It is local to this module; production service code does not import it.
package diagnosticcheck

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"text/template"
)

type Form struct {
	Name  string
	Value any
}

// Detector never reports the matched secret. Its inputs must be synthetic.
type Detector struct {
	needles  []string
	elements []*regexp.Regexp
}

func NewDetector(raw []byte, scalar bool) Detector {
	n := []string{string(raw), hex.EncodeToString(raw), strings.ToUpper(hex.EncodeToString(raw)),
		fmt.Sprint(raw), fmt.Sprintf("%#v", raw), fmt.Sprintf("% x", raw),
		strconv.Quote(string(raw)), fmt.Sprintf("%q", raw)}
	// Scalar windows contain no shared user/password fixture labels. Password
	// detectors retain whole-value needles to avoid treating those labels as secrets.
	if scalar {
		// Eight original bytes remain distinctive after encoding; windows catch
		// partial slice output without treating a short incidental match as a leak.
		for i := 0; i+8 <= len(raw); i++ {
			w := raw[i : i+8]
			n = append(n, string(w))
			n = append(n, hex.EncodeToString(w), strings.ToUpper(hex.EncodeToString(w)), base64.StdEncoding.EncodeToString(w), base64.RawStdEncoding.EncodeToString(w))
			for _, verb := range []string{"%v", "%#v", "%x", "%X", "%d", "%o", "%O", "%b", "%U", "%q"} {
				rendered := fmt.Sprintf(verb, w)
				// Slice brackets are context, not part of the secret window.
				n = append(n, strings.TrimSuffix(strings.TrimPrefix(rendered, "["), "]"))
			}
		}
	}
	var elements []*regexp.Regexp
	if scalar {
		if len(raw) != 32 {
			panic("synthetic scalar must have 32 bytes")
		}
		var words [8]uint32
		for i := range words {
			words[i] = binary.BigEndian.Uint32(raw[28-4*i : 32-4*i])
		}
		// Match individual scalar limbs with digit boundaries. This catches
		// per-element bad verbs, Unicode/octal forms and flag/width padding.
		for _, word := range words {
			// Short numbers are not distinctive enough for individual matching.
			if word < 1<<20 {
				continue
			}
			for _, base := range []int{2, 8, 10, 16} {
				class := map[int]string{2: "01", 8: "0-7", 10: "0-9", 16: "0-9a-fA-F"}[base]
				digits := strconv.FormatUint(uint64(word), base)
				for _, text := range []string{digits, strings.ToUpper(digits)} {
					elements = append(elements, regexp.MustCompile(`(?:^|[^`+class+`])`+regexp.QuoteMeta(text)+`(?:$|[^`+class+`])`))
				}
			}
		}
		for _, verb := range []string{"%v", "%#v", "%x", "%X", "%d", "%o", "%b"} {
			n = append(n, fmt.Sprintf(verb, words))
		}
	}
	return Detector{needles: n, elements: elements}
}

func (d Detector) Leaks(out string) bool {
	for _, n := range d.needles {
		if n != "" && strings.Contains(out, n) {
			return true
		}
	}
	for _, element := range d.elements {
		if element.MatchString(out) {
			return true
		}
	}
	return false
}

type sink struct {
	name   string
	render func(any) string
}

// Sinks matches the full 28-verb / 43-sink diagnostic battery. Encoder errors
// are scanned alongside partial output rather than treated as a clean result.
func sinks() []sink {
	var out []sink
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%t", "%c", "%U", "%e", "%b", "%o", "%O", "%T", "%p", "%+p", "%#p", "%020p", "%-30p", "%w", "%!", "%z", "%10.3s", "%[1]p", "%#s", "%+q"} {
		out = append(out, sink{"Sprintf/" + verb, func(v any) string { return fmt.Sprintf(verb, v) }})
	}
	return append(out,
		sink{"Errorf/w", func(v any) string { format := "ctx: %w"; return fmt.Errorf(format, v).Error() }},
		sink{"Errorf/w-error", func(v any) string { format := "%w: %w"; return fmt.Errorf(format, os.ErrNotExist, v).Error() }},
		sink{"Sprint", func(v any) string { return fmt.Sprint(v) }},
		sink{"Sprintln", func(v any) string { return fmt.Sprintln(v) }},
		sink{"Append/s", func(v any) string { return string(fmt.Appendf(nil, "%s", v)) }},
		sink{"Sprintf/extra", func(v any) string { format := "x"; return fmt.Sprintf(format, v) }},
		sink{"log", func(v any) string {
			var b bytes.Buffer
			l := log.New(&b, "", 0)
			format := "%p %s %w"
			l.Printf(format, v, v, v)
			l.Print(v)
			return b.String()
		}},
		sink{"slog/text", func(v any) string {
			var b bytes.Buffer
			slog.New(slog.NewTextHandler(&b, nil)).Info("m", "r", v, slog.Any("a", v))
			return b.String()
		}},
		sink{"slog/json", func(v any) string {
			var b bytes.Buffer
			slog.New(slog.NewJSONHandler(&b, nil)).Info("m", "r", v)
			return b.String()
		}},
		sink{"slog/group", func(v any) string {
			var b bytes.Buffer
			slog.New(slog.NewTextHandler(&b, nil)).Info("m", slog.Group("g", "r", v))
			return b.String()
		}},
		sink{"slog/default", func(v any) string {
			var b bytes.Buffer
			old := log.Writer()
			log.SetOutput(&b)
			defer log.SetOutput(old)
			slog.Default().Info("m", "r", v)
			return b.String()
		}},
		sink{"json", func(v any) string { b, e := json.Marshal(v); return encoded(b, e) }},
		sink{"json/wrapped", func(v any) string { b, e := json.Marshal(struct{ V any }{v}); return encoded(b, e) }},
		sink{"xml", func(v any) string { b, e := xml.Marshal(v); return encoded(b, e) }},
		sink{"text-template", func(v any) (out string) {
			// text/template can panic when handed an unexported reflect.Value. Scan
			// that diagnostic too, matching the runtime-recovered formatting surface.
			defer func() {
				if r := recover(); r != nil {
					out = fmt.Sprint(r)
				}
			}()
			var b bytes.Buffer
			tmpl := template.Must(template.New("t").Parse(`{{.}}|{{printf "%p" .}}|{{printf "%s" .}}|{{printf "%w" .}}`))
			e := tmpl.Execute(&b, v)
			return encoded(b.Bytes(), e)
		}},
	)
}

func encoded(b []byte, err error) string {
	if err != nil {
		return string(b) + "|" + err.Error()
	}
	return string(b)
}

// Check proves zero leaks on every listed form/sink; a plain control must
// individually leak through this same battery, preventing vacuous controls.
func Check(t *testing.T, forms []Form, controls []Form, d Detector) {
	t.Helper()
	ss := sinks()
	controlsLeaking := 0
	for _, f := range controls {
		controlLeaks := 0
		for _, s := range ss {
			if d.Leaks(s.render(f.Value)) {
				controlLeaks++
			}
		}
		if controlLeaks == 0 {
			t.Fatalf("plain diagnostic control %s did not leak", f.Name)
		}
		t.Logf("control=%s leaks=%d", f.Name, controlLeaks)
		controlsLeaking += controlLeaks
	}
	if len(controls) == 0 {
		t.Fatal("plain diagnostic controls missing")
	}
	leaks := 0
	for _, f := range forms {
		for _, s := range ss {
			t.Run(f.Name+"/"+s.name, func(t *testing.T) {
				defer func() {
					if recover() != nil {
						t.Error("diagnostic sink unexpectedly panicked")
					}
				}()
				if d.Leaks(s.render(f.Value)) {
					leaks++
					t.Error("diagnostic output exposes synthetic material")
				}
			})
		}
	}
	t.Logf("forms=%d sinks=%d pairs=%d leaks=%d plain-control-leaks=%d", len(forms), len(ss), len(forms)*len(ss), leaks, controlsLeaking)
}

// PanicCheck exercises actual runtime panic printing in one child per form.
// A panic is the expected sink here, never a mutation kill or passing gate.
func PanicCheck(t *testing.T, test string, forms []Form, d Detector) {
	t.Helper()
	if name := os.Getenv("DIAGNOSTIC_PANIC_FORM"); name != "" {
		for _, f := range forms {
			if f.Name == name {
				panic(f.Value)
			}
		}
		t.Fatal("unknown panic form")
	}
	for _, f := range forms {
		t.Run(f.Name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^"+test+"$", "-test.count=1")
			cmd.Env = append(os.Environ(), "DIAGNOSTIC_PANIC_FORM="+f.Name)
			// exec.Cmd owns and waits for this exact child PID; no shared process is stopped.
			out, err := cmd.CombinedOutput()
			if cmd.Process != nil {
				t.Logf("runtime panic child PID=%d", cmd.Process.Pid)
			}
			if err == nil || !strings.Contains(string(out), "panic:") {
				t.Fatal("runtime panic control did not execute")
			}
			if d.Leaks(string(out)) {
				t.Error("runtime panic output exposes synthetic material")
			}
		})
	}
	t.Logf("runtime-panic forms=%d", len(forms))
}
