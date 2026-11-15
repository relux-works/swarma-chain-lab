package g2run

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// Op is one typed operation of a step. Validate runs for every operation of the step before any of them runs, so a
// malformed value is refused by name before anything changes; Do performs the operation and returns its error.
type Op interface {
	Kind() string
	Validate() error
	Do(*Ctx) error
}

// RecoveryRule makes a recovery step eligible. It is admitted when its purpose matches (if Purpose is set) and either
// a STOP is recorded (or INFLIGHT is present) while AfterStop is true, or the last line of DONE is `OK X` for an X in
// AfterLast.
type RecoveryRule struct {
	Step      string
	Purpose   string
	AfterStop bool
	AfterLast []string
}

// Plan is a compiled step plan. P is the plan's typed parameters, decoded from the signed install package.
type Plan[P any] struct {
	// BootstrapLine is the first line DONE must hold before any step runs (the bootstrap block writes it).
	BootstrapLine string
	// Sequences maps each purpose to its normal steps, in order. "INIT-<purpose>" precedes each sequence.
	Sequences map[string][]string
	// Recovery lists the recovery steps and their eligibility.
	Recovery []RecoveryRule
	// Steps builds each step's operations from the decoded parameters.
	Steps map[string]func(P) []Op
	// Programs is the ExecFixed table: program name -> absolute path.
	Programs map[string]string
	// PackageFiles must each be listed exactly once in the package's SHA256SUMS; ParamsFile is one of them.
	PackageFiles []string
	ParamsFile   string
	// Decode strictly decodes the parameters file and refuses a malformed one by name.
	Decode func([]byte) (P, error)
}

var stepPattern = regexp.MustCompile(`^[A-Z][A-Za-z0-9]*([.-][A-Za-z0-9]+)*$`)
var purposePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// forbiddenPrograms can run other programs or evaluate text. None of them may appear in the ExecFixed table: values
// never reach an interpreter, and file work is Go code.
var forbiddenPrograms = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "busybox": true, "env": true,
	"python": true, "python3": true, "perl": true, "ruby": true, "node": true, "awk": true, "gawk": true, "mawk": true,
	"sed": true, "find": true, "xargs": true, "sudo": true, "su": true, "doas": true, "runuser": true,
	"setpriv": true, "nohup": true, "timeout": true, "nice": true, "setsid": true, "install": true, "eval": true,
	"exec": true, "script": true, "expect": true, "tclsh": true, "lua": true, "php": true,
}

// isInitStep reports the purpose of an INIT-<purpose> step.
func initPurpose(step string) (string, bool) {
	if !strings.HasPrefix(step, "INIT-") {
		return "", false
	}
	return step[len("INIT-"):], true
}

// Validate checks the compiled plan itself; a plan that fails is a build defect, refused before any state is read.
func (p Plan[P]) Validate() error {
	if p.BootstrapLine == "" || strings.ContainsAny(p.BootstrapLine, "\n\r") {
		return errors.New("PLAN_BOOTSTRAP_LINE")
	}
	if len(p.Sequences) == 0 || p.Decode == nil || p.Steps == nil {
		return errors.New("PLAN_INCOMPLETE")
	}
	known := map[string]bool{}
	for purpose, seq := range p.Sequences {
		if !purposePattern.MatchString(purpose) || len(seq) == 0 {
			return fmt.Errorf("PLAN_PURPOSE %q", purpose)
		}
		seen := map[string]bool{}
		for _, s := range seq {
			if !stepPattern.MatchString(s) || seen[s] {
				return fmt.Errorf("PLAN_SEQUENCE_STEP %q", s)
			}
			if _, init := initPurpose(s); init {
				return fmt.Errorf("PLAN_SEQUENCE_STEP %q", s)
			}
			seen[s] = true
			if p.Steps[s] == nil {
				return fmt.Errorf("PLAN_STEP_MISSING %s", s)
			}
			known[s] = true
		}
	}
	for _, r := range p.Recovery {
		if !stepPattern.MatchString(r.Step) || known[r.Step] || p.Steps[r.Step] == nil {
			return fmt.Errorf("PLAN_RECOVERY_STEP %q", r.Step)
		}
		if r.Purpose != "" && p.Sequences[r.Purpose] == nil {
			return fmt.Errorf("PLAN_RECOVERY_PURPOSE %q", r.Purpose)
		}
		if !r.AfterStop && len(r.AfterLast) == 0 {
			return fmt.Errorf("PLAN_RECOVERY_NEVER_ELIGIBLE %s", r.Step)
		}
		known[r.Step] = true
	}
	for s := range p.Steps {
		if !known[s] {
			return fmt.Errorf("PLAN_STEP_UNREACHABLE %s", s)
		}
	}
	for name, abs := range p.Programs {
		if !validProgram(name, abs) {
			return fmt.Errorf("PLAN_PROGRAM %q", name)
		}
	}
	seen := map[string]bool{}
	for _, f := range p.PackageFiles {
		if !validPackagePath(f) || seen[f] {
			return fmt.Errorf("PLAN_PACKAGE_FILE %q", f)
		}
		seen[f] = true
	}
	if !seen[p.ParamsFile] {
		return errors.New("PLAN_PARAMS_FILE")
	}
	return nil
}

func validProgram(name, abs string) bool {
	if name == "" || name != path.Base(abs) || forbiddenPrograms[name] || strings.HasPrefix(name, "python") {
		return false
	}
	return filepath.IsAbs(abs) && filepath.Clean(abs) == abs && !strings.ContainsAny(abs, "\x00\r\n ")
}

func validPackagePath(p string) bool {
	return p != "" && !filepath.IsAbs(p) && filepath.Clean(p) == p && !strings.HasPrefix(p, "..") &&
		!strings.ContainsAny(p, "\x00\r\n\t ")
}

// classify returns the step's class: "init", "normal" or "recovery", and for init the purpose.
func (p Plan[P]) classify(step string) (class, purpose string, ok bool) {
	if pur, init := initPurpose(step); init {
		if p.Sequences[pur] == nil {
			return "", "", false
		}
		return "init", pur, true
	}
	for _, r := range p.Recovery {
		if r.Step == step {
			return "recovery", "", true
		}
	}
	for _, seq := range p.Sequences {
		for _, s := range seq {
			if s == step {
				return "normal", "", true
			}
		}
	}
	return "", "", false
}

// StrictJSON decodes raw into v and refuses unknown fields, trailing values and any encoding but the canonical one
// (which also refuses duplicate or aliased keys, nulls for required values and alternate number spellings).
func StrictJSON(raw []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return errors.New("PARAMS_DECODE")
	}
	if e := d.Decode(new(any)); e != io.EOF {
		return errors.New("PARAMS_TRAILING")
	}
	canon, e := json.Marshal(v)
	if e != nil {
		return errors.New("PARAMS_ENCODE")
	}
	if !bytes.Equal(bytes.TrimSuffix(raw, []byte("\n")), canon) {
		return errors.New("PARAMS_NONCANONICAL")
	}
	return nil
}
