// Run from rental. Inspect real production dependency graphs and then prove the
// fence with a compilable discovery import planted via Go's read-only overlay.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const rentalPath = "github.com/relux-works/swarma-chain-lab/experiments/rental"

type pkg struct{ ImportPath, Dir string }
type entry struct {
	Module                   string
	Packages, RentalPackages int
	Clean                    bool
}

func execute(dir string, args ...string) ([]byte, error) {
	c := exec.Command("go", args...)
	c.Dir = dir
	c.Env = append(os.Environ(), "GOWORK=off", "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local")
	var out, errout bytes.Buffer
	c.Stdout = &out
	c.Stderr = &errout
	if e := c.Start(); e != nil {
		return nil, e
	}
	fmt.Printf("go PID %d: %s\n", c.Process.Pid, strings.Join(args, " "))
	if e := c.Wait(); e != nil {
		return nil, fmt.Errorf("go command: %w: %s", e, errout.String())
	}
	return out.Bytes(), nil
}
func inspect(raw []byte, root string) (int, int, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	total, owned := 0, 0
	for {
		var p pkg
		e := d.Decode(&p)
		if e == io.EOF {
			break
		}
		if e != nil {
			return total, owned, e
		}
		total++
		if p.ImportPath == rentalPath+"/discovery" {
			return total, owned, errors.New("DISCOVERY_AUTHORITY_DEPENDENCY")
		}
		if p.ImportPath == rentalPath || strings.HasPrefix(p.ImportPath, rentalPath+"/") {
			owned++
			want := filepath.Join(root, strings.TrimPrefix(strings.TrimPrefix(p.ImportPath, rentalPath), "/"))
			got, e := filepath.EvalSymlinks(p.Dir)
			if e != nil {
				return total, owned, e
			}
			want, e = filepath.EvalSymlinks(want)
			if e != nil || got != want {
				return total, owned, errors.New("STALE_RENTAL_DEPENDENCY")
			}
		}
	}
	return total, owned, nil
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	out := flag.String("out", ".temp/n1-dependencies", "evidence directory")
	flag.Parse()
	root, e := os.Getwd()
	if e != nil {
		return e
	}
	b, e := os.ReadFile("go.mod")
	if e != nil || !bytes.HasPrefix(b, []byte("module "+rentalPath+"\n")) {
		return errors.New("run from rental")
	}
	if e = os.MkdirAll(*out, 0700); e != nil {
		return e
	}
	dir, e := os.MkdirTemp(*out, "run-")
	if e != nil {
		return e
	}
	dir, e = filepath.Abs(dir)
	if e != nil {
		return e
	}
	fmt.Println("evidence:", dir)
	entries := []entry{}
	for _, m := range []string{"rental", "grantcheck", "rental-gateway/kernelbind", "rental-gateway", "signer-service", "agent-wallet", "rental-executor", "grant-store", "rental-booking", "station-lifecycle/gatewaybind", "station-lifecycle", "relay", "station-payload"} {
		args := []string{"list", "-deps", "-json", "./..."}
		if m == "rental" {
			args = []string{"list", "-deps", "-json", ".", "./cmd/rental-kernel", "./cmd/rental-plan", "./cmd/rental-issue", "./oplocator"}
		}
		raw, e := execute(filepath.Join(filepath.Dir(root), m), args...)
		if e != nil {
			return e
		}
		n, k, e := inspect(raw, root)
		if e != nil {
			return fmt.Errorf("%s: %w", m, e)
		}
		if e = os.WriteFile(filepath.Join(dir, strings.ReplaceAll(m, "/", "-")+".json"), raw, 0600); e != nil {
			return e
		}
		entries = append(entries, entry{m, n, k, true})
	}
	// Positive discovery graph proves that the same scanner sees its exact package.
	raw, e := execute(root, "list", "-deps", "-json", "./cmd/name-discovery")
	if e != nil {
		return e
	}
	_, _, e = inspect(raw, root)
	if e == nil || e.Error() != "DISCOVERY_AUTHORITY_DEPENDENCY" {
		return errors.New("discovery positive control missing")
	}
	source := filepath.Join(filepath.Dir(root), "grantcheck", "checker.go")
	original, e := os.ReadFile(source)
	if e != nil {
		return e
	}
	needle := "import ("
	if strings.Count(string(original), needle) != 1 {
		return errors.New("import plant not applicable")
	}
	mutant := []byte(strings.Replace(string(original), needle, needle+"\n _ \""+rentalPath+"/discovery\"", 1))
	replacement := filepath.Join(dir, "checker.go")
	if e = os.WriteFile(replacement, mutant, 0600); e != nil {
		return e
	}
	overlay, _ := json.Marshal(map[string]any{"Replace": map[string]string{source: replacement}})
	overlayPath := filepath.Join(dir, "overlay.json")
	if e = os.WriteFile(overlayPath, overlay, 0600); e != nil {
		return e
	}
	if _, e = execute(filepath.Dir(source), "build", "-overlay", overlayPath, "."); e != nil {
		return fmt.Errorf("plant must compile: %w", e)
	}
	raw, e = execute(filepath.Dir(source), "list", "-overlay", overlayPath, "-deps", "-json", ".")
	if e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(dir, "planted-deps.json"), raw, 0600); e != nil {
		return e
	}
	_, _, e = inspect(raw, root)
	if e == nil || e.Error() != "DISCOVERY_AUTHORITY_DEPENDENCY" {
		return errors.New("dependency plant undetected")
	}
	hash := func(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
	result := struct {
		Entries                      []entry
		Plant                        string
		OriginalSHA256, MutantSHA256 string
	}{entries, "DISCOVERY_AUTHORITY_DEPENDENCY", hash(original), hash(mutant)}
	raw, e = json.MarshalIndent(result, "", "  ")
	if e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(dir, "results.json"), append(raw, '\n'), 0600); e != nil {
		return e
	}
	fmt.Printf("%d production graphs clean; compilable import plant detected\n", len(entries))
	return nil
}
