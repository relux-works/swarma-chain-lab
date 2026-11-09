package smoke

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/relux-works/swarma-chain-lab/experiments/rental"
)

// Files creates a fresh private output directory. Infra atomically installs only
// the requested receipt filename; rejected bytes are never copied into evidence.
// The runner does not execute shell commands or fetch arbitrary receipt paths.
type Files struct {
	root  *os.Root
	names []string
}

func NewFiles(path string) (*Files, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, refuse("OUTPUT_PATH")
	}
	if e := os.Mkdir(path, 0700); e != nil {
		return nil, refuse("OUTPUT_FRESH")
	}
	root, e := os.OpenRoot(path)
	if e != nil {
		return nil, refuse("OUTPUT_OPEN")
	}
	return &Files{root: root}, nil
}
func (f *Files) Close() error { return f.root.Close() }
func (f *Files) write(name string, b []byte) error {
	file, e := f.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return refuse("OUTPUT_CREATE")
	}
	_, e = file.Write(b)
	if e == nil {
		e = file.Sync()
	}
	ce := file.Close()
	if e != nil || ce != nil {
		return refuse("OUTPUT_WRITE")
	}
	f.names = append(f.names, name)
	return nil
}
func readFile(root *os.Root, name string) ([]byte, error) {
	st, e := root.Lstat(name)
	if e != nil {
		return nil, e
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > 256<<10 || s.Nlink != 1 || s.Uid != uint32(os.Geteuid()) {
		return nil, refuse("INPUT_FILE_POLICY")
	}
	file, e := root.Open(name)
	if e != nil {
		return nil, refuse("INPUT_OPEN")
	}
	defer file.Close()
	opened, e := file.Stat()
	if e != nil || !os.SameFile(st, opened) {
		return nil, refuse("INPUT_CHANGED")
	}
	b, e := io.ReadAll(io.LimitReader(file, (256<<10)+1))
	if e != nil || len(b) > 256<<10 {
		return nil, refuse("INPUT_SIZE")
	}
	return b, nil
}
func ReadConfig(path string) (Config, error) {
	var c Config
	root, e := os.OpenRoot(filepath.Dir(path))
	if e != nil {
		return c, refuse("CONFIG_OPEN")
	}
	defer root.Close()
	b, e := readFile(root, filepath.Base(path))
	if e != nil {
		return c, refuse("CONFIG_FILE")
	}
	e = Strict(b, &c)
	return c, e
}
func (f *Files) Observe(ctx context.Context, q Request) (Receipt, error) {
	var receipt Receipt
	stem := fmt.Sprintf("%02d-%s", q.Sequence, q.Stage)
	if e := f.write(stem+".request.json", encode(q)); e != nil {
		return receipt, e
	}
	// The incoming file is an untrusted work item, not part of the sealed packet.
	// Infra retains it locally; the validated projection is stored separately.
	name := stem + ".incoming.json"
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	for {
		b, e := readFile(f.root, name)
		if e == nil {
			if e = Strict(b, &receipt); e != nil {
				return receipt, e
			}
			if e = ValidateReceipt(q, receipt, 0, time.Now().UnixMilli()); e != nil {
				return receipt, e
			}
			if e = f.write(stem+".receipt.json", encode(receipt)); e != nil {
				return receipt, e
			}
			return receipt, nil
		}
		if !os.IsNotExist(e) {
			return receipt, refuse("RECEIPT_FILE")
		}
		select {
		case <-ctx.Done():
			return receipt, refuse("RECEIPT_MISSING")
		case <-tick.C:
		}
	}
}
func (f *Files) Finish(report Report) error {
	if e := f.write("report.json", encode(report)); e != nil {
		return e
	}
	sort.Strings(f.names)
	var sums strings.Builder
	for _, name := range f.names {
		b, e := readFile(f.root, name)
		if e != nil {
			return refuse("SEAL_READ")
		}
		fmt.Fprintf(&sums, "%s  %s\n", rental.Hash(b), name)
	}
	return f.write("SHA256SUMS", []byte(sums.String()))
}

// Inventory is an explicitly sanitized projection, not command output. This
// permits Infra to retain reproducible release and host metadata in the packet
// without copying deployment configs, hostnames, argv or private journal data.
type Inventory struct {
	Source              string                 `json:"source"`
	Tree                string                 `json:"tree"`
	Binaries            map[string]string      `json:"binaries"`
	Helper              string                 `json:"helper"`
	Configs             map[string]string      `json:"configs"`
	Hosts               map[string]HostVersion `json:"hosts"`
	StoragePolicySHA256 string                 `json:"storage_policy_sha256"`
}
type HostVersion struct {
	Kernel  string `json:"kernel"`
	Systemd string `json:"systemd"`
}

func (f *Files) AddInventory(path, want string) error {
	root, e := os.OpenRoot(filepath.Dir(path))
	if e != nil {
		return refuse("INVENTORY_OPEN")
	}
	defer root.Close()
	b, e := readFile(root, filepath.Base(path))
	if e != nil {
		return refuse("INVENTORY_FILE")
	}
	var v Inventory
	if Strict(b, &v) != nil || rental.Hash(b) != want {
		return refuse("INVENTORY_BINDING")
	}
	if e = v.validate(); e != nil {
		return e
	}
	return f.write("inventory.json", b)
}

func (f *Files) AddConfig(c Config) error {
	if e := c.validate(host()); e != nil {
		return e
	}
	return f.write("config.json", encode(c))
}
