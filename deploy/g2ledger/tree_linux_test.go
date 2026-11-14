package g2ledger

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A busy process namespace can lose a PID between enumeration and read. The
// production call stops on that error. Tests retry only that named refusal,
// never a live-process, permission, parse, identity or injected-read failure.
func treeReplay(t *testing.T, l *Ledger, mode string) error {
	t.Helper()
	for attempt := 0; attempt < 100; attempt++ {
		e := l.Replay(mode)
		if e == nil || !strings.Contains(e.Error(), "PROC_READ") || !strings.Contains(e.Error(), "open /proc/") || !strings.Contains(e.Error(), "no such file or directory") {
			return e
		}
		t.Logf("strict process scan stopped on a vanished PID; retry %d: %v", attempt+1, e)
		time.Sleep(25 * time.Millisecond)
	}
	return errors.New("process namespace never settled for a checked scan")
}

func realProcessCensus(t *testing.T, required ...int) func() ([]string, error) {
	t.Helper()
	return func() ([]string, error) {
		all, e := processIDs()
		if e != nil {
			return nil, e
		}
		selected := []string{}
		for _, pid := range required {
			name := strconv.Itoa(pid)
			if !slices.Contains(all, name) {
				return nil, fmt.Errorf("required real process %s absent", name)
			}
			selected = append(selected, name)
		}
		return selected, nil
	}
}

func treeFixture(t *testing.T, purpose string) (*fixture, string) {
	t.Helper()
	f := setupWith(t, purpose, func(f *fixture) { f.declare("tree", "tree"); f.declare("tree2", "tree") })
	must(t, f.l.CreateAccount("group", "primary", "state", 0, uint32(os.Getegid())))
	must(t, f.l.CreateAccount("user", "demo", "state", uint32(os.Geteuid()), uint32(os.Getegid())))
	// Real filesystem UID is the test runner's; the synthetic account has no
	// processes in the test process namespace. Every scan still reads real /proc.
	f.l.procUID = func(uint32) uint32 { return 4000000000 }
	f.l.procPIDs = realProcessCensus(t, os.Getpid())
	return f, filepath.Join(f.root, "tree")
}
func makeTree(t *testing.T) (*fixture, string) {
	t.Helper()
	f, p := treeFixture(t, "rehearsal")
	must(t, f.l.CreateTree(p, "demo", "rehearsal", 0700, nil))
	must(t, os.WriteFile(filepath.Join(p, "a-safe"), []byte("safe"), 0600))
	must(t, os.Mkdir(filepath.Join(p, "nested"), 0700))
	foreign(t, filepath.Join(p, "nested", "payload"), "file")
	return f, p
}
func treeRefusal(t *testing.T, f *fixture, reason string, paths ...string) {
	t.Helper()
	e := treeReplay(t, f.l, "rehearsal")
	code(t, e, 1)
	for _, p := range paths {
		exists(t, p)
	}
	if !strings.Contains(e.Error(), reason) {
		t.Fatalf("wanted %s: %v", reason, e)
	}
	if _, ok := f.sys.users["demo"]; !ok {
		t.Fatal("owner removed before tree")
	}
}
func validTreeNeighbour(t *testing.T) {
	t.Helper()
	f, p := makeTree(t)
	var out bytes.Buffer
	f.l.output = &out
	must(t, treeReplay(t, f.l, "rehearsal"))
	absent(t, p)
	if len(f.sys.users) != 0 || len(f.sys.groups) != 0 || !strings.Contains(out.String(), `"retained":0,"unlisted":0`) {
		t.Fatal("baseline not restored", out.String())
	}
	must(t, treeReplay(t, f.l, "rehearsal"))
}

// Claim: the creating call seals owner and empty-root identities before a real child writes; valid rehearsal replay removes the tree and restores S0.
func TestLedgerTreeOwnerBeforeWriterAndBaseline(t *testing.T) {
	f, p := treeFixture(t, "rehearsal")
	seenIntent := false
	f.l.afterIntent = func(a Action) error {
		if a.Kind == "tree" {
			absent(t, p)
			if len(f.l.rows) != 6 || f.l.rows[4].Body.Op != "commit" || f.l.rows[4].Body.Result.Identities[0].Account.Name != "demo" {
				t.Fatal("owner not committed first")
			}
			seenIntent = true
		}
		return nil
	}
	must(t, f.l.CreateTree(p, "demo", "rehearsal", 0700, nil))
	if !seenIntent {
		t.Fatal("missing intent")
	}
	entries, e := os.ReadDir(p)
	must(t, e)
	if len(entries) != 0 {
		t.Fatal("root was not empty at commit")
	}
	foreign(t, filepath.Join(p, "payload"), "file")
	f.l.Close()
	f.reopen(t)
	f.l.procUID = func(uint32) uint32 { return 4000000000 }
	f.l.procPIDs = realProcessCensus(t, os.Getpid())
	must(t, treeReplay(t, f.l, "rehearsal"))
	absent(t, p)
	validTreeNeighbour(t)
}

// Claim: a pre-existing nologin user grants no tree authority even after S0 absence; an attempt-created user does.
func TestLedgerTreePreexistingOwnerRefused(t *testing.T) {
	f := setupWith(t, "rehearsal", func(f *fixture) { f.declare("tree", "tree") })
	f.sys.users["demo"] = Account{Name: "demo", UID: uint32(os.Geteuid()), GID: uint32(os.Getegid()), Shell: "/usr/sbin/nologin"}
	p := filepath.Join(f.root, "tree")
	n := len(f.l.rows)
	e := f.l.CreateTree(p, "demo", "rehearsal", 0700, nil)
	code(t, e, 1)
	if !strings.Contains(e.Error(), "TREE_OWNER_NOT_CREATED") || len(f.l.rows) != n {
		t.Fatal("pre-existing owner adopted", e)
	}
	absent(t, p)
	validTreeNeighbour(t)
}

// Claim: forbidden UID and primary GID values refuse both creation and a correctly rehashed replay before any tree deletion; ordinary owners pass.
func TestLedgerTreeForbiddenOwnersCreateAndReplay(t *testing.T) {
	for _, id := range []uint32{0, 1000, 210001, 210101} {
		for _, field := range []string{"uid", "gid"} {
			t.Run(fmt.Sprintf("%s-%d", field, id), func(t *testing.T) {
				f, p := treeFixture(t, "rehearsal")
				original := f.sys.users["demo"]
				bad := original
				if field == "uid" {
					bad.UID = id
				} else {
					bad.GID = id
				}
				f.sys.users["demo"] = bad
				e := f.l.CreateTree(p, "demo", "rehearsal", 0700, nil)
				code(t, e, 1)
				if !strings.Contains(e.Error(), "TREE_OWNER_FORBIDDEN") {
					t.Fatal(e)
				}
				absent(t, p)
				f.sys.users["demo"] = original
				must(t, f.l.CreateTree(p, "demo", "rehearsal", 0700, nil))
				rows := append([]Record(nil), f.l.rows...)
				a := *rows[5].Body.Action
				owner := *a.Before[0].Account
				if field == "uid" {
					a.UID = id
					owner.UID = id
				} else {
					a.GID = id
					owner.GID = id
				}
				a.Before = []Identity{{Account: &owner}}
				rows[5].Body.Action = &a
				f.l.Close()
				writeRows(t, f, rows, true)
				_, e = Open(f.dir, f.sys)
				code(t, e, 1)
				if !strings.Contains(e.Error(), "TREE_OWNER_FORBIDDEN") {
					t.Fatal(e)
				}
				exists(t, p)
			})
		}
	}
	validTreeNeighbour(t)
}

// Claim: an OWNER-owned symlink is removed only as a link, while its outside file or directory target and contents survive unchanged.
func TestLedgerTreeSymlinkNeverFollowed(t *testing.T) {
	for _, targetKind := range []string{"file", "dir"} {
		t.Run(targetKind, func(t *testing.T) {
			f, p := makeTree(t)
			outside := filepath.Join(t.TempDir(), "outside")
			if targetKind == "dir" {
				must(t, os.Mkdir(outside, 0700))
				must(t, os.WriteFile(filepath.Join(outside, "keep"), []byte("keep"), 0600))
			} else {
				must(t, os.WriteFile(outside, []byte("keep"), 0600))
			}
			must(t, os.Symlink(outside, filepath.Join(p, "link")))
			before, e := os.Lstat(outside)
			must(t, e)
			replayErr := treeReplay(t, f.l, "rehearsal")
			after, e := os.Lstat(outside)
			must(t, e)
			if !os.SameFile(before, after) {
				t.Fatal("target replaced")
			}
			target := outside
			if targetKind == "dir" {
				target = filepath.Join(outside, "keep")
			}
			raw, e := os.ReadFile(target)
			must(t, e)
			if string(raw) != "keep" {
				t.Fatal("outside target touched")
			}
			must(t, replayErr)
			absent(t, p)
		})
	}
}

// Claim: a real hardlink is refused before any deletion even when both names have OWNER ownership; a single-link neighbour is removable.
func TestLedgerTreeHardlinkStops(t *testing.T) {
	f, p := makeTree(t)
	original := filepath.Join(p, "nested", "payload")
	outside := filepath.Join(t.TempDir(), "hardlink")
	must(t, os.Link(original, outside))
	treeRefusal(t, f, "TREE_HARDLINK", p, original, outside, filepath.Join(p, "a-safe"))
	validTreeNeighbour(t)
}

// Claim: real setuid and setgid files stop the whole verified walk before deleting safe neighbours; plain files pass.
func TestLedgerTreeSetIDStops(t *testing.T) {
	for _, bit := range []os.FileMode{os.ModeSetuid, os.ModeSetgid} {
		t.Run(fmt.Sprint(bit), func(t *testing.T) {
			f, p := makeTree(t)
			target := filepath.Join(p, "nested", "payload")
			must(t, os.Chmod(target, 0600|bit))
			treeRefusal(t, f, "TREE_SETID", p, target, filepath.Join(p, "a-safe"))
		})
	}
	validTreeNeighbour(t)
}

// Claim: real FIFOs and unlisted Unix sockets stop the walk; only a named socket entry is allowed and is unlinked without following anything.
func TestLedgerTreeUnexpectedIPCStops(t *testing.T) {
	for _, kind := range []string{"fifo", "socket"} {
		t.Run(kind, func(t *testing.T) {
			f, p := makeTree(t)
			target := filepath.Join(p, "zzz-ipc")
			if kind == "fifo" {
				must(t, unix.Mkfifo(target, 0600))
			} else {
				listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: target, Net: "unix"})
				must(t, e)
				listener.SetUnlinkOnClose(false)
				must(t, listener.Close())
			}
			reason := "TREE_SPECIAL_FILE"
			if kind == "socket" {
				reason = "TREE_UNEXPECTED_SOCKET"
			}
			treeRefusal(t, f, reason, p, target, filepath.Join(p, "a-safe"), filepath.Join(p, "nested", "payload"))
		})
	}
	f, p := treeFixture(t, "rehearsal")
	must(t, f.l.CreateTree(p, "demo", "rehearsal", 0700, []string{"named.sock"}))
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(p, "named.sock"), Net: "unix"})
	must(t, e)
	listener.SetUnlinkOnClose(false)
	must(t, listener.Close())
	must(t, treeReplay(t, f.l, "rehearsal"))
	absent(t, p)
	validTreeNeighbour(t)
}

// Claim: seam-observed foreign ownership, devices, device crossings and same-device bind mounts stop a real walk without deleting any entry; normal observations pass.
func TestLedgerTreeStatHazardsStop(t *testing.T) {
	for _, hazard := range []string{"foreign-owner", "device", "cross-device", "bind-mount"} {
		t.Run(hazard, func(t *testing.T) {
			f, p := makeTree(t)
			injected := false
			f.l.treeStat = func(d *os.File, name string) (unix.Stat_t, uint64, error) {
				st, mid, e := realTreeStat(d, name)
				if e == nil && name == "payload" {
					injected = true
					switch hazard {
					case "foreign-owner":
						st.Uid++
					case "device":
						st.Mode = unix.S_IFCHR | 0600
					case "cross-device":
						st.Dev++
					case "bind-mount":
						mid++
					}
				}
				return st, mid, e
			}
			reasons := map[string]string{"foreign-owner": "TREE_FOREIGN_OWNER", "device": "TREE_SPECIAL_FILE", "cross-device": "TREE_CROSS_DEVICE_OR_MOUNT", "bind-mount": "TREE_CROSS_DEVICE_OR_MOUNT"}
			treeRefusal(t, f, reasons[hazard], p, filepath.Join(p, "nested", "payload"), filepath.Join(p, "a-safe"))
			if !injected {
				t.Fatal("stat plant not exercised")
			}
		})
	}
	validTreeNeighbour(t)
}

// Claim: every inter-phase addition, replacement, symlink, content or metadata change stops before deleting either tree or its safe entries.
func TestLedgerTreePhaseChangeStops(t *testing.T) {
	for _, change := range []string{"addition", "replacement", "symlink", "content", "mode", "root-rename"} {
		t.Run(change, func(t *testing.T) {
			f, p := makeTree(t)
			q := filepath.Join(f.root, "tree2")
			must(t, f.l.CreateTree(q, "demo", "rehearsal", 0700, nil))
			target := filepath.Join(p, "nested", "payload")
			safe := filepath.Join(q, "safe")
			must(t, os.WriteFile(safe, []byte("safe"), 0600))
			boundaryReached := false
			f.l.afterTreeVerify = func() error {
				boundaryReached = true
				switch change {
				case "addition":
					return os.WriteFile(filepath.Join(p, "extra"), []byte("extra"), 0600)
				case "replacement":
					if e := os.Rename(target, target+".saved"); e != nil {
						return e
					}
					return os.WriteFile(target, []byte("new"), 0600)
				case "symlink":
					if e := os.Rename(target, target+".saved"); e != nil {
						return e
					}
					return os.Symlink(f.src, target)
				case "content":
					return os.WriteFile(target, []byte("changed"), 0600)
				case "mode":
					return os.Chmod(target, 0644)
				case "root-rename":
					return os.Rename(p, p+".saved")
				}
				return nil
			}
			retained := p
			if change == "root-rename" {
				retained = p + ".saved"
			}
			reason := "TREE_CHANGED"
			if change == "root-rename" {
				reason = "TREE_RECHECK"
			}
			treeRefusal(t, f, reason, retained, q, safe, filepath.Join(retained, "a-safe"), filepath.Join(retained, "nested", "payload"))
			if !boundaryReached {
				t.Fatal("phase-boundary plant did not run")
			}
		})
	}
	validTreeNeighbour(t)
}

// Claim: any /proc read failure (including a vanished PID) stops tree removal; the same tree passes a complete real scan with a mapped unused UID.
func TestLedgerTreeProcReadErrorStops(t *testing.T) {
	f, p := makeTree(t)
	called := false
	f.l.procRead = func(path string) ([]byte, error) { called = true; return nil, os.ErrNotExist }
	treeRefusal(t, f, "PROC_READ", p, filepath.Join(p, "a-safe"), filepath.Join(p, "nested", "payload"))
	if !called {
		t.Fatal("proc seam not reached")
	}
	f.l.procRead = nil
	must(t, treeReplay(t, f.l, "rehearsal"))
	absent(t, p)
}

// Claim: the process fixture is a real child that holds stdin open until its parent closes it; it performs no privileged operations.
func TestLedgerTreeProcessHelper(t *testing.T) {
	if os.Getenv("G2_TREE_CHILD") != "1" {
		return
	}
	fmt.Println("ready")
	_, _ = io.Copy(io.Discard, os.Stdin)
	os.Exit(0)
}
func treeChild(t *testing.T) int {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestLedgerTreeProcessHelper$")
	cmd.Env = append(os.Environ(), "G2_TREE_CHILD=1")
	input, e := cmd.StdinPipe()
	must(t, e)
	output, e := cmd.StdoutPipe()
	must(t, e)
	must(t, cmd.Start())
	t.Logf("child PID %d", cmd.Process.Pid)
	t.Cleanup(func() {
		_ = input.Close()
		if e := cmd.Wait(); e != nil {
			t.Error(e)
		}
	})
	line, e := bufio.NewReader(output).ReadString('\n')
	must(t, e)
	if line != "ready\n" {
		t.Fatal("child not ready")
	}
	return cmd.Process.Pid
}

// Claim: a real live child with the mapped OWNER UID stops tree removal; scanning each real/effective/saved UID is required, while an unused UID permits removal.
func TestLedgerTreeLiveOwnerProcessStops(t *testing.T) {
	f, p := makeTree(t)
	pid := treeChild(t)
	f.sys.live["demo"] = true // shadow-utils would also refuse deleting this live user
	f.l.procUID = nil
	f.l.procPIDs = realProcessCensus(t, os.Getpid(), pid)
	// Other real PIDs retain real status but map their UID fields away so this
	// witness proves the child, rather than relying on the test runner itself.
	childStatus := fmt.Sprintf("/proc/%d/status", pid)
	f.l.procRead = func(path string) ([]byte, error) {
		raw, e := os.ReadFile(path)
		if e != nil || path == childStatus {
			return raw, e
		}
		lines := bytes.Split(raw, []byte{'\n'})
		for j, line := range lines {
			if bytes.HasPrefix(line, []byte("Uid:")) {
				lines[j] = []byte("Uid:\t4000000000\t4000000000\t4000000000\t4000000000")
			}
		}
		return bytes.Join(lines, []byte{'\n'}), nil
	}
	treeRefusal(t, f, fmt.Sprintf("LIVE_OWNER_PROCESS pid=%d", pid), p, filepath.Join(p, "a-safe"), filepath.Join(p, "nested", "payload"))
	validTreeNeighbour(t)
}

// Claim: saved/effective-only OWNER matches and malformed/missing UID records stop a real /proc scan; no OWNER UID in a well-formed record passes.
func TestLedgerTreeProcUIDFields(t *testing.T) {
	for _, fields := range []string{"77 88 99 11", "88 77 99 11", "88 99 77 11", "77 broken", "missing"} {
		e := scanProcessUIDs(77, []string{strconv.Itoa(os.Getpid())}, func(string) ([]byte, error) {
			if fields == "missing" {
				return []byte("Name: fixture\n"), nil
			}
			return []byte("Uid:\t" + fields + "\n"), nil
		})
		if e == nil {
			t.Fatal("bad process accepted", fields)
		}
	}
	var e error
	for attempt := 0; attempt < 100; attempt++ {
		e = scanProcessUIDs(77, []string{strconv.Itoa(os.Getpid())}, func(string) ([]byte, error) { return []byte("Uid:\t88 99 11 77\n"), nil })
		if e == nil || !strings.Contains(e.Error(), "open /proc/") || !strings.Contains(e.Error(), "no such file or directory") {
			break
		}
		t.Log("strict task enumeration refused a vanished PID; retrying the positive control")
		time.Sleep(25 * time.Millisecond)
	}
	must(t, e)
}

// Claim: station refuses tree removal retention at create and journal load, keeps a valid state tree and names retained contents; rehearsal remains removable.
func TestLedgerTreeStationRetention(t *testing.T) {
	f, p := treeFixture(t, "station")
	n := len(f.l.rows)
	e := f.l.CreateTree(p, "demo", "remove", 0700, nil)
	code(t, e, 1)
	if !strings.Contains(e.Error(), "STATION_PROTECTED_RETENTION") || len(f.l.rows) != n {
		t.Fatal(e)
	}
	absent(t, p)
	must(t, f.l.CreateTree(p, "demo", "state", 0700, nil))
	foreign(t, filepath.Join(p, "payload"), "file")
	var out bytes.Buffer
	f.l.output = &out
	must(t, treeReplay(t, f.l, "station"))
	exists(t, p)
	if !strings.Contains(out.String(), "retain-station-protected-tree-content") {
		t.Fatal("tree content missing from compare", out.String())
	}
	rows := append([]Record(nil), f.l.rows...)
	a := *rows[5].Body.Action
	a.Ret = "remove"
	rows[5].Body.Action = &a
	f.l.Close()
	writeRows(t, f, rows, true)
	_, e = Open(f.dir, f.sys)
	code(t, e, 1)
	if !strings.Contains(e.Error(), "STATION_PROTECTED_RETENTION") {
		t.Fatal(e)
	}
	exists(t, p)
	validTreeNeighbour(t)
}

// Claim: owner drift, a later account role, a retained tree, and overlapping per-file scopes cannot grant tree/account deletion authority.
func TestLedgerTreeDedicatedOwnerAndAccountOrder(t *testing.T) {
	f, p := makeTree(t)
	must(t, f.l.CreateAccount("group", "access", "state", 0, 32003))
	e := f.l.AddMember("demo", "access")
	code(t, e, 1)
	if !strings.Contains(e.Error(), "TREE_OWNER_NOT_DEDICATED") {
		t.Fatal(e)
	}
	code(t, f.l.CreateFS(filepath.Join(f.root, "owned"), f.src, "file", "remove", uint32(os.Geteuid()), uint32(os.Getegid()), 0600), 1)
	a := f.sys.users["demo"]
	a.GID++
	f.sys.users["demo"] = a
	treeRefusal(t, f, "IDENTITY_MISMATCH", p)
	a.GID--
	f.sys.users["demo"] = a
	must(t, treeReplay(t, f.l, "rehearsal"))
	absent(t, p)
	g, q := treeFixture(t, "rehearsal")
	must(t, g.l.CreateTree(q, "demo", "d6", 0700, nil))
	treeRefusal(t, g, "TREE_OWNER_STILL_IN_USE", q)
	if validateScope(Scope{Paths: []ScopePath{{Path: "/fixture/tree", Kind: "tree"}, {Path: "/fixture/tree/file", Kind: "file"}}}) == nil {
		t.Fatal("tree scope overlap accepted")
	}
	validTreeNeighbour(t)
}

// Claim: a replay tree intent without a preceding committed owner is refused even with an otherwise valid chain and HEAD.
func TestLedgerTreeReplayRequiresCreatedOwner(t *testing.T) {
	f, p := makeTree(t)
	rows := append([]Record(nil), f.l.rows...)
	// Remove the user intent/result and repair the tree result's sequence link.
	rows = append(rows[:3], rows[5:]...)
	result := *rows[4].Body.Result
	result.Intent = 3
	rows[4].Body.Result = &result
	f.l.Close()
	writeRows(t, f, rows, true)
	_, e := Open(f.dir, f.sys)
	code(t, e, 1)
	if !strings.Contains(e.Error(), "TREE_OWNER_NOT_CREATED") {
		t.Fatal(e)
	}
	exists(t, p)
	validTreeNeighbour(t)
}

// Claim: failure after a real tree-root sync leaves a preserved named orphan; no committed tree authority is invented.
func TestLedgerTreePayloadSyncFailure(t *testing.T) {
	f, p := treeFixture(t, "rehearsal")
	f.l.payloadSync = func(*os.File) error { return errors.New("injected sync failure") }
	code(t, f.l.CreateTree(p, "demo", "rehearsal", 0700, nil), 3)
	exists(t, p)
	f.l.Close()
	_, e := Open(f.dir, f.sys)
	code(t, e, 3)
	validTreeNeighbour(t)
}

// Claim: a replacement after phase 2 starts is rechecked and preserved, while any earlier exact-list deletion is reported by STOP rather than guessed rollback.
func TestLedgerTreePhaseTwoReplacementStops(t *testing.T) {
	f, p := treeFixture(t, "rehearsal")
	must(t, f.l.CreateTree(p, "demo", "rehearsal", 0700, nil))
	first := filepath.Join(p, "a")
	later := filepath.Join(p, "b")
	must(t, os.WriteFile(first, []byte("first"), 0600))
	must(t, os.WriteFile(later, []byte("later"), 0600))
	injected := false
	f.l.payloadSync = func(parent *os.File) error {
		if !injected {
			injected = true
			if e := os.Rename(later, later+".saved"); e != nil {
				return e
			}
			return os.WriteFile(later, []byte("replacement"), 0600)
		}
		return nil
	}
	treeRefusal(t, f, "TREE_CHANGED", p, later, later+".saved")
	if !injected {
		t.Fatal("phase-2 plant not reached")
	}
	absent(t, first)
	raw, e := os.ReadFile(later)
	must(t, e)
	if string(raw) != "replacement" {
		t.Fatal("replacement touched")
	}
	validTreeNeighbour(t)
}

// Claim: the create-tree CLI dispatch commits an empty tree for a recorded owner and rejects malformed socket paths or a pre-existing root without adoption.
func TestLedgerTreeCLIAndExclusiveRoot(t *testing.T) {
	f, p := treeFixture(t, "rehearsal")
	f.l.Close()
	must(t, Run([]string{"create-tree", "-dir", f.dir, "-path", p, "-owner", "demo", "-mode", "0700", "-ret", "rehearsal"}, f.sys, io.Discard))
	f.reopen(t)
	f.l.procUID = func(uint32) uint32 { return 4000000000 }
	f.l.procPIDs = realProcessCensus(t, os.Getpid())
	row := f.l.rows[len(f.l.rows)-1]
	if row.Body.Op != "commit" || row.Body.Result.Identities[0].Path != p {
		t.Fatal("CLI did not commit root")
	}
	must(t, treeReplay(t, f.l, "rehearsal"))
	absent(t, p)
	for _, sockets := range [][]string{{"../outside"}, {"/absolute"}, {"a", "a"}, {"."}} {
		g, q := treeFixture(t, "rehearsal")
		code(t, g.l.CreateTree(q, "demo", "rehearsal", 0700, sockets), 1)
		absent(t, q)
	}
	g, q := treeFixture(t, "rehearsal")
	foreign(t, q, "dir")
	e := g.l.CreateTree(q, "demo", "rehearsal", 0700, nil)
	code(t, e, 1)
	if !strings.Contains(e.Error(), "EXCLUSIVE_REFUSED") || g.l.rows[len(g.l.rows)-1].Body.Op != "abort" {
		t.Fatal("pre-existing root adopted", e)
	}
	exists(t, q)
	validTreeNeighbour(t)
}

// Claim: a recorded ordinary directory/file or supplementary role before create-tree makes that owner non-dedicated, with no tree intent or mkdir; a dedicated owner passes.
func TestLedgerTreeOwnerRoleBeforeTreeRefused(t *testing.T) {
	for _, role := range []string{"file", "dir", "membership"} {
		t.Run(role, func(t *testing.T) {
			f, p := treeFixture(t, "rehearsal")
			if role == "membership" {
				must(t, f.l.CreateAccount("group", "access", "state", 0, 32003))
				must(t, f.l.AddMember("demo", "access"))
			} else {
				name := "owned"
				mode := uint32(0600)
				if role == "dir" {
					name = "directory"
					mode = 0700
				}
				must(t, f.l.CreateFS(filepath.Join(f.root, name), f.src, role, "state", uint32(os.Geteuid()), uint32(os.Getegid()), mode))
			}
			n := len(f.l.rows)
			e := f.l.CreateTree(p, "demo", "rehearsal", 0700, nil)
			code(t, e, 1)
			if !strings.Contains(e.Error(), "TREE_OWNER_NOT_DEDICATED") || len(f.l.rows) != n {
				t.Fatal("owner granted extra role", e)
			}
			absent(t, p)
		})
	}
	validTreeNeighbour(t)
}

// Claim: scanning only process leaders is insufficient; a real child task's OWNER UID stops removal even when the read seam maps its leader and other tasks away.
func TestLedgerTreeOwnerThreadStops(t *testing.T) {
	f, p := makeTree(t)
	pid := treeChild(t)
	f.sys.live["demo"] = true // shadow-utils would also refuse deleting this live user
	f.l.procUID = nil
	f.l.procPIDs = realProcessCensus(t, os.Getpid(), pid)
	target := fmt.Sprintf("/proc/%d/task/%d/status", pid, pid)
	seen := false
	f.l.procRead = func(path string) ([]byte, error) {
		raw, e := os.ReadFile(path)
		if e != nil {
			return nil, e
		}
		if path == target {
			seen = true
			return raw, nil
		}
		lines := bytes.Split(raw, []byte{'\n'})
		for j, line := range lines {
			if bytes.HasPrefix(line, []byte("Uid:")) {
				lines[j] = []byte("Uid:\t4000000000\t4000000000\t4000000000\t4000000000")
			}
		}
		return bytes.Join(lines, []byte{'\n'}), nil
	}
	treeRefusal(t, f, fmt.Sprintf("LIVE_OWNER_PROCESS pid=%d", pid), p, filepath.Join(p, "a-safe"), filepath.Join(p, "nested", "payload"))
	if !seen {
		t.Fatal("real task status not inspected")
	}
	validTreeNeighbour(t)
}

// Claim: the production /proc census includes the current process and a real live child; a census error stops tree replay before deleting any payload.
func TestLedgerTreeProductionCensusAndEnumerationError(t *testing.T) {
	pid := treeChild(t)
	pids, e := processIDs()
	must(t, e)
	if !slices.Contains(pids, strconv.Itoa(pid)) || !slices.Contains(pids, strconv.Itoa(os.Getpid())) {
		t.Fatal("default census missed a live real process")
	}
	f, p := makeTree(t)
	f.l.procPIDs = func() ([]string, error) { return nil, os.ErrPermission }
	treeRefusal(t, f, "TREE_PROCESS_CHECK_PROC_ENUM", p, filepath.Join(p, "a-safe"), filepath.Join(p, "nested", "payload"))
	validTreeNeighbour(t)
}

// Claim: the production full-census path preserves a tree with a real same-UID child; an earlier checked /proc error is also a conservative STOP, never absence evidence.
func TestLedgerTreeProductionProcessGuard(t *testing.T) {
	f, p := makeTree(t)
	_ = treeChild(t)
	f.l.procUID = nil
	f.l.procPIDs = nil
	f.sys.live["demo"] = true
	e := f.l.Replay("rehearsal")
	code(t, e, 1)
	for _, path := range []string{p, filepath.Join(p, "a-safe"), filepath.Join(p, "nested", "payload")} {
		exists(t, path)
	}
	if !strings.Contains(e.Error(), "TREE_PROCESS_CHECK") {
		t.Fatal("production process guard was bypassed", e)
	}
	validTreeNeighbour(t)
}
