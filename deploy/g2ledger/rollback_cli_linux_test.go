package g2ledger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Claim: the built deploy-kit dispatch writes exact stopped/running success lines plus JSON; runtime effects and loaded-policy attestation are injected offline fixtures, not native capabilities.
func TestRollbackBuiltCLIStateLines(t *testing.T) {
	root := t.TempDir()
	repo, err := filepath.Abs("../..")
	must(t, err)
	mainPath := filepath.Join(repo, "deploy/cmd/deploy-kit/main.go")
	raw, err := os.ReadFile(mainPath)
	must(t, err)
	old := "g2ledger.RunRollback(args[1:], nil, os.Stdout)"
	if strings.Count(string(raw), old) != 1 {
		t.Fatal("CLI injection anchor changed")
	}
	mainFixture := filepath.Join(root, "main.go")
	must(t, os.WriteFile(mainFixture, []byte(strings.Replace(string(raw), old, "g2ledger.RunRollback(args[1:], rollbackCLISystem{}, os.Stdout)", 1)), 0600))
	helper := filepath.Join(root, "runtime.go")
	must(t, os.WriteFile(helper, []byte(`package main
import (
 "fmt"
 "os"
 "github.com/relux-works/swarma-chain-lab/deploy/g2ledger"
)
type rollbackCLISystem struct{g2ledger.RealSystem}
func (rollbackCLISystem) Run(command string,args ...string)(string,int,error){
 if command!="/usr/bin/systemctl" || len(args)==0 {return "",1,fmt.Errorf("unexpected fixture command")}
 path:=os.Getenv("ROLLBACK_CLI_STATE")
 switch args[0] {
 case "stop": return "",0,os.WriteFile(path,[]byte("stopped"),0600)
 case "start": return "",0,os.WriteFile(path,[]byte("running"),0600)
 case "show":
  b,e:=os.ReadFile(path); if e!=nil{return "",1,e}
  if string(b)=="running" {return "LoadState=loaded\nActiveState=active\nMainPID=73\n",0,nil}
  return "LoadState=loaded\nActiveState=inactive\nMainPID=0\n",0,nil
 }
 return "",1,fmt.Errorf("unexpected fixture command")
}
`), 0600))
	source := filepath.Join(repo, "deploy/g2ledger/rollback_linux.go")
	raw, err = os.ReadFile(source)
	must(t, err)
	old = "func (n systemNode) Policy(string) (NodePolicy, error) { return NodePolicy{}, nil }"
	if strings.Count(string(raw), old) != 1 {
		t.Fatal("policy fixture anchor changed")
	}
	policy := filepath.Join(root, "rollback.go")
	replacement := "func (n systemNode) Policy(string) (NodePolicy, error) { return NodePolicy{Readable: true, ConfigSHA256: \"" + digest(rollbackOld) + "\"}, nil }"
	must(t, os.WriteFile(policy, []byte(strings.Replace(string(raw), old, replacement, 1)), 0600))
	overlay := filepath.Join(root, "overlay.json")
	b, err := json.Marshal(map[string]any{"Replace": map[string]string{mainPath: mainFixture, filepath.Join(repo, "deploy/cmd/deploy-kit/rollback_cli_fixture.go"): helper, source: policy}})
	must(t, err)
	must(t, os.WriteFile(overlay, b, 0600))
	kit := filepath.Join(root, "deploy-kit")
	build := exec.Command("go", "build", "-overlay", overlay, "-o", kit, "./cmd/deploy-kit")
	build.Dir = filepath.Join(repo, "deploy")
	if b, e := build.CombinedOutput(); e != nil {
		t.Fatalf("build: %v %s", e, b)
	}
	for _, running := range []bool{false, true} {
		name := "stopped"
		if running {
			name = "running"
		}
		t.Run(name, func(t *testing.T) {
			n := &rollbackNode{running: running}
			f := setupWith(t, "station", func(f *fixture) {
				f.scope.Users, f.scope.Groups, f.scope.Units = nil, nil, nil
				n.config = filepath.Join(f.root, "config")
				preimage := filepath.Join(f.root, "baseline", "node.conf")
				must(t, os.WriteFile(n.config, rollbackOld, 0640))
				must(t, os.WriteFile(preimage, rollbackOld, 0600))
				f.scope.Node = &NodeScope{Unit: "node.service", Config: n.config, Preimage: preimage}
				f.sys.fault = func(command string, args []string) (fakeReply, bool) {
					if command == "/usr/bin/systemctl" && len(args) > 0 && args[0] == "show" {
						active, pid := "inactive", 0
						if running {
							active, pid = "active", 73
						}
						return fakeReply{out: fmt.Sprintf("LoadState=loaded\nActiveState=%s\nMainPID=%d\n", active, pid)}, true
					}
					return fakeReply{}, false
				}
			})
			installRollbackConfig(t, f, n, true)
			f.l.Close()
			state := filepath.Join(root, "state-"+name)
			must(t, os.WriteFile(state, []byte("running"), 0600))
			reason := "BASELINE_STOPPED"
			if running {
				reason = ""
			}
			invoke := func(retry string) {
				t.Helper()
				cmd := exec.Command(kit, "g2-rollback", "-dir", f.dir, "-mode", "station")
				cmd.Env = append(os.Environ(), "ROLLBACK_CLI_STATE="+state)
				var out, stderr bytes.Buffer
				cmd.Stdout = &out
				cmd.Stderr = &stderr
				if e := cmd.Run(); e != nil {
					t.Fatalf("CLI: %v stdout=%s stderr=%s", e, out.String(), stderr.String())
				}
				lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
				want := "ROLLBACK_OK node=" + name + " config=baseline-verified retry=" + retry
				if len(lines) < 2 || lines[len(lines)-1] != want {
					t.Fatalf("stdout=%s want last line %q", out.String(), want)
				}
				var receipt struct{ Type, Reason string }
				must(t, json.Unmarshal([]byte(lines[len(lines)-2]), &receipt))
				if receipt.Type != "rollback_verified" || receipt.Reason != reason || stderr.Len() != 0 {
					t.Fatalf("bad receipt/stderr: %s %s", out.String(), stderr.String())
				}
				got, e := os.ReadFile(state)
				must(t, e)
				if string(got) != name {
					t.Fatal("state line disagrees with runtime fixture")
				}
			}
			invoke("reconciled")
			if !running {
				invoke("noop")
			}
		})
	}
}
