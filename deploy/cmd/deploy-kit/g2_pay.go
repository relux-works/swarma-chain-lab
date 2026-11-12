package main

// PX1 S5 subcommands: g2-render, g2-host-flow, g2-agent-groups,
// g2-custody-probe, g2-custody-verify.

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/relux-works/swarma-chain-lab/deploy"
)

func readBounded(path string, limit int64) ([]byte, error) {
	file, e := os.Open(path)
	if e != nil {
		return nil, deploy.ErrPolicy
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || int64(len(raw)) > limit {
		return nil, deploy.ErrPolicy
	}
	return raw, nil
}

// g2Render writes the G2File* set into a new directory (mode 0700, files
// 0600). It refuses an existing output path, so it never overwrites.
func g2Render(args []string, out io.Writer) error {
	f := flag.NewFlagSet("g2-render", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	params := f.String("params", "", "canonical G2PayParameters JSON")
	dir := f.String("out", "", "new absolute output directory")
	if f.Parse(args) != nil || f.NArg() != 0 || !filepath.IsAbs(*dir) || filepath.Clean(*dir) != *dir {
		return deploy.ErrInput
	}
	raw, e := readBounded(*params, 1<<16)
	if e != nil {
		return e
	}
	p, e := deploy.ParseG2PayParameters(bytes.TrimSuffix(raw, []byte("\n")))
	if e != nil {
		return e
	}
	files, e := deploy.RenderG2PayTemplates(p)
	if e != nil {
		return e
	}
	if e := os.Mkdir(*dir, 0700); e != nil {
		return deploy.ErrInput
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if e := os.WriteFile(filepath.Join(*dir, name), files[name], 0600); e != nil {
			return deploy.ErrPolicy
		}
	}
	return json.NewEncoder(out).Encode(struct {
		Status string   `json:"status"`
		Files  []string `json:"files"`
	}{"G2_RENDERED", names})
}

func readSpec(path string) (deploy.CustodySpecV1, error) {
	raw, e := readBounded(path, 1<<16)
	if e != nil {
		return deploy.CustodySpecV1{}, e
	}
	return deploy.ParseCustodySpec(bytes.TrimSuffix(raw, []byte("\n")))
}

// g2CustodyProbe runs T18 as the calling UID and prints the report. A report
// that does not pass is still printed (evidence) and the command fails.
func g2CustodyProbe(args []string, out io.Writer) error {
	f := flag.NewFlagSet("g2-custody-probe", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	path := f.String("spec", "", "resolved custody-spec.json")
	if f.Parse(args) != nil || f.NArg() != 0 {
		return deploy.ErrInput
	}
	spec, e := readSpec(*path)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	report, e := deploy.RunCustodyProbe(ctx, spec)
	if e != nil {
		return e
	}
	b, _ := json.Marshal(report)
	if _, e := fmt.Fprintln(out, string(b)); e != nil {
		return e
	}
	if !report.Pass {
		return deploy.ErrCustody
	}
	return nil
}

// g2CustodyVerify checks a stored report against the launch spec.
func g2CustodyVerify(args []string, out io.Writer) error {
	f := flag.NewFlagSet("g2-custody-verify", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	specPath := f.String("spec", "", "resolved custody-spec.json")
	reportPath := f.String("report", "", "custody report JSON")
	launch := f.Bool("launch", true, "require the rendered launch layout")
	if f.Parse(args) != nil || f.NArg() != 0 {
		return deploy.ErrInput
	}
	spec, e := readSpec(*specPath)
	if e != nil {
		return e
	}
	if *launch {
		if e := deploy.ValidateG2CustodyLaunchSpec(spec); e != nil {
			return e
		}
	}
	raw, e := readBounded(*reportPath, 1<<20)
	if e != nil {
		return e
	}
	var report deploy.CustodyReportV1
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&report) != nil || d.More() {
		return deploy.ErrCustody
	}
	if e := deploy.VerifyCustodyReport(spec, report); e != nil {
		return e
	}
	_, e = fmt.Fprintln(out, "T18_CUSTODY_VERIFIED "+report.SpecSHA256)
	return e
}

// g2HostFlow runs the freeze-amendment-1 provisioning order on THIS host, the
// target host, as root: deploy.RunG2HostFlow over this host's account
// database (deploy.G2HostAccounts) with two host actions. Apply gives the
// sysusers.conf rendered from the same parameters to systemd-sysusers on
// standard input ("-"); its exit status authorizes nothing. Activate runs the
// command after "--" (for example systemctl start of agent-walletd) only after
// the post-apply account check passed. Any refusal stops before the next step.
//
//	deploy-kit g2-host-flow -params PARAMS [-sysusers PATH] -- ACTIVATION...
func g2HostFlow(args []string, out io.Writer) error {
	f := flag.NewFlagSet("g2-host-flow", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	params := f.String("params", "", "canonical G2PayParameters JSON")
	sysusers := f.String("sysusers", "systemd-sysusers", "systemd-sysusers binary")
	if f.Parse(args) != nil || f.NArg() == 0 || *sysusers == "" {
		return deploy.ErrInput
	}
	activation := f.Args()
	raw, e := readBounded(*params, 1<<16)
	if e != nil {
		return e
	}
	p, e := deploy.ParseG2PayParameters(bytes.TrimSuffix(raw, []byte("\n")))
	if e != nil {
		return e
	}
	e = deploy.RunG2HostFlow(p, deploy.G2HostAccounts{}, deploy.G2HostSteps{
		Apply: func(conf []byte) error {
			cmd := exec.Command(*sysusers, "-")
			cmd.Stdin, cmd.Stdout, cmd.Stderr = bytes.NewReader(conf), os.Stderr, os.Stderr
			if cmd.Run() != nil {
				return deploy.ErrPolicy
			}
			return nil
		},
		Activate: func() error {
			cmd := exec.Command(activation[0], activation[1:]...)
			cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
			if cmd.Run() != nil {
				return deploy.ErrPolicy
			}
			return nil
		},
	})
	if e != nil {
		return e
	}
	_, e = fmt.Fprintln(out, "G2_HOST_FLOW_ACTIVATED")
	return e
}

// g2AgentGroups is the T18 credential readback: the GIDs after "--" are the
// running agent's `id -G` output, one argument each, and must be exactly the
// set {own primary GID, agent_socket_gid} that deploy.CheckG2AgentGroups
// derives from the parameters (the primary GID from G2AgentSysusers). A GID
// that is not a canonical decimal refuses ErrInput. It prints
// G2_AGENT_GROUPS_OK with the two GIDs only when the readback passes.
//
//	deploy-kit g2-agent-groups -params PARAMS -- GID...
func g2AgentGroups(args []string, out io.Writer) error {
	f := flag.NewFlagSet("g2-agent-groups", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	params := f.String("params", "", "canonical G2PayParameters JSON")
	if f.Parse(args) != nil {
		return deploy.ErrInput
	}
	readback := make([]uint32, 0, f.NArg())
	for _, s := range f.Args() {
		v, e := strconv.ParseUint(s, 10, 32)
		if e != nil || strconv.FormatUint(v, 10) != s {
			return deploy.ErrInput
		}
		readback = append(readback, uint32(v))
	}
	raw, e := readBounded(*params, 1<<16)
	if e != nil {
		return e
	}
	p, e := deploy.ParseG2PayParameters(bytes.TrimSuffix(raw, []byte("\n")))
	if e != nil {
		return e
	}
	if e := deploy.CheckG2AgentGroups(p, readback); e != nil {
		return e
	}
	primary, socket, e := deploy.G2AgentSlotGIDs(p)
	if e != nil {
		return e
	}
	_, e = fmt.Fprintf(out, "G2_AGENT_GROUPS_OK primary=%d socket=%d\n", primary, socket)
	return e
}
