package main

import (
	"context"
	"flag"
	"fmt"
	smoke "github.com/relux-works/swarma-chain-lab/experiments/m5-host-smoke"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() { os.Exit(run()) }
func run() int {
	config := flag.String("config", "", "private-mode public config JSON")
	inventory := flag.String("inventory", "", "sanitized inventory JSON, pinned by config")
	out := flag.String("out", "", "new absolute evidence/handoff directory")
	flag.Parse()
	if flag.NArg() != 0 || *config == "" || *out == "" || *inventory == "" {
		fmt.Fprintln(os.Stderr, "USAGE: m5-host-smoke -config PUBLIC.json -inventory INVENTORY.json -out NEW_ABSOLUTE_DIR")
		return 2
	}
	c, e := smoke.ReadConfig(*config)
	if e != nil {
		fmt.Fprintln(os.Stderr, "CONFIG_REFUSED")
		return 2
	}
	files, e := smoke.NewFiles(*out)
	if e != nil {
		fmt.Fprintln(os.Stderr, "OUTPUT_REFUSED")
		return 2
	}
	defer files.Close()
	if files.AddConfig(c) != nil {
		fmt.Fprintln(os.Stderr, "CONFIG_REFUSED")
		return 2
	}
	if files.AddInventory(*inventory, c.EvidenceSHA256) != nil {
		fmt.Fprintln(os.Stderr, "INVENTORY_REFUSED")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 2*time.Hour)
	defer cancel()
	report, e := smoke.Run(ctx, c, files)
	if files.Finish(report) != nil {
		fmt.Fprintln(os.Stderr, "PACKET_SEAL_FAILED")
		return 1
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, "STOP", report.Failure)
		return 1
	}
	fmt.Println(report.Outcome)
	return 0
}
