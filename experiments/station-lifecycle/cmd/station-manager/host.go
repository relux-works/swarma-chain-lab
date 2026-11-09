//go:build !darwin || !slotdfake

package main

import (
	"relux.works/swarma-chain-lab/experiments/station-lifecycle/slotd"
	"time"
)

// Production retains the root peer check and Linux boot clock, even if someone
// passes the rehearsal build tag to a Linux release build.
func newHost(c config) (*slotd.Host, error) {
	helper, e := slotd.NewUnixClient(c.Socket)
	if e != nil {
		return nil, e
	}
	return &slotd.Host{Client: helper, Now: time.Now, BootClock: slotd.SystemBootClock}, nil
}
