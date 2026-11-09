//go:build !linux

package slotd

import lifecycle "relux.works/swarma-chain-lab/experiments/station-lifecycle"

func SystemBootClock() (lifecycle.CreateFence, error) {
	return lifecycle.CreateFence{}, failure("SLOTD_LINUX_ONLY")
}
