//go:build !linux

package slotd

// Host authority is unavailable on this platform. Tests exercise the same wire
// codec through an explicit fake transport, never a production bypass flag.
func NewUnixClient(string) (*Client, error) { return nil, failure("SLOTD_LINUX_ONLY") }
