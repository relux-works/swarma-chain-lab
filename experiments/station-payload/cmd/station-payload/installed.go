package main

import "github.com/relux-works/swarma-chain-lab/experiments/single-use/configguard"

var installedRead = func(path string, limit int64) ([]byte, error) { return configguard.ReadService("payload", path, limit) }
