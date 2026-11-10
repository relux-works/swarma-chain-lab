package signerservice

import "github.com/relux-works/swarma-chain-lab/experiments/single-use/configguard"

// installedRead is the static deployment boundary; mutable state keeps its own reader.
var installedRead = func(path string, limit int64) ([]byte, error) { return configguard.ReadService("issuer", path, limit) }
