package modelproxy

import "github.com/relux-works/swarma-chain-lab/experiments/single-use/configguard"

// installedRead is the static deployment boundary; mutable state keeps its own reader.
const installedService = "model"

var installedRead = func(path string, limit int64) ([]byte, error) {
	return configguard.ReadService(installedService, path, limit)
}

// ReadInstalledFile enforces root-owned0640 static input; dynamic per-slot files
// continue through their distinct DK5b private-file contract.
func ReadInstalledFile(path string, limit int64) ([]byte, error) { return installedRead(path, limit) }
