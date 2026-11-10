package deploy

import "github.com/relux-works/swarma-chain-lab/experiments/single-use/configguard"

// RenderInstallAnchor formats public pins supplied by the install owner. It
// never reads installed configs, secret material or private signing keys, and
// does not choose/approve the supplied release, manifest digest or public key.
func RenderInstallAnchor(manifest, signature, manifestDigest, releaseDigest, algorithm, publicKey string) ([]byte, error) {
	return configguard.RenderDropIn(configguard.Anchor{Manifest: manifest, Signature: signature, Digest: manifestDigest, Release: releaseDigest, Algorithm: algorithm, PublicKey: publicKey})
}
