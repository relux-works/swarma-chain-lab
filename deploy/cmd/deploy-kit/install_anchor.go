package main

import (
	"flag"
	"github.com/relux-works/swarma-chain-lab/deploy"
	"io"
)

func renderInstallAnchor(args []string, out io.Writer) error {
	f := flag.NewFlagSet("render-install-anchor", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	manifest := f.String("manifest", "", "installed private manifest absolute path")
	signature := f.String("signature", "", "installed detached signature absolute path")
	digest := f.String("manifest-sha256", "", "independently approved manifest digest")
	release := f.String("release-sha256", "", "accepted public release manifest digest")
	algorithm := f.String("algorithm", "", "pinned signature algorithm")
	public := f.String("public-key", "", "base64 PKIX public key DER, never a private key")
	if f.Parse(args) != nil || f.NArg() != 0 {
		return deploy.ErrInput
	}
	b, e := deploy.RenderInstallAnchor(*manifest, *signature, *digest, *release, *algorithm, *public)
	if e != nil {
		return e
	}
	_, e = out.Write(b)
	return e
}
