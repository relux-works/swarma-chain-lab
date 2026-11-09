package rehearsal

import (
	"bytes"
	_ "embed"
	"github.com/relux-works/swarma-chain-lab/experiments/rental"
	"os"
	"path/filepath"
)

//go:embed fixtures/registrar.go.txt
var registrarSource []byte

// The pinned wrapper, endpoint checks, caps and all gateway admission code stay
// byte-identical. Normal builds never read this overlay or its private config.
func (l *lab) registrarOverlay() string {
	t := l.t
	t.Helper()
	target := filepath.Join(l.repo, "experiments/rental-gateway/cmd/gateway/model_proxy.go")
	original, e := os.ReadFile(target)
	checked(t, e, "registrar source")
	needle := []byte("proxy.Client{SocketPath: p.AdminSocket, ServerUID: *p.ServerUID}")
	if bytes.Count(original, needle) != 1 {
		t.Fatal("registrar substitution boundary changed")
	}
	replaced := bytes.Replace(original, needle, []byte("rehearsalRegistrar(p)"), 1)
	root := l.dir("overlay")
	changed := filepath.Join(root, "model_proxy.go")
	helper := filepath.Join(root, "rehearsal_registrar.go")
	l.write(changed, replaced, 0600)
	l.write(helper, registrarSource, 0600)
	overlay := l.json("overlay.json", struct{ Replace map[string]string }{map[string]string{target: changed, filepath.Join(filepath.Dir(target), "rehearsal_registrar.go"): helper}}, 0600)
	l.evidence["registrar_overlay"] = map[string]string{"original_sha256": rental.Hash(original), "overlay_sha256": rental.Hash(replaced), "helper_sha256": rental.Hash(registrarSource), "substitution": "proxy.Client construction only; real in-process MP1 Service; production Linux admin untouched"}
	return overlay
}
