package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	if len(os.Args) != 3 {
		panic("arguments")
	}
	repo, out := os.Args[1], os.Args[2]
	if e := os.Mkdir(out, 0700); e != nil {
		panic(e)
	}
	target := filepath.Join(repo, "experiments/rental-gateway/gateway/inbound.go")
	raw, e := os.ReadFile(target)
	if e != nil {
		panic(e)
	}
	needle := "\tif !slot.Started && !(slot.Starting && g.starting[slot.ID] != nil) {\n\t\treturn deny(\"session not started\")\n\t}\n"
	if strings.Count(string(raw), needle) != 1 {
		panic("plant boundary")
	}
	replacement := filepath.Join(out, "inbound.go")
	oldGate := "\tif !slot.Started {\n\t\treturn deny(\"session not started\")\n\t}\n"
	if e = os.WriteFile(replacement, []byte(strings.Replace(string(raw), needle, oldGate, 1)), 0600); e != nil {
		panic(e)
	}
	b, e := json.Marshal(struct{ Replace map[string]string }{map[string]string{target: replacement}})
	if e != nil {
		panic(e)
	}
	if e = os.WriteFile(filepath.Join(out, "overlay.json"), b, 0600); e != nil {
		panic(e)
	}
}
