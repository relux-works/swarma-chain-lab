package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
)

func main() {
	args := os.Args[1:]
	if len(args) != 3 {
		panic("arguments")
	}
	source, overlay, out := args[0], args[1], args[2]
	b, e := os.ReadFile(filepath.Join(source, "manifest.json"))
	if e != nil {
		panic(e)
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		panic("manifest")
	}
	binary, e := os.ReadFile(overlay)
	if e != nil {
		panic(e)
	}
	h := sha256.Sum256(binary)
	for _, v := range m["artifacts"].([]any) {
		a := v.(map[string]any)
		if a["service"] == "gateway" {
			a["sha256"] = hex.EncodeToString(h[:])
		}
	}
	if e = os.Mkdir(out, 0700); e != nil {
		panic(e)
	}
	if e = os.Mkdir(filepath.Join(out, "bin"), 0700); e != nil {
		panic(e)
	}
	b, e = json.Marshal(m)
	if e != nil {
		panic(e)
	}
	if e = os.WriteFile(filepath.Join(out, "manifest.json"), b, 0600); e != nil {
		panic(e)
	}
	if e = os.WriteFile(filepath.Join(out, "bin/gateway"), binary, 0700); e != nil {
		panic(e)
	}
}
