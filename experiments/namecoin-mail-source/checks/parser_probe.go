// Run inside the pinned ncdns module, in the offline sandbox. No DNS listeners.
package main

import (
	"encoding/json"
	"fmt"
	"github.com/namecoin/ncdns/ncdomain"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type item struct {
	Case  string `json:"case"`
	Name  string `json:"name"`
	Apex  string `json:"apex"`
	Bytes int    `json:"bytes"`
}

func main() {
	root := os.Args[1]
	b, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	must(err)
	var cases []item
	must(json.Unmarshal(b, &cases))
	for _, c := range cases {
		raw, err := os.ReadFile(filepath.Join(root, c.Case+".json"))
		must(err)
		if len(raw) != c.Bytes || len(raw) > 520 {
			panic("name value byte bound")
		}
		var parseErrs []string
		value := ncdomain.ParseValue(c.Name, string(raw), func(string) (string, error) { return "", fmt.Errorf("external resolution prohibited") }, func(e error, w bool) {
			if !w {
				parseErrs = append(parseErrs, e.Error())
			}
		})
		if value == nil || len(parseErrs) > 0 {
			panic(fmt.Sprint("parse: ", parseErrs))
		}
		rrs, err := value.RRsRecursive(nil, c.Apex, c.Apex)
		must(err)
		var lines []string
		for _, rr := range rrs {
			lines = append(lines, strings.Join(strings.Fields(rr.String()), " "))
		}
		sort.Strings(lines)
		actual := strings.Join(lines, "\n")
		if len(lines) > 0 {
			actual += "\n"
		}
		want, err := os.ReadFile(filepath.Join(root, c.Case+".rr"))
		must(err)
		if actual != string(want) {
			panic(fmt.Sprintf("%s\nactual:%s\nwant:%s", c.Case, actual, want))
		}
		fmt.Printf("PASS %s bytes=%d RRs=%d\n%s", c.Case, len(raw), len(rrs), actual)
	}
}
func must(err error) {
	if err != nil {
		panic(err)
	}
}
