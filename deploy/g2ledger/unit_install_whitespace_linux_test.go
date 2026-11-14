//go:build linux

package g2ledger

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// Claim: non-ASCII keys and Unicode whitespace values refuse before intent or enable; ASCII whitespace controls enable and undo.
func TestInstallWhitespace(t *testing.T) {
	chars := []struct{ name, text string }{
		{"NBSP", "\u00a0"}, {"EN_SPACE", "\u2002"}, {"IDEOGRAPHIC_SPACE", "\u3000"},
		{"BOM", "\ufeff"}, {"NEXT_LINE", "\u0085"},
	}
	for _, key := range []string{"Alias", "WantedBy", "RequiredBy"} {
		t.Run(key, func(t *testing.T) {
			name, path := "one.target", "one.target.wants/demo.service"
			switch key {
			case "Alias":
				name, path = "one.service", "one.service"
			case "RequiredBy":
				path = "one.target.requires/demo.service"
			}
			run := func(t *testing.T, assignment, reason string) {
				t.Helper()
				f := setup(t)
				source := installFixture(t, f, "[Install]\n"+assignment+"\n")
				link := UnitLink{Path: filepath.Join(f.sys.unitRoot, path), Target: source}
				installReply(t, f, []UnitLink{link}, []UnitLink{link})
				f.l.Close()
				before, err := os.ReadFile(filepath.Join(f.dir, recordsName))
				must(t, err)
				err = Run([]string{"enable", "-dir", f.dir, "-unit", "demo.service"}, f.sys, io.Discard)
				if reason == "" {
					must(t, err)
					exists(t, link.Path)
					must(t, Run([]string{"replay", "-dir", f.dir, "-mode", "station"}, f.sys, io.Discard))
					absent(t, link.Path)
					return
				}
				code(t, err, 1)
				if err.Error() != "g2-ledger: UNIT_INSTALL demo.service: "+reason {
					t.Fatalf("wrong refusal: %v", err)
				}
				after, err := os.ReadFile(filepath.Join(f.dir, recordsName))
				must(t, err)
				if !bytes.Equal(before, after) || f.sys.called("/usr/bin/systemctl enable") || f.sys.units["demo.service"] != "disabled" {
					t.Fatal("refusal changed journal or crossed enable boundary")
				}
				absent(t, link.Path)
			}
			for _, ws := range []string{" ", "\t", "\r", " \t\r"} {
				t.Run(fmt.Sprintf("ASCII-%q", ws), func(t *testing.T) {
					run(t, ws+key+ws+"="+ws+name+ws, "")
				})
			}
			for _, ch := range chars {
				for _, side := range []string{"before", "after"} {
					t.Run(ch.name+"/key-"+side, func(t *testing.T) {
						k := ch.text + key
						if side == "after" {
							k = key + ch.text
						}
						run(t, " \t"+k+" \t="+name, "UNIT_INSTALL_KEY_NON_ASCII")
					})
				}
				for _, value := range []struct{ position, text string }{
					{"before", ch.text + name}, {"after", name + ch.text},
					{"inside", "one" + ch.text + name[3:]},
					{"separator", name + ch.text + name},
					{"quoted", "'" + name + ch.text + "'"},
				} {
					t.Run(ch.name+"/value-"+value.position, func(t *testing.T) {
						run(t, key+"="+value.text, "UNIT_INSTALL_VALUE_WHITESPACE_REFUSED")
					})
				}
			}
			for _, bad := range []struct{ key, reason string }{
				{key + "\u00e9", "UNIT_INSTALL_KEY_NON_ASCII"},
				{key + "\xff", "UNIT_INSTALL_KEY_NON_ASCII"},
				{key + "Typo", "UNIT_INSTALL_DIRECTIVE_REFUSED"},
			} {
				t.Run(fmt.Sprintf("unknown-%q", bad.key), func(t *testing.T) {
					run(t, bad.key+"="+name, bad.reason)
				})
			}
		})
	}
}
