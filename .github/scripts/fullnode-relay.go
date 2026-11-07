// Offline test-only stdio relay. It executes no source, verifier, node or RPC.
// The launcher supplies sibling namespaces through private FIFOs. The protocol
// and limits follow the historical sibling controller; verdicts and exit codes
// come exclusively from the actual isolated verifier.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const maxLine = 8 * 1024 * 1024

type channel struct {
	in, out *os.File
	reader  *bufio.Reader
	path    string
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func connect(name string) *channel {
	p := filepath.Join("/channels", name)
	in, err := os.OpenFile(p+".in", os.O_WRONLY, 0)
	check(err)
	out, err := os.Open(p + ".out")
	check(err)
	return &channel{in, out, bufio.NewReaderSize(out, 65536), p}
}

func (c *channel) line() ([]byte, error) {
	var data []byte
	for {
		part, err := c.reader.ReadSlice('\n')
		data = append(data, part...)
		if len(data) > maxLine {
			return nil, fmt.Errorf("controller line bound")
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			return nil, err
		}
		return data, nil
	}
}

func (c *channel) send(data []byte) {
	if len(data) == 0 || data[len(data)-1] != '\n' {
		data = append(data, '\n')
	}
	if len(data) > maxLine {
		panic("controller write bound")
	}
	_, err := c.in.Write(data)
	check(err)
}

func (c *channel) exit() int {
	status, err := os.Open(c.path + ".exit")
	check(err)
	defer status.Close()
	data, err := io.ReadAll(io.LimitReader(status, 16))
	check(err)
	code, err := strconv.Atoi(strings.TrimSpace(string(data)))
	check(err)
	if code < 0 || code > 255 {
		panic("invalid namespace exit")
	}
	return code
}

func run() int {
	// One immutable wall cutoff includes FIFO opens, reads, writes and exit waits.
	time.AfterFunc(110*time.Second, func() {
		fmt.Fprintln(os.Stderr, "controller immutable deadline")
		os.Exit(124)
	})
	parent := connect("tests")
	defer parent.in.Close()
	defer parent.out.Close()
	used := 0
	for {
		raw, err := parent.line()
		if err == io.EOF {
			return parent.exit()
		}
		check(err)
		var event struct {
			Type  string          `json:"type"`
			Input json.RawMessage `json:"input"`
		}
		if json.Unmarshal(raw, &event) != nil {
			_, err := os.Stdout.Write(raw)
			check(err)
			continue
		}
		if event.Type != "verify" || len(event.Input) == 0 {
			panic("unexpected broker event")
		}
		// Four actual verifier invocations in the complete discovery suite. A new
		// invocation requires explicitly expanding the launcher, never a fallback.
		if used == 4 {
			panic("verifier namespace count bound")
		}
		verifier := connect(fmt.Sprintf("verifier-%d", used))
		used++
		verifier.send(event.Input)
		finished := false
		for n := 0; n < 2101; n++ {
			request, err := verifier.line()
			if err == io.EOF {
				panic(fmt.Sprintf("verifier closed without decision; exit=%d", verifier.exit()))
			}
			check(err)
			var message struct {
				Type   string          `json:"type"`
				Result json.RawMessage `json:"result"`
			}
			check(json.Unmarshal(request, &message))
			if message.Type == "startup_error" {
				panic(fmt.Sprintf("verifier startup failure: %s", request))
			}
			if message.Type == "decision" {
				code := verifier.exit()
				fmt.Fprintf(os.Stderr, "CONTROLLER_VERIFIER_EXIT index=%d exit=%d\n", used-1, code)
				verdict, err := json.Marshal(struct {
					Type   string          `json:"type"`
					Result json.RawMessage `json:"result"`
					Exit   int             `json:"exit"`
				}{"verdict", message.Result, code})
				check(err)
				parent.send(verdict)
				finished = true
				break
			}
			if message.Type != "rpc" {
				panic("unexpected verifier event")
			}
			parent.send(request)
			reply, err := parent.line()
			check(err)
			var response struct {
				Type string `json:"type"`
			}
			check(json.Unmarshal(reply, &response))
			if response.Type != "rpc_result" {
				panic("unexpected broker reply")
			}
			verifier.send(reply)
		}
		verifier.in.Close()
		verifier.out.Close()
		if !finished {
			panic("verifier request-count bound")
		}
	}
}

func main() { os.Exit(run()) }
