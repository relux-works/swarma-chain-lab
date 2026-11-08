// Offline subprocess fixture. Never connects to a node or reads a conf/datadir.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 6 {
		os.Exit(2)
	}
	method := os.Args[5]
	switch method {
	case "getblockhash":
		fmt.Println("000000000062b72c5e2ceb45fbc8587e807c155b0da735e6483dfba2f0a9c770")
	case "gettxout":
		return
	case "getblock":
		time.Sleep(4 * time.Second)
	default:
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"argv": os.Args[1:], "home": os.Getenv("HOME"), "path": os.Getenv("PATH"), "unexpected_env": os.Getenv("W3_OPERATOR_SECRET_CONTROL")})
	}
}
