package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"relux.works/swarma-chain-lab/experiments/rental-gateway/stationlink"
)

// runStationStub is the scripted agent for the local-test driver. It
// dials the gateway itself (station-initiated), echoes deliveries as
// replies, and understands two trigger contents used by controls:
// "__end_early__" asks to end; "__extend__" attempts an extension
// (the gateway must refuse) and replies with the refusal frame type.
func runStationStub() error {
	sock := os.Getenv("GATEWAY_SOCKET")
	slotID := os.Getenv("SLOT_ID")
	stationName := os.Getenv("STATION_NAME")
	secretFile := os.Getenv("CHANNEL_SECRET_FILE")
	if sock == "" || slotID == "" || stationName == "" || secretFile == "" {
		return fmt.Errorf("station-stub: GATEWAY_SOCKET, SLOT_ID, STATION_NAME and CHANNEL_SECRET_FILE are required")
	}
	secretRaw, err := os.ReadFile(secretFile)
	if err != nil {
		return fmt.Errorf("station-stub: channel secret: %w", err)
	}
	secret, err := hex.DecodeString(strings.TrimSpace(string(secretRaw)))
	if err != nil || len(secret) != stationlink.ChannelSecretBytes {
		return fmt.Errorf("station-stub: channel secret malformed")
	}
	// Stations must tolerate the gateway not listening yet (process
	// start order, gateway restart): retry the dial briefly.
	var conn net.Conn
	deadline := time.Now().Add(10 * time.Second)
	for {
		var err error
		conn, err = net.Dial("unix", sock)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
	defer conn.Close()
	client := stationlink.NewClient(conn)
	sys, err := client.Hello(slotID, stationName, secret)
	if err != nil {
		return err
	}
	if sys.Type != stationlink.TypeSystem {
		return fmt.Errorf("station-stub: hello refused: %s %s", sys.Type, sys.Reason)
	}
	for {
		frame, err := client.Pull()
		if err != nil {
			return err
		}
		switch frame.Type {
		case stationlink.TypeDeliver:
			switch frame.Content {
			case "__end_early__":
				end, err := client.EndEarly()
				if err != nil {
					return err
				}
				if end.Type == stationlink.TypeEnd {
					return nil
				}
				return fmt.Errorf("station-stub: end_early answered %s", end.Type)
			case "__extend__":
				ext, err := client.Extend()
				if err != nil {
					return err
				}
				if _, err := client.Reply("extend answered: " + ext.Type); err != nil {
					return err
				}
			default:
				if _, err := client.Reply("echo: " + frame.Content); err != nil {
					return err
				}
			}
		case stationlink.TypeNotice, stationlink.TypeNone:
			continue
		case stationlink.TypeEnd:
			return nil
		default:
			return fmt.Errorf("station-stub: unexpected frame %s", frame.Type)
		}
	}
}
