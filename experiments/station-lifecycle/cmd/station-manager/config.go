//go:build !darwin || !slotdfake

package main

type config struct {
	StateDir          string `json:"state_dir"`
	Socket            string `json:"slotd_socket"`
	SlotMin           uint16 `json:"slot_min"`
	SlotMax           uint16 `json:"slot_max"`
	PayloadID         string `json:"payload_id"`
	PayloadSHA256     string `json:"payload_sha256"`
	Endpoint          string `json:"gateway_endpoint"`
	GatewayCertSHA256 string `json:"gateway_cert_sha256"`
	ClientCert        string `json:"client_cert"`
	ClientKey         string `json:"client_key"`
	ServerCA          string `json:"server_ca"`
}
