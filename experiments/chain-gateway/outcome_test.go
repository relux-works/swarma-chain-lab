package chaingateway

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// All oracles in this file model contract decisions, not operating-system or node qualification.
type qualificationInput struct {
	Platform       string   `json:"platform"`
	EndpointProof  bool     `json:"endpoint_proof"`
	DumpProtected  bool     `json:"dump_protected"`
	NodeUID        uint32   `json:"node_uid"`
	ServerUID      uint32   `json:"server_uid"`
	AllowedUIDs    []uint32 `json:"allowed_uids"`
	WorkloadUIDs   []uint32 `json:"workload_uids"`
	Dedicated      bool     `json:"dedicated"`
	InitialUser    bool     `json:"initial_user"`
	InitialNetwork bool     `json:"initial_network"`
	LoopbackBind   bool     `json:"loopback_bind"`
	LoopbackAllow  bool     `json:"loopback_allow"`
}

func qualificationOracle(q qualificationInput) bool {
	if q.Platform != "linux" || !q.EndpointProof || !q.DumpProtected {
		return false
	}
	if !q.Dedicated || !q.InitialUser || !q.InitialNetwork || !q.LoopbackBind || !q.LoopbackAllow {
		return false
	}
	if slices.Contains([]uint32{0, 65534, 65535, 4294967295}, q.NodeUID) || q.NodeUID == q.ServerUID {
		return false
	}
	return !slices.Contains(q.AllowedUIDs, q.NodeUID) && !slices.Contains(q.WorkloadUIDs, q.NodeUID)
}

type snapshotAttempt struct {
	Before      map[string]any   `json:"before,omitempty"`
	After       map[string]any   `json:"after,omitempty"`
	BeforeReply map[string]any   `json:"before_reply,omitempty"`
	AfterReply  map[string]any   `json:"after_reply,omitempty"`
	Requests    []map[string]any `json:"requests,omitempty"`
	Replies     []map[string]any `json:"replies,omitempty"`
	ReplyWires  []string         `json:"reply_wires,omitempty"`
	Bestblocks  []string         `json:"bestblocks,omitempty"`
	Failure     string           `json:"failure,omitempty"`
}

func fixtureTip() map[string]any {
	return map[string]any{"hash": strings.Repeat("1", 64), "height": json.Number("100"), "time": json.Number("1699999990")}
}

var publicationStages = []string{"lock", "lock_busy", "config", "serialize", "cleanup", "ancestor_sync", "temp_create", "temp_write", "temp_validate", "temp_metadata", "file_sync", "file_close", "rename", "directory_open", "directory_sync", "directory_close", "own_temp_cleanup"}

// Domain errors are fixture errors, never supervisor exits. Rename is an explicit stage fact.
func snapshotOutcome(config map[string]any, attempts []snapshotAttempt, stage string, renamed bool) (map[string]any, error) {
	waits := []any{}
	result := func(code int, renamed bool) map[string]any {
		previous := "unchanged"
		if renamed {
			previous = "replaced"
		}
		return map[string]any{"exit": json.Number(fmt.Sprint(code)), "write": renamed, "previous": previous, "wait_ms": waits}
	}
	if e := snapshotDomain(config, attempts, stage, renamed); e != nil {
		return nil, e
	}
	if slices.Contains([]string{"lock", "lock_busy", "config"}, stage) {
		if stage == "lock_busy" {
			return result(14, false), nil
		}
		return result(11, false), nil
	}
	byHash := map[string]map[string]any{}
	for i, a := range attempts {
		moved, limited, failed := false, false, a.Failure != ""
		tips := []map[string]any{}
		// All successful reads must match their own request and protected network.
		read := func(r, req map[string]any) {
			if response(r) != nil {
				failed = true
				return
			}
			if r["ok"] == true {
				if r["network"] != config["network"] || r["method"] != req["method"] {
					failed = true
				}
				p, s := req["params"].(map[string]any), r["result"].(map[string]any)
				switch req["method"] {
				case "name_show":
					failed = failed || p["name"] != s["name"]
				case "gettxout":
					failed = failed || p["txid"] != s["txid"] || p["vout"] != s["vout"]
				}
				tips = append(tips, r["tip"].(map[string]any))
				return
			}
			switch r["error"].(map[string]any)["code"] {
			case "tip_moved":
				moved = true
			case "rate_limited":
				limited = true
			default:
				failed = true
			}
		}
		bracketRequest := map[string]any{"method": "getblockcount", "params": map[string]any{}}
		bracket := func(at, reply map[string]any) {
			if reply != nil {
				read(reply, bracketRequest)
			} else if at != nil {
				tips = append(tips, at)
			}
		}
		bracket(a.Before, a.BeforeReply)
		openingRefused := a.BeforeReply != nil && a.BeforeReply["ok"] == false
		if !openingRefused {
			replies := responseInputs(a.Replies, a.ReplyWires)
			// Missing/duplicate/unconfigured reads are terminal, not a partial success.
			if !snapshotRequestSet(config, a.Requests) || len(replies) != len(a.Requests) {
				failed = true
			}
			for j, r := range replies {
				if j >= len(a.Requests) {
					failed = true
					continue
				}
				read(r, a.Requests[j])
			}
			bracket(a.After, a.AfterReply)
		}
		var first map[string]any
		for _, at := range tips {
			if tip(at) != nil {
				failed = true
				continue
			}
			h := str(at["hash"])
			if old, ok := byHash[h]; ok && !same(old, at) {
				failed = true
			}
			byHash[h] = at
			if first == nil {
				first = at
			} else if at["hash"] != first["hash"] {
				moved = true
			}
		}
		for _, h := range a.Bestblocks {
			if !hash(h) || first == nil {
				failed = true
			} else if h != first["hash"] {
				moved = true
			}
		}
		terminal := failed || !moved && !limited || i == 2
		if terminal && i != len(attempts)-1 {
			return nil, bad("snapshot domain: retry after terminal")
		}
		if failed {
			if renamed || stage != "" {
				return nil, bad("snapshot domain: stage without collection")
			}
			return result(11, false), nil
		}
		if !moved && !limited {
			if stage != "" {
				if renamed {
					return result(13, true), nil
				}
				return result(11, false), nil
			}
			return result(0, true), nil
		}
		if i == 2 {
			if stage != "" || renamed {
				return nil, bad("snapshot domain: stage without collection")
			}
			if limited {
				return result(11, false), nil
			}
			return result(12, false), nil
		}
		wait := 100 * (i + 1) // Inter-attempt ordinal, not count of movement events.
		if limited {
			wait = 1000
		}
		waits = append(waits, json.Number(fmt.Sprint(wait)))
	}
	return nil, bad("snapshot domain: premature exhaustion")
}

func snapshotRequestSet(config map[string]any, requests []map[string]any) bool {
	want := map[string]bool{}
	for _, n := range config["names"].([]any) {
		want[string(wire(map[string]any{"method": "name_show", "params": map[string]any{"name": n}, "v": json.Number("1")}))] = true
	}
	for _, p := range config["seals"].([]any) {
		want[string(wire(map[string]any{"method": "gettxout", "params": p, "v": json.Number("1")}))] = true
	}
	for _, r := range requests {
		k := string(wire(r))
		if !want[k] {
			return false
		}
		delete(want, k)
	}
	return len(want) == 0
}

func snapshotDomain(config map[string]any, attempts []snapshotAttempt, stage string, renamed bool) error {
	if config == nil || observationShape(observation{Kind: "collection", Config: config}) != nil {
		return bad("snapshot domain: config")
	}
	names, seals := config["names"].([]any), config["seals"].([]any)
	if len(names) > 16 || len(seals) > 256 {
		return bad("snapshot domain: config")
	}
	seen := map[string]bool{}
	for _, values := range [][]any{names, seals} {
		for _, value := range values {
			k := string(wire(value))
			if seen[k] {
				return bad("snapshot domain: config")
			}
			seen[k] = true
		}
	}
	if stage != "" && !slices.Contains(publicationStages, stage) {
		return bad("snapshot domain: stage")
	}
	if renamed != strings.HasPrefix(stage, "directory_") {
		return bad("snapshot domain: rename fact")
	}
	if slices.Contains([]string{"lock", "lock_busy", "config"}, stage) {
		if len(attempts) != 0 {
			return bad("snapshot domain: early stage attempts")
		}
		return nil
	}
	if len(attempts) < 1 || len(attempts) > 3 {
		return bad("snapshot domain: attempt count")
	}
	for _, a := range attempts {
		if !slices.Contains([]string{"", "timeout", "authentication", "platform"}, a.Failure) {
			return bad("snapshot domain: failure")
		}
		if a.Replies != nil && a.ReplyWires != nil {
			return bad("snapshot domain: reply representation")
		}
		if (a.Before == nil) == (a.BeforeReply == nil) || a.Before != nil && tip(a.Before) != nil || a.BeforeReply != nil && response(a.BeforeReply) != nil {
			return bad("snapshot domain: opening bracket")
		}
		if a.BeforeReply != nil && a.BeforeReply["ok"] == false {
			if a.After != nil || a.AfterReply != nil || len(a.Requests)+len(a.Replies)+len(a.ReplyWires)+len(a.Bestblocks) != 0 {
				return bad("snapshot domain: reads after opening refusal")
			}
		} else if (a.After == nil) == (a.AfterReply == nil) || a.After != nil && tip(a.After) != nil || a.AfterReply != nil && response(a.AfterReply) != nil {
			return bad("snapshot domain: closing bracket")
		}
		for _, r := range a.Requests {
			if request(r) != nil {
				return bad("snapshot domain: request")
			}
		}
	}
	return nil
}

// Wire inputs traverse the canonical response gate before any projection is used.
func responseInputs(objects []map[string]any, wires []string) []map[string]any {
	if wires == nil {
		return objects
	}
	out := make([]map[string]any, 0, len(wires))
	for _, w := range wires {
		if validate("response", []byte(w)) != nil {
			out = append(out, nil)
			continue
		}
		m, _ := parse([]byte(w), 4096)
		out = append(out, m)
	}
	return out
}

type reflectionInput struct {
	Mode   string `json:"mode"`
	User   string `json:"user"`
	Secret string `json:"secret"`
	Value  string `json:"value"`
}

func reflectionOracle(r reflectionInput) string {
	raw := r.User + ":" + r.Secret
	encoded := base64.StdEncoding.EncodeToString([]byte(raw))
	entries := []string{raw, encoded, "Basic " + encoded, r.Secret}
	if slices.Contains(entries, r.Value) {
		return "unavailable"
	}
	return "ok"
}

func upstreamOracle(u upstreamInput) string { return upstreamClass(u) }
