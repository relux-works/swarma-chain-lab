package grantstore

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
)

// Version 2 stores [event ID, expiration, signer] tuples. IDs and keys use
// unpadded base64url; decimal expiration remains exact. At most 512 tuples,
// each at most 115 bytes plus a comma, fit the reused 64 KiB durable writer.
// An empty signer denotes a preserved v1 entry, never a newly reserved event.
type replayDisk struct {
	Version  int         `json:"version"`
	LastTime int64       `json:"last_time"`
	Entries  [][3]string `json:"entries"`
}

func packReplayHex(v string) (string, error) {
	if v == "" {
		return "", nil
	}
	if !digest(v) {
		return "", errStorage
	}
	b, _ := hex.DecodeString(v)
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func unpackReplayHex(v string) (string, error) {
	if v == "" {
		return "", nil
	}
	b, e := base64.RawURLEncoding.Strict().DecodeString(v)
	if e != nil || len(b) != 32 {
		return "", errStorage
	}
	return hex.EncodeToString(b), nil
}
func encodeReplay(s replayState) ([]byte, error) {
	d := replayDisk{Version: 2, LastTime: s.LastTime, Entries: [][3]string{}}
	if s.Version != 2 || s.LastTime < 0 || len(s.Entries) > 512 {
		return nil, errStorage
	}
	for _, v := range s.Entries {
		id, e := packReplayHex(v.ID)
		if e != nil || id == "" || v.Expiry < 0 {
			return nil, errStorage
		}
		pub, e := packReplayHex(v.PubKey)
		if e != nil {
			return nil, e
		}
		d.Entries = append(d.Entries, [3]string{id, strconv.FormatInt(v.Expiry, 10), pub})
	}
	b, e := json.Marshal(d)
	if e != nil || len(b) > 65536 {
		return nil, errStorage
	}
	return b, nil
}
func decodeReplay(raw []byte) (replayState, error) {
	var d replayDisk
	if canonical(raw, &d) && d.Version == 2 && d.Entries != nil {
		s := replayState{Version: 2, LastTime: d.LastTime, Entries: []replayEntry{}}
		for _, v := range d.Entries {
			id, e := unpackReplayHex(v[0])
			if e != nil || id == "" {
				return replayState{}, errStorage
			}
			pub, e := unpackReplayHex(v[2])
			if e != nil {
				return replayState{}, errStorage
			}
			expiry, e := strconv.ParseInt(v[1], 10, 64)
			if e != nil || strconv.FormatInt(expiry, 10) != v[1] {
				return replayState{}, errStorage
			}
			s.Entries = append(s.Entries, replayEntry{ID: id, Expiry: expiry, PubKey: pub})
		}
		return s, nil
	}
	// Legacy entries have no signer. Keep their IDs, expiration and high-water;
	// charge their slots globally until natural expiry, without guessing owners.
	var legacy replayState
	if !canonical(raw, &legacy) || legacy.Version != 1 {
		return replayState{}, errStorage
	}
	for _, v := range legacy.Entries {
		if v.PubKey != "" {
			return replayState{}, errStorage
		}
	}
	legacy.Version = 2
	return legacy, nil
}
