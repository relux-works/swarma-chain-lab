//go:build linux

package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"strconv"
	"syscall"
	"testing"

	"github.com/relux-works/swarma-chain-lab/deploy"
	"github.com/relux-works/swarma-chain-lab/deploy/internal/ownerid"
)

func g2OwnerCall(t *testing.T, command, path string, extra []string, resolver ownerid.Resolver, ops g2SecretOps, out io.Writer) error {
	t.Helper()
	if command == "g2-keygen" {
		return g2KeygenUsing(append([]string{"-out", path}, extra...), out, bytes.NewReader(g2TestGoodScalar("creation-owner")), resolver, ops)
	}
	_, params, public := g2OutputInputs(t)
	return g2RPCAuthUsing(append([]string{"-wallet-config-out", path, "-params", params, "-wallet-public", public}, extra...), out, bytes.NewReader(bytes.Repeat([]byte{0x41}, 144)), resolver, ops)
}

func g2OwnerEmpty(t *testing.T, f *os.File, mode os.FileMode) {
	t.Helper()
	info, err := f.Stat()
	if err != nil || info.Size() != 0 || info.Mode().Perm() != mode {
		t.Fatal("metadata must precede content on the exclusively opened 0600 file")
	}
}

// Claim: both generators resolve names/numeric IDs and call fchown then fchmod on the empty original fd before content/publication.
func TestG2OwnerMetadataBeforeContent(t *testing.T) {
	for _, command := range []string{"g2-keygen", "g2-rpcauth"} {
		for _, form := range []string{"names", "numeric"} {
			t.Run(command+"/"+form, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "secret")
				var events []string
				resolver := ownerid.Resolver{
					User: func(name string) (string, error) {
						if name != "fixture-owner" {
							t.Fatal("wrong owner")
						}
						events = append(events, "user")
						return "12345", nil
					},
					Group: func(name string) (string, error) {
						if name != "fixture-group" {
							t.Fatal("wrong group")
						}
						events = append(events, "group")
						return "23456", nil
					},
				}
				args := []string{"-owner", "fixture-owner", "-group", "fixture-group"}
				want := []string{"user", "group", "chown", "chmod", "public"}
				if form == "numeric" {
					args = []string{"-owner=12345", "--group=23456"}
					want = want[2:]
				}
				mode := os.FileMode(0640)
				if command == "g2-keygen" {
					args = append(args, "-mode", "0640")
				}
				var held *os.File
				ops := g2SecretOps{
					chown: func(f *os.File, uid, gid int) error {
						if uid != 12345 || gid != 23456 {
							t.Fatal("requested ids lost")
						}
						g2OwnerEmpty(t, f, 0600)
						linked, err := os.Lstat(path)
						opened, statErr := f.Stat()
						if err != nil || statErr != nil || !os.SameFile(opened, linked) {
							t.Fatal("chown is not on the created fd")
						}
						held = f
						events = append(events, "chown")
						return nil
					},
					chmod: func(f *os.File, m os.FileMode) error {
						if f != held || m != mode {
							t.Fatal("mode not applied to same descriptor")
						}
						g2OwnerEmpty(t, f, 0600)
						events = append(events, "chmod")
						return f.Chmod(m)
					},
				}
				out := g2OutputFunc(func(b []byte) (int, error) {
					data, err := os.ReadFile(path)
					if err != nil || len(data) == 0 {
						t.Fatal("publication before content")
					}
					clear(data)
					events = append(events, "public")
					return len(b), nil
				})
				if err := g2OwnerCall(t, command, path, args, resolver, ops, out); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(events, want) {
					t.Fatalf("creation order %v want %v", events, want)
				}
			})
		}
	}
}

// Claim: unknown accounts and lookup errors in either field refuse both generators before creation, metadata calls, or public output.
func TestG2OwnerLookupFailureBeforeCreate(t *testing.T) {
	for _, command := range []string{"g2-keygen", "g2-rpcauth"} {
		for _, field := range []string{"owner", "group"} {
			for _, failure := range []string{"unknown", "lookup-error"} {
				t.Run(command+"/"+field+"/"+failure, func(t *testing.T) {
					path := filepath.Join(t.TempDir(), "secret")
					failed := false
					lookup := func(string) (string, error) {
						failed = true
						if failure == "unknown" {
							if field == "group" {
								return "", user.UnknownGroupError("missing-fixture-group")
							}
							return "", user.UnknownUserError("missing-fixture-account")
						}
						return "", syscall.EIO
					}
					resolver := ownerid.Resolver{User: func(string) (string, error) { return "12345", nil }, Group: func(string) (string, error) { return "23456", nil }}
					if field == "owner" {
						resolver.User = lookup
					} else {
						resolver.Group = lookup
					}
					ops := g2SecretOps{chown: func(*os.File, int, int) error { t.Fatal("metadata after failed lookup"); return nil }, chmod: func(*os.File, os.FileMode) error { t.Fatal("metadata after failed lookup"); return nil }}
					var out bytes.Buffer
					err := g2OwnerCall(t, command, path, []string{"-owner", "fixture-owner", "-group", "fixture-group"}, resolver, ops, &out)
					if !failed || !errors.Is(err, deploy.ErrInput) || out.Len() != 0 {
						t.Fatal("lookup error did not refuse")
					}
					if _, err := os.Lstat(path); !os.IsNotExist(err) {
						t.Fatal("lookup failure created output")
					}
				})
			}
		}
	}
}

// Claim: EPERM at fchown or fchmod leaves no created path, content bytes, or stdout; seams model privileged-ID outcomes per fchown(2).
// https://man7.org/linux/man-pages/man2/fchown.2.html (real current-ID controls are in TestG2OwnerRealCurrentAndDefaults).
func TestG2OwnerMetadataFailureRemovesEmptyFile(t *testing.T) {
	for _, command := range []string{"g2-keygen", "g2-rpcauth"} {
		for _, at := range []string{"chown", "chmod"} {
			t.Run(command+"/"+at, func(t *testing.T) {
				dir := t.TempDir()
				path := filepath.Join(dir, "secret")
				var reader *os.File
				calls := 0
				ops := g2SecretOps{
					chown: func(f *os.File, uid, gid int) error {
						calls++
						g2OwnerEmpty(t, f, 0600)
						if uid != 12345 || gid != 23456 {
							t.Fatal("requested ids lost")
						}
						var err error
						reader, err = os.Open(path)
						if err != nil {
							t.Fatal(err)
						}
						t.Cleanup(func() { reader.Close() })
						if at == "chown" {
							return syscall.EPERM
						}
						return nil
					},
					chmod: func(f *os.File, m os.FileMode) error {
						calls++
						g2OwnerEmpty(t, f, 0600)
						if at != "chmod" {
							t.Fatal("chmod after failed chown")
						}
						return syscall.EPERM
					},
				}
				var out bytes.Buffer
				err := g2OwnerCall(t, command, path, []string{"-owner", "12345", "-group", "23456"}, ownerid.System(), ops, &out)
				wantCalls := 1
				if at == "chmod" {
					wantCalls = 2
				}
				if !errors.Is(err, deploy.ErrPolicy) || out.Len() != 0 || calls != wantCalls {
					t.Fatal("metadata failure not propagated")
				}
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatal("metadata failure left the created file")
				}
				data, err := io.ReadAll(reader)
				if err != nil || len(data) != 0 {
					t.Fatal("metadata failure wrote content to unlinked inode")
				}
				entries, err := os.ReadDir(dir)
				if err != nil {
					t.Fatal(err)
				}
				keyBytes := []byte(hex.EncodeToString(g2TestGoodScalar("creation-owner")))
				passwordBytes := bytes.Repeat([]byte("41"), 32)
				for _, entry := range entries {
					data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
					if err != nil {
						t.Fatal(err)
					}
					if bytes.Contains(data, keyBytes) || bytes.Contains(data, passwordBytes) {
						t.Fatal("metadata failure left plaintext bytes")
					}
					clear(data)
				}
			})
		}
	}
}

// Claim: metadata-failure rollback preserves a different inode at the output pathname and reports the identity refusal.
func TestG2OwnerMetadataFailurePreservesReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	ops := g2SecretSystem()
	ops.chown = func(f *os.File, uid, gid int) error {
		g2OwnerEmpty(t, f, 0600)
		if err := os.Rename(path, path+".original"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("replacement fixture"), 0600); err != nil {
			t.Fatal(err)
		}
		return syscall.EPERM
	}
	err := g2OwnerCall(t, "g2-keygen", path, []string{"-owner", "12345"}, ownerid.System(), ops, io.Discard)
	data, readErr := os.ReadFile(path)
	original, statErr := os.Stat(path + ".original")
	if !errors.Is(err, deploy.ErrPolicy) || readErr != nil || string(data) != "replacement fixture" || statErr != nil || original.Size() != 0 {
		t.Fatal("replacement or empty original changed")
	}
}

// Claim: real current-ID/name fchown succeeds, absent flags preserve ownership/modes without chown, and existing files are never adopted.
func TestG2OwnerRealCurrentAndDefaults(t *testing.T) {
	current, err := user.LookupId(strconv.Itoa(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	group, err := user.LookupGroupId(strconv.Itoa(os.Getegid()))
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"g2-keygen", "g2-rpcauth"} {
		for _, form := range []string{"names", "numeric", "owner-only", "group-only", "defaults"} {
			t.Run(command+"/"+form, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "secret")
				args := []string{"-owner", current.Username, "-group", group.Name}
				ops := g2SecretSystem()
				switch form {
				case "numeric":
					args = []string{"-owner", current.Uid, "-group", group.Gid}
				case "owner-only":
					args = []string{"-owner", current.Uid}
				case "group-only":
					args = []string{"-group", group.Gid}
				case "defaults":
					args = nil
					ops.chown = func(*os.File, int, int) error { t.Fatal("absent flags called chown"); return syscall.EPERM }
				}
				var out bytes.Buffer
				if err := g2OwnerCall(t, command, path, args, ownerid.System(), ops, &out); err != nil {
					t.Fatal(err)
				}
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				s := info.Sys().(*syscall.Stat_t)
				mode := os.FileMode(0600)
				if command == "g2-rpcauth" {
					mode = 0640
				}
				if s.Uid != uint32(os.Geteuid()) || s.Gid != uint32(os.Getegid()) || info.Mode().Perm() != mode || out.Len() == 0 {
					t.Fatal("creation identity changed")
				}
				before, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				defer clear(before)
				out.Reset()
				if err := g2OwnerCall(t, command, path, args, ownerid.System(), ops, &out); !errors.Is(err, deploy.ErrInput) || out.Len() != 0 {
					t.Fatal("existing output accepted")
				}
				after, err := os.ReadFile(path)
				defer clear(after)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("existing output changed")
				}
			})
		}
	}
}

// Claim: explicit empty, noncanonical, out-of-range, sentinel IDs and an invented RPC mode refuse without output beside valid current-ID cases.
func TestG2OwnerInvalidFlags(t *testing.T) {
	for _, command := range []string{"g2-keygen", "g2-rpcauth"} {
		for _, field := range []string{"-owner", "-group"} {
			for _, value := range []string{"", "01", "+1", "-1", "4294967295", "4294967296", " 1", "missing-fixture-account-7d43"} {
				path := filepath.Join(t.TempDir(), "secret")
				if err := g2OwnerCall(t, command, path, []string{field, value}, ownerid.System(), g2SecretSystem(), io.Discard); !errors.Is(err, deploy.ErrInput) {
					t.Fatal("invalid ID accepted")
				}
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatal("invalid ID created output")
				}
			}
		}
	}
	path := filepath.Join(t.TempDir(), "secret")
	if err := g2OwnerCall(t, "g2-rpcauth", path, []string{"-mode", "0600"}, ownerid.System(), g2SecretSystem(), io.Discard); !errors.Is(err, deploy.ErrInput) {
		t.Fatal("RPC mode invented")
	}
}
