package service

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	check "github.com/relux-works/swarma-chain-lab/experiments/notary-checker"
)

// Claim: regular 0600 keys and credentials load; a FIFO in either position
// refuses promptly with the exact custody error and no partial service.
func TestPrivateFileFIFORefusal(t *testing.T) {
	for _, kind := range []string{"key", "credential"} {
		t.Run(kind, func(t *testing.T) {
			s, _, _ := setup(t) // positive: both regular files loaded by Load
			if _, err := check.NewNodeNameReader(s.config.RPCEndpoint, s.config.RPCCredentialFile); err != nil {
				t.Fatal("regular credential", err)
			}
			k, err := loadKey(s.config.KeyFile)
			if err != nil {
				t.Fatal("regular key", err)
			}
			k.Zero()
			fifo := filepath.Join(t.TempDir(), "fifo")
			if err := syscall.Mkfifo(fifo, 0600); err != nil {
				t.Fatal(err)
			}
			c := s.config
			want := "KEY_FILE"
			if kind == "key" {
				c.KeyFile = fifo
			} else {
				c.RPCCredentialFile = fifo
				want = "NODE_CREDENTIALS"
			}
			path := filepath.Join(t.TempDir(), "config")
			put(t, path, encode(t, c))
			done := make(chan error, 1)
			go func() {
				got, err := Load(path)
				if got != nil {
					got.Close()
				}
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil || err.Error() != want {
					t.Fatalf("want %s, got %v", want, err)
				}
			case <-time.After(time.Second):
				// Release only this fixture's blocked open, including under the mutant.
				w, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer w.Close()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("fixture did not release")
				}
				t.Fatal("FIFO open did not refuse promptly")
			}
		})
	}
}

// Claim: regular configuration and policy load; a FIFO in either position
// refuses promptly with the exact custody error and no partial service.
func TestOperatorFileFIFORefusal(t *testing.T) {
	for _, kind := range []string{"config", "policy"} {
		t.Run(kind, func(t *testing.T) {
			s, _, _ := setup(t) // positive: both regular files loaded by Load
			fifo := filepath.Join(t.TempDir(), "fifo")
			if err := syscall.Mkfifo(fifo, 0600); err != nil {
				t.Fatal(err)
			}
			c := s.config
			path := filepath.Join(t.TempDir(), "config")
			want := "CONFIG"
			if kind == "config" {
				path = fifo
			} else {
				c.DeploymentPolicyFile = fifo
				put(t, path, encode(t, c))
				want = "POLICY_FILE"
			}
			done := make(chan error, 1)
			go func() {
				got, err := Load(path)
				if got != nil {
					got.Close()
				}
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil || err.Error() != want {
					t.Fatalf("want %s, got %v", want, err)
				}
			case <-time.After(time.Second):
				// Release only this fixture's blocked open, including under the mutant.
				w, err := os.OpenFile(fifo, os.O_RDWR|syscall.O_NONBLOCK, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer w.Close()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("fixture did not release")
				}
				t.Fatal("FIFO open did not refuse promptly")
			}
		})
	}
}
