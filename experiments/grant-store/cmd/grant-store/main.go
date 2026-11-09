package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	store "github.com/relux-works/swarma-chain-lab/experiments/grant-store"
	"github.com/relux-works/swarma-chain-lab/experiments/rental-gateway/nostr"
	"github.com/relux-works/swarma-chain-lab/experiments/single-use/durable"
	"strings"
	"syscall"
	"time"
)

func signingKey(path string) (*nostr.PrivKey, error) {
	info, e := os.Lstat(path)
	if e != nil || !durable.PrivateRegular(info) || info.Size() != 64 {
		return nil, errors.New("key must be an owner-private 0600 file containing exactly 64 hex bytes")
	}
	f, e := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, errors.New("key unavailable")
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(info, opened) {
		return nil, errors.New("key changed")
	}
	b, e := io.ReadAll(io.LimitReader(f, 65))
	if e != nil || len(b) != 64 {
		return nil, errors.New("invalid key file")
	}
	return nostr.PrivKeyFromHex(string(b))
}
func main() {
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: grant-store serve|put|get|delete|list")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	server := fs.String("server", "", "Blossom server base URL")
	keyFile := fs.String("key", "", "0600 file containing a 64-hex signing key")
	input := fs.String("in", "", "upload file")
	out := fs.String("out", "", "download file (exclusive create)")
	hash := fs.String("hash", "", "blob hash")
	readers := fs.String("readers", "", "comma-separated reader keys")
	config := fs.String("config", "", "server JSON config")
	listen := fs.String("listen", "127.0.0.1:0", "loopback listen address")
	if e := fs.Parse(args[1:]); e != nil {
		return e
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	if args[0] == "serve" {
		host, _, e := net.SplitHostPort(*listen)
		ip := net.ParseIP(host)
		if e != nil || ip == nil || !ip.IsLoopback() {
			return errors.New("serve requires a loopback IP")
		}
		f, e := os.Open(*config)
		if e != nil {
			return errors.New("config unavailable")
		}
		defer f.Close()
		raw, e := io.ReadAll(io.LimitReader(f, 16385))
		if e != nil || len(raw) > 16384 {
			return errors.New("config too large")
		}
		var cfg store.Config
		d := json.NewDecoder(strings.NewReader(string(raw)))
		d.DisallowUnknownFields()
		if e = d.Decode(&cfg); e != nil {
			return errors.New("invalid config")
		}
		var extra any
		if d.Decode(&extra) != io.EOF {
			return errors.New("trailing config")
		}
		ln, e := net.Listen("tcp", *listen)
		if e != nil {
			return e
		}
		defer ln.Close()
		if cfg.PublicURL == "" {
			cfg.PublicURL = "http://" + ln.Addr().String()
		}
		handler, e := store.Open(cfg)
		if e != nil {
			return e
		}
		defer handler.Close()
		srv := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		done := make(chan error, 1)
		go func() { done <- srv.Serve(ln) }()
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"url": cfg.PublicURL, "pid": os.Getpid()})
		select {
		case e := <-done:
			if e != nil && !errors.Is(e, http.ErrServerClosed) {
				return e
			}
			return nil
		case <-ctx.Done():
			deadline, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return srv.Shutdown(deadline)
		}
	}
	k, e := signingKey(*keyFile)
	if e != nil {
		return e
	}
	c := &store.Client{Signer: k}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	switch args[0] {
	case "put":
		f, e := os.Open(*input)
		if e != nil {
			return errors.New("input unavailable")
		}
		defer f.Close()
		b, e := io.ReadAll(io.LimitReader(f, (1<<20)+1))
		if e != nil {
			return errors.New("input unreadable")
		}
		var ps []string
		if *readers != "" {
			ps = strings.Split(*readers, ",")
		}
		desc, e := c.Put(ctx, *server, b, ps)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(desc)
	case "get":
		if *out == "" {
			return errors.New("get requires -out")
		}
		b, e := c.Get(ctx, *server, *hash)
		if e != nil {
			return e
		}
		f, e := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return errors.New("output exists or is unavailable")
		}
		_, e = f.Write(b)
		if e == nil {
			e = f.Sync()
		}
		ce := f.Close()
		if e != nil {
			_ = os.Remove(*out)
			return e
		}
		if ce != nil {
			_ = os.Remove(*out)
		}
		return ce
	case "delete":
		return c.Delete(ctx, *server, *hash)
	case "list":
		list, e := c.List(ctx, *server)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(list)
	default:
		return errors.New("unknown command")
	}
}
