//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	proxy "github.com/relux-works/swarma-chain-lab/experiments/model-proxy"
	"github.com/relux-works/swarma-chain-lab/experiments/model-proxy/service"
)

// This nonsecret mapping is admitted by the same installed-file manifest and
// ownership boundary as the gateway configuration. It is never worker input.
type brokerFile struct {
	Socket             string `json:"socket"`
	BrokerUID          uint32 `json:"broker_uid"`
	ServiceGeneration  string `json:"service_generation"`
	Account            string `json:"account"`
	AgentUID           uint32 `json:"agent_uid"`
	AgentGeneration    string `json:"agent_generation"`
	LaunchID           string `json:"launch_id"`
	MaxLifetimeSeconds uint64 `json:"max_lifetime_seconds"`
}

var _ proxy.ManagedSource = (*service.Source)(nil)

const managedPollInterval = time.Second
const managedCheckInterval = managedPollInterval / 4
const managedIOTimeout = managedPollInterval / 4

type managedSession struct {
	client    *service.Client
	source    *service.Source
	authority context.Context
	cancel    context.CancelFunc
	watchdog  *time.Timer
	prefix    string
	version   string
	renewAt   time.Time
}

type managedHolder struct {
	mu      sync.Mutex
	config  brokerFile
	ctx     context.Context
	stop    context.CancelFunc
	done    chan struct{}
	session *managedSession
	serial  uint64
	started bool
	blocked bool
}

func (*managedHolder) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("<managed-holder>"))
}

func managedSource(ctx context.Context, raw []byte) (proxy.CredentialSource, func(), error) {
	var c brokerFile
	if len(raw) == 0 || len(raw) > proxy.MaxBody || json.Unmarshal(raw, &c) != nil {
		return nil, nil, errors.New("CREDENTIAL_SOURCE")
	}
	canonical, e := json.Marshal(c)
	if e != nil || !bytes.Equal(bytes.TrimSpace(raw), canonical) || c.MaxLifetimeSeconds == 0 || c.MaxLifetimeSeconds > 900 {
		return nil, nil, errors.New("CREDENTIAL_SOURCE")
	}
	lifetime, stop := context.WithCancel(context.Background())
	holder := &managedHolder{config: c, ctx: lifetime, stop: stop, done: make(chan struct{})}
	if e := holder.connect(ctx); e != nil {
		stop()
		return nil, nil, errors.New("CREDENTIAL_SOURCE")
	}
	adapted, e := proxy.AdaptManagedSource(holder)
	if e != nil {
		holder.invalidate(e)
		stop()
		return nil, nil, errors.New("CREDENTIAL_SOURCE")
	}
	go holder.supervise()
	return adapted, holder.close, nil
}

func (holder *managedHolder) connect(ctx context.Context) error {
	config := holder.config
	call, cancel := context.WithTimeout(ctx, managedIOTimeout)
	defer cancel()
	client, err := service.Dial(call, service.Config{Socket: config.Socket, BrokerUID: config.BrokerUID, ServiceUID: uint32(os.Geteuid()), Generation: config.ServiceGeneration, MaxLifetime: time.Duration(config.MaxLifetimeSeconds) * time.Second})
	if err != nil {
		return err
	}
	source, err := service.NewSource(client, service.Caller{Account: config.Account, UID: config.AgentUID, Generation: config.AgentGeneration, LaunchID: config.LaunchID})
	if err != nil {
		client.Close()
		return err
	}
	holder.serial++
	authority, cancelAuthority := context.WithCancel(holder.ctx)
	holder.session = &managedSession{client: client, source: source, authority: authority, cancel: cancelAuthority, prefix: fmt.Sprintf("session-%d/", holder.serial)}
	return nil
}

func (holder *managedHolder) invalidate(err error) {
	if err == service.Code("account_hold_active") || err == service.Code("account_hold_unknown") {
		holder.blocked = true
	}
	if session := holder.session; session != nil {
		session.cancel()
		if session.watchdog != nil {
			session.watchdog.Stop()
		}
		session.client.Close()
		holder.session = nil
	}
}

func (holder *managedHolder) value(ctx context.Context, renew bool, rejected string) (string, []byte, string, error) {
	session := holder.session
	if holder.blocked || holder.ctx.Err() != nil || session == nil {
		return "", nil, "", service.ErrInactive
	}
	if session.authority.Err() != nil {
		holder.invalidate(service.ErrInactive)
		return "", nil, "", service.ErrInactive
	}
	call, cancel := context.WithTimeout(ctx, managedIOTimeout)
	defer cancel()
	var scheme, version string
	var material []byte
	var err error
	if renew {
		if !strings.HasPrefix(rejected, session.prefix) {
			return "", nil, "", service.ErrInactive
		}
		scheme, material, version, err = session.source.RenewValue(call, strings.TrimPrefix(rejected, session.prefix))
	} else {
		scheme, material, version, err = session.source.CredentialValue(call)
	}
	if err != nil || session.authority.Err() != nil || holder.ctx.Err() != nil {
		clear(material)
		holder.invalidate(err)
		return "", nil, "", service.ErrInactive
	}
	if session.watchdog == nil {
		session.watchdog = time.AfterFunc(managedPollInterval, session.cancel)
	} else {
		session.watchdog.Reset(managedPollInterval)
	}
	if renew || session.version == "" {
		interval := min(time.Duration(holder.config.MaxLifetimeSeconds)*time.Second/3, managedPollInterval/2)
		session.renewAt = time.Now().Add(interval)
	}
	session.version = session.prefix + version
	return scheme, material, session.version, nil
}

func (holder *managedHolder) CredentialValue(ctx context.Context) (string, []byte, string, error) {
	if ctx == nil {
		return "", nil, "", service.ErrInput
	}
	holder.mu.Lock()
	defer holder.mu.Unlock()
	holder.started = true
	return holder.value(context.WithoutCancel(ctx), false, "")
}

func (holder *managedHolder) RenewValue(ctx context.Context, rejected string) (string, []byte, string, error) {
	if ctx == nil {
		return "", nil, "", service.ErrInput
	}
	holder.mu.Lock()
	defer holder.mu.Unlock()
	return holder.value(context.WithoutCancel(ctx), true, rejected)
}

func (holder *managedHolder) CredentialContext(ctx context.Context, version string) (context.Context, context.CancelFunc) {
	call, cancel := context.WithCancel(ctx)
	holder.mu.Lock()
	defer holder.mu.Unlock()
	session := holder.session
	if session == nil || session.authority.Err() != nil || !strings.HasPrefix(version, session.prefix) {
		cancel()
		return call, cancel
	}
	stop := context.AfterFunc(session.authority, cancel)
	return call, func() { stop(); cancel() }
}

func (holder *managedHolder) supervise() {
	defer close(holder.done)
	ticker := time.NewTicker(managedCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-holder.ctx.Done():
			return
		case <-ticker.C:
			holder.mu.Lock()
			if holder.started && !holder.blocked {
				if holder.session == nil {
					_ = holder.connect(holder.ctx)
				}
				if session := holder.session; session != nil {
					renew := session.version != "" && !time.Now().Before(session.renewAt)
					_, material, _, _ := holder.value(holder.ctx, renew, session.version)
					clear(material)
				}
			}
			holder.mu.Unlock()
		}
	}
}

func (holder *managedHolder) close() {
	holder.stop()
	<-holder.done
	holder.mu.Lock()
	defer holder.mu.Unlock()
	if session := holder.session; session != nil {
		session.cancel()
		ctx, cancel := context.WithTimeout(context.Background(), managedIOTimeout)
		_ = session.source.Close(ctx)
		cancel()
		holder.invalidate(service.ErrInactive)
	}
}
