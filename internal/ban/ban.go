// Package ban maintains temporary IP bans. The source of truth is the state
// store (file-backed memory or Redis); a reconcile loop keeps the blocklist map
// of every configured HAProxy instance in sync with it via the Runtime API.
package ban

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/orcinustools/bima/internal/store"
)

type runtimeAPI struct{ network, addr string }

type Manager struct {
	apis    []runtimeAPI
	mapFile string
	ladder  []time.Duration
	enabled bool
	st      store.Store

	mu    sync.RWMutex
	cache map[string]time.Time

	Reconciles, APIErrors atomic.Uint64

	// OnChange, if set, is called after a ban is placed or lifted here
	// (e.g. to push bans to a Cloudflare IP list right away).
	OnChange func()
}

func (m *Manager) changed() {
	if m.OnChange != nil {
		m.OnChange()
	}
}

func New(st store.Store, runtimeAPIs []string, mapFile string, ladder []time.Duration, enabled bool) (*Manager, error) {
	m := &Manager{st: st, mapFile: mapFile, ladder: ladder, enabled: enabled, cache: map[string]time.Time{}}
	for _, a := range runtimeAPIs {
		network, addr, ok := strings.Cut(a, ":")
		if !ok || (network != "tcp" && network != "unix") {
			return nil, fmt.Errorf("runtime api must be tcp:host:port or unix:/path, got %q", a)
		}
		m.apis = append(m.apis, runtimeAPI{network, addr})
	}
	return m, nil
}

// Run reconciles store -> HAProxy maps every interval until ctx is done.
func (m *Manager) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		m.Reconcile()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Reconcile refreshes the local ban cache from the store and makes every
// HAProxy map match it (adds missing bans, removes expired/foreign entries).
func (m *Manager) Reconcile() {
	c, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	bans, err := m.st.Bans(c)
	if err != nil {
		slog.Warn("ban store read failed; keeping cached bans", "err", err)
		return
	}
	m.mu.Lock()
	m.cache = bans
	m.mu.Unlock()
	m.Reconciles.Add(1)
	if !m.enabled {
		return
	}
	for _, api := range m.apis {
		inMap, err := m.mapEntries(api)
		if err != nil {
			m.APIErrors.Add(1)
			slog.Debug("runtime api unreachable", "api", api.addr, "err", err)
			continue
		}
		for ip, until := range bans {
			if _, ok := inMap[ip]; !ok {
				if _, err := m.cmd(api, fmt.Sprintf("add map %s %s %d", m.mapFile, ip, until.Unix())); err != nil {
					m.APIErrors.Add(1)
					slog.Warn("add map failed", "api", api.addr, "ip", ip, "err", err)
				} else {
					slog.Info("ban synced to haproxy", "api", api.addr, "ip", ip)
				}
			}
		}
		for ip := range inMap {
			if _, ok := bans[ip]; !ok {
				if _, err := m.cmd(api, fmt.Sprintf("del map %s %s", m.mapFile, ip)); err != nil {
					m.APIErrors.Add(1)
				} else {
					slog.Info("ban lifted", "api", api.addr, "ip", ip)
				}
			}
		}
	}
}

func (m *Manager) mapEntries(api runtimeAPI) (map[string]struct{}, error) {
	out, err := m.cmd(api, "show map "+m.mapFile)
	if err != nil {
		return nil, err
	}
	entries := map[string]struct{}{}
	for line := range strings.SplitSeq(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && strings.HasPrefix(f[0], "0x") {
			entries[f[1]] = struct{}{}
		}
	}
	return entries, nil
}

// IsBanned reports whether ip is banned (local cache, refreshed by Reconcile).
func (m *Manager) IsBanned(ip string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.cache[ip]
	return ok && time.Now().Before(t)
}

// Ban bans ip for the ladder duration at level. Returns the duration and
// whether a new ban was placed. The HAProxy maps are updated immediately.
func (m *Manager) Ban(ip string, level int) (time.Duration, bool, error) {
	if level >= len(m.ladder) {
		level = len(m.ladder) - 1
	}
	d := m.ladder[level]
	if m.IsBanned(ip) {
		return d, false, nil
	}
	until := time.Now().Add(d)
	c, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := m.st.PutBan(c, ip, until); err != nil {
		slog.Error("ban store write failed", "ip", ip, "err", err)
	}
	m.mu.Lock()
	m.cache[ip] = until
	m.mu.Unlock()
	m.changed()
	if !m.enabled {
		return d, true, nil
	}
	var firstErr error
	for _, api := range m.apis {
		_, _ = m.cmd(api, fmt.Sprintf("del map %s %s", m.mapFile, ip))
		if _, err := m.cmd(api, fmt.Sprintf("add map %s %s %d", m.mapFile, ip, until.Unix())); err != nil {
			m.APIErrors.Add(1)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return d, true, firstErr
}

func (m *Manager) Unban(ip string) error {
	c, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := m.st.DelBan(c, ip)
	m.mu.Lock()
	delete(m.cache, ip)
	m.mu.Unlock()
	m.changed()
	for _, api := range m.apis {
		_, _ = m.cmd(api, fmt.Sprintf("del map %s %s", m.mapFile, ip))
	}
	return err
}

func (m *Manager) Active() map[string]time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]time.Time, len(m.cache))
	now := time.Now()
	for k, v := range maps.All(m.cache) {
		if v.After(now) {
			out[k] = v
		}
	}
	return out
}

// Exec runs one Runtime API command against "unix:/path" or "tcp:host:port".
func Exec(api, c string) (string, error) {
	network, addr, ok := strings.Cut(api, ":")
	if !ok || (network != "tcp" && network != "unix") {
		return "", fmt.Errorf("runtime api must be tcp:host:port or unix:/path, got %q", api)
	}
	return (&Manager{}).cmd(runtimeAPI{network, addr}, c)
}

func (m *Manager) cmd(api runtimeAPI, c string) (string, error) {
	conn, err := net.DialTimeout(api.network, api.addr, 2*time.Second)
	if err != nil {
		return "", fmt.Errorf("runtime api dial: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte(c + "\n")); err != nil {
		return "", err
	}
	var sb strings.Builder
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 64<<10), 16<<20)
	for sc.Scan() {
		sb.WriteString(sc.Text())
		sb.WriteByte('\n')
	}
	out := strings.TrimSpace(sb.String())
	low := strings.ToLower(out)
	if strings.Contains(low, "unknown") || strings.Contains(low, "error") || strings.Contains(low, "denied") {
		return out, fmt.Errorf("runtime api %q: %s", c, out)
	}
	return out, nil
}
