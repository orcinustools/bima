package store

import (
	"context"
	"encoding/json"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type entry struct {
	set     map[string]struct{}
	n       int
	score   float64
	at      time.Time // score timestamp
	expires time.Time
}

// Memory is an in-process Store. Bans are optionally persisted to a JSON file
// so they survive agent restarts.
type Memory struct {
	mu      sync.Mutex
	m       map[string]*entry
	bans    map[string]time.Time
	banFile string
	now     func() time.Time
}

func NewMemory(banFile string) *Memory {
	s := &Memory{m: map[string]*entry{}, bans: map[string]time.Time{}, banFile: banFile, now: time.Now}
	if banFile != "" {
		if b, err := os.ReadFile(banFile); err == nil {
			var saved map[string]time.Time
			if json.Unmarshal(b, &saved) == nil {
				now := s.now()
				for ip, t := range saved {
					if t.After(now) {
						s.bans[ip] = t
					}
				}
				slog.Info("restored bans from state file", "file", banFile, "count", len(s.bans))
			}
		}
	}
	go s.janitor()
	return s
}

func (s *Memory) get(key string, ttl time.Duration, create bool) *entry {
	now := s.now()
	e := s.m[key]
	if e != nil && now.After(e.expires) {
		delete(s.m, key)
		e = nil
	}
	if e == nil && create {
		e = &entry{expires: now.Add(ttl), at: now}
		s.m[key] = e
	}
	return e
}

func (s *Memory) SAddCard(_ context.Context, key, member string, ttl time.Duration) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.get(key, ttl, true)
	if e.set == nil {
		e.set = map[string]struct{}{}
	}
	e.set[member] = struct{}{}
	return len(e.set), nil
}

func (s *Memory) SMembers(_ context.Context, key string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.get(key, 0, false)
	if e == nil {
		return nil, nil
	}
	out := make([]string, 0, len(e.set))
	for m := range e.set {
		out = append(out, m)
	}
	return out, nil
}

func (s *Memory) Incr(_ context.Context, key string, ttl time.Duration) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.get(key, ttl, true)
	e.n++
	return e.n, nil
}

func (s *Memory) GetInt(_ context.Context, key string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.get(key, 0, false); e != nil {
		return e.n, nil
	}
	return 0, nil
}

func (s *Memory) SetFlag(_ context.Context, key string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[key] = &entry{expires: s.now().Add(ttl)}
	return nil
}

func (s *Memory) Flag(_ context.Context, key string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.get(key, 0, false) != nil, nil
}

func (s *Memory) Del(_ context.Context, keys ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range keys {
		delete(s.m, k)
	}
	return nil
}

func (s *Memory) ScoreAdd(_ context.Context, key string, delta float64, halfLife, ttl time.Duration) (float64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	e := s.get(key, ttl, true)
	if dt := now.Sub(e.at); dt > 0 && e.score > 0 {
		e.score = decay(e.score, dt, halfLife)
	}
	e.at = now
	e.score += delta
	e.expires = now.Add(ttl) // sliding expiry for scores
	return e.score, nil
}

func (s *Memory) RequestStep(ctx context.Context, rqKey, scoreKey string, delta float64, halfLife, scoreTTL, window time.Duration, setKey, member string) (float64, int, error) {
	_, _ = s.Incr(ctx, rqKey, window)
	score, _ := s.ScoreAdd(ctx, scoreKey, delta, halfLife, scoreTTL)
	n := 0
	if setKey != "" {
		n, _ = s.SAddCard(ctx, setKey, member, window)
	}
	return score, n, nil
}

func decay(v float64, dt, halfLife time.Duration) float64 {
	v *= math.Pow(0.5, float64(dt)/float64(halfLife))
	v = math.Round(v*10) / 10 // avoid 80 -> 79.9999 flapping across thresholds
	if v < 0.5 {
		v = 0
	}
	return v
}

func (s *Memory) PutBan(_ context.Context, ip string, until time.Time) error {
	s.mu.Lock()
	s.bans[ip] = until
	s.mu.Unlock()
	return s.persist()
}

func (s *Memory) DelBan(_ context.Context, ip string) error {
	s.mu.Lock()
	delete(s.bans, ip)
	s.mu.Unlock()
	return s.persist()
}

func (s *Memory) Bans(_ context.Context) (map[string]time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	out := make(map[string]time.Time, len(s.bans))
	for ip, t := range s.bans {
		if t.After(now) {
			out[ip] = t
		}
	}
	return out, nil
}

func (s *Memory) persist() error {
	if s.banFile == "" {
		return nil
	}
	s.mu.Lock()
	b, err := json.Marshal(s.bans)
	s.mu.Unlock()
	if err != nil {
		return err
	}
	tmp := s.banFile + ".tmp"
	if err := os.MkdirAll(filepath.Dir(s.banFile), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.banFile)
}

func (s *Memory) janitor() {
	t := time.NewTicker(30 * time.Second)
	for range t.C {
		s.mu.Lock()
		now := s.now()
		for k, e := range s.m {
			if now.After(e.expires) {
				delete(s.m, k)
			}
		}
		for ip, until := range s.bans {
			if now.After(until) {
				delete(s.bans, ip)
			}
		}
		s.mu.Unlock()
	}
}

func (s *Memory) Close() error { return s.persist() }
