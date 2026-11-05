// Package store provides the shared state primitives used by the scorer and
// the ban manager. Two implementations with identical semantics exist:
// Memory (single agent) and Redis (multiple agents sharing state).
//
// All keys are created with a TTL on first write (fixed window semantics).
package store

import (
	"context"
	"time"
)

type Store interface {
	// SAddCard adds member to the set at key (TTL set on creation) and returns the set size.
	SAddCard(ctx context.Context, key, member string, ttl time.Duration) (int, error)
	// SMembers returns all members of the set.
	SMembers(ctx context.Context, key string) ([]string, error)
	// Incr increments the counter at key (TTL set on creation) and returns the new value.
	Incr(ctx context.Context, key string, ttl time.Duration) (int, error)
	// Get returns the counter at key (0 if missing).
	GetInt(ctx context.Context, key string) (int, error)
	// SetFlag sets key with ttl; Flag reports whether it exists.
	SetFlag(ctx context.Context, key string, ttl time.Duration) error
	Flag(ctx context.Context, key string) (bool, error)
	Del(ctx context.Context, keys ...string) error
	// ScoreAdd applies exponential decay (half-life) to the score at key, adds
	// delta and returns the result. delta=0 reads the decayed score.
	ScoreAdd(ctx context.Context, key string, delta float64, halfLife, ttl time.Duration) (float64, error)
	// RequestStep is the per-request hot path in ONE round trip: increment the
	// request counter rqKey (window TTL), add delta to the decayed score at
	// scoreKey and, if setKey != "", add member to that set. Returns the score
	// and the set size.
	RequestStep(ctx context.Context, rqKey, scoreKey string, delta float64, halfLife, scoreTTL, window time.Duration, setKey, member string) (float64, int, error)

	// Bans: ip -> expiry.
	PutBan(ctx context.Context, ip string, until time.Time) error
	DelBan(ctx context.Context, ip string) error
	Bans(ctx context.Context) (map[string]time.Time, error)

	Close() error
}
