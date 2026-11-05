package store

import (
	"context"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// Redis is a Store shared by several Bima agents. Every primitive is a single
// round trip (Lua scripts make read-modify-write operations atomic).
type Redis struct {
	c      *redis.Client
	prefix string
}

func NewRedis(addr, password string, db int, prefix string, attempts int) (*Redis, error) {
	c := redis.NewClient(&redis.Options{
		Addr: addr, Password: password, DB: db,
		DialTimeout: 100 * time.Millisecond, ReadTimeout: 50 * time.Millisecond, WriteTimeout: 50 * time.Millisecond,
		PoolTimeout: 50 * time.Millisecond, MaxRetries: -1, PoolSize: 128, MinIdleConns: 8,
	})
	var err error
	for i := 0; i < max(attempts, 1); i++ { // redis may start after us
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err = c.Ping(ctx).Err()
		cancel()
		if err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		return nil, err
	}
	if prefix == "" {
		prefix = "bima:"
	}
	return &Redis{c: c, prefix: prefix}, nil
}

func (r *Redis) k(key string) string { return r.prefix + key }

var saddCard = redis.NewScript(`
local added = redis.call('SADD', KEYS[1], ARGV[1])
if redis.call('PTTL', KEYS[1]) < 0 then redis.call('PEXPIRE', KEYS[1], ARGV[2]) end
return redis.call('SCARD', KEYS[1])`)

var incrTTL = redis.NewScript(`
local v = redis.call('INCR', KEYS[1])
if v == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
return v`)

// score hash: v = value, t = unix millis of last update
var scoreAdd = redis.NewScript(`
local now = tonumber(ARGV[1])
local delta = tonumber(ARGV[2])
local half = tonumber(ARGV[3])
local ttl = tonumber(ARGV[4])
local cur = redis.call('HMGET', KEYS[1], 'v', 't')
local v = tonumber(cur[1]) or 0
local t = tonumber(cur[2]) or now
if v > 0 and now > t then
  v = v * math.pow(0.5, (now - t) / half)
  v = math.floor(v * 10 + 0.5) / 10
  if v < 0.5 then v = 0 end
end
v = v + delta
redis.call('HSET', KEYS[1], 'v', tostring(v), 't', now)
redis.call('PEXPIRE', KEYS[1], ttl)
return tostring(v)`)

var requestStep = redis.NewScript(`
local now, delta, half = tonumber(ARGV[1]), tonumber(ARGV[2]), tonumber(ARGV[3])
local sttl, win, member = tonumber(ARGV[4]), tonumber(ARGV[5]), ARGV[6]
if redis.call('INCR', KEYS[1]) == 1 then redis.call('PEXPIRE', KEYS[1], win) end
local cur = redis.call('HMGET', KEYS[2], 'v', 't')
local v = tonumber(cur[1]) or 0
local t = tonumber(cur[2]) or now
if v > 0 and now > t then
  v = v * math.pow(0.5, (now - t) / half)
  v = math.floor(v * 10 + 0.5) / 10
  if v < 0.5 then v = 0 end
end
v = v + delta
if v > 0 or cur[1] then
  redis.call('HSET', KEYS[2], 'v', tostring(v), 't', now)
  redis.call('PEXPIRE', KEYS[2], sttl)
end
local n = 0
if member ~= '' then
  redis.call('SADD', KEYS[3], member)
  if redis.call('PTTL', KEYS[3]) < 0 then redis.call('PEXPIRE', KEYS[3], win) end
  n = redis.call('SCARD', KEYS[3])
end
return {tostring(v), n}`)

func (r *Redis) RequestStep(ctx context.Context, rqKey, scoreKey string, delta float64, halfLife, scoreTTL, window time.Duration, setKey, member string) (float64, int, error) {
	sk := r.k(setKey)
	if setKey == "" {
		sk, member = r.k("_"), ""
	}
	res, err := requestStep.Run(ctx, r.c, []string{r.k(rqKey), r.k(scoreKey), sk},
		time.Now().UnixMilli(), strconv.FormatFloat(delta, 'f', -1, 64), halfLife.Milliseconds(),
		scoreTTL.Milliseconds(), window.Milliseconds(), member).Slice()
	if err != nil {
		return 0, 0, err
	}
	v, _ := strconv.ParseFloat(res[0].(string), 64)
	return v, int(res[1].(int64)), nil
}

func (r *Redis) SAddCard(ctx context.Context, key, member string, ttl time.Duration) (int, error) {
	n, err := saddCard.Run(ctx, r.c, []string{r.k(key)}, member, ttl.Milliseconds()).Int()
	return n, err
}

func (r *Redis) SMembers(ctx context.Context, key string) ([]string, error) {
	return r.c.SMembers(ctx, r.k(key)).Result()
}

func (r *Redis) Incr(ctx context.Context, key string, ttl time.Duration) (int, error) {
	return incrTTL.Run(ctx, r.c, []string{r.k(key)}, ttl.Milliseconds()).Int()
}

func (r *Redis) GetInt(ctx context.Context, key string) (int, error) {
	v, err := r.c.Get(ctx, r.k(key)).Int()
	if err == redis.Nil {
		return 0, nil
	}
	return v, err
}

func (r *Redis) SetFlag(ctx context.Context, key string, ttl time.Duration) error {
	return r.c.Set(ctx, r.k(key), 1, ttl).Err()
}

func (r *Redis) Flag(ctx context.Context, key string) (bool, error) {
	n, err := r.c.Exists(ctx, r.k(key)).Result()
	return n > 0, err
}

func (r *Redis) Del(ctx context.Context, keys ...string) error {
	full := make([]string, len(keys))
	for i, k := range keys {
		full[i] = r.k(k)
	}
	return r.c.Del(ctx, full...).Err()
}

func (r *Redis) ScoreAdd(ctx context.Context, key string, delta float64, halfLife, ttl time.Duration) (float64, error) {
	s, err := scoreAdd.Run(ctx, r.c, []string{r.k(key)},
		time.Now().UnixMilli(), strconv.FormatFloat(delta, 'f', -1, 64), halfLife.Milliseconds(), ttl.Milliseconds()).Text()
	if err != nil {
		return 0, err
	}
	return strconv.ParseFloat(s, 64)
}

// Bans live in a sorted set (score = expiry unix seconds) so all agents see
// the same list and expired entries are pruned atomically.
func (r *Redis) PutBan(ctx context.Context, ip string, until time.Time) error {
	return r.c.ZAdd(ctx, r.k("bans"), redis.Z{Score: float64(until.Unix()), Member: ip}).Err()
}

func (r *Redis) DelBan(ctx context.Context, ip string) error {
	return r.c.ZRem(ctx, r.k("bans"), ip).Err()
}

func (r *Redis) Bans(ctx context.Context) (map[string]time.Time, error) {
	now := time.Now().Unix()
	pipe := r.c.TxPipeline()
	pipe.ZRemRangeByScore(ctx, r.k("bans"), "-inf", strconv.FormatInt(now, 10))
	res := pipe.ZRangeWithScores(ctx, r.k("bans"), 0, -1)
	if _, err := pipe.Exec(ctx); err != nil {
		return nil, err
	}
	out := map[string]time.Time{}
	for _, z := range res.Val() {
		out[z.Member.(string)] = time.Unix(int64(z.Score), 0)
	}
	return out, nil
}

func (r *Redis) Close() error { return r.c.Close() }
