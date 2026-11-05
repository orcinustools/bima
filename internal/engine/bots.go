package engine

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/orcinustools/bima/internal/detect"
	"github.com/orcinustools/bima/internal/metrics"
)

// Crawler verification. User-Agents claiming a well-known crawler are checked
// with reverse DNS + forward confirmation (the method the search engines
// document). Lookups run asynchronously and are cached, so the request path
// never waits on DNS: the first request from an unseen IP is "pending".

type crawler struct {
	name     string
	ua       []string // lowercase UA substrings
	suffixes []string // reverse-DNS domains; nil = cannot be verified by rDNS
}

var crawlers = []crawler{
	{"Googlebot", []string{"googlebot", "google-inspectiontool", "googleother", "adsbot-google", "mediapartners-google", "apis-google", "feedfetcher-google"}, []string{".googlebot.com", ".google.com", ".googleusercontent.com"}},
	{"Bingbot", []string{"bingbot", "msnbot", "bingpreview", "adidxbot"}, []string{".search.msn.com"}},
	{"Applebot", []string{"applebot"}, []string{".applebot.apple.com"}},
	{"YandexBot", []string{"yandexbot", "yandeximages", "yandex.com/bots"}, []string{".yandex.ru", ".yandex.net", ".yandex.com"}},
	{"Baiduspider", []string{"baiduspider"}, []string{".baidu.com", ".baidu.jp"}},
	{"PetalBot", []string{"petalbot"}, []string{".petalsearch.com"}},
	{"Amazonbot", []string{"amazonbot"}, []string{".crawl.amazonbot.amazon"}},
	// AI / misc crawlers: no rDNS verification published — only the
	// internal-address and secret-probing checks apply.
	{"ClaudeBot", []string{"claudebot", "claude-user", "claude-searchbot", "anthropic-ai"}, nil},
	{"GPTBot", []string{"gptbot", "chatgpt-user", "oai-searchbot"}, nil},
	{"PerplexityBot", []string{"perplexitybot", "perplexity-user"}, nil},
	{"CCBot", []string{"ccbot"}, nil},
	{"Bytespider", []string{"bytespider"}, nil},
	{"cohere-ai", []string{"cohere-ai", "cohere-training"}, nil},
	{"ChatGLM-Spider", []string{"chatglm-spider"}, nil},
	{"DuckDuckBot", []string{"duckduckbot"}, nil},
	{"facebookexternalhit", []string{"facebookexternalhit", "meta-externalagent"}, nil},
}

func claimedCrawler(ua string) *crawler {
	if ua == "" {
		return nil
	}
	l := strings.ToLower(ua)
	for i := range crawlers {
		for _, s := range crawlers[i].ua {
			if strings.Contains(l, s) {
				return &crawlers[i]
			}
		}
	}
	return nil
}

type botState int

const (
	botPending botState = iota
	botVerified
	botFake
	botUnverifiable
)

// Resolver is the DNS subset used for verification (injectable in tests).
type Resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

type botVerifier struct {
	res     Resolver
	timeout time.Duration
	mu      sync.Mutex
	cache   map[string]botCache // "ip|crawler"
	slots   chan struct{}
}

type botCache struct {
	state botState
	exp   time.Time
}

func newBotVerifier(res Resolver, timeout time.Duration) *botVerifier {
	if res == nil {
		res = net.DefaultResolver
	}
	return &botVerifier{res: res, timeout: timeout, cache: map[string]botCache{}, slots: make(chan struct{}, 32)}
}

func (b *botVerifier) set(key string, s botState, ttl time.Duration) {
	b.mu.Lock()
	b.cache[key] = botCache{s, time.Now().Add(ttl)}
	if len(b.cache) > 100000 { // crude bound
		for k, v := range b.cache {
			if time.Now().After(v.exp) {
				delete(b.cache, k)
			}
		}
	}
	b.mu.Unlock()
}

// state returns the verification state, starting an async check if needed.
func (b *botVerifier) state(ip netip.Addr, c *crawler) botState {
	if !public(ip) {
		return botFake // a crawler never reaches you from an internal address
	}
	if c.suffixes == nil {
		return botUnverifiable
	}
	key := ip.String() + "|" + c.name
	b.mu.Lock()
	e, ok := b.cache[key]
	b.mu.Unlock()
	if ok && time.Now().Before(e.exp) {
		return e.state
	}
	if ok && e.state == botPending {
		return botPending
	}
	select {
	case b.slots <- struct{}{}:
	default:
		return botPending // verifier saturated; try again later
	}
	b.set(key, botPending, b.timeout*2)
	go func() {
		defer func() { <-b.slots }()
		s, ttl := b.verify(ip, c)
		b.set(key, s, ttl)
		metrics.BotChecks.WithLabelValues(c.name, map[botState]string{botVerified: "verified", botFake: "fake", botUnverifiable: "error"}[s]).Inc()
	}()
	return botPending
}

func (b *botVerifier) verify(ip netip.Addr, c *crawler) (botState, time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), b.timeout)
	defer cancel()
	names, err := b.res.LookupAddr(ctx, ip.String())
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return botFake, time.Hour // no PTR at all: not a real crawler
		}
		return botUnverifiable, 5 * time.Minute // DNS trouble: don't punish
	}
	for _, n := range names {
		host := strings.TrimSuffix(strings.ToLower(n), ".")
		for _, suf := range c.suffixes {
			if !strings.HasSuffix(host, suf) {
				continue
			}
			addrs, err := b.res.LookupIPAddr(ctx, host)
			if err != nil {
				return botUnverifiable, 5 * time.Minute
			}
			for _, a := range addrs {
				if fa, ok := netip.AddrFromSlice(a.IP); ok && fa.Unmap() == ip.Unmap() {
					return botVerified, 24 * time.Hour
				}
			}
		}
	}
	return botFake, time.Hour
}

// verified reports whether ip was verified for any crawler (used to spare
// real crawlers from 404-based enumeration scoring).
func (b *botVerifier) verified(ip netip.Addr) bool {
	prefix := ip.String() + "|"
	b.mu.Lock()
	defer b.mu.Unlock()
	for k, v := range b.cache {
		if strings.HasPrefix(k, prefix) && v.state == botVerified && time.Now().Before(v.exp) {
			return true
		}
	}
	return false
}

// botFindings evaluates a crawler claim. sensitive reports whether the
// request probes a sensitive path (crawlers don't go after .env/.git).
func (e *Engine) botFindings(ip netip.Addr, ua string, sensitive bool) (fs []detect.Finding, verified bool) {
	c := claimedCrawler(ua)
	if c == nil || e.bots == nil {
		return nil, false
	}
	st := e.bots.state(ip, c)
	if st == botVerified {
		return nil, true
	}
	if st == botFake {
		fs = append(fs, detect.Finding{RuleID: "BIMA-BOT-301", Category: "fake-crawler", Severity: detect.Medium,
			Msg: "User-Agent claims " + c.name + " but the client address is not " + c.name + "'s", Location: "header:user-agent", Match: ua, Score: 30})
	}
	if sensitive {
		fs = append(fs, detect.Finding{RuleID: "BIMA-BOT-302", Category: "fake-crawler", Severity: detect.Medium,
			Msg: "Crawler User-Agent (" + c.name + ") probing secrets/build artifacts", Location: "path", Match: ua, Score: 20})
	}
	return fs, false
}
