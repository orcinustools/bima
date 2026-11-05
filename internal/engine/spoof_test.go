package engine

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

type fakeResolver struct {
	ptr map[string][]string // ip -> names
	fwd map[string][]string // name -> ips
}

func (f fakeResolver) LookupAddr(_ context.Context, addr string) ([]string, error) {
	if n, ok := f.ptr[addr]; ok {
		return n, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
}

func (f fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	var out []net.IPAddr
	for _, s := range f.fwd[host] {
		out = append(out, net.IPAddr{IP: net.ParseIP(s)})
	}
	if len(out) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return out, nil
}

// The exact traffic from a real access log: one scanner, a random internal
// X-Forwarded-For per request and a rotating fake crawler User-Agent, probing
// JS build artifacts and env files.
var logReplay = []struct{ xff, path, ua string }{
	{"192.168.60.245", "/.vercel/project.json", "Mozilla/5.0 (compatible; cohere-ai; +https://cohere.com/crawler)"},
	{"10.100.20.99", "/.next/prerender-manifest.json", "Mozilla/5.0 (compatible; ChatGLM-Spider/1.0; +https://zhipuai.cn/)"},
	{"192.168.121.22", "/.next/routes-manifest.json", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)"},
	{"10.184.8.39", "/.netlify/state.json", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)"},
	{"192.168.179.141", "/.next/server/pages/index.js", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)"},
	{"192.168.120.248", "/.next/required-server-files.json", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)"},
	{"10.169.175.104", "/prisma/schema.prisma", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-User/1.0; +claudebot@anthropic.com)"},
	{"100.127.105.44", "/.output/nitro.json", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)"},
	{"192.168.143.14", "/.output/server/index.mjs", "Mozilla/5.0 (compatible; Bytespider; spider-feedback@bytedance.com) AppleWebKit/537.36"},
	{"192.168.135.194", "/.next/server/app/page.js", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Perplexity-User/1.0; +https://perplexity.ai/perplexity-user)"},
	{"192.168.224.109", "/.env.shared", "CCBot/2.0 (https://commoncrawl.org/faq/)"},
	{"172.26.54.205", "/packages/api/.env", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"},
	{"10.213.25.60", "/prisma/.env", "Mozilla/5.0 (compatible; ChatGLM-Spider/1.0; +https://zhipuai.cn/)"},
	{"10.160.196.240", "/.env.monorepo", "Mozilla/5.0 (compatible; Amazonbot/0.1; +https://developer.amazon.com/support/amazonbot)"},
	{"10.114.183.186", "/.env.common", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Perplexity-User/1.0; +https://perplexity.ai/perplexity-user)"},
}

func spoofReq(src, peer, xff, path, ua string) *Request {
	r := &Request{IP: netip.MustParseAddr(src), Method: "GET", Path: path, Version: "2.0",
		Headers: [][2]string{{"Host", "shop.example.com"}, {"User-Agent", ua}, {"Accept", "*/*"}}}
	if peer != "" {
		r.Peer = netip.MustParseAddr(peer)
	}
	if xff != "" {
		r.Headers = append(r.Headers, [2]string{"X-Forwarded-For", xff})
	}
	return r
}

// Correct HAProxy config: XFF is not trusted, src == peer == the scanner.
func TestLogReplayCorrectConfig(t *testing.T) {
	e := newEngine(t, false)
	e.SetResolver(fakeResolver{})
	var actions []string
	bannedAt := 0
	for i, l := range logReplay {
		v := e.OnRequest(spoofReq("203.0.113.77", "203.0.113.77", l.xff, l.path, l.ua))
		actions = append(actions, string(v.Action))
		if bannedAt == 0 && e.bans.IsBanned("203.0.113.77") {
			bannedAt = i + 1
		}
	}
	if bannedAt == 0 || bannedAt > 3 {
		t.Fatalf("scanner should be banned within 3 requests, banned at %d: %v", bannedAt, actions)
	}
	if strings.Join(actions[3:], ",") != strings.Repeat("block,", len(actions)-4)+"block" {
		t.Fatalf("everything after the ban must be blocked: %v", actions)
	}
	rep := e.Report.Snapshot()
	seen := map[string]bool{}
	for _, r := range rep.Rules {
		seen[r.Rule] = true
	}
	if !seen["BIMA-ENUM-102"] || !seen["BIMA-BOT-302"] {
		t.Fatalf("expected sensitive-path and crawler-probe findings, got %v", seen)
	}
}

// Misconfigured HAProxy that trusts XFF from anyone: src rotates, the peer is
// the scanner. With trusted_proxies configured, Bima holds the peer accountable.
func TestLogReplayMisconfiguredTrust(t *testing.T) {
	e := newEngine(t, false)
	e.SetResolver(fakeResolver{})
	if err := e.cfg.SetTrustedProxies([]string{"10.0.0.0/30"}); err != nil {
		t.Fatal(err)
	}
	for _, l := range logReplay {
		e.OnRequest(spoofReq(l.xff, "198.51.100.200", l.xff, l.path, l.ua))
	}
	if !e.bans.IsBanned("198.51.100.200") {
		t.Fatal("the TCP peer (real scanner) must be banned")
	}
	for _, l := range logReplay {
		if e.bans.IsBanned(l.xff) {
			t.Fatalf("spoofed address %s must not be banned", l.xff)
		}
	}
}

// Misconfigured trust and NO trusted_proxies configured: header rotation
// across many internal networks flags the peer as a spoofer.
func TestRotationFlagsPeer(t *testing.T) {
	e := newEngine(t, false)
	e.SetResolver(fakeResolver{})
	peer := "172.16.9.9" // internal peer: no other rule applies
	ranges := []string{"10.%d.1.1", "192.168.%d.1", "172.20.%d.1", "100.100.%d.1", "10.%d.200.7", "192.168.%d.77", "172.21.%d.3", "100.90.%d.8", "10.%d.9.9"}
	var last Verdict
	for i, r := range ranges {
		x := fmt.Sprintf(r, i+10)
		last = e.OnRequest(spoofReq(x, peer, x, "/products", "Mozilla/5.0 Chrome/130"))
	}
	if !e.spoof.flagged(peer) {
		t.Fatal("peer should be flagged as a header spoofer")
	}
	if last.RuleID != "BIMA-SPOOF-202" && !e.bans.IsBanned(peer) && last.Action == Allow {
		t.Fatalf("rotation must be acted on, got %+v", last)
	}
	id, reason := e.identity(netip.MustParseAddr("10.1.1.1"), netip.MustParseAddr(peer))
	if id.String() != peer || reason != "spoofer" {
		t.Fatalf("flagged peer must be the identity, got %s (%s)", id, reason)
	}
}

// A corporate proxy forwards many employees from ONE internal network.
func TestCorporateProxyNotFlagged(t *testing.T) {
	e := newEngine(t, false)
	e.SetResolver(fakeResolver{})
	for i := 1; i <= 40; i++ {
		x := fmt.Sprintf("10.1.%d.%d", i%4, i)
		v := e.OnRequest(spoofReq("203.0.113.88", "203.0.113.88", x, "/products", "Mozilla/5.0 Chrome/130"))
		if v.Action != Allow {
			t.Fatalf("corporate proxy request %d blocked: %+v", i, v)
		}
	}
	if e.spoof.flagged("203.0.113.88") {
		t.Fatal("one internal /16 must not count as rotation")
	}
}

// Forged XFF claiming an allowlisted office address through an untrusted peer.
func TestAllowlistBypassBlocked(t *testing.T) {
	e := newEngine(t, false)
	if err := e.cfg.SetTrustedProxies([]string{"10.0.0.1/32"}); err != nil {
		t.Fatal(err)
	}
	e.cfg.Allowlist = []string{"10.200.0.0/16"}
	cfgReload(t, e)
	v := e.OnRequest(spoofReq("10.200.1.1", "198.51.100.201", "10.200.1.1", "/api/ping", "curl/8"))
	if v.Action != Block || v.RuleID != "BIMA-SPOOF-203" {
		t.Fatalf("forged allowlisted address must be blocked, got %+v", v)
	}
	// the genuine office request through the trusted proxy is still allowlisted
	v = e.OnRequest(spoofReq("10.200.1.1", "10.0.0.1", "10.200.1.1", "/api/ping?host=;id", "curl/8"))
	if v.Action != Allow {
		t.Fatalf("real allowlisted client via trusted proxy must pass, got %+v", v)
	}
}

func TestCrawlerVerification(t *testing.T) {
	e := newEngine(t, false)
	e.SetResolver(fakeResolver{
		ptr: map[string][]string{"66.249.66.1": {"crawl-66-249-66-1.googlebot.com."}, "198.51.100.9": {"host.evil.example."}},
		fwd: map[string][]string{"crawl-66-249-66-1.googlebot.com": {"66.249.66.1"}},
	})
	gb := "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	e.OnRequest(spoofReq("66.249.66.1", "66.249.66.1", "", "/", gb))
	e.OnRequest(spoofReq("198.51.100.9", "198.51.100.9", "", "/", gb))
	time.Sleep(100 * time.Millisecond) // async verification
	// real Googlebot following 30 stale links: never punished
	for i := 0; i < 30; i++ {
		p := fmt.Sprintf("/old-%d", i)
		if v := e.OnRequest(spoofReq("66.249.66.1", "66.249.66.1", "", p, gb)); v.Action != Allow {
			t.Fatalf("verified Googlebot blocked at %d: %+v", i, v)
		}
		e.OnResponse("", netip.MustParseAddr("66.249.66.1"), netip.Addr{}, "GET", p, 404, "")
	}
	// fake Googlebot: penalised once verification failed
	v := e.OnRequest(spoofReq("198.51.100.9", "198.51.100.9", "", "/", gb))
	if v.RuleID != "BIMA-BOT-301" {
		t.Fatalf("fake Googlebot should be flagged, got %+v", v)
	}
	v = e.OnRequest(spoofReq("198.51.100.9", "198.51.100.9", "", "/", gb))
	if v.Action == Allow {
		t.Fatalf("fake Googlebot should be throttled on repeat, got %+v", v)
	}
	// crawler claim from an internal address is fake without any DNS
	if st := e.bots.state(netip.MustParseAddr("192.168.1.5"), claimedCrawler(gb)); st != botFake {
		t.Fatalf("internal-address crawler must be fake, got %v", st)
	}
}

func TestForwardedClaimsParsing(t *testing.T) {
	src := netip.MustParseAddr("198.51.100.1")
	h := [][2]string{
		{"X-Forwarded-For", "10.1.2.3, 192.168.1.1:8080, 8.8.8.8, 198.51.100.1"},
		{"Forwarded", `for=172.16.0.9;proto=https, for="[fd00::1]:443"`},
		{"X-Real-IP", "100.64.1.2"},
		{"User-Agent", "10.9.9.9"},
	}
	got := forwardedClaims(h, src)
	want := "10.1.2.3,192.168.1.1,172.16.0.9,fd00::1,100.64.1.2"
	var s []string
	for _, a := range got {
		s = append(s, a.String())
	}
	if strings.Join(s, ",") != want {
		t.Fatalf("got %v want %s", s, want)
	}
}

// cfgReload re-parses list fields after a test mutates them.
func cfgReload(t *testing.T, e *Engine) {
	t.Helper()
	c := *e.cfg
	if err := c.SetTrustedProxies(c.TrustedProxies); err != nil {
		t.Fatal(err)
	}
	if err := c.SetAllowlist(c.Allowlist); err != nil {
		t.Fatal(err)
	}
	*e.cfg = c
}

// A load balancer in front appends the real (public) client to XFF; the client
// itself sends rotating fake internal addresses. The CLIENT must be flagged,
// never the load balancer (that would merge all users into one identity).
func TestRotationBehindLBBlamesClient(t *testing.T) {
	e := newEngine(t, false)
	lb, client := "198.51.100.250", "203.0.113.99"
	for i := 0; i < 12; i++ {
		fake := []string{"10.%d.1.1", "192.168.%d.1", "172.20.%d.1", "100.100.%d.1"}[i%4]
		xff := fmt.Sprintf(fake, i) + ", " + client
		e.OnRequest(spoofReq(client, lb, xff, "/products", "Mozilla/5.0 Chrome/130"))
	}
	if e.spoof.flagged(lb) {
		t.Fatal("load balancer must never be flagged for its clients' headers")
	}
	if !e.spoof.flagged(client) {
		t.Fatal("the rotating client should be flagged")
	}
	// an innocent user behind the same LB is unaffected
	if v := e.OnRequest(spoofReq("198.51.100.77", lb, "198.51.100.77", "/products", "Mozilla/5.0 Firefox/131")); v.Action != Allow {
		t.Fatalf("other users behind the LB must be served, got %+v", v)
	}
}
