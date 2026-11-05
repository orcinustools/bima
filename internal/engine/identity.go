package engine

import (
	"context"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/orcinustools/bima/internal/detect"
	"github.com/orcinustools/bima/internal/metrics"
	"github.com/orcinustools/bima/internal/store"
)

// Client identity and forwarding-header spoofing.
//
// HAProxy sends both the client address it decided on (src, possibly taken
// from X-Forwarded-For) and the TCP peer (fc_src). Attackers rotate fake
// X-Forwarded-For values (typically random private addresses) to dodge per-IP
// limits, poison logs and slip into allowlists. Bima therefore decides which
// address to hold accountable:
//
//   - the TCP peer, when HAProxy trusted a forwarding header from a peer that
//     is not in trusted_proxies (misconfiguration);
//   - the TCP peer, when a public peer claims an internal client address;
//   - the TCP peer, while the peer is flagged as a header spoofer;
//   - otherwise the address HAProxy chose.

const (
	spoofMinValues  = 8 // distinct internal addresses claimed by one peer in the window
	spoofMinPrefix  = 4 // ... spread over at least this many /16 networks
	spoofFlagTTL    = 10 * time.Minute
	spoofCacheTTL   = 10 * time.Second
	spoofHeaderList = "x-forwarded-for,x-real-ip,forwarded,true-client-ip,x-client-ip,cf-connecting-ip,x-originating-ip,x-remote-ip,x-remote-addr,x-cluster-client-ip,client-ip"
)

var spoofHeaders = func() map[string]bool {
	m := map[string]bool{}
	for h := range strings.SplitSeq(spoofHeaderList, ",") {
		m[h] = true
	}
	return m
}()

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// public reports whether a is a globally routable unicast address.
func public(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsValid() && a.IsGlobalUnicast() && !a.IsPrivate() && !cgnat.Contains(a)
}

type spoofTracker struct {
	st     store.Store
	window time.Duration
	mu     sync.Mutex
	cache  map[string]spoofEntry // peer -> flagged? (local cache of the shared flag)
	warned sync.Map              // peers already logged as untrusted forwarders
}

type spoofEntry struct {
	flagged bool
	exp     time.Time
}

func newSpoofTracker(st store.Store, window time.Duration) *spoofTracker {
	return &spoofTracker{st: st, window: window, cache: map[string]spoofEntry{}}
}

func (s *spoofTracker) flagged(peer string) bool {
	s.mu.Lock()
	e, ok := s.cache[peer]
	s.mu.Unlock()
	if ok && time.Now().Before(e.exp) {
		return e.flagged
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	f, _ := s.st.Flag(ctx, "spoofer:"+peer)
	s.mu.Lock()
	s.cache[peer] = spoofEntry{flagged: f, exp: time.Now().Add(spoofCacheTTL)}
	s.mu.Unlock()
	return f
}

func (s *spoofTracker) flag(peer string) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_ = s.st.SetFlag(ctx, "spoofer:"+peer, spoofFlagTTL)
	s.mu.Lock()
	s.cache[peer] = spoofEntry{flagged: true, exp: time.Now().Add(spoofFlagTTL)}
	s.mu.Unlock()
}

// identity picks the address to hold accountable; reason is "" when it is src.
func (e *Engine) identity(src, peer netip.Addr) (netip.Addr, string) {
	src, peer = src.Unmap(), peer.Unmap()
	if !peer.IsValid() || peer == src {
		return src, ""
	}
	if e.spoof.flagged(peer.String()) {
		return peer, "spoofer"
	}
	if trusted, configured := e.cfg.Trusted(peer); configured && !trusted {
		metrics.UntrustedForwarder.Inc()
		if _, seen := e.spoof.warned.LoadOrStore(peer.String(), true); !seen {
			slog.Warn("HAProxy took the client IP from a forwarding header sent by an untrusted peer; using the TCP peer as identity (fix set-src trust in haproxy.cfg)",
				"peer", peer.String(), "claimed", src.String())
		}
		return peer, "untrusted-forwarder"
	}
	if public(peer) && !public(src) {
		return peer, "internal-claim"
	}
	return src, ""
}

// forwardedClaims returns the internal (non-public) addresses found in
// forwarding headers. An internet-facing site never has internal clients, so
// every such address is a claim worth tracking (traffic from peers listed in
// trusted_proxies is exempted by the caller).
func forwardedClaims(headers [][2]string, _ netip.Addr) []netip.Addr {
	var out []netip.Addr
	add := func(s string) {
		s = strings.TrimSpace(strings.Trim(strings.TrimSpace(s), `"[]`))
		if h, _, ok := strings.Cut(s, "]:"); ok { // [v6]:port
			s = h
		}
		if strings.Count(s, ":") == 1 { // v4:port
			s, _, _ = strings.Cut(s, ":")
		}
		a, err := netip.ParseAddr(s)
		if err != nil || public(a) {
			return
		}
		out = append(out, a.Unmap())
	}
	for _, h := range headers {
		name := strings.ToLower(h[0])
		if !spoofHeaders[name] {
			continue
		}
		for part := range strings.SplitSeq(h[1], ",") {
			if name == "forwarded" {
				for kv := range strings.SplitSeq(part, ";") {
					if k, v, ok := strings.Cut(strings.TrimSpace(kv), "="); ok && strings.EqualFold(k, "for") {
						add(v)
					}
				}
				continue
			}
			add(part)
		}
	}
	return out
}

// observeSpoofing records internal addresses claimed by peer and flags the
// peer once the claims rotate across many networks (log-poisoning / limit
// evasion). Corporate proxies (one internal network) do not trip it.
func (e *Engine) observeSpoofing(peer string, claims []netip.Addr) *detect.Finding {
	if len(claims) == 0 || peer == "" {
		return nil
	}
	if pa, err := netip.ParseAddr(peer); err == nil {
		if trusted, _ := e.cfg.Trusted(pa); trusted {
			return nil // a configured proxy (e.g. intranet LB) forwards internal clients legitimately
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	var nv, np int
	for _, a := range claims {
		v, err := e.spoof.st.SAddCard(ctx, "spv:"+peer, a.String(), e.cfg.Score.Window)
		if err != nil {
			return nil
		}
		p16 := a.String()
		if a.Is4() {
			b := a.As4()
			p16 = strconv.Itoa(int(b[0])) + "." + strconv.Itoa(int(b[1]))
		} else if p, err := a.Prefix(32); err == nil {
			p16 = p.String()
		}
		n, _ := e.spoof.st.SAddCard(ctx, "sp16:"+peer, p16, e.cfg.Score.Window)
		nv, np = max(nv, v), max(np, n)
	}
	if nv < spoofMinValues || np < spoofMinPrefix {
		return nil
	}
	if e.spoof.flagged(peer) {
		return nil // already reported
	}
	e.spoof.flag(peer)
	metrics.Spoofers.Inc()
	return &detect.Finding{RuleID: "BIMA-SPOOF-202", Category: "ip-spoofing", Severity: detect.High,
		Msg:      "Forwarding-header IP rotation: " + strconv.Itoa(nv) + " internal addresses across " + strconv.Itoa(np) + " networks from one peer",
		Location: "header:x-forwarded-for", Match: claims[0].String(), Score: 50}
}
