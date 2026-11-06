package engine

import (
	"testing"

	"github.com/orcinustools/bima/internal/cloudflare"
)

const cfEdge = "172.64.10.20" // inside 172.64.0.0/13

func behindCloudflare(t *testing.T) *Engine {
	e := newEngine(t, false)
	e.SetResolver(fakeResolver{})
	if err := e.cfg.SetTrustedProxies(cloudflare.EdgeRanges); err != nil {
		t.Fatal(err)
	}
	return e
}

func cfReq(client, path, ua string) *Request {
	r := spoofReq(client, cfEdge, client, path, ua)
	r.Headers = append(r.Headers, [2]string{"CF-Connecting-IP", client}, [2]string{"CF-Ray", "8f1c2d3e4f5a6b7c-SIN"},
		[2]string{"CF-IPCountry", "ID"}, [2]string{"CDN-Loop", "cloudflare"})
	r.JA3 = "cloudflare-edge-ja3"
	return r
}

// A scanner behind Cloudflare: HAProxy restored its address from
// CF-Connecting-IP. The scanner is banned, the Cloudflare edge never is.
func TestBehindCloudflareBansClientNotEdge(t *testing.T) {
	e := behindCloudflare(t)
	for _, l := range logReplay {
		e.OnRequest(cfReq("203.0.113.77", l.path, l.ua))
	}
	if !e.bans.IsBanned("203.0.113.77") {
		t.Fatal("scanner behind Cloudflare must be banned by its real address")
	}
	if e.bans.IsBanned(cfEdge) {
		t.Fatal("Cloudflare edge must never be banned")
	}
	// other clients behind the same edge are unaffected
	if v := e.OnRequest(cfReq("198.51.100.9", "/products", "Mozilla/5.0 Chrome/130")); v.Action != Allow {
		t.Fatalf("innocent client behind the same edge: %+v", v)
	}
}

// The edge's TLS handshake is shared by every client: it must not feed the
// client fingerprint (it would merge all visitors into one "group").
func TestBehindCloudflareIgnoresEdgeJA3(t *testing.T) {
	e := behindCloudflare(t)
	a := cfReq("203.0.113.1", "/", "Mozilla/5.0 Chrome/130")
	b := cfReq("203.0.113.1", "/", "Mozilla/5.0 Chrome/130")
	b.JA3 = "another-edge-ja3"
	if e.fingerprint(a) != e.fingerprint(b) {
		t.Fatal("JA3 of a trusted proxy must be ignored")
	}
	c := cfReq("203.0.113.1", "/", "Mozilla/5.0 Chrome/130")
	c.Headers = c.Headers[:len(c.Headers)-4+1] // drop CF-Ray etc. except CF-Connecting-IP
	if e.fingerprint(a) != e.fingerprint(c) {
		t.Fatal("cf-* headers must not change the fingerprint")
	}
	// direct connection: JA3 still counts
	d1 := spoofReq("203.0.113.2", "203.0.113.2", "", "/", "x")
	d2 := spoofReq("203.0.113.2", "203.0.113.2", "", "/", "x")
	d1.JA3, d2.JA3 = "a", "b"
	if e.fingerprint(d1) == e.fingerprint(d2) {
		t.Fatal("JA3 must count for direct clients")
	}
}

func TestNeverBanTrustedProxy(t *testing.T) {
	e := behindCloudflare(t)
	if lbl := e.ban(cfEdge, 500); lbl != "" || e.bans.IsBanned(cfEdge) {
		t.Fatalf("trusted proxy was banned (%q)", lbl)
	}
	if lbl := e.ban("203.0.113.50", 500); lbl == "" {
		t.Fatal("normal ban broken")
	}
}
