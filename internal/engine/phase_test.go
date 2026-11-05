package engine

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/orcinustools/bima/internal/ban"
	"github.com/orcinustools/bima/internal/config"
	"github.com/orcinustools/bima/internal/fingerprint"
	"github.com/orcinustools/bima/internal/store"
)

func TestDistributedEnumerationBansGroup(t *testing.T) {
	e := newEngine(t, false)
	e.cfg.Group.By = []string{"fingerprint"}
	fp := "deadbeefdeadbeef"
	var ips []netip.Addr
	for i := 1; i <= 12; i++ {
		ips = append(ips, netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}))
	}
	// each IP: 8 distinct 404s (per-IP threshold is 20, so never trips alone)
	for i, ip := range ips {
		for j := 0; j < 8; j++ {
			p := fmt.Sprintf("/w-%d-%d", i, j)
			e.OnRequest(&Request{IP: ip, Method: "GET", Path: p})
			e.OnResponse("", ip, "GET", p, 404, fp)
		}
	}
	banned := 0
	for _, ip := range ips {
		if e.bans.IsBanned(ip.String()) {
			banned++
		}
	}
	if banned < 10 {
		t.Fatalf("expected most of the group banned, got %d/12", banned)
	}
}

func TestDistributedNeedsMultipleIPs(t *testing.T) {
	e := newEngine(t, false)
	ip := netip.MustParseAddr("192.0.2.200")
	// one IP, 19 distinct 404s: below per-IP threshold and only 1 IP in group
	for j := 0; j < 19; j++ {
		p := fmt.Sprintf("/x-%d", j)
		e.OnResponse("", ip, "GET", p, 404, "fp1")
	}
	if e.bans.IsBanned(ip.String()) {
		t.Fatal("single IP below threshold must not be banned by group logic")
	}
}

func TestExclusionSuppressesFinding(t *testing.T) {
	e := newEngine(t, false)
	e.cfg.Exclusions = []config.Exclusion{{Rules: []string{"BIMA-RCE-*"}, PathRe: regexp.MustCompile(`^/api/snippets$`), Locations: []string{"body"}}}
	r := req("POST", "/api/snippets", map[string]string{"Content-Type": "application/json"}, `{"code":"ls -la; cat README"}`)
	if v := e.OnRequest(r); v.Action != Allow {
		t.Fatalf("excluded rule should allow, got %s %s", v.Action, v.RuleID)
	}
	r2 := req("POST", "/api/other", map[string]string{"Content-Type": "application/json"}, `{"code":"ls -la; cat README"}`)
	if v := e.OnRequest(r2); v.Action != Block {
		t.Fatalf("exclusion must be path-scoped, got %s", v.Action)
	}
}

func TestReportFlagsLikelyFP(t *testing.T) {
	e := newEngine(t, false)
	e.cfg.Mode = config.ModeDetect
	for i := 0; i < 8; i++ {
		r := req("POST", "/api/snippets", map[string]string{"Content-Type": "application/json"}, `{"code":"echo hi; whoami"}`)
		e.OnRequest(r)
	}
	rep := e.Report.Snapshot()
	if len(rep.Rules) == 0 || !rep.Rules[0].LikelyFalsePositive || !strings.Contains(rep.Rules[0].SuggestedExclusion, "/api/snippets") {
		t.Fatalf("expected FP hint with suggested exclusion, got %+v", rep.Rules)
	}
}

func TestBanPersistsAcrossRestart(t *testing.T) {
	f := filepath.Join(t.TempDir(), "bans.json")
	st := store.NewMemory(f)
	m, _ := ban.New(st, []string{"tcp:127.0.0.1:1"}, "/x.map", []time.Duration{time.Hour}, false)
	if _, placed, _ := m.Ban("198.51.100.9", 0); !placed {
		t.Fatal("ban not placed")
	}
	if _, err := os.Stat(f); err != nil {
		t.Fatal("ban file not written")
	}
	st2 := store.NewMemory(f) // "restart"
	m2, _ := ban.New(st2, []string{"tcp:127.0.0.1:1"}, "/x.map", []time.Duration{time.Hour}, false)
	m2.Reconcile()
	if !m2.IsBanned("198.51.100.9") {
		t.Fatal("ban lost after restart")
	}
}

func TestJA3(t *testing.T) {
	h, raw := fingerprint.JA3(771, []byte{0x13, 0x01, 0x13, 0x02}, []byte{0x00, 0x00, 0x00, 0x0b}, []byte{0x00, 0x1d}, []byte{0})
	if raw != "771,4865-4866,0-11,29,0" || len(h) != 32 {
		t.Fatalf("bad ja3: %s %s", raw, h)
	}
	if h2, _ := fingerprint.JA3(0, nil, nil, nil, nil); h2 != "" {
		t.Fatal("plain http must yield empty ja3")
	}
}

func TestCRSFastPath(t *testing.T) {
	plain := &Request{Path: "/api/users", Query: "id=7&q=hello", Headers: [][2]string{
		{"Host", "x"}, {"User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130"}, {"Accept", "text/html,*/*;q=0.8"},
		{"Cookie", "session=abc123; theme=dark"}, {"Authorization", "Bearer eyJ.eyJ.sig"}}}
	if crsNeeded(plain) {
		t.Fatal("plain GET should take the fast path")
	}
	cases := map[string]*Request{
		"sqli in query":     {Path: "/a", Query: "id=1'or'1"},
		"spaces (encoded)":  {Path: "/a", Query: "q=1+or+true"},
		"percent encoding":  {Path: "/a", Query: "q=%27"},
		"body":              {Path: "/a", Body: []byte("x")},
		"traversal":         {Path: "/a/../../etc"},
		"shellshock UA":     {Path: "/", Headers: [][2]string{{"User-Agent", "() { :; }; /bin/bash"}}},
		"custom header":     {Path: "/", Headers: [][2]string{{"X-Api-Version", "1 union select"}}},
		"cookie with quote": {Path: "/", Headers: [][2]string{{"Cookie", "a=b'c"}}},
		"ssrf url":          {Path: "/", Query: "url=http://169.254.169.254/"},
	}
	for name, r := range cases {
		if !crsNeeded(r) {
			t.Errorf("%s: CRS must run", name)
		}
	}
}

func TestShortDur(t *testing.T) {
	for d, want := range map[time.Duration]string{20 * time.Second: "20s", 40 * time.Second: "40s", time.Minute: "1m",
		10 * time.Minute: "10m", time.Hour: "1h", 24 * time.Hour: "24h", 90 * time.Second: "1m30s"} {
		if got := shortDur(d); got != want {
			t.Errorf("shortDur(%v) = %q, want %q", d, got, want)
		}
	}
}
