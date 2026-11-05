// scenariorun sends the data-driven corpus (test/scenarios) and behavioural
// multi-request flows through a live HAProxy+Bima, with a distinct client IP
// per scenario (X-Forwarded-For), and prints a detection matrix.
//
// Requests are written as raw HTTP/1.1 so malformed-but-real attack shapes
// (Host with '/', 24 KB Host, un-normalized '..' paths) reach the proxy as is.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/orcinustools/bima/test/scenarios"
)

var target string

type resp struct {
	status int
	action string
	dur    time.Duration
	err    error
}

// send writes one raw HTTP/1.1 request.
func send(ip, method, path string, headers map[string]string, body string) resp {
	u, _ := url.Parse(target)
	start := time.Now()
	conn, err := net.DialTimeout("tcp", u.Host, 5*time.Second)
	if err != nil {
		return resp{err: err}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	h := map[string]string{"Host": "shop.example.com", "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/130", "Accept": "*/*"}
	for k, v := range headers {
		for hk := range h {
			if strings.EqualFold(hk, k) {
				delete(h, hk)
			}
		}
		h[k] = v
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", method, path)
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	hasConn := false
	for _, k := range keys {
		if strings.EqualFold(k, "connection") {
			hasConn = true
		}
		fmt.Fprintf(&b, "%s: %s\r\n", k, h[k])
	}
	if ip != "" {
		fmt.Fprintf(&b, "X-Forwarded-For: %s\r\n", ip)
	}
	if body != "" || method == "POST" || method == "PUT" || method == "PATCH" {
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(body))
	}
	if !hasConn {
		b.WriteString("Connection: close\r\n")
	}
	b.WriteString("\r\n")
	b.WriteString(body)
	if _, err := io.WriteString(conn, b.String()); err != nil {
		return resp{err: err}
	}
	r, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return resp{err: err, dur: time.Since(start)}
	}
	_, _ = io.Copy(io.Discard, r.Body)
	r.Body.Close()
	return resp{status: r.StatusCode, action: r.Header.Get("X-Bima-Action"), dur: time.Since(start)}
}

func verdict(r resp) string {
	switch {
	case r.err != nil:
		return "error"
	case r.status == 403:
		return "block"
	case r.status == 400 || r.status == 431 || r.status == 414:
		return "block-l0" // rejected by HAProxy itself (malformed / too large)
	case r.status == 429:
		return "tarpit"
	default:
		return "allow"
	}
}

type result struct {
	ID     string `json:"id"`
	Cat    string `json:"cat"`
	CVE    string `json:"cve,omitempty"`
	Desc   string `json:"desc"`
	Expect string `json:"expect"`
	Got    string `json:"got"`
	Status int    `json:"status"`
	OK     bool   `json:"ok"`
	Gap    string `json:"gap,omitempty"`
}

func main() {
	flag.StringVar(&target, "url", "http://haproxy:8080", "HAProxy frontend")
	jsonOut := flag.String("json", "", "write full results to this file")
	only := flag.String("only", "", "comma-separated parts: corpus,flows,spoof (default corpus,flows; run spoof from its own container: it gets that container banned)")
	flag.Parse()

	var results []result
	if *only == "" || strings.Contains(*only, "corpus") {
		all, err := scenarios.Load()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		for i, s := range all {
			ip := fmt.Sprintf("198.19.%d.%d", i/250, i%250+1)
			h := map[string]string{}
			for k, v := range s.Headers {
				h[k] = v
			}
			if s.CT != "" {
				if _, ok := h["Content-Type"]; !ok {
					h["Content-Type"] = s.CT
				}
			}
			r := send(ip, s.Method, s.Path, h, s.Body)
			got := verdict(r)
			ok := got == s.Expect || (s.Expect == "block" && (got == "tarpit" || got == "block-l0"))
			results = append(results, result{s.ID, s.Cat, s.CVE, s.Desc, s.Expect, got, r.status, ok, s.Gap})
		}
	}
	if *only == "" || strings.Contains(*only, "flows") {
		results = append(results, runFlows()...)
	}
	if strings.Contains(*only, "spoof") {
		results = append(results, runSpoofFlows()...)
	}

	// matrix
	type t struct{ total, ok, gap int }
	cats := map[string]*t{}
	var fails []result
	for _, r := range results {
		c := cats[r.Cat]
		if c == nil {
			c = &t{}
			cats[r.Cat] = c
		}
		c.total++
		switch {
		case r.OK:
			c.ok++
		case r.Gap != "":
			c.gap++
		default:
			fails = append(fails, r)
		}
	}
	names := make([]string, 0, len(cats))
	for n := range cats {
		names = append(names, n)
	}
	sort.Strings(names)
	fmt.Printf("%-18s %6s %6s %9s\n", "category", "total", "pass", "known-gap")
	var T, O, G int
	for _, n := range names {
		c := cats[n]
		fmt.Printf("%-18s %6d %6d %9d\n", n, c.total, c.ok, c.gap)
		T, O, G = T+c.total, O+c.ok, G+c.gap
	}
	fmt.Printf("%-18s %6d %6d %9d\n", "TOTAL", T, O, G)
	for _, r := range results {
		if !r.OK && r.Gap != "" {
			fmt.Printf("  gap  %-24s %s — %s\n", r.ID, r.Desc, r.Gap)
		}
	}
	for _, r := range fails {
		fmt.Printf("  FAIL %-24s want %-6s got %-8s (HTTP %d) %s\n", r.ID, r.Expect, r.Got, r.Status, r.Desc)
	}
	if *jsonOut != "" {
		b, _ := json.MarshalIndent(results, "", " ")
		_ = os.WriteFile(*jsonOut, b, 0o644)
	}
	fmt.Printf("RESULT: %d/%d passed, %d known gaps, %d failed\n", O, T, G, len(fails))
	if len(fails) > 0 {
		os.Exit(1)
	}
}

// ---------------------------------------------------------------- flows

var flowN int

func flowIP() string { flowN++; return fmt.Sprintf("198.20.%d.%d", flowN/250, flowN%250+1) }

func flow(id, desc string, pass bool, detail string) result {
	if detail != "" {
		desc += " (" + detail + ")"
	}
	got := "fail"
	if pass {
		got = "pass"
	}
	return result{ID: id, Cat: "flow", Desc: desc, Expect: "pass", Got: got, OK: pass}
}

func get(ip, path string, h map[string]string) resp { return send(ip, "GET", path, h, "") }

func runFlows() []result {
	var out []result
	browser := map[string]string{"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130"}

	// F01 ffuf-style directory brute force
	ip := flowIP()
	words := []string{"admin", "backup", "old", "test", "dev", "staging", "api2", "v0", "private", "secret", "tmp", "logs", "cms", "panel",
		"portal", "db", "sql", "files", "uploads2", "shop2", "config", "install", "setup", "debug", "console2", "manage", "internal", "beta", "demo", "temp"}
	for _, w := range words {
		get(ip, "/"+w, map[string]string{"User-Agent": "Fuzz Faster U Fool v2.1.0"})
	}
	r := get(ip, "/", browser)
	out = append(out, flow("flow-01", "ffuf-style dir brute force (30 paths) → banned", r.status == 403, fmt.Sprintf("final HTTP %d", r.status)))

	// F02 slow/low scan below the per-IP threshold
	ip = flowIP()
	for i := 0; i < 12; i++ {
		get(ip, fmt.Sprintf("/maybe-%d", i), browser)
	}
	r = get(ip, "/products", browser)
	out = append(out, flow("flow-02", "low-volume probing (12 404s) stays below threshold → served", r.status == 200, fmt.Sprintf("HTTP %d", r.status)))

	// F03 sequential ID enumeration
	ip = flowIP()
	blockedAt := 0
	for i := 1; i <= 60 && blockedAt == 0; i++ {
		if s := get(ip, fmt.Sprintf("/api/users/%d", i), browser).status; s == 403 || s == 429 {
			blockedAt = i
		}
	}
	out = append(out, flow("flow-03", "sequential ID enumeration → stopped", blockedAt > 0, fmt.Sprintf("at id=%d", blockedAt)))

	// F04 normal browsing of a few IDs
	ip = flowIP()
	okAll := true
	for _, id := range []int{7, 42, 13, 99, 5, 314, 27, 8, 60, 11} {
		if get(ip, fmt.Sprintf("/api/users/%d", id), browser).status != 200 {
			okAll = false
		}
	}
	out = append(out, flow("flow-04", "user opens 10 random profiles → all served", okAll, ""))

	// F05 credential brute force
	ip = flowIP()
	tarpit := false
	for i := 0; i < 25 && !tarpit; i++ {
		tarpit = send(ip, "POST", "/login", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, fmt.Sprintf("email=a@b.c&password=guess%d", i)).status == 429
	}
	out = append(out, flow("flow-05", "login brute force (25 attempts) → tarpit", tarpit, ""))

	// F06 forgetful user: 3 wrong passwords then correct
	ip = flowIP()
	fine := true
	for i := 0; i < 3; i++ {
		if s := send(ip, "POST", "/login", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, "email=a@b.c&password=wrong"+strconv.Itoa(i)).status; s != 401 {
			fine = false
		}
	}
	s := send(ip, "POST", "/login", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, "email=a@b.c&password=correct-horse").status
	out = append(out, flow("flow-06", "3 failed logins then success → not punished", fine && s == 200, fmt.Sprintf("final HTTP %d", s)))

	// F07 scanner user agents
	n := 0
	scanners := []string{"sqlmap/1.8", "Nikto/2.5.0", "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)", "gobuster/3.6", "WPScan v3.8.25",
		"Mozilla/5.0 (compatible; Nmap Scripting Engine)", "dirsearch/0.4.3", "feroxbuster/2.10", "wfuzz/3.1", "Acunetix-Aspect"}
	for _, ua := range scanners {
		if get(flowIP(), "/", map[string]string{"User-Agent": ua}).status == 429 {
			n++
		}
	}
	out = append(out, flow("flow-07", "10 different scanner User-Agents → each tarpitted", n == len(scanners), fmt.Sprintf("%d/%d", n, len(scanners))))

	// F08 normal shopping session incl. typos
	ip = flowIP()
	bad := 0
	session := []string{"/", "/products", "/products?page=2", "/search?q=kopi", "/p/kelas-ui-ux", "/static/app.js", "/static/style.css",
		"/api/users/42", "/prodcts", "/search?q=kopi+susu", "/checkout", "/dashboard", "/api/profile", "/favicon.ico", "/robots.txt"}
	for i := 0; i < 4; i++ {
		for _, p := range session {
			if st := get(ip, p, browser).status; st == 403 || st == 429 {
				bad++
			}
		}
	}
	out = append(out, flow("flow-08", "60-request shopping session with typo 404s → never blocked", bad == 0, fmt.Sprintf("%d blocked", bad)))

	// F09 API client polling
	ip = flowIP()
	bad = 0
	for i := 0; i < 250; i++ {
		if st := get(ip, "/api/orders?status=pending", map[string]string{"User-Agent": "okhttp/4.12.0", "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI0MiJ9.sig"}).status; st == 403 || st == 429 {
			bad++
		}
	}
	out = append(out, flow("flow-09", "mobile app polling 250× (under rate limit) → never blocked", bad == 0, fmt.Sprintf("%d blocked", bad)))

	// F10 banned IP stays banned for clean requests
	ip = flowIP()
	get(ip, "/api/ping?host=;id", browser)
	get(ip, "/api/ping?host=|uname", browser)
	blocked := 0
	for _, p := range []string{"/", "/products", "/api/users/1", "/static/app.js", "/health"} {
		if get(ip, p, browser).status == 403 {
			blocked++
		}
	}
	out = append(out, flow("flow-10", "after 2 RCE attempts → banned, 5 clean requests refused", blocked == 5, fmt.Sprintf("%d/5", blocked)))

	// F11 UA rotation does not evade per-IP detection
	ip = flowIP()
	uas := []string{"Mozilla/5.0 Chrome/120", "Mozilla/5.0 Firefox/121", "Mozilla/5.0 Safari/17", "curl/8.4", "python-requests/2.31"}
	for i := 0; i < 25; i++ {
		get(ip, fmt.Sprintf("/rot-%d", i), map[string]string{"User-Agent": uas[i%len(uas)]})
	}
	get(ip, "/.env", browser)
	get(ip, "/.git/config", browser)
	r = get(ip, "/", browser)
	out = append(out, flow("flow-11", "attacker rotating 5 User-Agents (25 404s + .env + .git) → banned", r.status == 403, fmt.Sprintf("HTTP %d", r.status)))

	// F12 sensitive-path escalation
	ip = flowIP()
	s1 := get(ip, "/.env", browser).status
	s2 := get(ip, "/.git/config", browser).status
	s3 := get(ip, "/wp-admin/", browser).status
	s4 := get(ip, "/", browser).status
	out = append(out, flow("flow-12", "sensitive probes escalate: .env (allow) → .git (tarpit) → wp-admin (ban)",
		s1 == 404 && s2 == 429 && (s3 == 403 || s3 == 429) && s4 == 403, fmt.Sprintf("%d,%d,%d,%d", s1, s2, s3, s4)))

	// F13 CVE spray from one IP (scanner running templates)
	ip = flowIP()
	spray := []func() resp{
		func() resp {
			return get(ip, "/admin", map[string]string{"X-Middleware-Subrequest": "middleware:middleware:middleware"})
		},
		func() resp { return get(ip, "/hax?jsp=/app/rest/users;.jsp", nil) },
		func() resp {
			return get(ip, "/geoserver/wfs?valueReference=exec(java.lang.Runtime.getRuntime(),'id')", nil)
		},
		func() resp { return get(ip, "/products", browser) },
	}
	var codes []string
	for _, f := range spray {
		codes = append(codes, strconv.Itoa(f().status))
	}
	out = append(out, flow("flow-13", "CVE template spray from one IP → blocked then banned", codes[0] == "403" && codes[3] == "403", strings.Join(codes, ",")))

	// F14 one accidental bad input does not ban a real user
	ip = flowIP()
	a := get(ip, "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", browser).status
	b := get(ip, "/products", browser).status
	out = append(out, flow("flow-14", "single suspicious search → that request blocked, next request served", a == 403 && b == 200, fmt.Sprintf("%d then %d", a, b)))

	// F15 fake Googlebot from a public address without googlebot.com rDNS
	ip = flowIP()
	gb := map[string]string{"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"}
	get(ip, "/products", gb) // triggers async verification
	time.Sleep(3 * time.Second)
	var seq []string
	for i := 0; i < 4; i++ {
		seq = append(seq, strconv.Itoa(get(ip, "/products", gb).status))
	}
	out = append(out, flow("flow-15", "fake Googlebot (no googlebot.com rDNS) → throttled after verification",
		strings.Contains(strings.Join(seq, ","), "429") || strings.Contains(strings.Join(seq, ","), "403"), strings.Join(seq, ",")))

	// F16 real Googlebot address following 45 stale links: never banned
	if names, err := net.LookupAddr("66.249.66.1"); err == nil && len(names) > 0 {
		get("66.249.66.1", "/", gb)
		time.Sleep(3 * time.Second)
		bad = 0
		for i := 0; i < 45; i++ {
			if st := get("66.249.66.1", fmt.Sprintf("/old-link-%d", i), gb).status; st == 403 || st == 429 {
				bad++
			}
		}
		out = append(out, flow("flow-16", "verified Googlebot (rDNS "+strings.TrimSuffix(names[0], ".")+") follows 45 dead links → never blocked", bad == 0, fmt.Sprintf("%d blocked", bad)))
	} else {
		r := flow("flow-16", "verified Googlebot follows dead links", false, "")
		r.Gap = "no outbound DNS in this environment: " + fmt.Sprint(err)
		out = append(out, r)
	}
	return out
}

// runSpoofFlows: forged X-Forwarded-For traffic. Run in a dedicated container
// (its own TCP peer): the last flow gets that peer banned.
func runSpoofFlows() []result {
	var out []result
	// S1 corporate proxy: many employees from ONE internal network
	bad := 0
	for i := 1; i <= 30; i++ {
		st := send(fmt.Sprintf("10.1.%d.%d", i%3, i), "GET", []string{"/", "/products", "/search?q=kopi", "/api/users/42"}[i%4], map[string]string{"User-Agent": "Mozilla/5.0 Chrome/130"}, "").status
		if st == 403 || st == 429 {
			bad++
		}
	}
	out = append(out, flow("spoof-01", "corporate proxy: 30 users from one internal /16 → never blocked", bad == 0, fmt.Sprintf("%d blocked", bad)))

	// S2 the real access log: random internal XFF + rotating fake crawler UAs
	replay := []struct{ xff, path, ua string }{
		{"192.168.60.245", "/.vercel/project.json", "Mozilla/5.0 (compatible; cohere-ai; +https://cohere.com/crawler)"},
		{"10.100.20.99", "/.next/prerender-manifest.json", "Mozilla/5.0 (compatible; ChatGLM-Spider/1.0; +https://zhipuai.cn/)"},
		{"192.168.121.22", "/.next/routes-manifest.json", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)"},
		{"10.184.8.39", "/.netlify/state.json", "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)"},
		{"192.168.179.141", "/.next/server/pages/index.js", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)"},
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
	var codes []string
	served := 0
	for _, l := range replay {
		st := send(l.xff, "GET", l.path, map[string]string{"User-Agent": l.ua}, "").status
		codes = append(codes, strconv.Itoa(st))
		if st != 403 && st != 429 {
			served++
		}
	}
	out = append(out, flow("spoof-02", "replay of the real log (15 probes, rotating internal XFF + fake crawler UAs) → stopped early", served <= 8 && codes[len(codes)-1] == "403", strings.Join(codes, ",")))

	// S3 the scanner is held accountable by its TCP address, whatever it claims
	st1 := send("8.8.8.8", "GET", "/products", map[string]string{"User-Agent": "Mozilla/5.0 Chrome/130"}, "").status
	st2 := send("", "GET", "/products", map[string]string{"User-Agent": "Mozilla/5.0 Chrome/130"}, "").status
	out = append(out, flow("spoof-03", "after the replay, a clean request with a new forged or no XFF is still refused (peer banned)", st1 == 403 && st2 == 403, fmt.Sprintf("%d,%d", st1, st2)))
	return out
}
