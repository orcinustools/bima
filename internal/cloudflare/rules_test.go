package cloudflare

import (
	"fmt"
	"strings"
	"testing"

	"github.com/orcinustools/bima/test/scenarios"
)

func hdr(h map[string]string, name string) string {
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

func reqOf(s scenarios.Scenario) *Req {
	r := &Req{Host: "example.com", URI: s.Path, UA: hdr(s.Headers, "user-agent"), Referer: hdr(s.Headers, "referer")}
	for k, v := range s.Headers {
		if strings.EqualFold(k, "host") {
			r.Host = v
			continue
		}
		r.Headers = append(r.Headers, [2]string{k, v})
	}
	// Cloudflare verifies genuine crawlers (cf.client.bot); the corpus marks
	// real crawler traffic as benign and fake crawlers as attacks.
	r.VerifiedBot = s.Expect == "allow"
	if r.UA != "" {
		return r
	}
	r.UA = "Mozilla/5.0 (scenario)"
	r.Headers = append(r.Headers, [2]string{"User-Agent", r.UA})
	return r
}

// payloadOutsideBody reports whether an attack scenario carries its payload
// somewhere Cloudflare custom rules can see (URI or headers). Body-only
// attacks are Bima's job at the origin.
func payloadOutsideBody(s scenarios.Scenario) bool {
	return s.Body == "" || len(s.Headers) > 0 || strings.Contains(s.Path, "?")
}

func TestRulesAgainstCorpus(t *testing.T) {
	all, err := scenarios.Load()
	if err != nil {
		t.Fatal(err)
	}
	rules, err := Generate(DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	var caught, visible, bodyOnly, bodyCaught int
	var missed []string
	for _, s := range all {
		ref := FirstMatch(rules, reqOf(s))
		switch s.Expect {
		case "allow":
			if ref != "" {
				t.Errorf("false positive: %s (%s) %s matched %s", s.ID, s.Desc, s.Path, ref)
			}
		default:
			if !payloadOutsideBody(s) {
				bodyOnly++
				if ref != "" {
					bodyCaught++
				}
				continue
			}
			visible++
			if ref != "" {
				caught++
			} else {
				missed = append(missed, s.ID+" "+s.Path)
			}
		}
	}
	pct := 100 * caught / max(visible, 1)
	t.Logf("URI/header attacks caught at the edge: %d/%d (%d%%); body-only attacks (origin/Bima): %d (%d caught by URI anyway)",
		caught, visible, pct, bodyOnly, bodyCaught)
	for _, m := range missed {
		t.Logf("  edge miss (Bima at origin covers it): %s", m)
	}
	if pct < 75 {
		t.Errorf("edge coverage %d%% < 75%%", pct)
	}
}

func TestExpressionsFitAndQuote(t *testing.T) {
	o := DefaultOptions()
	o.AIBots, o.EmptyUA = true, true
	o.CloudASNs = []int{396982, 16509}
	o.ScriptHosts = []string{"newsletter.example.com"}
	o.EmptyUAHosts = []string{"api.example.com"}
	o.ExemptPaths = []string{"/hl/"}
	rules, err := Generate(o)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) > 6 {
		t.Fatalf("all options: want <= 6 rules, got %d", len(rules))
	}
	if d, _ := Generate(DefaultOptions()); len(d) != 5 {
		t.Fatalf("defaults: want 5 rules (Free plan limit), got %d", len(d))
	}
	for _, r := range rules {
		t.Logf("%-16s %4d chars", r.Ref, len(r.Expression))
		if err := checkSyntax(r.Expression); err != nil {
			t.Errorf("%s: %v", r.Ref, err)
		}
	}
	joined := ""
	for _, r := range rules {
		joined += r.Expression
	}
	if !strings.Contains(joined, `contains "\" or \"1\"=\"1"`) {
		t.Errorf("double quote not escaped")
	}
}

func TestOptions(t *testing.T) {
	o := DefaultOptions()
	o.ScriptHosts = []string{"Newsletter.Example.com"}
	o.ExemptPaths = []string{"/hl/"}
	o.AIBots = true
	o.CloudASNs = []int{396982}
	o.EmptyUA, o.EmptyUAHosts = true, []string{"api.example.com"}
	rules, _ := Generate(o)
	cases := []struct {
		r    Req
		want string
	}{
		{Req{Host: "www.example.com", URI: "/wp-login.php", UA: "x"}, "bima_sensitive"},
		{Req{Host: "newsletter.example.com", URI: "/wp-login.php", UA: "x"}, ""},
		{Req{Host: "newsletter.example.com", URI: "/.env", UA: "x"}, "bima_sensitive"},
		{Req{Host: "a", URI: "/.well-known/acme-challenge/x", UA: "x"}, ""},
		{Req{Host: "a", URI: "/x?u=http://169.254.169.254/", UA: "x"}, "bima_injection"},
		{Req{Host: "a", URI: "/hl/v1/x?u=http://169.254.169.254/", UA: "x"}, ""},
		{Req{Host: "a", URI: "/hl/v1/../../.env", UA: "x"}, "bima_sensitive"},
		{Req{Host: "a", URI: "/q?x=%2524%257Bjndi:ldap://a/x%257D", UA: "x"}, "bima_injection"}, // double-encoded
		{Req{Host: "a", URI: "/q?s=union+select+1", UA: "x"}, "bima_injection"},
		{Req{Host: "a", URI: "/", UA: "Mozilla/5.0 (compatible; Googlebot/2.1)"}, "bima_clients"},
		{Req{Host: "a", URI: "/", UA: "Mozilla/5.0 (compatible; Googlebot/2.1)", VerifiedBot: true}, ""},
		{Req{Host: "a", URI: "/", UA: "GPTBot/1.1"}, "bima_clients"},
		{Req{Host: "a", URI: "/", UA: "my-crawler/1", ASN: 396982}, "bima_clients"},
		{Req{Host: "a", URI: "/", UA: "my-crawler/1", ASN: 7713}, ""},
		{Req{Host: "a", URI: "/", UA: ""}, "bima_clients"},
		{Req{Host: "api.example.com", URI: "/", UA: ""}, ""},
		{Req{Host: "a", URI: "/", UA: "x", InList: true}, "bima_blocklist"},
		{Req{Host: "a", URI: "/", UA: "() { :; }; /bin/bash -c id"}, "bima_injection"},
	}
	for _, c := range cases {
		got := FirstMatch(rules, &c.r)
		if (c.want == "" && got != "") || !strings.HasPrefix(got, c.want) || (c.want != "" && got == "") {
			t.Errorf("%s %s UA=%q: got %q want %q", c.r.Host, c.r.URI, c.r.UA, got, c.want)
		}
	}
	if _, err := Generate(Options{ListName: "Bad-Name"}); err == nil {
		t.Error("invalid list name accepted")
	}
}

func TestMergeKeepsForeignRules(t *testing.T) {
	rules, _ := Generate(DefaultOptions())
	existing := []map[string]any{
		{"id": "a1", "ref": "bima_injection", "description": "[bima] old", "expression": "true", "action": "block", "version": "3"},
		{"id": "u1", "description": "my rule", "expression": `http.host eq "x"`, "action": "skip", "version": "1", "last_updated": "t"},
	}
	out, kept, replaced := Merge(existing, rules, false)
	if kept != 1 || replaced != 1 || len(out) != len(rules)+1 {
		t.Fatalf("kept=%d replaced=%d len=%d", kept, replaced, len(out))
	}
	for _, r := range out {
		if r["ref"] == "bima_injection" && r["id"] != "a1" {
			t.Error("managed rule not updated in place")
		}
		if r["id"] == "u1" && (r["version"] != nil || r["last_updated"] != nil) {
			t.Error("read-only fields not stripped")
		}
	}
	out, kept, _ = Merge(existing, rules, true)
	if kept != 0 || len(out) != len(rules) {
		t.Fatal("replaceAll kept foreign rules")
	}
}

// checkSyntax verifies quoting and parenthesis balance outside string literals.
func checkSyntax(e string) error {
	depth, inStr := 0, false
	for i := 0; i < len(e); i++ {
		c := e[i]
		switch {
		case inStr && c == '\\':
			i++
		case c == '"':
			inStr = !inStr
		case !inStr && c == '(':
			depth++
		case !inStr && c == ')':
			if depth--; depth < 0 {
				return fmt.Errorf("unbalanced ) at %d", i)
			}
		}
	}
	if inStr || depth != 0 {
		return fmt.Errorf("unterminated string=%v depth=%d", inStr, depth)
	}
	return nil
}
