package cloudflare

import (
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// Cloudflare WAF custom rules generated from Bima's signatures.
//
// Rules are built as data (Cond) and rendered to the Cloudflare Rules
// language. The same data is evaluated in Go (Match) so the generated rules
// are tested against Bima's scenario corpus. Only fields and functions that
// work on every plan are used (lower, url_decode, contains, starts_with,
// ends_with, in, cf.client.bot, ip.src.asnum, IP lists); request bodies are
// not visible to Cloudflare custom rules below Enterprise, which is what Bima
// at the origin is for.

// MaxExpression is Cloudflare's limit on the length of a rule expression.
const MaxExpression = 4096

// RefPrefix marks rules managed by Bima in a zone's custom ruleset.
const RefPrefix = "bima_"

// DescPrefix starts the description of every Bima-managed rule.
const DescPrefix = "[bima] "

// Req is the subset of a request that the generated rules look at.
type Req struct {
	Host, URI, UA, Referer string // URI = raw path?query as received
	Headers                [][2]string
	ASN                    int
	VerifiedBot            bool // cf.client.bot
	InList                 bool // ip.src in $<list>
}

func (r *Req) path() string { p, _, _ := strings.Cut(r.URI, "?"); return p }

// Field is a request field as written in a rule, with its Go equivalent.
type Field struct {
	Expr string
	Get  func(*Req) string
}

var (
	fPath = Field{"lower(http.request.uri.path)", func(r *Req) string { return strings.ToLower(r.path()) }}
	fURI  = Field{`lower(url_decode(http.request.uri,"r"))`, func(r *Req) string { return strings.ToLower(decodeAll(r.URI)) }}
	fUA   = Field{"lower(http.user_agent)", func(r *Req) string { return strings.ToLower(r.UA) }}
	fHost = Field{"http.host", func(r *Req) string { return strings.ToLower(r.Host) }}
	fExt  = Field{"http.request.uri.path.extension", func(r *Req) string { return extension(r.path()) }}
)

// decodeAll mirrors url_decode(x, "r"): recursive percent-decoding, '+' to space.
func decodeAll(s string) string {
	for range 4 {
		d, err := url.PathUnescape(strings.ReplaceAll(s, "+", " "))
		if err != nil || d == s {
			return s
		}
		s = d
	}
	return s
}

func extension(p string) string {
	seg := p[strings.LastIndexByte(p, '/')+1:]
	i := strings.LastIndexByte(seg, '.')
	if i < 0 {
		return ""
	}
	return strings.ToLower(seg[i+1:])
}

// Cond is one boolean expression.
type Cond interface {
	Expr() string
	Match(*Req) bool
}

type op int

const (
	opContains op = iota
	opPrefix
	opSuffix
	opEq
)

// anyOf matches when field <op> any token.
type anyOf struct {
	f    Field
	op   op
	toks []string
}

func quote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

func (a anyOf) one(t string) string {
	switch a.op {
	case opPrefix:
		return "starts_with(" + a.f.Expr + ", " + quote(t) + ")"
	case opSuffix:
		return "ends_with(" + a.f.Expr + ", " + quote(t) + ")"
	case opEq:
		return a.f.Expr + " eq " + quote(t)
	}
	return a.f.Expr + " contains " + quote(t)
}

func (a anyOf) Expr() string {
	parts := make([]string, len(a.toks))
	for i, t := range a.toks {
		parts[i] = a.one(t)
	}
	return strings.Join(parts, " or ")
}

func (a anyOf) Match(r *Req) bool {
	v := a.f.Get(r)
	for _, t := range a.toks {
		switch {
		case a.op == opContains && strings.Contains(v, t),
			a.op == opPrefix && strings.HasPrefix(v, t),
			a.op == opSuffix && strings.HasSuffix(v, t),
			a.op == opEq && v == t:
			return true
		}
	}
	return false
}

// inSet: field in {"a" "b"} (exact, one comparison for the whole set).
type inSet struct {
	f    Field
	vals []string
}

func (s inSet) Expr() string {
	q := make([]string, len(s.vals))
	for i, v := range s.vals {
		q[i] = quote(v)
	}
	return s.f.Expr + " in {" + strings.Join(q, " ") + "}"
}
func (s inSet) Match(r *Req) bool { return slices.Contains(s.vals, s.f.Get(r)) }

type all []Cond
type some []Cond
type not struct{ c Cond }

func group(c Cond) string {
	switch c.(type) {
	case all, some, anyOf:
		return "(" + c.Expr() + ")"
	}
	return c.Expr()
}

func (a all) Expr() string {
	p := make([]string, len(a))
	for i, c := range a {
		p[i] = group(c)
	}
	return strings.Join(p, " and ")
}
func (a all) Match(r *Req) bool {
	for _, c := range a {
		if !c.Match(r) {
			return false
		}
	}
	return true
}

func (s some) Expr() string {
	p := make([]string, len(s))
	for i, c := range s {
		p[i] = group(c)
	}
	return strings.Join(p, " or ")
}
func (s some) Match(r *Req) bool {
	for _, c := range s {
		if c.Match(r) {
			return true
		}
	}
	return false
}

func (n not) Expr() string      { return "not " + group(n.c) }
func (n not) Match(r *Req) bool { return !n.c.Match(r) }

// raw is a field-specific expression with its Go equivalent.
type raw struct {
	expr string
	m    func(*Req) bool
}

func (x raw) Expr() string      { return x.expr }
func (x raw) Match(r *Req) bool { return x.m(r) }

var verifiedBot = raw{"cf.client.bot", func(r *Req) bool { return r.VerifiedBot }}

// Rule is one Cloudflare custom rule.
type Rule struct {
	Ref         string `json:"ref"`
	Description string `json:"description"`
	Action      string `json:"action"`
	Expression  string `json:"expression"`
	Enabled     bool   `json:"enabled"`
	cond        Cond
}

// Match evaluates the rule in Go (tests / dry runs).
func (r Rule) Match(q *Req) bool { return r.cond.Match(q) }

// Options tune the generated rules. The zero value plus DefaultOptions gives
// Bima's default rule set; site-specific exemptions are opt-in.
type Options struct {
	Action        string   // block (default) | managed_challenge | js_challenge | log (Enterprise)
	ListName      string   // IP list with Bima bans ("" = no blocklist rule)
	ScriptHosts   []string // hosts that legitimately serve .php/.asp/WordPress paths
	ExemptPaths   []string // path prefixes skipped by the injection rules
	AIBots        bool     // also block AI crawlers / assistants
	CloudASNs     []int    // block bot-like UAs (unverified) from these ASNs
	EmptyUA       bool     // block requests without a User-Agent
	EmptyUAHosts  []string // ... except on these hosts (APIs)
	FakeCrawlers  bool     // block UAs claiming a search crawler that Cloudflare did not verify
	ScannerAgents bool     // block vulnerability scanner User-Agents
}

func DefaultOptions() Options {
	return Options{Action: "block", ListName: "bima_blocklist", FakeCrawlers: true, ScannerAgents: true}
}

// Token lists. They mirror Bima's signatures (internal/detect) and the
// sensitive-path / scanner lists (internal/enum) in literal form.
var (
	sensitiveContains = []string{
		"private-key", "privatekey", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
		"/prisma/", ".prisma", "wp-config", "nuxt.config", "next.config", "vite.config", "webpack.config",
		"docker-compose", "terraform.tfstate", "appsettings.", "credentials.json", "/node_modules/",
		"/phpinfo", "phpmyadmin", "/adminer", "/server-status", "/server-info", "/actuator",
		"/_profiler", "/telescope", "web.config", "elmah.axd", "trace.axd", "/solr/admin",
		"/jmx-console", "/manager/html",
		"/cgi-bin/", "/boaform/", "/goform/", "/hnap1",
	}
	sensitiveSuffix = []string{"/package.json", "/package-lock.json", "/composer.json", "/composer.lock",
		"/yarn.lock", "/tsconfig.json", "/gemfile", "/requirements.txt"}
	sensitiveExt = []string{"env", "key", "pem", "p12", "pfx", "jks", "keystore", "kdbx", "ovpn", "rdp",
		"sql", "sqlite", "sqlite3", "db", "mdb", "bak", "old", "orig", "save", "swp", "tfstate",
		"tar", "tgz", "7z", "rar", "log", "ini", "conf", "cfg"}
	scriptExt = []string{"phtml", "php3", "php5", "phar", "asp", "aspx", "jsp", "jspx", "cgi", "pl"}
	wordpress = []string{".php", "/wp-admin", "/wp-login", "/wp-content", "/wp-includes", "/wp-json", "/wp-cron", "/wp-signup", "/wp-trackback", "xmlrpc"}
	// URI injection tokens (decoded, lowercased). One list, packed into as
	// many rules as the 4096-char expression limit needs (two by default).
	injectionTokens = []string{
		// shells, commands, system files
		"/bin/sh", "/bin/bash", "/bin/busybox", "cmd.exe", "powershell", "/etc/passwd", "/etc/shadow",
		"/proc/self/", "win.ini", "/dev/tcp/", "wget http", "curl http", "chmod ", "bash -i", "nc -e",
		";cat ", "|cat ", "$(",
		// Log4Shell/JNDI and its obfuscations (${${::-j}ndi:, ${lower:j}...), ${IFS}, ${7*7}
		"${jndi:", "${${", "${::-", "${lower:", "${upper:", "${env:", "${sys:", "${ifs", "${7*",
		// PHP
		"<?", "php://", "phar://", "data://", "expect://", "zip://", "allow_url_include", "auto_prepend_file",
		"passthru(", "system(", "exec(", "eval(", "assert(", "base64_decode(", "phpunit",
		"invokefunction", "call_user_func",
		// SSRF
		"file://", "gopher://", "dict://", "ldap://", "169.254.169.254", "metadata.google.internal", "100.100.100.200",
		"://127.", "://0.0.0.0", "://0x7f", "://2852039166", "://[::",
		// SSTI / OGNL / Spring4Shell
		"{{", "{%", "<%=", "#{7*", "__proto__", "constructor[prototype]", "__class__", "__globals__", "__import__", "getruntime(",
		"processbuilder", "class.module.classloader", "%{(",
		// SQL injection
		"union select", "union all select", "information_schema", "sleep(", "benchmark(",
		"waitfor delay", "' or ", "'or'", "or 1=1", "'--", "/**/", "drop table", "order by 1", "\" or \"1\"=\"1", "load_file(", "into outfile",
		"xp_cmdshell", "extractvalue(", "updatexml(", "@@version", "[$ne]", "[$gt]", "[$regex]", "[$where]",
		// XSS
		"<script", "javascript:", "onerror=", "onload=", "onmouseover=", "<svg", "<iframe",
		"document.cookie", "alert(", "prompt(", "string.fromcharcode",
		// traversal (after decoding; also catches double encoding)
		"../..", "/../", "..\\..", "..;/", "boot.ini",
	}
	scannerUAs = []string{"sqlmap", "nikto", "nuclei", "zgrab", "masscan", "dirbuster", "dirsearch", "gobuster",
		"wpscan", "acunetix", "nessus", "nmap", "ffuf", "fuzz faster u fool", "feroxbuster", "wfuzz", "whatweb",
		"openvas", "netsparker", "jaeles", "arachni", "w3af", "commix", "xsstrike", "hydra", "interactsh",
		"qualys", "appscan", "jorgee", "zmeu", "dirb/", "httpx - open-source", "katana"}
	crawlerUAs = []string{"googlebot", "google-inspectiontool", "adsbot-google", "bingbot", "applebot",
		"duckduckbot", "yandexbot", "baiduspider", "bravebot"}
	aiUAs = []string{"gptbot", "chatgpt", "oai-", "openai", "claude", "anthropic", "perplexity", "qwen",
		"chatglm", "zhipu", "kimi", "deepseek", "mistral", "gemini", "meta-externalagent", "meta-externalfetcher",
		"meta-webindexer", "bytespider", "ccbot", "cohere", "youbot", "duckassistbot", "amazonbot",
		"applebot-extended", "diffbot", "ai2bot", "timpibot", "img2dataset", "omgili", "iaskspider", "petalbot", "novaact"}
	botWords = []string{"bot", "spider", "crawler"}
	// payloads in any header value (User-Agent, Referer, Cookie, Content-Type, ...)
	headerTokens = []string{"${", "%{(", "() {", "<?php", "#_memberaccess", "/bin/sh", "/bin/bash",
		"/etc/passwd", "/../../", "<script", "union select", "' or '", "'or'", "ro0ab"}
	headerNames = []string{"x-middleware-subrequest"}
)

// Generate returns Bima's Cloudflare custom rules for o.
func Generate(o Options) ([]Rule, error) {
	if o.Action == "" {
		o.Action = "block"
	}
	switch o.Action {
	case "block", "managed_challenge", "js_challenge", "challenge", "log":
	default:
		return nil, fmt.Errorf("action %q: use block, managed_challenge, js_challenge, challenge or log", o.Action)
	}
	if o.ListName != "" && !validListName(o.ListName) {
		return nil, fmt.Errorf("list name %q: only lowercase letters, digits and underscores (max 50)", o.ListName)
	}
	var rules []Rule
	add := func(ref, desc string, c Cond) {
		rules = append(rules, Rule{Ref: RefPrefix + ref, Description: DescPrefix + desc, Action: o.Action, Enabled: true, cond: c})
	}
	if o.ListName != "" {
		name := o.ListName
		add("blocklist", "IPs banned by Bima (synced list)", raw{"ip.src in $" + name, func(r *Req) bool { return r.InList }})
	}

	// 1. sensitive files / config probes
	scripts := some{anyOf{fPath, opContains, wordpress}, inSet{fExt, scriptExt}}
	var scriptCond Cond = scripts
	if len(o.ScriptHosts) > 0 {
		scriptCond = all{not{inSet{fHost, lowerAll(o.ScriptHosts)}}, scripts}
	}
	add("sensitive", "Block sensitive file scanners", some{
		all{anyOf{fPath, opContains, []string{"/."}}, not{anyOf{fPath, opPrefix, []string{"/.well-known/"}}}},
		inSet{fExt, sensitiveExt},
		anyOf{fPath, opContains, sensitiveContains},
		anyOf{fPath, opSuffix, sensitiveSuffix},
		scriptCond,
	})

	// 2. injection in the URI (packed into several rules) and headers
	exemptPaths := lowerAll(o.ExemptPaths)
	exempt := func(c Cond) Cond {
		if len(exemptPaths) == 0 {
			return c
		}
		return all{not{anyOf{fPath, opPrefix, exemptPaths}}, c}
	}
	headers := some{headerValues(headerTokens), headerNamed(headerNames),
		raw{`http.host contains "/"`, func(r *Req) bool { return strings.Contains(r.Host, "/") }}}
	chunks := pack(injectionTokens, func(toks []string, first bool) Cond {
		c := some{exempt(anyOf{fURI, opContains, toks})}
		if first {
			c = append(c, headers) // header payloads are never path-exempt
		}
		return c
	})
	for i, c := range chunks {
		ref, desc := "injection", "Block injection in URI and headers: RCE, Log4Shell, PHP, SSRF, SSTI, SQLi, NoSQL, XSS, traversal"
		if len(chunks) > 1 {
			ref += "_" + strconv.Itoa(i+1)
			desc += fmt.Sprintf(" (%d/%d)", i+1, len(chunks))
		}
		add(ref, desc, c)
	}

	// 3. bad clients: scanners, fake crawlers, optional bot policies
	var bots some
	var what []string
	if o.ScannerAgents {
		bots = append(bots, anyOf{fUA, opContains, scannerUAs})
		what = append(what, "scanner tools")
	}
	if o.FakeCrawlers {
		bots = append(bots, all{anyOf{fUA, opContains, crawlerUAs}, not{verifiedBot}})
		what = append(what, "fake crawlers")
	}
	if o.AIBots {
		bots = append(bots, anyOf{fUA, opContains, aiUAs})
		what = append(what, "AI bots")
	}
	if len(o.CloudASNs) > 0 {
		asns := make([]string, len(o.CloudASNs))
		for i, a := range o.CloudASNs {
			asns[i] = strconv.Itoa(a)
		}
		bots = append(bots, all{
			raw{"ip.src.asnum in {" + strings.Join(asns, " ") + "}", func(r *Req) bool { return slices.Contains(o.CloudASNs, r.ASN) }},
			not{verifiedBot}, anyOf{fUA, opContains, botWords}})
		what = append(what, "unverified bots from cloud ASNs")
	}
	if o.EmptyUA {
		var c Cond = raw{`http.user_agent eq ""`, func(r *Req) bool { return r.UA == "" }}
		if len(o.EmptyUAHosts) > 0 {
			c = all{c, not{inSet{fHost, lowerAll(o.EmptyUAHosts)}}}
		}
		bots = append(bots, c)
		what = append(what, "empty User-Agent")
	}
	if len(bots) > 0 {
		add("clients", "Block "+strings.Join(what, ", "), bots)
	}

	for i := range rules {
		rules[i].Expression = rules[i].cond.Expr()
		if n := len(rules[i].Expression); n > MaxExpression {
			return nil, fmt.Errorf("rule %s: expression is %d chars (Cloudflare limit %d)", rules[i].Ref, n, MaxExpression)
		}
	}
	return rules, nil
}

func lowerAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(strings.TrimSpace(s))
	}
	return out
}

func validListName(s string) bool {
	if s == "" || len(s) > 50 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// headerValues: any request header value (lowercased) contains a token.
func headerValues(toks []string) Cond {
	parts := make([]string, len(toks))
	for i, t := range toks {
		parts[i] = "any(lower(http.request.headers.values[*])[*] contains " + quote(t) + ")"
	}
	return raw{"(" + strings.Join(parts, " or ") + ")", func(r *Req) bool {
		hs := r.Headers
		if hs == nil {
			hs = [][2]string{{"user-agent", r.UA}, {"referer", r.Referer}}
		}
		for _, h := range hs {
			v := strings.ToLower(h[1])
			for _, t := range toks {
				if strings.Contains(v, t) {
					return true
				}
			}
		}
		return false
	}}
}

// headerNamed: a request header with one of these (lowercase) names is present.
func headerNamed(names []string) Cond {
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = quote(n)
	}
	return raw{"any(lower(http.request.headers.names[*])[*] in {" + strings.Join(q, " ") + "})", func(r *Req) bool {
		for _, h := range r.Headers {
			if slices.Contains(names, strings.ToLower(h[0])) {
				return true
			}
		}
		return false
	}}
}

// pack splits toks into the fewest consecutive groups whose rendered
// expression (build) stays under MaxExpression.
func pack(toks []string, build func(toks []string, first bool) Cond) []Cond {
	var out []Cond
	for len(toks) > 0 {
		first := len(out) == 0
		n := 1
		for n < len(toks) && len(build(toks[:n+1], first).Expr()) <= MaxExpression {
			n++
		}
		out = append(out, build(toks[:n], first))
		toks = toks[n:]
	}
	return out
}

// FirstMatch returns the ref of the first rule matching q ("" if none).
func FirstMatch(rules []Rule, q *Req) string {
	for _, r := range rules {
		if r.Match(q) {
			return r.Ref
		}
	}
	return ""
}
