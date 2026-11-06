// Package engine combines signature detection, CRS, behavioural scoring, bans
// and alerting into a single verdict per request.
package engine

import (
	"fmt"
	"log/slog"
	"mime"
	"net/netip"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/orcinustools/bima/internal/alert"
	"github.com/orcinustools/bima/internal/ban"
	"github.com/orcinustools/bima/internal/config"
	"github.com/orcinustools/bima/internal/detect"
	"github.com/orcinustools/bima/internal/enum"
	"github.com/orcinustools/bima/internal/fingerprint"
	"github.com/orcinustools/bima/internal/geoip"
	"github.com/orcinustools/bima/internal/metrics"
)

type Action string

const (
	Allow  Action = "allow"
	Tarpit Action = "tarpit"
	Block  Action = "block"
)

type Request struct {
	ID      string
	IP      netip.Addr
	Method  string
	Path    string
	Query   string
	Version string
	Headers [][2]string
	Body    []byte
	JA3     string     // empty for plain HTTP
	Peer    netip.Addr // TCP peer (HAProxy fc_src); IP may differ when taken from a header
}

func (r *Request) Header(name string) string {
	for _, h := range r.Headers {
		if strings.EqualFold(h[0], name) {
			return h[1]
		}
	}
	return ""
}

type Verdict struct {
	Action Action
	Score  float64
	RuleID string
	FP     string // client fingerprint, echoed back by HAProxy on the response
}

type Engine struct {
	cfg    *config.Config
	crs    *detect.CRS
	scorer *enum.Scorer
	bans   *ban.Manager
	alerts *alert.Alerter
	geo    *geoip.DB
	Report *Report

	crsSlots chan struct{} // bounds concurrent CRS evaluations
	spoof    *spoofTracker
	bots     *botVerifier
}

func New(cfg *config.Config, crs *detect.CRS, scorer *enum.Scorer, bans *ban.Manager, alerts *alert.Alerter, geo *geoip.DB) *Engine {
	metrics.Mode.WithLabelValues(string(cfg.Mode)).Set(1)
	if cfg.CRS.Timeout <= 0 {
		cfg.CRS.Timeout = 50 * time.Millisecond
	}
	e := &Engine{cfg: cfg, crs: crs, scorer: scorer, bans: bans, alerts: alerts, geo: geo, Report: newReport(),
		crsSlots: make(chan struct{}, 4*runtime.NumCPU()),
		spoof:    newSpoofTracker(scorer.Store(), cfg.Score.Window)}
	if cfg.Bots.Verify {
		e.bots = newBotVerifier(nil, cfg.Bots.Timeout)
	}
	return e
}

// ResetIP clears the behavioural score of ip (manual unban).
func (e *Engine) ResetIP(ip string) { e.scorer.ResetScore(ip) }

// SetResolver replaces the DNS resolver used for crawler verification (tests).
func (e *Engine) SetResolver(r Resolver) {
	if e.bots != nil {
		e.bots = newBotVerifier(r, e.cfg.Bots.Timeout)
	}
}

// targets splits request data into individually inspected values so that
// structural separators (& in query strings, ; in cookies) are not mistaken
// for shell metacharacters.
func (e *Engine) targets(r *Request) []detect.Target {
	t := []detect.Target{{Location: "path", Raw: r.Path}}
	if r.Query != "" {
		addValues(&t, "query", r.Query)
	}
	for _, h := range r.Headers {
		name := strings.ToLower(h[0])
		switch name {
		case "host", "content-length", "accept", "accept-encoding", "accept-language", "connection":
			continue
		case "cookie":
			for c := range strings.SplitSeq(h[1], ";") {
				k, v, _ := strings.Cut(strings.TrimSpace(c), "=")
				t = append(t, detect.Target{Location: "cookie:" + k, Raw: v})
			}
		default:
			t = append(t, detect.Target{Location: "header:" + name, Raw: h[1]})
		}
	}
	if len(r.Body) > 0 {
		body := r.Body
		if len(body) > e.cfg.MaxBodyInspect {
			body = body[:e.cfg.MaxBodyInspect]
		}
		ct, _, _ := mime.ParseMediaType(r.Header("content-type"))
		switch ct {
		case "application/x-www-form-urlencoded":
			addValues(&t, "body", string(body))
		case "image/png", "image/jpeg", "image/gif", "image/webp", "video/mp4", "application/octet-stream", "application/zip", "application/pdf":
			// binary: skip content inspection
		default:
			t = append(t, detect.Target{Location: "body", Raw: string(body)})
		}
	}
	return t
}

func addValues(t *[]detect.Target, prefix, raw string) {
	for pair := range strings.SplitSeq(raw, "&") {
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		if dk, err := url.QueryUnescape(k); err == nil {
			k = dk
		}
		// keep v raw; the normalizer decodes it (possibly repeatedly)
		*t = append(*t, detect.Target{Location: prefix + ":" + k, Raw: v})
		*t = append(*t, detect.Target{Location: prefix + "-name", Raw: k})
	}
}

// inspectCRS runs CRS under its own deadline (well below the SPOE timeout) and
// a concurrency cap. If CRS cannot answer in time the verdict is taken from the
// other layers: an attacker must not be able to make the agent time out
// (HAProxy would fail open) by sending bodies that are expensive for CRS.
func (e *Engine) inspectCRS(req *detect.Request) *detect.Finding {
	select {
	case e.crsSlots <- struct{}{}:
	default:
		metrics.CRSOverload.Inc()
		return nil
	}
	ch := make(chan *detect.Finding, 1)
	go func() {
		defer func() { <-e.crsSlots }()
		ch <- e.crs.Inspect(req)
	}()
	select {
	case f := <-ch:
		return f
	case <-time.After(e.cfg.CRS.Timeout):
		metrics.CRSTimeouts.Inc()
		slog.Warn("CRS deadline exceeded; verdict from signatures only", "ip", req.ClientIP, "uri", snippet(req.URI, 120), "body_bytes", len(req.Body))
		return nil
	}
}

// plainValue: characters that cannot form an injection payload on their own.
func plainValue(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == ',' || c == '@' || c == '-') {
			return false
		}
	}
	return true
}

// standardHeaders carry structured, browser-generated values (;, (, =, *, /
// are normal there); they only force CRS when they contain characters used by
// injection payloads.
var standardHeaders = map[string]bool{
	"host": true, "user-agent": true, "accept": true, "accept-encoding": true, "accept-language": true,
	"connection": true, "content-type": true, "content-length": true, "cache-control": true, "pragma": true,
	"referer": true, "origin": true, "upgrade-insecure-requests": true, "dnt": true, "te": true,
	"sec-fetch-site": true, "sec-fetch-mode": true, "sec-fetch-dest": true, "sec-fetch-user": true,
	"sec-ch-ua": true, "sec-ch-ua-mobile": true, "sec-ch-ua-platform": true, "priority": true,
	"x-forwarded-for": true, "x-forwarded-proto": true, "x-real-ip": true, "x-request-id": true,
	"if-none-match": true, "if-modified-since": true, "authorization": true,
}

const dangerous = "<>'\"`${}|\\"

// crsNeeded reports whether CRS must inspect r. It returns false only when
// every input is trivially plain; anything else (bodies, encoded or
// punctuated values, custom headers, odd standard headers) goes to CRS.
func crsNeeded(r *Request) bool {
	if len(r.Body) > 0 || strings.Contains(r.Path, "..") || strings.ContainsAny(r.Path, "%;'\"<>\\${}|`:=") {
		return true
	}
	if r.Query != "" {
		for pair := range strings.SplitSeq(r.Query, "&") {
			k, v, _ := strings.Cut(pair, "=")
			if !plainValue(k) || !plainValue(v) {
				return true
			}
		}
	}
	for _, h := range r.Headers {
		name := strings.ToLower(h[0])
		switch {
		case name == "cookie":
			for c := range strings.SplitSeq(h[1], ";") {
				k, v, _ := strings.Cut(strings.TrimSpace(c), "=")
				if !plainValue(k) || !plainValue(strings.TrimRight(v, "=")) {
					return true
				}
			}
		case standardHeaders[name]:
			if strings.ContainsAny(h[1], dangerous) {
				return true
			}
		default:
			if !plainValue(h[1]) {
				return true
			}
		}
	}
	return false
}

// crsLocation maps Coraza variable names onto Bima's location scheme
// (path, query:<k>, body[:<k>], header:<h>, cookie:<c>) so exclusions and
// reports use one vocabulary for both engines.
func crsLocation(loc, query string) string {
	v, k, _ := strings.Cut(loc, ":")
	switch v {
	case "args_get":
		return "query:" + k
	case "args_post", "files", "files_names", "request_body", "xml", "json":
		if k == "" {
			return "body"
		}
		return "body:" + k
	case "args":
		if strings.HasPrefix(k, "json.") || strings.HasPrefix(k, "xml") {
			return "body:" + k
		}
		if q, err := url.ParseQuery(query); err == nil && q.Has(k) {
			return "query:" + k
		}
		return "body:" + k
	case "args_names", "args_get_names":
		return "query-name"
	case "args_post_names":
		return "body-name"
	case "request_headers":
		return "header:" + k
	case "request_headers_names":
		return "header-name"
	case "request_cookies", "request_cookies_names":
		return "cookie:" + k
	case "request_uri", "request_uri_raw", "request_filename", "request_basename", "request_line", "request_method", "request_protocol":
		return "path"
	}
	return loc
}

func (e *Engine) excluded(f detect.Finding, path string) bool {
	for i := range e.cfg.Exclusions {
		if e.cfg.Exclusions[i].Match(f.RuleID, path, f.Location) {
			metrics.Excluded.WithLabelValues(f.RuleID).Inc()
			return true
		}
	}
	return false
}

func (e *Engine) filter(fs []detect.Finding, path string) []detect.Finding {
	if len(e.cfg.Exclusions) == 0 {
		return fs
	}
	out := fs[:0]
	for _, f := range fs {
		if !e.excluded(f, path) {
			out = append(out, f)
		}
	}
	return out
}

func (e *Engine) fingerprint(r *Request) string {
	names := make([]string, 0, len(r.Headers))
	for _, h := range r.Headers {
		n := strings.ToLower(h[0])
		switch n {
		case "x-forwarded-for", "x-real-ip", "cookie", "content-length", "x-request-id",
			"x-forwarded-proto", "true-client-ip", "cdn-loop":
			continue // per-request / proxy-added, not client behaviour
		}
		if strings.HasPrefix(n, "cf-") {
			continue // added by Cloudflare
		}
		names = append(names, h[0])
	}
	ja3 := r.JA3
	if e.viaTrustedProxy(r) {
		ja3 = "" // the TLS handshake is the CDN's, not the client's
	}
	return fingerprint.Client(ja3, names, r.Header("user-agent"))
}

// viaTrustedProxy reports whether the request reached HAProxy through a
// configured CDN/LB (the TCP peer is a trusted proxy, not the client).
func (e *Engine) viaTrustedProxy(r *Request) bool {
	if !r.Peer.IsValid() || r.Peer.Unmap() == r.IP.Unmap() {
		return false
	}
	t, _ := e.cfg.Trusted(r.Peer)
	return t
}

// OnRequest is called for each request (SPOE check-request).
func (e *Engine) OnRequest(r *Request) Verdict {
	start := time.Now()
	defer func() { metrics.Inspect.WithLabelValues("total").Observe(time.Since(start).Seconds()) }()
	metrics.Requests.Inc()

	fp := e.fingerprint(r)

	// Decide who is accountable BEFORE the allowlist: a forged
	// X-Forwarded-For must not buy an allowlisted identity.
	var pre []detect.Finding
	claims := forwardedClaims(r.Headers, r.IP)
	// Who is rotating the headers? A public src was appended by a proxy in
	// front of us (the real client): blame it. An internal src means HAProxy
	// took a forged value: blame the TCP peer. Never blame a proxy for its
	// clients' headers.
	key := r.IP
	if !public(r.IP) && r.Peer.IsValid() {
		key = r.Peer
	}
	if f := e.observeSpoofing(key.Unmap().String(), claims); f != nil {
		pre = append(pre, *f)
	}
	claimed := r.IP
	id, reason := e.identity(r.IP, r.Peer)
	r.IP = id
	if reason != "" && e.cfg.Allowed(claimed) && !e.cfg.Allowed(id) {
		pre = append(pre, detect.Finding{RuleID: "BIMA-SPOOF-203", Category: "ip-spoofing", Severity: detect.High,
			Msg:      "Allowlist bypass attempt: forwarding header claims allowlisted " + claimed.String() + " (" + reason + ")",
			Location: "header:x-forwarded-for", Match: claimed.String(), Score: 50, Block: true})
	}
	if len(pre) == 0 && e.cfg.Allowed(r.IP) {
		metrics.Verdicts.WithLabelValues("allow").Inc()
		return Verdict{Action: Allow, FP: fp}
	}
	ip := r.IP.Unmap().String()

	if e.bans.IsBanned(ip) {
		return e.finish(Verdict{Action: Block, Score: e.scorer.Score(ip), RuleID: "BIMA-BANNED", FP: fp})
	}

	t0 := time.Now()
	findings := append(pre, detect.Signatures(e.targets(r))...)
	findings = append(findings, detect.VirtualPatches(&detect.HTTPRequest{Method: r.Method, Path: r.Path, Query: r.Query, Headers: r.Headers, Body: r.Body})...)
	metrics.Inspect.WithLabelValues("signatures").Observe(time.Since(t0).Seconds())
	findings = e.filter(findings, r.Path)

	decided := false
	for _, f := range findings {
		if f.Block {
			decided = true
		}
	}
	// CRS is the expensive layer: skip when signatures/virtual patches already
	// decided to block, or (fast path) when no input can carry a payload.
	runCRS := e.crs != nil && !decided
	if runCRS && e.cfg.CRS.FastPath && !crsNeeded(r) {
		runCRS = false
		metrics.CRSSkipped.Inc()
	}
	if runCRS {
		uri := r.Path
		if r.Query != "" {
			uri += "?" + r.Query
		}
		body := r.Body
		truncated := false
		if len(body) > e.cfg.MaxBodyInspect {
			body, truncated = body[:e.cfg.MaxBodyInspect], true
		}
		if cl, err := strconv.Atoi(r.Header("content-length")); err == nil && cl > len(body) {
			truncated = true // HAProxy only buffered a prefix (tune.bufsize)
		}
		t1 := time.Now()
		f := e.inspectCRS(&detect.Request{ClientIP: ip, Method: r.Method, URI: uri, Version: r.Version, Headers: r.Headers, Body: body, Truncated: truncated})
		metrics.Inspect.WithLabelValues("crs").Observe(time.Since(t1).Seconds())
		if f != nil {
			f.Location = crsLocation(f.Location, r.Query)
			if !e.excluded(*f, r.Path) {
				findings = append(findings, *f)
			}
		}
	}

	var add float64
	for _, f := range findings {
		add += f.Score
	}
	ua := r.Header("user-agent")
	botFs, verifiedBot := e.botFindings(r.IP, ua, enum.IsSensitivePath(r.Path))
	botFs = e.filter(botFs, r.Path)
	for _, f := range botFs {
		add += f.Score
	}
	findings = append(findings, botFs...)
	if verifiedBot {
		ua = "" // verified crawlers are not scored as scanners
	}
	beh, score := e.scorer.ObserveRequest(ip, r.Path, ua, add)
	findings = append(findings, e.filter(beh, r.Path)...)

	v := Verdict{Action: Allow, Score: score, FP: fp}
	for _, f := range findings {
		if f.Block {
			v.Action = Block
			if v.RuleID == "" {
				v.RuleID = f.RuleID
			}
		}
	}
	if v.RuleID == "" && len(findings) > 0 {
		v.RuleID = findings[0].RuleID
	}
	if v.Action == Allow && score >= e.cfg.Score.Tarpit {
		v.Action = Tarpit
	}
	banLabel := ""
	if score >= e.cfg.Score.Ban {
		v.Action = Block
		banLabel = e.ban(ip, score)
	}
	for _, f := range findings {
		e.emit(r, f, v, banLabel, "")
	}
	return e.finish(v)
}

func (e *Engine) groups(ip, fp string) []string {
	var g []string
	for _, by := range e.cfg.Group.By {
		switch by {
		case "asn":
			if info := e.geo.Lookup(ip); info.ASN != 0 {
				g = append(g, "AS"+strconv.FormatUint(uint64(info.ASN), 10))
			}
		case "fingerprint":
			if fp != "" {
				g = append(g, "fp:"+fp)
			}
		}
	}
	return g
}

// OnResponse feeds the response status into the behavioural scorer.
func (e *Engine) OnResponse(id string, ipAddr, peer netip.Addr, method, path string, status int, fp string) {
	metrics.Responses.Inc()
	ipAddr, _ = e.identity(ipAddr, peer)
	if e.cfg.Allowed(ipAddr) {
		return
	}
	if e.bots != nil && status == 404 && e.bots.verified(ipAddr.Unmap()) {
		return // verified crawlers follow stale links; don't score their 404s
	}
	ip := ipAddr.Unmap().String()
	findings, others := e.scorer.ObserveResponse(ip, path, status, e.groups(ip, fp))
	findings = e.filter(findings, path)
	if len(findings) == 0 && len(others) == 0 {
		return
	}
	score := e.scorer.Score(ip)
	v := Verdict{Action: Allow, Score: score}
	if score >= e.cfg.Score.Tarpit {
		v.Action = Tarpit
	}
	banLabel := ""
	if score >= e.cfg.Score.Ban {
		v.Action = Block
		banLabel = e.ban(ip, score)
	}
	// Distributed enumeration: ban the rest of the group too.
	var bannedOthers []string
	for _, o := range others {
		if s := e.scorer.Score(o); s >= e.cfg.Score.Ban {
			if l := e.ban(o, s); l != "" {
				bannedOthers = append(bannedOthers, o)
			}
		}
	}
	extra := ""
	if len(bannedOthers) > 0 {
		extra = fmt.Sprintf("also banned %d IPs: %s", len(bannedOthers), strings.Join(bannedOthers, ", "))
	}
	r := &Request{ID: id, IP: ipAddr, Method: method, Path: path}
	for _, f := range findings {
		e.emit(r, f, v, banLabel, extra)
	}
}

// ban places an escalating ban; returns a label such as "ban 10m" or "" if
// the IP was already banned.
func (e *Engine) ban(ip string, score float64) string {
	if e.cfg.Mode == config.ModeDetect {
		return "would-ban"
	}
	if e.bans.IsBanned(ip) {
		return ""
	}
	if a, err := netip.ParseAddr(ip); err == nil {
		if t, _ := e.cfg.Trusted(a); t {
			// never ban a CDN/LB edge: it would cut off every client behind it
			slog.Error("refusing to ban a trusted proxy address (check set-src / trusted_proxies)", "ip", ip, "score", score)
			return ""
		}
	}
	level := e.scorer.NextBanLevel(ip)
	d, placed, err := e.bans.Ban(ip, level)
	if err != nil {
		slog.Error("ban via runtime api failed (store/agent-side ban still active)", "ip", ip, "err", err)
	}
	if !placed {
		return ""
	}
	metrics.Bans.Inc()
	e.scorer.ResetScore(ip)
	slog.Warn("ip banned", "ip", ip, "duration", d.String(), "level", level, "score", score)
	return "ban " + shortDur(d)
}

func shortDur(d time.Duration) string {
	switch {
	case d >= time.Hour && d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d >= time.Minute && d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	default:
		return d.String()
	}
}

// finish records the verdict metric and applies detect mode.
func (e *Engine) finish(v Verdict) Verdict {
	if e.cfg.Mode == config.ModeDetect && v.Action != Allow {
		metrics.Verdicts.WithLabelValues("would_" + string(v.Action)).Inc()
		return Verdict{Action: Allow, Score: v.Score, RuleID: v.RuleID, FP: v.FP}
	}
	metrics.Verdicts.WithLabelValues(string(v.Action)).Inc()
	return v
}

func (e *Engine) emit(r *Request, f detect.Finding, v Verdict, banLabel, extra string) {
	action := string(v.Action)
	if banLabel != "" {
		action = banLabel + " + block"
	}
	if e.cfg.Mode == config.ModeDetect && v.Action != Allow {
		action = "would-" + strings.TrimPrefix(action, "would-")
	}
	path := r.Path
	if r.Query != "" {
		path += "?" + r.Query
	}
	host := r.Header("host")
	if host == "" {
		host = e.cfg.Host
	}
	ip := r.IP.Unmap().String()
	metrics.Detections.WithLabelValues(f.RuleID, f.Category, f.Severity.String()).Inc()
	e.Report.add(f, ip, path, v.Action != Allow)
	geo := e.geo.Lookup(ip).String()
	msg := f.Msg
	if extra != "" {
		msg += " — " + extra
	}
	slog.Info("detection", "ip", ip, "geo", geo, "rule", f.RuleID, "cat", f.Category, "sev", f.Severity.String(),
		"action", action, "score", fmt.Sprintf("%.0f", v.Score), "path", path, "loc", f.Location, "id", r.ID, "ja3", r.JA3)
	if f.Severity == detect.Low && f.Score == 0 {
		return // log-only (e.g. protocol hygiene)
	}
	e.alerts.Emit(alert.Event{
		Severity: f.Severity, Category: f.Category, RuleID: f.RuleID, Msg: msg,
		IP: ip, Geo: geo, Method: r.Method, Host: host, Path: path, Location: f.Location,
		Payload: f.Match, Action: action, Score: v.Score, ReqID: r.ID,
	})
}
