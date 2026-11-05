// Package enum tracks per-IP and per-group (ASN / client fingerprint)
// behaviour to detect enumeration, scanning and brute force, and maintains the
// decaying per-IP threat score. State lives in a store.Store so several agents
// can share it (Redis).
package enum

import (
	"context"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/orcinustools/bima/internal/detect"
	"github.com/orcinustools/bima/internal/store"
)

type Thresholds struct {
	Distinct404   int     // distinct 404 paths per IP in window
	IDEnum        int     // distinct numeric ids on same route template in window
	AuthFail      int     // 401/403 on auth endpoints in window
	ErrRatioMinN  int     // minimum requests before error ratio is considered
	ErrRatio      float64 // 4xx / requests
	ScannerUA     float64
	SensitivePath float64

	// Distributed enumeration: many IPs from one ASN / fingerprint each staying
	// under the per-IP threshold.
	GroupDistinct404 int           // distinct 404 paths for the whole group in window
	GroupMinIPs      int           // contributing IPs required
	GroupMember404   int           // an IP contributes once it has this many distinct 404s
	GroupPenalty     float64       // score added to every contributing IP
	GroupFlagTTL     time.Duration // how long a group stays flagged
}

var DefaultThresholds = Thresholds{
	Distinct404: 20, IDEnum: 30, AuthFail: 10,
	ErrRatioMinN: 50, ErrRatio: 0.7,
	ScannerUA: 50, SensitivePath: 30,
	GroupDistinct404: 60, GroupMinIPs: 3, GroupMember404: 3, GroupPenalty: 80, GroupFlagTTL: 10 * time.Minute,
}

var scannerUAs = []string{"sqlmap", "nikto", "nuclei", "ffuf", "gobuster", "dirbuster", "dirsearch", "feroxbuster", "wfuzz",
	"wpscan", "masscan", "zgrab", "acunetix", "netsparker", "nessus", "openvas", "nmap", "hydra", "whatweb", "jaeles",
	"arachni", "w3af", "commix", "xsstrike", "burpcollaborator",
	"fuzz faster u fool", "httpx - open-source", "katana", "zgrab", "interactsh", "masscan", "nessus", "qualys", "openvas", "netsparker", "appscan", "jorgee", "zmeu"}

func isScannerUA(ua string) bool {
	ua = strings.ToLower(ua)
	for _, s := range scannerUAs {
		if strings.Contains(ua, s) {
			return true
		}
	}
	return false
}

var sensitivePath = regexp.MustCompile(`(?i)/\.(?:env(?:\.[a-z]+)?|git|svn|hg|bzr|ds_store|aws|ssh|docker|kube|npmrc|htaccess|htpasswd|bash_history|vscode|idea)(?:/|$)|` +
	`/(?:wp-admin|wp-login\.php|wp-config\.php|xmlrpc\.php|phpinfo(?:\.php)?|phpmyadmin|pma|adminer(?:\.php)?|server-status|server-info|actuator(?:/|$)|` +
	`_profiler|telescope|elmah\.axd|trace\.axd|web\.config|id_[rd]sa|vendor/phpunit|cgi-bin/|boaform|hnap1|solr/admin|jmx-console|manager/html)|` +
	// JS build/deploy artifacts and ORM schemas scanned for leaked secrets
	`/\.(?:next|vercel|netlify|output|nuxt|svelte-kit|turbo|terraform|serverless|firebase|circleci|github/workflows)/|` +
	`/(?:prisma/schema\.prisma|terraform\.tfstate(?:\.backup)?|docker-compose\.ya?ml|appsettings(?:\.\w+)?\.json|credentials\.json|secrets?\.(?:json|ya?ml)|\.env\.[\w-]+)$|` +
	`\.(?:bak|old|orig|save|swp|sql|sqlite|db|tar|tgz|tar\.gz|7z|rar|zip|pem|key)$`)

var authPath = regexp.MustCompile(`(?i)login|signin|sign-in|auth|token|session|password|otp|2fa|mfa`)

var numSeg = regexp.MustCompile(`/\d+(?:/|$)`)

// opTimeout bounds every store call; the whole SPOE budget is 100ms.
const opTimeout = 25 * time.Millisecond

// Circuit breaker: after breakerErrors consecutive store failures the store is
// bypassed for breakerOpen, so a dead Redis costs ~0ms instead of a timeout on
// every request (signatures/CRS keep blocking; scoring is skipped = fail-open).
const (
	breakerErrors = 3
	breakerOpen   = 5 * time.Second
)

type Scorer struct {
	st       store.Store
	halfLife time.Duration
	window   time.Duration
	th       Thresholds
	Errors   atomic.Uint64 // store errors (fail-open)
	Skipped  atomic.Uint64 // store calls skipped while the breaker was open

	consecutive atomic.Int32
	openUntil   atomic.Int64 // unix nanos
}

// IsSensitivePath reports whether path is a typical secret/config probe.
func IsSensitivePath(path string) bool { return sensitivePath.MatchString(path) }

// Store exposes the state store (shared with identity/spoof tracking).
func (s *Scorer) Store() store.Store { return s.st }

func NewScorer(st store.Store, halfLife, window time.Duration, th Thresholds) *Scorer {
	return &Scorer{st: st, halfLife: halfLife, window: window, th: th}
}

func ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), opTimeout)
}

func (s *Scorer) fail(op string, err error) {
	s.Errors.Add(1)
	if s.consecutive.Add(1) >= breakerErrors && !s.open() {
		s.openUntil.Store(time.Now().Add(breakerOpen).UnixNano())
		slog.Error("state store failing: circuit open, scoring bypassed (fail-open)", "for", breakerOpen.String(), "op", op, "err", err)
		return
	}
	slog.Warn("state store error (fail-open)", "op", op, "err", err)
}

func (s *Scorer) ok() { s.consecutive.Store(0) }

func (s *Scorer) open() bool { return time.Now().UnixNano() < s.openUntil.Load() }

// guard reports whether the store may be used now.
func (s *Scorer) guard() bool {
	if s.open() {
		s.Skipped.Add(1)
		return false
	}
	return true
}

func (s *Scorer) scoreTTL() time.Duration { return 8 * s.halfLife }

// Add adds delta to the IP score and returns the new score.
func (s *Scorer) Add(ip string, delta float64) float64 {
	if !s.guard() {
		return 0
	}
	c, cancel := ctx()
	defer cancel()
	v, err := s.st.ScoreAdd(c, "s:"+ip, delta, s.halfLife, s.scoreTTL())
	if err != nil {
		s.fail("score", err)
		return 0
	}
	s.ok()
	return v
}

func (s *Scorer) Score(ip string) float64 { return s.Add(ip, 0) }

func (s *Scorer) ResetScore(ip string) {
	if !s.guard() {
		return
	}
	c, cancel := ctx()
	defer cancel()
	if err := s.st.Del(c, "s:"+ip); err != nil {
		s.fail("del", err)
	}
}

// NextBanLevel returns the escalation level for a new ban of ip (0-based).
func (s *Scorer) NextBanLevel(ip string) int {
	if !s.guard() {
		return 0
	}
	c, cancel := ctx()
	defer cancel()
	n, err := s.st.Incr(c, "bl:"+ip, 48*time.Hour)
	if err != nil {
		s.fail("incr", err)
		return 0
	}
	return n - 1
}

// ObserveRequest evaluates request-time behavioural signals, adds extra
// (score from signature/CRS findings) and returns findings plus the new score.
// Typical cost: one store round trip.
func (s *Scorer) ObserveRequest(ip, path, ua string, extra float64) ([]detect.Finding, float64) {
	var out []detect.Finding
	if ua != "" && isScannerUA(ua) {
		out = append(out, detect.Finding{RuleID: "BIMA-ENUM-101", Category: "scanner", Severity: detect.Medium,
			Msg: "Known vulnerability scanner User-Agent", Location: "header:user-agent", Match: ua, Score: s.th.ScannerUA})
	}
	if sensitivePath.MatchString(path) {
		out = append(out, detect.Finding{RuleID: "BIMA-ENUM-102", Category: "enumeration", Severity: detect.Medium,
			Msg: "Probe of sensitive path", Location: "path", Match: path, Score: s.th.SensitivePath})
	}
	delta := extra
	for _, f := range out {
		delta += f.Score
	}
	setKey, member, tmpl := "", "", ""
	if loc := numSeg.FindAllStringIndex(path, -1); len(loc) > 0 {
		tmpl = numSeg.ReplaceAllStringFunc(path, func(m string) string {
			if strings.HasSuffix(m, "/") {
				return "/{n}/"
			}
			return "/{n}"
		})
		last := loc[len(loc)-1]
		member = strings.Trim(path[last[0]:last[1]], "/")
		setKey = "id:" + ip + ":" + tmpl
	}
	if !s.guard() {
		return out, 0
	}
	c, cancel := ctx()
	defer cancel()
	score, n, err := s.st.RequestStep(c, "rq:"+ip, "s:"+ip, delta, s.halfLife, s.scoreTTL(), s.window, setKey, member)
	if err != nil {
		s.fail("request", err)
		return out, 0
	}
	s.ok()
	if setKey != "" && n >= s.th.IDEnum {
		f := detect.Finding{RuleID: "BIMA-ENUM-103", Category: "enumeration", Severity: detect.Medium,
			Msg: "Sequential ID enumeration (IDOR probing)", Location: "path", Match: tmpl, Score: 40}
		out = append(out, f)
		_ = s.st.Del(c, setKey)
		score = s.Add(ip, f.Score)
	}
	return out, score
}

func (s *Scorer) addFindings(ip string, fs []detect.Finding) {
	var total float64
	for _, f := range fs {
		total += f.Score
	}
	if total > 0 {
		s.Add(ip, total)
	}
}

// ObserveResponse evaluates response-time signals. groups are aggregation keys
// for this client (e.g. "asn:64500", "fp:ab12…"). It returns findings for ip
// and, when a distributed enumeration is detected, the other IPs that were
// penalised as part of the group.
func (s *Scorer) ObserveResponse(ip, path string, status int, groups []string) (out []detect.Finding, others []string) {
	// Every response signal is a 4xx: successful responses cost nothing.
	if status < 400 || status >= 500 || !s.guard() {
		return nil, nil
	}
	c, cancel := ctx()
	defer cancel()

	if _, err := s.st.Incr(c, "er:"+ip, s.window); err != nil {
		s.fail("incr", err)
		return nil, nil
	}
	s.ok()
	if status == 404 {
		n, err := s.st.SAddCard(c, "w404:"+ip, path, s.window)
		if err != nil {
			s.fail("sadd", err)
		} else {
			if n >= s.th.Distinct404 {
				out = append(out, detect.Finding{RuleID: "BIMA-ENUM-104", Category: "enumeration", Severity: detect.Medium,
					Msg: "Directory/file brute force (many distinct 404s)", Location: "path", Match: path, Score: 40})
				_ = s.st.Del(c, "w404:"+ip)
			}
			for _, g := range groups {
				f, o := s.group(c, g, ip, path, n)
				if f != nil {
					out = append(out, *f)
				}
				others = append(others, o...)
			}
		}
	}
	if (status == 401 || status == 403) && authPath.MatchString(path) {
		n, err := s.st.Incr(c, "af:"+ip, s.window)
		if err != nil {
			s.fail("incr", err)
		} else if n >= s.th.AuthFail {
			out = append(out, detect.Finding{RuleID: "BIMA-ENUM-105", Category: "bruteforce", Severity: detect.Medium,
				Msg: "Credential brute force on auth endpoint", Location: "path", Match: path, Score: 30})
			_ = s.st.Del(c, "af:"+ip)
		}
	}
	rq, err1 := s.st.GetInt(c, "rq:"+ip)
	er, err2 := s.st.GetInt(c, "er:"+ip)
	if err1 == nil && err2 == nil && rq >= s.th.ErrRatioMinN && float64(er)/float64(rq) >= s.th.ErrRatio {
		out = append(out, detect.Finding{RuleID: "BIMA-ENUM-106", Category: "enumeration", Severity: detect.Medium,
			Msg: "High client error ratio", Location: "status", Match: path, Score: 30})
		_ = s.st.Del(c, "rq:"+ip, "er:"+ip)
	}
	s.addFindings(ip, out)
	return out, others
}

// group handles distributed-enumeration accounting for one aggregation key.
func (s *Scorer) group(c context.Context, g, ip, path string, ip404 int) (*detect.Finding, []string) {
	gc, err := s.st.SAddCard(c, "g404:"+g, path, s.window)
	if err != nil {
		s.fail("sadd", err)
		return nil, nil
	}
	if ip404 < s.th.GroupMember404 {
		return nil, nil
	}
	ipsN, err := s.st.SAddCard(c, "gips:"+g, ip, s.window)
	if err != nil {
		s.fail("sadd", err)
		return nil, nil
	}
	finding := func(n int) *detect.Finding {
		return &detect.Finding{RuleID: "BIMA-ENUM-107", Category: "distributed-enum", Severity: detect.High,
			Msg:      "Distributed enumeration from " + g + " (" + strconv.Itoa(n) + " IPs)",
			Location: "group:" + g, Match: path, Score: 0}
	}
	flagged, _ := s.st.Flag(c, "gflag:"+g)
	if flagged {
		// group already flagged: penalise each new contributing IP once
		if done, _ := s.st.Flag(c, "gpen:"+g+":"+ip); done {
			return nil, nil
		}
		_ = s.st.SetFlag(c, "gpen:"+g+":"+ip, s.th.GroupFlagTTL)
		s.Add(ip, s.th.GroupPenalty)
		return finding(ipsN), nil
	}
	if gc < s.th.GroupDistinct404 || ipsN < s.th.GroupMinIPs {
		return nil, nil
	}
	_ = s.st.SetFlag(c, "gflag:"+g, s.th.GroupFlagTTL)
	members, err := s.st.SMembers(c, "gips:"+g)
	if err != nil {
		s.fail("smembers", err)
		return nil, nil
	}
	var others []string
	for _, m := range members {
		_ = s.st.SetFlag(c, "gpen:"+g+":"+m, s.th.GroupFlagTTL)
		s.Add(m, s.th.GroupPenalty)
		if m != ip {
			others = append(others, m)
		}
	}
	slog.Warn("distributed enumeration detected", "group", g, "ips", len(members), "distinct404", gc)
	return finding(len(members)), others
}
