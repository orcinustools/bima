package detect

import (
	"fmt"
	"strconv"
	"strings"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
)

// CRS wraps a Coraza WAF loaded with the OWASP Core Rule Set (request phases only).
type CRS struct {
	waf coraza.WAF
}

type Request struct {
	ClientIP string
	Method   string
	URI      string // path + "?" + query
	Version  string
	Headers  [][2]string
	Body     []byte
	// Truncated: Body is only a prefix of the real body (inspection window).
	// Body parse errors are then expected and must not block.
	Truncated bool
}

// DefaultAllowedMethods extends CRS's default (GET HEAD POST OPTIONS) with the
// verbs REST APIs use; otherwise every PUT/PATCH/DELETE scores as an anomaly.
const DefaultAllowedMethods = "GET HEAD POST OPTIONS PUT PATCH DELETE"

func NewCRS(paranoia, threshold int, allowedMethods, extra string) (*CRS, error) {
	if allowedMethods == "" {
		allowedMethods = DefaultAllowedMethods
	}
	if paranoia < 1 || paranoia > 4 {
		return nil, fmt.Errorf("crs paranoia must be 1..4")
	}
	directives := fmt.Sprintf(`
Include @coraza.conf-recommended
Include @crs-setup.conf.example
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess Off
SecAuditEngine Off
SecDebugLogLevel 0
SecAction "id:900000,phase:1,pass,t:none,nolog,setvar:tx.blocking_paranoia_level=%d"
SecAction "id:900110,phase:1,pass,t:none,nolog,setvar:tx.inbound_anomaly_score_threshold=%d,setvar:tx.outbound_anomaly_score_threshold=4"
SecAction "id:900200,phase:1,pass,t:none,nolog,setvar:'tx.allowed_methods=%s'"
Include @owasp_crs/REQUEST-*.conf
# Secrets are free-form: don't run injection heuristics on password fields.
SecRuleUpdateTargetByTag "attack-sqli" "!ARGS:/(?i)^(password|passwd|pass|pwd|new_password|old_password|password_confirmation)$/"
SecRuleUpdateTargetByTag "attack-xss" "!ARGS:/(?i)^(password|passwd|pass|pwd|new_password|old_password|password_confirmation)$/"
SecRuleUpdateTargetByTag "attack-rce" "!ARGS:/(?i)^(password|passwd|pass|pwd|new_password|old_password|password_confirmation)$/"
%s
`, paranoia, threshold, allowedMethods, extra)
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().
		WithRootFS(coreruleset.FS).
		WithDirectives(directives))
	if err != nil {
		return nil, err
	}
	return &CRS{waf: waf}, nil
}

// crsCategory maps CRS rule-file prefixes to Bima categories.
func crsCategory(id int) (string, Severity) {
	switch id / 1000 {
	case 932:
		return "rce", Critical
	case 944:
		return "java", Critical
	case 933:
		return "rce", Critical // PHP injection
	case 934:
		return "rce", High // generic (node.js, SSTI, SSRF)
	case 930:
		return "lfi", High
	case 931:
		return "rfi", High
	case 942:
		return "sqli", High
	case 941:
		return "xss", High
	case 943:
		return "session-fixation", High
	case 913:
		return "scanner", Medium
	case 921:
		return "protocol-attack", High
	case 920, 911, 922:
		return "protocol", Medium
	default:
		return "crs", Medium
	}
}

// Inspect evaluates the request. It returns a single aggregated finding when the
// CRS anomaly threshold is exceeded (i.e. CRS would have blocked), else nil.
func (c *CRS) Inspect(r *Request) *Finding {
	tx := c.waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		_ = tx.Close()
	}()

	tx.ProcessConnection(r.ClientIP, 0, "", 0)
	ver := r.Version
	if ver == "" {
		ver = "1.1"
	}
	tx.ProcessURI(r.URI, r.Method, "HTTP/"+ver)
	for _, h := range r.Headers {
		tx.AddRequestHeader(h[0], h[1])
	}
	it := tx.ProcessRequestHeaders()
	if it == nil && len(r.Body) > 0 {
		if it2, _, err := tx.WriteRequestBody(r.Body); err == nil && it2 != nil {
			it = it2
		}
	}
	if it == nil {
		it, _ = tx.ProcessRequestBody()
	}
	if it == nil {
		return nil
	}
	f := summarize(tx.MatchedRules(), it)
	if r.Truncated && f != nil && f.Category == "crs" && (it.RuleID == 200002 || it.RuleID == 200003 || it.RuleID == 200004) {
		return nil // REQBODY parse error caused by our own truncation
	}
	return f
}

func summarize(matched []types.MatchedRule, it *types.Interruption) *Finding {
	// Pick the most severe attack rule (ignore 949/980 blocking/correlation rules).
	var best types.MatchedRule
	bestSev := Severity(-1)
	var ids []string
	for _, m := range matched {
		id := m.Rule().ID()
		// skip paranoia-gating / init / blocking-evaluation rules (no message)
		if id < 911000 || id >= 949000 || m.Message() == "" {
			continue
		}
		ids = append(ids, strconv.Itoa(id))
		_, sev := crsCategory(id)
		if sev > bestSev {
			best, bestSev = m, sev
		}
	}
	if best == nil {
		return &Finding{RuleID: fmt.Sprintf("CRS-%d", it.RuleID), Category: "crs", Severity: High,
			Msg: "OWASP CRS anomaly threshold exceeded", Score: 30, Block: true}
	}
	cat, sev := crsCategory(best.Rule().ID())
	if cat == "scanner" {
		// Scanner UA is handled by the behavioural scorer (tarpit, then ban);
		// don't double count or hard-block on it here.
		return nil
	}
	data := best.Data()
	if data == "" && len(best.MatchedDatas()) > 0 {
		data = best.MatchedDatas()[0].Value()
	}
	loc := ""
	if md := best.MatchedDatas(); len(md) > 0 {
		loc = strings.ToLower(md[0].Variable().Name())
		if k := md[0].Key(); k != "" {
			loc += ":" + k
		}
	}
	score := 30.0
	if sev == Critical {
		score = 50
	}
	block := true
	if cat == "protocol" || cat == "crs" {
		// Only protocol-hygiene rules fired (e.g. numeric Host, missing Accept):
		// common for API clients/health checks. Log it, don't block or score.
		sev, score, block = Low, 0, false
	}
	if len(ids) > 6 {
		ids = append(ids[:6], "…")
	}
	return &Finding{
		RuleID:   fmt.Sprintf("CRS-%d", best.Rule().ID()),
		Category: cat, Severity: sev,
		Msg:      best.Message() + " [crs: " + strings.Join(ids, ",") + "]",
		Location: loc, Match: snippet(data, 200), Score: score, Block: block,
	}
}
