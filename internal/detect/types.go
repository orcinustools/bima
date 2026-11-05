package detect

// Severity of a finding. Critical/High signature hits block the request outright.
type Severity int

const (
	Low Severity = iota
	Medium
	High
	Critical
)

func (s Severity) String() string {
	switch s {
	case Critical:
		return "CRITICAL"
	case High:
		return "HIGH"
	case Medium:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// Finding is a single detection result.
type Finding struct {
	RuleID   string
	Category string // rce, log4shell, java, ssti, lfi, sqli, xss, upload, scanner, enumeration, bruteforce, ...
	Severity Severity
	Msg      string
	Location string  // where it matched: path, query:<name>, body, header:<name>
	Match    string  // matched snippet (raw, will be sanitized by alerter)
	Score    float64 // contribution to the per-IP score
	Block    bool    // block this request regardless of score
}

// Target is one piece of request data to inspect.
type Target struct {
	Location string
	Raw      string
}
