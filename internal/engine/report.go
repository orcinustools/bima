package engine

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/orcinustools/bima/internal/detect"
)

// Report aggregates findings per rule so false positives can be tuned during
// shadow mode (GET /report). Memory is bounded per rule.
type Report struct {
	mu    sync.Mutex
	since time.Time
	rules map[string]*ruleStats
}

type ruleStats struct {
	Rule      string         `json:"rule"`
	Category  string         `json:"category"`
	Severity  string         `json:"severity"`
	Msg       string         `json:"msg"`
	Hits      int            `json:"hits"`
	Blocking  int            `json:"blocking"` // hits whose verdict was (would-)block/tarpit
	IPs       map[string]int `json:"-"`
	Paths     map[string]int `json:"-"`
	Locations map[string]int `json:"-"`
	Samples   []string       `json:"samples"`
}

const maxKeys = 50

func newReport() *Report { return &Report{since: time.Now(), rules: map[string]*ruleStats{}} }

func bump(m map[string]int, k string) {
	if _, ok := m[k]; ok || len(m) < maxKeys {
		m[k]++
	}
}

func (r *Report) add(f detect.Finding, ip, path string, blocking bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.rules[f.RuleID]
	if s == nil {
		s = &ruleStats{Rule: f.RuleID, Category: f.Category, Severity: f.Severity.String(), Msg: f.Msg,
			IPs: map[string]int{}, Paths: map[string]int{}, Locations: map[string]int{}}
		r.rules[f.RuleID] = s
	}
	s.Hits++
	if blocking {
		s.Blocking++
	}
	bump(s.IPs, ip)
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	bump(s.Paths, path)
	bump(s.Locations, f.Location)
	if len(s.Samples) < 3 {
		s.Samples = append(s.Samples, snippet(f.Match, 160))
	}
}

func snippet(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

type kv struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

func top(m map[string]int, n int) []kv {
	out := make([]kv, 0, len(m))
	for k, v := range m {
		out = append(out, kv{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Count > out[j].Count || out[i].Count == out[j].Count && out[i].Key < out[j].Key
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

type RuleReport struct {
	Rule         string   `json:"rule"`
	Category     string   `json:"category"`
	Severity     string   `json:"severity"`
	Msg          string   `json:"msg"`
	Hits         int      `json:"hits"`
	Blocking     int      `json:"blocking"`
	DistinctIPs  int      `json:"distinct_ips"`
	TopPaths     []kv     `json:"top_paths"`
	TopLocations []kv     `json:"top_locations"`
	Samples      []string `json:"samples"`
	// Heuristic: many distinct IPs hitting the same path+location is the
	// typical false-positive shape (real attacks come from few IPs).
	LikelyFalsePositive bool   `json:"likely_false_positive"`
	SuggestedExclusion  string `json:"suggested_exclusion,omitempty"`
}

type ReportOut struct {
	Since time.Time    `json:"since"`
	Rules []RuleReport `json:"rules"`
}

func (r *Report) Snapshot() ReportOut {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := ReportOut{Since: r.since}
	for _, s := range r.rules {
		rr := RuleReport{Rule: s.Rule, Category: s.Category, Severity: s.Severity, Msg: s.Msg, Hits: s.Hits,
			Blocking: s.Blocking, DistinctIPs: len(s.IPs), TopPaths: top(s.Paths, 5), TopLocations: top(s.Locations, 5),
			Samples: s.Samples}
		if len(rr.TopPaths) > 0 && len(rr.TopLocations) > 0 {
			p, l := rr.TopPaths[0], rr.TopLocations[0]
			rr.LikelyFalsePositive = rr.DistinctIPs >= 5 && p.Count*2 >= s.Hits && l.Count*2 >= s.Hits &&
				!strings.HasPrefix(s.Rule, "BIMA-ENUM") && !strings.HasPrefix(s.Rule, "BIMA-BANNED")
			if rr.LikelyFalsePositive {
				rr.SuggestedExclusion = fmt.Sprintf("- rules: [%q]\n  path: %q\n  locations: [%q]\n  reason: \"FP seen in shadow mode\"",
					s.Rule, "^"+regexpQuote(p.Key)+"$", l.Key)
			}
		}
		out.Rules = append(out.Rules, rr)
	}
	sort.Slice(out.Rules, func(i, j int) bool { return out.Rules[i].Hits > out.Rules[j].Hits })
	return out
}

func regexpQuote(s string) string {
	var b strings.Builder
	for _, r := range s {
		if strings.ContainsRune(`\.+*?()|[]{}^$`, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

func (r *Report) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rules = map[string]*ruleStats{}
	r.since = time.Now()
}
