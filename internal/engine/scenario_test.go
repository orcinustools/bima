package engine

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/orcinustools/bima/internal/config"
	"github.com/orcinustools/bima/test/scenarios"
)

// TestScenarios runs the whole data-driven corpus (attacks, recent CVEs,
// benign traffic) through the engine with CRS enabled and the default config
// (no exclusions). Each scenario gets its own client IP.
func TestScenarios(t *testing.T) {
	// untuned: default config, CRS PL1 without exclusions — false positives are
	// reported (what shadow mode would surface), attacks must still be caught.
	t.Run("untuned", func(t *testing.T) { runScenarios(t, nil, false) })
	// tuned: the exclusions from deploy/e2e/config.yaml (the documented tuning
	// for free-text search, rich text, GraphQL, snippets) — zero tolerance.
	tuned, err := config.Load("../../deploy/e2e/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	t.Run("tuned", func(t *testing.T) { runScenarios(t, tuned.Exclusions, true) })
}

func runScenarios(t *testing.T, excl []config.Exclusion, strictBenign bool) {
	all, err := scenarios.Load()
	if err != nil {
		t.Fatal(err)
	}
	e := newEngine(t, true)
	e.cfg.Exclusions = excl
	type tally struct{ total, pass, gapStill, gapFixed, fpUntuned int }
	byCat := map[string]*tally{}
	var failures []string
	for i, s := range all {
		r := &Request{IP: netip.AddrFrom4([4]byte{100, 70, byte(i >> 8), byte(i)}), Method: s.Method,
			Path: s.PathOnly(), Query: s.Query(), Version: "1.1", Body: []byte(s.Body)}
		h := map[string]string{"Host": "shop.example.com", "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/130", "Accept": "*/*"}
		if s.CT != "" {
			h["Content-Type"] = s.CT
		}
		if s.Body != "" {
			h["Content-Length"] = strconv.Itoa(len(s.Body))
		}
		for k, v := range s.Headers {
			for hk := range h {
				if strings.EqualFold(hk, k) {
					delete(h, hk)
				}
			}
			h[k] = v
		}
		for k, v := range h {
			r.Headers = append(r.Headers, [2]string{k, v})
		}
		v := e.OnRequest(r)
		got := map[Action]string{Allow: "allow", Block: "block", Tarpit: "tarpit"}[v.Action]
		ok := got == s.Expect || (s.Expect == "block" && got == "tarpit")
		tl := byCat[s.Cat]
		if tl == nil {
			tl = &tally{}
			byCat[s.Cat] = tl
		}
		tl.total++
		switch {
		case s.Gap != "" && !ok:
			tl.gapStill++
		case s.Gap != "" && ok:
			tl.gapFixed++
			tl.pass++
			t.Logf("gap now covered (remove gap note): %s — %s [%s]", s.ID, s.Desc, v.RuleID)
		case ok:
			tl.pass++
		case s.Expect == "allow" && !strictBenign:
			tl.fpUntuned++
			t.Logf("untuned FP (fixed by tuning): %-24s rule=%-14s %s", s.ID, v.RuleID, s.Desc)
		default:
			failures = append(failures, fmt.Sprintf("%-28s %-6s want %-5s got %-5s rule=%-14s %s", s.ID, s.Cat, s.Expect, got, v.RuleID, s.Desc))
		}
	}
	cats := make([]string, 0, len(byCat))
	for c := range byCat {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	var sb strings.Builder
	fmt.Fprintf(&sb, "\n%-18s %6s %6s %9s %10s\n", "category", "total", "pass", "known-gap", "untunedFP")
	tot, pass, gap, fp := 0, 0, 0, 0
	for _, c := range cats {
		tl := byCat[c]
		fmt.Fprintf(&sb, "%-18s %6d %6d %9d %10d\n", c, tl.total, tl.pass, tl.gapStill, tl.fpUntuned)
		tot, pass, gap, fp = tot+tl.total, pass+tl.pass, gap+tl.gapStill, fp+tl.fpUntuned
	}
	fmt.Fprintf(&sb, "%-18s %6d %6d %9d %10d\n", "TOTAL", tot, pass, gap, fp)
	t.Log(sb.String())
	for _, f := range failures {
		t.Error(f)
	}
}
