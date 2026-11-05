// Package alert deduplicates detection events and fans them out to notifiers
// (Telegram, Discord) without ever blocking the inspection path.
package alert

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/orcinustools/bima/internal/detect"
	"github.com/orcinustools/bima/internal/metrics"
)

type Event struct {
	Time     time.Time
	Severity detect.Severity
	Category string
	RuleID   string
	Msg      string
	IP       string
	Geo      string // "AS64500 EXAMPLE-NET, ID"
	Method   string
	Host     string
	Path     string
	Location string
	Payload  string
	Action   string // allow, tarpit, block, ban 10m, would-block (detect mode) ...
	Score    float64
	ReqID    string
	Agent    string
	Evidence []string // other rules seen for this IP+category in the dedup window, e.g. "BIMA-ENUM-104×1"
}

// Notifier delivers a single immediate event or a digest.
type Notifier interface {
	Name() string
	SendEvent(ctx context.Context, e Event) error
	SendDigest(ctx context.Context, d Digest) error
}

type DigestLine struct {
	Key      string
	First    Event
	Count    int // total occurrences in the window
	Repeated bool
}

type Digest struct {
	Agent  string
	Period time.Duration
	Lines  []DigestLine
}

type bucket struct {
	first   Event
	rules   map[string]int
	count   int
	sent    bool // first event was already delivered immediately
	expires time.Time
}

type Alerter struct {
	in        chan Event
	notifiers []Notifier
	dedup     time.Duration
	digest    time.Duration
	agent     string

	mu      sync.Mutex
	buckets map[string]*bucket
	Dropped atomic.Uint64

	// one ordered queue + worker per notifier: messages arrive in the order
	// they happened (block before ban), and a slow notifier can't stall others.
	queues []chan func()
}

func New(agent string, dedup, digest time.Duration, notifiers ...Notifier) *Alerter {
	a := &Alerter{
		in: make(chan Event, 4096), notifiers: notifiers,
		dedup: dedup, digest: digest, agent: agent,
		buckets: map[string]*bucket{},
	}
	for range notifiers {
		q := make(chan func(), 1024)
		a.queues = append(a.queues, q)
		go func() {
			for job := range q {
				job()
			}
		}()
	}
	return a
}

func (a *Alerter) enqueue(i int, job func()) {
	select {
	case a.queues[i] <- job:
	default:
		a.Dropped.Add(1)
	}
}

// Emit is non-blocking: if the queue is full the event is dropped and counted.
func (a *Alerter) Emit(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	e.Agent = a.agent
	select {
	case a.in <- e:
	default:
		a.Dropped.Add(1)
	}
}

func (a *Alerter) Run(ctx context.Context) {
	tick := time.NewTicker(a.digest)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			a.flush(true)
			return
		case e := <-a.in:
			a.handle(e)
		case <-tick.C:
			a.flush(false)
		}
	}
}

func key(e Event) string { return e.IP + "|" + e.Category }

func (a *Alerter) handle(e Event) {
	k := key(e)
	a.mu.Lock()
	b := a.buckets[k]
	if b != nil && time.Now().Before(b.expires) {
		b.count++
		b.rules[e.RuleID]++
		// Escalation inside the window (e.g. tarpit -> ban, or medium -> critical) is always sent.
		escalate := (strings.HasPrefix(e.Action, "ban") && !strings.HasPrefix(b.first.Action, "ban")) || e.Severity > b.first.Severity
		if escalate {
			e.Evidence = evidence(b.rules)
			b.first = e
			b.sent = true
		}
		a.mu.Unlock()
		if escalate {
			a.sendEvent(e)
		}
		return
	}
	immediate := e.Severity >= detect.High || strings.HasPrefix(e.Action, "ban")
	a.buckets[k] = &bucket{first: e, rules: map[string]int{e.RuleID: 1}, count: 1, sent: immediate, expires: time.Now().Add(a.dedup)}
	a.mu.Unlock()
	if immediate {
		a.sendEvent(e)
	}
	// Low severity: log only.
	if e.Severity == detect.Low {
		slog.Info("low severity event", "ip", e.IP, "rule", e.RuleID)
	}
}

// flush sends a digest of medium events not yet delivered and repeat counts for
// buckets that were already delivered. Expired buckets are dropped.
func (a *Alerter) flush(all bool) {
	now := time.Now()
	var lines []DigestLine
	a.mu.Lock()
	for k, b := range a.buckets {
		switch {
		case !b.sent && b.first.Severity >= detect.Medium:
			f := b.first
			f.Evidence = evidence(b.rules)
			lines = append(lines, DigestLine{Key: k, First: f, Count: b.count})
			b.sent = true
			b.count = 0
		case b.sent && b.count > 1:
			lines = append(lines, DigestLine{Key: k, First: b.first, Count: b.count - 1, Repeated: true})
			b.count = 1
		}
		if all || now.After(b.expires) {
			delete(a.buckets, k)
		}
	}
	a.mu.Unlock()
	if len(lines) == 0 {
		return
	}
	sort.Slice(lines, func(i, j int) bool { return lines[i].First.Severity > lines[j].First.Severity })
	d := Digest{Agent: a.agent, Period: a.digest, Lines: lines}
	for i, n := range a.notifiers {
		a.enqueue(i, func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			record(n.Name(), "digest", n.SendDigest(ctx, d))
		})
	}
}

func (a *Alerter) sendEvent(e Event) {
	for i, n := range a.notifiers {
		a.enqueue(i, func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			record(n.Name(), "event", n.SendEvent(ctx, e))
		})
	}
}

func record(notifier, kind string, err error) {
	status := "ok"
	if err != nil {
		status = "error"
		slog.Error("alert send failed", "notifier", notifier, "kind", kind, "err", err)
	}
	metrics.AlertsSent.WithLabelValues(notifier, kind, status).Inc()
}

// SendTest synchronously delivers a sample event to every notifier and
// returns per-notifier errors. Used by `bima -test-alert`.
func (a *Alerter) SendTest(ctx context.Context) map[string]error {
	e := Event{Time: time.Now(), Severity: detect.High, Category: "test", RuleID: "BIMA-TEST",
		Msg: "Test alert from Bima — delivery check", IP: "192.0.2.1", Geo: "TEST-NET-1", Method: "GET",
		Host: a.agent, Path: "/bima/test?x=<b>escaped</b>&y=`code`", Location: "query:x",
		Payload: "<script>alert(1)</script>", Action: "none (test)", Agent: a.agent}
	out := map[string]error{}
	for _, n := range a.notifiers {
		err := n.SendEvent(ctx, e)
		record(n.Name(), "test", err)
		out[n.Name()] = err
	}
	return out
}

func evidence(rules map[string]int) []string {
	out := make([]string, 0, len(rules))
	for id, n := range rules {
		out = append(out, fmt.Sprintf("%s×%d", id, n))
	}
	sort.Strings(out)
	return out
}

// ---- formatting helpers shared by notifiers ----

func emoji(s detect.Severity) string {
	switch s {
	case detect.Critical:
		return "🚨"
	case detect.High:
		return "🔴"
	case detect.Medium:
		return "🟠"
	default:
		return "🔵"
	}
}

func title(e Event) string {
	return fmt.Sprintf("%s [%s] %s — %s", emoji(e.Severity), e.Severity, strings.ToUpper(e.Category), strings.ToUpper(e.Action))
}

// sanitize strips control chars and truncates payload text for display.
func sanitize(s string, n int) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 && r != ' ' || r == 0x7f {
			b.WriteString(fmt.Sprintf("\\x%02x", r))
			continue
		}
		b.WriteRune(r)
	}
	out := b.String()
	if len([]rune(out)) > n {
		out = string([]rune(out)[:n]) + "…"
	}
	return out
}
