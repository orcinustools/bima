package alert

import (
	"context"
	"fmt"
	"html"
	"strings"
)

type Telegram struct {
	APIBase string
	Token   string
	ChatID  string
}

func (t *Telegram) Name() string { return "telegram" }

func (t *Telegram) url() string {
	return strings.TrimRight(t.APIBase, "/") + "/bot" + t.Token + "/sendMessage"
}

func (t *Telegram) send(ctx context.Context, text string) error {
	if len(text) > 4000 { // Telegram limit is 4096 chars
		text = text[:4000] + "…"
	}
	return postJSON(ctx, t.url(), map[string]any{
		"chat_id":                  t.ChatID,
		"text":                     text,
		"parse_mode":               "HTML",
		"disable_web_page_preview": true,
	})
}

func esc(s string) string { return html.EscapeString(s) }

func (t *Telegram) SendEvent(ctx context.Context, e Event) error {
	var b strings.Builder
	fmt.Fprintf(&b, "<b>%s</b>\n", esc(title(e)))
	if e.Geo != "" {
		fmt.Fprintf(&b, "<b>IP</b>      : <code>%s</code> (%s)\n", esc(e.IP), esc(e.Geo))
	} else {
		fmt.Fprintf(&b, "<b>IP</b>      : <code>%s</code>\n", esc(e.IP))
	}
	fmt.Fprintf(&b, "<b>Rule</b>    : %s %s\n", esc(e.RuleID), esc(e.Msg))
	fmt.Fprintf(&b, "<b>Request</b> : <code>%s %s</code>\n", esc(e.Method), esc(sanitize(e.Path, 200)))
	if e.Payload != "" {
		fmt.Fprintf(&b, "<b>Payload</b> : <code>%s</code> (%s)\n", esc(sanitize(e.Payload, 200)), esc(e.Location))
	}
	if len(e.Evidence) > 0 {
		fmt.Fprintf(&b, "<b>Evidence</b>: %s\n", esc(strings.Join(e.Evidence, ", ")))
	}
	fmt.Fprintf(&b, "<b>Score</b>   : %.0f\n", e.Score)
	fmt.Fprintf(&b, "<b>Host</b>    : %s | agent: %s\n", esc(e.Host), esc(e.Agent))
	if e.ReqID != "" {
		fmt.Fprintf(&b, "<b>ReqID</b>   : <code>%s</code>\n", esc(e.ReqID))
	}
	fmt.Fprintf(&b, "<i>%s</i>", e.Time.UTC().Format("2006-01-02 15:04:05 UTC"))
	return t.send(ctx, b.String())
}

func (t *Telegram) SendDigest(ctx context.Context, d Digest) error {
	var b strings.Builder
	fmt.Fprintf(&b, "<b>📋 Bima digest</b> (%s, %d items)\n", esc(d.Agent), len(d.Lines))
	for _, l := range d.Lines {
		if b.Len() > 3600 { // stay under Telegram's 4096 limit without cutting HTML tags
			b.WriteString("…")
			break
		}
		e := l.First
		if l.Repeated {
			fmt.Fprintf(&b, "• <code>%s</code> %s: <b>+%d</b> more hits (%s)\n", esc(e.IP), esc(e.Category), l.Count, esc(e.Action))
		} else {
			rules := e.RuleID
			if len(e.Evidence) > 1 {
				rules = strings.Join(e.Evidence, ", ")
			}
			fmt.Fprintf(&b, "• %s <code>%s</code> %s ×%d — %s <code>%s</code> → %s\n",
				emoji(e.Severity), esc(e.IP), esc(e.Category), l.Count, esc(rules), esc(sanitize(e.Path, 80)), esc(e.Action))
		}
	}
	return t.send(ctx, b.String())
}
