package alert

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/orcinustools/bima/internal/detect"
)

// Discord delivers via an incoming webhook (WebhookURL) or, when no webhook is
// configured, as a bot (BotToken + ChannelID) through the REST API.
type Discord struct {
	WebhookURL string
	BotToken   string
	ChannelID  string
	APIBase    string // default https://discord.com/api/v10
}

func (d *Discord) post(ctx context.Context, payload map[string]any) error {
	if d.WebhookURL != "" {
		payload["username"] = "Bima WAF"
		return postJSON(ctx, d.WebhookURL, payload)
	}
	base := d.APIBase
	if base == "" {
		base = "https://discord.com/api/v10"
	}
	url := strings.TrimRight(base, "/") + "/channels/" + d.ChannelID + "/messages"
	return postJSON(ctx, url, payload, "Authorization", "Bot "+d.BotToken)
}

func (d *Discord) Name() string { return "discord" }

func color(s detect.Severity) int {
	switch s {
	case detect.Critical:
		return 0x8B0000
	case detect.High:
		return 0xE53935
	case detect.Medium:
		return 0xFB8C00
	default:
		return 0x1E88E5
	}
}

// code wraps text in an inline code span safe for Discord markdown.
func code(s string) string {
	s = strings.ReplaceAll(s, "`", "ˋ")
	if s == "" {
		s = "-"
	}
	return "`" + s + "`"
}

func field(name, value string, inline bool) map[string]any {
	if len(value) > 1000 {
		value = value[:1000] + "…"
	}
	return map[string]any{"name": name, "value": value, "inline": inline}
}

func (d *Discord) SendEvent(ctx context.Context, e Event) error {
	fields := []map[string]any{
		field("IP", code(e.IP), true),
		field("Origin", code(e.Geo), true),
		field("Score", fmt.Sprintf("%.0f", e.Score), true),
		field("Action", code(e.Action), true),
		field("Rule", code(e.RuleID)+" "+sanitize(e.Msg, 200), false),
		field("Request", code(e.Method+" "+sanitize(e.Path, 200)), false),
	}
	if e.Payload != "" {
		fields = append(fields, field("Payload ("+e.Location+")", code(sanitize(e.Payload, 200)), false))
	}
	if len(e.Evidence) > 0 {
		fields = append(fields, field("Evidence", code(strings.Join(e.Evidence, ", ")), false))
	}
	if e.ReqID != "" {
		fields = append(fields, field("ReqID", code(e.ReqID), true))
	}
	fields = append(fields, field("Host", code(e.Host), true))
	return d.post(ctx, map[string]any{
		"allowed_mentions": map[string]any{"parse": []string{}},
		"embeds": []map[string]any{{
			"title":     title(e),
			"color":     color(e.Severity),
			"fields":    fields,
			"footer":    map[string]any{"text": "agent: " + e.Agent},
			"timestamp": e.Time.UTC().Format(time.RFC3339),
		}},
	})
}

func (d *Discord) SendDigest(ctx context.Context, dg Digest) error {
	var b strings.Builder
	maxSev := detect.Low
	for _, l := range dg.Lines {
		e := l.First
		if e.Severity > maxSev {
			maxSev = e.Severity
		}
		var line string
		if l.Repeated {
			line = fmt.Sprintf("• %s %s: **+%d** more hits (%s)\n", code(e.IP), e.Category, l.Count, e.Action)
		} else {
			rules := e.RuleID
			if len(e.Evidence) > 1 {
				rules = strings.Join(e.Evidence, ", ")
			}
			line = fmt.Sprintf("• %s %s %s ×%d — %s %s → %s\n", emoji(e.Severity), code(e.IP), e.Category, l.Count, code(rules), code(sanitize(e.Path, 80)), e.Action)
		}
		if b.Len()+len(line) > 3900 { // embed description limit 4096
			b.WriteString("…\n")
			break
		}
		b.WriteString(line)
	}
	return d.post(ctx, map[string]any{
		"allowed_mentions": map[string]any{"parse": []string{}},
		"embeds": []map[string]any{{
			"title":       fmt.Sprintf("📋 Bima digest (%d items)", len(dg.Lines)),
			"description": b.String(),
			"color":       color(maxSev),
			"footer":      map[string]any{"text": "agent: " + dg.Agent},
			"timestamp":   time.Now().UTC().Format(time.RFC3339),
		}},
	})
}
