// mocknotify emulates the Telegram Bot API (sendMessage) and a Discord webhook
// so alert delivery can be asserted end-to-end without real credentials.
//
//   - Validates Telegram HTML the way Telegram does (only allowed tags, balanced),
//     returning 400 on malformed markup, so escaping bugs surface in tests.
//   - Returns one 429 with retry_after on the first Telegram call (RATE_LIMIT_FIRST=1)
//     to exercise the notifier retry path.
package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
)

type msg struct {
	Channel string          `json:"channel"`
	Time    time.Time       `json:"time"`
	Body    json.RawMessage `json:"body"`
	Text    string          `json:"text"`
}

var (
	mu         sync.Mutex
	msgs       = []msg{}
	rejected   int
	rateLimits int
	limitFirst = os.Getenv("RATE_LIMIT_FIRST") == "1"
)

var allowedTags = map[string]bool{"b": true, "strong": true, "i": true, "em": true, "u": true, "s": true, "code": true, "pre": true, "a": true}

func validTelegramHTML(s string) bool {
	z := html.NewTokenizer(strings.NewReader(s))
	var stack []string
	for {
		switch z.Next() {
		case html.ErrorToken:
			return z.Err() == io.EOF && len(stack) == 0
		case html.StartTagToken:
			n, _ := z.TagName()
			if !allowedTags[string(n)] {
				return false
			}
			stack = append(stack, string(n))
		case html.EndTagToken:
			n, _ := z.TagName()
			if len(stack) == 0 || stack[len(stack)-1] != string(n) {
				return false
			}
			stack = stack[:len(stack)-1]
		case html.SelfClosingTagToken:
			return false
		}
	}
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch {
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/bot") && strings.HasSuffix(r.URL.Path, "/sendMessage"):
			mu.Lock()
			if limitFirst && rateLimits == 0 {
				rateLimits++
				mu.Unlock()
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 1","parameters":{"retry_after":1}}`))
				return
			}
			mu.Unlock()
			var p struct {
				ChatID    json.RawMessage `json:"chat_id"` // Bima sends a string, Alertmanager a number
				Text      string          `json:"text"`
				ParseMode string          `json:"parse_mode"`
			}
			if json.Unmarshal(body, &p) != nil || len(p.ChatID) == 0 || (p.ParseMode == "HTML" && !validTelegramHTML(p.Text)) {
				mu.Lock()
				rejected++
				mu.Unlock()
				log.Printf("REJECTED telegram message: %s", body)
				http.Error(w, `{"ok":false,"error_code":400,"description":"Bad Request: can't parse entities"}`, http.StatusBadRequest)
				return
			}
			record("telegram", body, p.Text)
			// Same shape as the real Bot API (clients such as Alertmanager parse it).
			resp, _ := json.Marshal(map[string]any{"ok": true, "result": map[string]any{
				"message_id": len(msgs), "date": time.Now().Unix(), "text": p.Text,
				"chat": map[string]any{"id": json.RawMessage(p.ChatID), "type": "supergroup", "title": "bima-alerts"},
				"from": map[string]any{"id": 123456, "is_bot": true, "first_name": "Bima", "username": "bima_bot"}}})
			_, _ = w.Write(resp)
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/v10/channels/") && strings.HasSuffix(r.URL.Path, "/messages"):
			// Discord bot API: requires "Authorization: Bot <token>"; webhook-only fields are rejected.
			var p map[string]any
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Bot ") {
				http.Error(w, `{"message":"401: Unauthorized","code":0}`, http.StatusUnauthorized)
				return
			}
			if json.Unmarshal(body, &p) != nil || p["embeds"] == nil || p["username"] != nil {
				http.Error(w, `{"message":"Invalid Form Body","code":50035}`, http.StatusBadRequest)
				return
			}
			b, _ := json.Marshal(p["embeds"])
			record("discord-bot", body, string(b))
			_, _ = w.Write([]byte(`{"id":"1","channel_id":"1"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/discord/webhook":
			var p struct {
				Embeds []struct {
					Title       string `json:"title"`
					Description string `json:"description"`
					Fields      []struct{ Name, Value string }
				} `json:"embeds"`
			}
			if json.Unmarshal(body, &p) != nil || len(p.Embeds) == 0 {
				http.Error(w, `{"message":"Cannot send an empty message"}`, http.StatusBadRequest)
				return
			}
			var sb strings.Builder
			for _, e := range p.Embeds {
				sb.WriteString(e.Title + "\n" + e.Description + "\n")
				for _, f := range e.Fields {
					sb.WriteString(f.Name + ": " + f.Value + "\n")
				}
			}
			record("discord", body, sb.String())
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && r.URL.Path == "/messages":
			mu.Lock()
			msgs, rejected = []msg{}, 0
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/messages":
			mu.Lock()
			defer mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"messages": msgs, "rejected": rejected, "rate_limited": rateLimits})
		default:
			http.NotFound(w, r)
		}
	})
	log.Println("mocknotify listening on :8090")
	log.Fatal(http.ListenAndServe(":8090", nil))
}

func record(ch string, body []byte, text string) {
	mu.Lock()
	defer mu.Unlock()
	msgs = append(msgs, msg{Channel: ch, Time: time.Now(), Body: body, Text: text})
	log.Printf("%s message #%d: %.120q", ch, len(msgs), text)
}
