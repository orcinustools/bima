// mockcf is a small stand-in for the Cloudflare API v4 used by the e2e tests:
// token verify, account IP lists + items, and a zone's custom-rules
// entrypoint. Like Cloudflare it rejects rules longer than 4096 chars and
// rules that reference an IP list that does not exist.
// GET /_state dumps everything for assertions.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
)

type item struct {
	ID      string `json:"id"`
	IP      string `json:"ip"`
	Comment string `json:"comment,omitempty"`
}

type list struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	NumItems int    `json:"num_items"`
	items    []item
}

var (
	mu     sync.Mutex
	lists  = map[string]*list{} // id -> list
	zones  = map[string][]map[string]any{}
	nextID int
	calls  []string
	token  = env("MOCKCF_TOKEN", "cf-test-token")
	listRe = regexp.MustCompile(`\$([a-z0-9_]+)`)
	strRe  = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`) // string literals: "$x" inside them is not a list
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func id() string { nextID++; return fmt.Sprintf("%032x", nextID) }

func reply(w http.ResponseWriter, code int, result any, msg ...string) {
	errs := []map[string]any{}
	for _, m := range msg {
		errs = append(errs, map[string]any{"code": 10000 + code, "message": m})
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"success": code < 300, "errors": errs, "messages": []any{}, "result": result})
}

func main() {
	http.HandleFunc("/", handle)
	addr := env("ADDR", ":8095")
	log.Println("mockcf listening on", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func handle(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	p := r.URL.Path
	if p == "/_state" {
		out := map[string]any{"zones": zones, "calls": calls}
		ls := map[string]any{}
		for _, l := range lists {
			ls[l.Name] = map[string]any{"id": l.ID, "items": l.items}
		}
		out["lists"] = ls
		_ = json.NewEncoder(w).Encode(out)
		return
	}
	calls = append(calls, r.Method+" "+p)
	if r.Header.Get("Authorization") != "Bearer "+token {
		reply(w, 403, nil, "Authentication error")
		return
	}
	parts := strings.Split(strings.Trim(p, "/"), "/")
	switch {
	case p == "/user/tokens/verify":
		reply(w, 200, map[string]any{"id": "t", "status": "active"})

	case len(parts) == 4 && parts[0] == "accounts" && parts[2] == "rules" && parts[3] == "lists":
		if r.Method == http.MethodPost {
			var l list
			_ = json.NewDecoder(r.Body).Decode(&l)
			for _, x := range lists {
				if x.Name == l.Name {
					reply(w, 400, nil, "duplicate list name")
					return
				}
			}
			l.ID = id()
			lists[l.ID] = &l
			reply(w, 200, l)
			return
		}
		out := []list{}
		for _, l := range lists {
			c := *l
			c.NumItems = len(l.items)
			out = append(out, c)
		}
		reply(w, 200, out)

	case len(parts) == 6 && parts[0] == "accounts" && parts[5] == "items":
		l := lists[parts[4]]
		if l == nil {
			reply(w, 404, nil, "list not found")
			return
		}
		switch r.Method {
		case http.MethodGet:
			reply(w, 200, l.items)
		case http.MethodPost:
			var in []item
			_ = json.NewDecoder(r.Body).Decode(&in)
			for _, it := range in {
				it.ID = id()
				l.items = append(l.items, it)
			}
			reply(w, 200, map[string]string{"operation_id": id()})
		case http.MethodDelete:
			var in struct{ Items []item }
			_ = json.NewDecoder(r.Body).Decode(&in)
			drop := map[string]bool{}
			for _, it := range in.Items {
				drop[it.ID] = true
			}
			keep := l.items[:0]
			for _, it := range l.items {
				if !drop[it.ID] {
					keep = append(keep, it)
				}
			}
			l.items = keep
			reply(w, 200, map[string]string{"operation_id": id()})
		}

	case len(parts) == 6 && parts[0] == "zones" && parts[5] == "entrypoint":
		z := parts[1]
		rules, ok := zones[z]
		switch r.Method {
		case http.MethodGet:
			if !ok {
				reply(w, 404, nil, "Could not find entrypoint ruleset in the http_request_firewall_custom phase")
				return
			}
			reply(w, 200, map[string]any{"id": "rs-" + z, "rules": rules})
		case http.MethodPut:
			if !ok {
				reply(w, 404, nil, "Could not find entrypoint ruleset")
				return
			}
			var b struct{ Rules []map[string]any }
			_ = json.NewDecoder(r.Body).Decode(&b)
			if msg := validate(b.Rules); msg != "" {
				reply(w, 400, nil, msg)
				return
			}
			zones[z] = assignIDs(b.Rules)
			reply(w, 200, map[string]any{"id": "rs-" + z, "rules": zones[z]})
		}

	case len(parts) == 3 && parts[0] == "zones" && parts[2] == "rulesets" && r.Method == http.MethodPost:
		var b struct {
			Phase string
			Rules []map[string]any
		}
		_ = json.NewDecoder(r.Body).Decode(&b)
		if b.Phase != "http_request_firewall_custom" {
			reply(w, 400, nil, "unsupported phase")
			return
		}
		if msg := validate(b.Rules); msg != "" {
			reply(w, 400, nil, msg)
			return
		}
		zones[parts[1]] = assignIDs(b.Rules)
		reply(w, 200, map[string]any{"id": "rs-" + parts[1]})

	default:
		reply(w, 404, nil, "no route for "+r.Method+" "+p)
	}
}

func validate(rules []map[string]any) string {
	for _, r := range rules {
		e, _ := r["expression"].(string)
		if e == "" || len(e) > 4096 {
			return fmt.Sprintf("rule %v: expression empty or longer than 4096 (%d)", r["ref"], len(e))
		}
		for _, m := range listRe.FindAllStringSubmatch(strRe.ReplaceAllString(e, `""`), -1) {
			found := false
			for _, l := range lists {
				found = found || l.Name == m[1]
			}
			if !found {
				return "filter parsing error: unknown list $" + m[1]
			}
		}
		for _, k := range []string{"version", "last_updated"} {
			if _, ro := r[k]; ro {
				return "read-only field " + k
			}
		}
	}
	return ""
}

func assignIDs(rules []map[string]any) []map[string]any {
	for _, r := range rules {
		if r["id"] == nil {
			r["id"] = id()
		}
		r["version"] = "1" // read-only on Cloudflare: returned by GET, refused on PUT
	}
	return rules
}
