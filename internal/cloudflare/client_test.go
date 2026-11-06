package cloudflare

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeRulesets serves the custom-rules entrypoint of one zone.
type fakeRulesets struct {
	exists bool
	rules  []map[string]any
	puts   int
	posts  int
}

func (f *fakeRulesets) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reply := func(code int, result any) {
		w.WriteHeader(code)
		errs := []any{}
		if code >= 300 {
			errs = append(errs, map[string]any{"code": 10003, "message": "not found"})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"success": code < 300, "errors": errs, "result": result})
	}
	const ep = "/zones/z1/rulesets/phases/http_request_firewall_custom/entrypoint"
	switch {
	case r.URL.Path == ep && r.Method == http.MethodGet:
		if !f.exists {
			reply(404, nil)
			return
		}
		reply(200, map[string]any{"id": "rs1", "rules": f.rules})
	case r.URL.Path == ep && r.Method == http.MethodPut:
		if !f.exists {
			reply(404, nil)
			return
		}
		var b struct{ Rules []map[string]any }
		_ = json.NewDecoder(r.Body).Decode(&b)
		f.rules, f.puts = b.Rules, f.puts+1
		reply(200, map[string]any{"id": "rs1", "rules": f.rules})
	case r.URL.Path == "/zones/z1/rulesets" && r.Method == http.MethodPost:
		var b struct {
			Phase string
			Rules []map[string]any
		}
		_ = json.NewDecoder(r.Body).Decode(&b)
		if b.Phase != customPhase {
			reply(400, nil)
			return
		}
		f.exists, f.rules, f.posts = true, b.Rules, f.posts+1
		reply(200, map[string]any{"id": "rs1"})
	default:
		reply(404, nil)
	}
}

func TestApplyCreatesThenUpdatesInPlace(t *testing.T) {
	f := &fakeRulesets{}
	srv := httptest.NewServer(f)
	defer srv.Close()
	c := NewClient(srv.URL, "tok")
	ctx := context.Background()
	rules, _ := Generate(DefaultOptions())

	// zone without custom rules: entrypoint is created
	if _, err := c.CustomRules(ctx, "z1"); !NotFound(err) {
		t.Fatalf("want 404, got %v", err)
	}
	merged, _, _ := Merge(nil, rules, false)
	if err := c.PutCustomRules(ctx, "z1", merged); err != nil {
		t.Fatal(err)
	}
	if f.posts != 1 || len(f.rules) != len(rules) {
		t.Fatalf("posts=%d rules=%d", f.posts, len(f.rules))
	}

	// the owner adds a rule; Cloudflare assigns ids; re-apply keeps it
	for i := range f.rules {
		f.rules[i]["id"] = "id-" + f.rules[i]["ref"].(string)
		f.rules[i]["version"] = "1"
	}
	f.rules = append(f.rules, map[string]any{"id": "mine", "description": "allow office", "action": "skip",
		"expression": `ip.src eq 192.0.2.1`, "enabled": true, "version": "4"})
	rs, err := c.CustomRules(ctx, "z1")
	if err != nil {
		t.Fatal(err)
	}
	merged, kept, replaced := Merge(rs.Rules, rules, false)
	if kept != 1 || replaced != len(rules) {
		t.Fatalf("kept=%d replaced=%d", kept, replaced)
	}
	if err := c.PutCustomRules(ctx, "z1", merged); err != nil {
		t.Fatal(err)
	}
	if f.puts != 1 || len(f.rules) != len(rules)+1 {
		t.Fatalf("puts=%d rules=%d", f.puts, len(f.rules))
	}
	for _, r := range f.rules {
		if Managed(r) && r["id"] != "id-"+r["ref"].(string) {
			t.Fatalf("bima rule not updated in place: %v", r["id"])
		}
		if r["version"] != nil {
			t.Fatal("read-only field sent back")
		}
	}
}
