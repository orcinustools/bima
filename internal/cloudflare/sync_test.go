package cloudflare

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeCF implements the list endpoints Bima uses.
type fakeCF struct {
	mu     sync.Mutex
	lists  []List
	items  map[string]ListItem // id -> item
	nextID int
	calls  []string
	token  string
}

func newFakeCF() *fakeCF { return &fakeCF{items: map[string]ListItem{}, token: "tok"} }

func (f *fakeCF) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	reply := func(code int, result any) {
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": code < 300, "errors": []any{}, "result": result})
	}
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		w.WriteHeader(403)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []map[string]any{{"code": 10000, "message": "Authentication error"}}})
		return
	}
	p := strings.TrimPrefix(r.URL.Path, "/accounts/acc/rules/lists")
	switch {
	case p == "" && r.Method == http.MethodGet:
		reply(200, f.lists)
	case p == "" && r.Method == http.MethodPost:
		var l List
		_ = json.NewDecoder(r.Body).Decode(&l)
		l.ID = "list1"
		f.lists = append(f.lists, l)
		reply(200, l)
	case strings.HasSuffix(p, "/items") && r.Method == http.MethodGet:
		var out []ListItem
		for _, it := range f.items {
			out = append(out, it)
		}
		reply(200, out)
	case strings.HasSuffix(p, "/items") && r.Method == http.MethodPost:
		var in []ListItem
		_ = json.NewDecoder(r.Body).Decode(&in)
		for _, it := range in {
			f.nextID++
			it.ID = fmt.Sprintf("i%d", f.nextID)
			f.items[it.ID] = it
		}
		reply(200, map[string]string{"operation_id": "op"})
	case strings.HasSuffix(p, "/items") && r.Method == http.MethodDelete:
		var in struct {
			Items []struct{ ID string } `json:"items"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)
		for _, it := range in.Items {
			delete(f.items, it.ID)
		}
		reply(200, map[string]string{"operation_id": "op"})
	default:
		reply(404, nil)
	}
}

func (f *fakeCF) ips() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, it := range f.items {
		out = append(out, it.IP)
	}
	slices.Sort(out)
	return out
}

func TestSyncerReconciles(t *testing.T) {
	f := newFakeCF()
	srv := httptest.NewServer(f)
	defer srv.Close()
	// an entry added by a human must survive
	f.items["manual"] = ListItem{ID: "manual", IP: "198.51.100.7", Comment: "added by ops"}

	var mu sync.Mutex
	bans := map[string]time.Time{
		"203.0.113.5":         time.Now().Add(time.Hour),
		"10.1.2.3":            time.Now().Add(time.Hour), // private: never sent to the edge
		"2001:db8:1:2:3::9":   time.Now().Add(time.Hour), // -> /64
		"::ffff:203.0.113.77": time.Now().Add(time.Hour),
	}
	s := NewSyncer(NewClient(srv.URL, "tok"), "acc", "bima_blocklist", time.Hour, func() map[string]time.Time {
		mu.Lock()
		defer mu.Unlock()
		out := map[string]time.Time{}
		for k, v := range bans {
			out[k] = v
		}
		return out
	})
	ctx := context.Background()
	if err := s.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	want := []string{"198.51.100.7", "2001:db8:1:2::/64", "203.0.113.5", "203.0.113.77"}
	if got := f.ips(); !slices.Equal(got, want) {
		t.Fatalf("after first sync: %v want %v", got, want)
	}
	if len(f.lists) != 1 || f.lists[0].Name != "bima_blocklist" || f.lists[0].Kind != "ip" {
		t.Fatalf("list not created: %+v", f.lists)
	}

	// idempotent: no writes when nothing changed
	f.calls = nil
	if err := s.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.calls {
		if !strings.HasPrefix(c, "GET") {
			t.Fatalf("unexpected write on steady state: %v", f.calls)
		}
	}

	// unban -> removed; manual entry untouched
	mu.Lock()
	delete(bans, "203.0.113.5")
	mu.Unlock()
	if err := s.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	want = []string{"198.51.100.7", "2001:db8:1:2::/64", "203.0.113.77"}
	if got := f.ips(); !slices.Equal(got, want) {
		t.Fatalf("after unban: %v want %v", got, want)
	}
	if s.Added.Load() != 3 || s.Removed.Load() != 1 {
		t.Fatalf("added=%d removed=%d", s.Added.Load(), s.Removed.Load())
	}
}

func TestSyncerBadToken(t *testing.T) {
	f := newFakeCF()
	srv := httptest.NewServer(f)
	defer srv.Close()
	s := NewSyncer(NewClient(srv.URL, "wrong"), "acc", "bima_blocklist", time.Hour, func() map[string]time.Time { return nil })
	err := s.SyncOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "Authentication error") {
		t.Fatalf("want auth error, got %v", err)
	}
	if s.Errors.Load() != 1 {
		t.Fatal("error not counted")
	}
}

func TestListKey(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.5": "203.0.113.5", "::ffff:203.0.113.5": "203.0.113.5",
		"2001:db8::1": "2001:db8::/64", "10.0.0.1": "", "127.0.0.1": "", "100.64.1.1": "", "junk": "",
	} {
		got, ok := ListKey(in)
		if got != want || ok != (want != "") {
			t.Errorf("ListKey(%s) = %q,%v want %q", in, got, ok, want)
		}
	}
}

func TestLoadRanges(t *testing.T) {
	r, err := LoadRanges("")
	if err != nil || len(r) < 20 {
		t.Fatal(err, len(r))
	}
}
