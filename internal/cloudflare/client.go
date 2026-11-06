package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const DefaultAPIBase = "https://api.cloudflare.com/client/v4"

const customPhase = "http_request_firewall_custom"

// Client is a minimal Cloudflare API v4 client (rulesets + IP lists).
// Token permissions: Zone > Zone WAF > Edit (rules), Account > Account Filter
// Lists > Edit (ban sync).
type Client struct {
	Base  string
	Token string
	HTTP  *http.Client
}

func NewClient(base, token string) *Client {
	if base == "" {
		base = DefaultAPIBase
	}
	return &Client{Base: strings.TrimRight(base, "/"), Token: token, HTTP: &http.Client{Timeout: 20 * time.Second}}
}

// APIError is a non-success Cloudflare response.
type APIError struct {
	Status int
	Errors []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
}

func (e *APIError) Error() string {
	var m []string
	for _, x := range e.Errors {
		m = append(m, fmt.Sprintf("%d: %s", x.Code, x.Message))
	}
	return fmt.Sprintf("cloudflare API HTTP %d: %s", e.Status, strings.Join(m, "; "))
}

// NotFound reports whether err is an HTTP 404 from the API.
func NotFound(err error) bool {
	e, ok := err.(*APIError)
	return ok && e.Status == http.StatusNotFound
}

type envelope struct {
	Success    bool            `json:"success"`
	Errors     json.RawMessage `json:"errors"`
	Result     json.RawMessage `json:"result"`
	ResultInfo struct {
		Cursors struct {
			After string `json:"after"`
		} `json:"cursors"`
	} `json:"result_info"`
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) (*envelope, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	var env envelope
	if err := json.Unmarshal(b, &env); err != nil {
		return nil, fmt.Errorf("cloudflare API HTTP %d: %.200s", resp.StatusCode, b)
	}
	if !env.Success || resp.StatusCode >= 300 {
		ae := &APIError{Status: resp.StatusCode}
		_ = json.Unmarshal(env.Errors, &ae.Errors)
		return nil, ae
	}
	if out != nil && len(env.Result) > 0 && string(env.Result) != "null" {
		if err := json.Unmarshal(env.Result, out); err != nil {
			return nil, err
		}
	}
	return &env, nil
}

// VerifyToken checks the API token (user or account token).
func (c *Client) VerifyToken(ctx context.Context, accountID string) error {
	var r struct {
		Status string `json:"status"`
	}
	_, err := c.do(ctx, http.MethodGet, "/user/tokens/verify", nil, &r)
	if err != nil && accountID != "" {
		_, err = c.do(ctx, http.MethodGet, "/accounts/"+accountID+"/tokens/verify", nil, &r)
	}
	if err != nil {
		return err
	}
	if r.Status != "active" {
		return fmt.Errorf("token status %q", r.Status)
	}
	return nil
}

// ---- custom rules (zone entrypoint ruleset of http_request_firewall_custom)

// Ruleset is the zone's custom-rules entrypoint. Rules are kept as raw JSON so
// rules not managed by Bima are written back untouched.
type Ruleset struct {
	ID    string           `json:"id"`
	Rules []map[string]any `json:"rules"`
}

func (c *Client) CustomRules(ctx context.Context, zone string) (*Ruleset, error) {
	var rs Ruleset
	_, err := c.do(ctx, http.MethodGet, "/zones/"+zone+"/rulesets/phases/"+customPhase+"/entrypoint", nil, &rs)
	if err != nil {
		return nil, err
	}
	return &rs, nil
}

// PutCustomRules replaces the zone's custom rules (creating the entrypoint
// ruleset when it does not exist yet).
func (c *Client) PutCustomRules(ctx context.Context, zone string, rules []map[string]any) error {
	_, err := c.do(ctx, http.MethodPut, "/zones/"+zone+"/rulesets/phases/"+customPhase+"/entrypoint",
		map[string]any{"rules": rules}, nil)
	if NotFound(err) {
		_, err = c.do(ctx, http.MethodPost, "/zones/"+zone+"/rulesets", map[string]any{
			"name": "default", "kind": "zone", "phase": customPhase, "rules": rules}, nil)
	}
	return err
}

// Managed reports whether an existing rule was created by Bima.
func Managed(rule map[string]any) bool {
	ref, _ := rule["ref"].(string)
	desc, _ := rule["description"].(string)
	return strings.HasPrefix(ref, RefPrefix) || strings.HasPrefix(desc, DescPrefix)
}

// Merge returns the rule list to PUT: Bima rules first (blocklist is the
// cheapest and most decisive), then every rule not managed by Bima unchanged.
// With replaceAll the existing non-Bima rules are dropped.
func Merge(existing []map[string]any, bima []Rule, replaceAll bool) (out []map[string]any, kept, replaced int) {
	byRef := map[string]map[string]any{}
	for _, r := range existing {
		if Managed(r) {
			if ref, _ := r["ref"].(string); ref != "" {
				byRef[ref] = r
			}
			replaced++
		}
	}
	for _, r := range bima {
		m := map[string]any{"ref": r.Ref, "description": r.Description, "action": r.Action,
			"expression": r.Expression, "enabled": r.Enabled}
		if old, ok := byRef[r.Ref]; ok && old["id"] != nil {
			m["id"] = old["id"] // update in place
		}
		out = append(out, m)
	}
	if replaceAll {
		return out, 0, replaced
	}
	for _, r := range existing {
		if Managed(r) {
			continue
		}
		cp := map[string]any{}
		for k, v := range r {
			switch k {
			case "version", "last_updated", "categories":
				continue // read-only
			}
			cp[k] = v
		}
		out = append(out, cp)
		kept++
	}
	return out, kept, replaced
}

// ---- IP lists (account level)

type List struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	NumItems    int    `json:"num_items"`
	Description string `json:"description"`
}

type ListItem struct {
	ID      string `json:"id,omitempty"`
	IP      string `json:"ip"`
	Comment string `json:"comment,omitempty"`
}

func (c *Client) Lists(ctx context.Context, account string) ([]List, error) {
	var ls []List
	_, err := c.do(ctx, http.MethodGet, "/accounts/"+account+"/rules/lists", nil, &ls)
	return ls, err
}

// EnsureList returns the IP list called name, creating it if needed.
func (c *Client) EnsureList(ctx context.Context, account, name string) (*List, bool, error) {
	ls, err := c.Lists(ctx, account)
	if err != nil {
		return nil, false, err
	}
	for i := range ls {
		if ls[i].Name == name {
			if ls[i].Kind != "ip" {
				return nil, false, fmt.Errorf("list %q exists but is of kind %q (need ip)", name, ls[i].Kind)
			}
			return &ls[i], false, nil
		}
	}
	var l List
	_, err = c.do(ctx, http.MethodPost, "/accounts/"+account+"/rules/lists",
		map[string]any{"name": name, "kind": "ip", "description": "IPs banned by Bima WAF (managed automatically)"}, &l)
	if err != nil {
		return nil, false, err
	}
	return &l, true, nil
}

func (c *Client) ListItems(ctx context.Context, account, listID string) ([]ListItem, error) {
	var all []ListItem
	cursor := ""
	for range 1000 {
		q := url.Values{"per_page": {"500"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var page []ListItem
		env, err := c.do(ctx, http.MethodGet, "/accounts/"+account+"/rules/lists/"+listID+"/items?"+q.Encode(), nil, &page)
		if err != nil {
			return nil, err
		}
		all = append(all, page...)
		if cursor = env.ResultInfo.Cursors.After; cursor == "" || len(page) == 0 {
			break
		}
	}
	return all, nil
}

// AddItems appends items (asynchronous bulk operation on Cloudflare's side).
func (c *Client) AddItems(ctx context.Context, account, listID string, items []ListItem) error {
	if len(items) == 0 {
		return nil
	}
	_, err := c.do(ctx, http.MethodPost, "/accounts/"+account+"/rules/lists/"+listID+"/items", items, nil)
	return err
}

func (c *Client) DeleteItems(ctx context.Context, account, listID string, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	items := make([]map[string]string, len(ids))
	for i, id := range ids {
		items[i] = map[string]string{"id": id}
	}
	_, err := c.do(ctx, http.MethodDelete, "/accounts/"+account+"/rules/lists/"+listID+"/items", map[string]any{"items": items}, nil)
	return err
}
