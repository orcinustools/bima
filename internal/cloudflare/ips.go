// Package cloudflare makes Bima work with Cloudflare: it generates Cloudflare
// WAF custom rules equivalent to Bima's URI/header signatures, syncs Bima bans
// to a Cloudflare IP list (blocked at the edge), and knows Cloudflare's edge
// address ranges so an origin behind Cloudflare restores the real client IP.
package cloudflare

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"
)

// EdgeRanges are Cloudflare's published edge ranges (https://www.cloudflare.com/ips/,
// API GET /client/v4/ips). Refresh with `bima cloudflare ips -fetch`.
var EdgeRanges = []string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
	"2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
}

// LoadRanges returns the CIDRs in file (one per line, # comments allowed), or
// the embedded EdgeRanges when file is "".
func LoadRanges(file string) ([]string, error) {
	if file == "" {
		return EdgeRanges, nil
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var out []string
	for line := range strings.SplitSeq(string(b), "\n") {
		line, _, _ = strings.Cut(line, "#")
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		if _, err := netip.ParsePrefix(line); err != nil {
			return nil, fmt.Errorf("%s: %q: %w", file, line, err)
		}
		out = append(out, line)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no CIDRs", file)
	}
	return out, nil
}

// FetchRanges downloads the current edge ranges from the Cloudflare API.
func FetchRanges(ctx context.Context, apiBase string) ([]string, error) {
	if apiBase == "" {
		apiBase = DefaultAPIBase
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/ips", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var r struct {
		Success bool `json:"success"`
		Result  struct {
			V4 []string `json:"ipv4_cidrs"`
			V6 []string `json:"ipv6_cidrs"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	out := append(r.Result.V4, r.Result.V6...)
	if !r.Success || len(out) == 0 {
		return nil, fmt.Errorf("cloudflare /ips: unexpected response (HTTP %d)", resp.StatusCode)
	}
	return out, nil
}
