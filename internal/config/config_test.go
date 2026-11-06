package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExampleConfigLoads(t *testing.T) {
	t.Setenv("BIMA_TELEGRAM_TOKEN", "x")
	t.Setenv("BIMA_TELEGRAM_CHAT_ID", "1")
	t.Setenv("BIMA_DISCORD_WEBHOOK", "http://x")
	c, err := Load("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if c.Mode != ModeDetect || len(c.Ban.RuntimeAPIs) != 1 || !c.CRS.FastPath || c.State.Backend != "memory" {
		t.Fatalf("unexpected: %+v", c)
	}
	for _, f := range []string{"../../deploy/e2e/config.yaml", "../../deploy/e2e/config.untuned.yaml", "../../deploy/e2e-prod/config.yaml"} {
		if _, err := Load(f); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
}

func loadYAML(t *testing.T, y string) (*Config, error) {
	t.Helper()
	p := t.TempDir() + "/c.yaml"
	if err := os.WriteFile(p, []byte("ban: {runtime_api: unix:/x}\n"+y), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(p)
}

func TestCloudflareTrustEdge(t *testing.T) {
	c, err := loadYAML(t, "trusted_proxies: [10.0.0.0/8]\ncloudflare: {trust_edge: true}\n")
	if err != nil {
		t.Fatal(err)
	}
	for ip, want := range map[string]bool{"172.64.1.1": true, "2606:4700::1": true, "10.2.3.4": true, "203.0.113.9": false} {
		if got, _ := c.Trusted(netip.MustParseAddr(ip)); got != want {
			t.Errorf("Trusted(%s)=%v want %v", ip, got, want)
		}
	}
	f := t.TempDir() + "/edge.lst"
	_ = os.WriteFile(f, []byte("# comment\n198.51.100.0/24\n"), 0o644)
	c, err = loadYAML(t, "cloudflare: {trust_edge: true, edge_ips_file: "+f+"}\n")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := c.Trusted(netip.MustParseAddr("198.51.100.7")); !got {
		t.Error("edge_ips_file not used")
	}
	if got, _ := c.Trusted(netip.MustParseAddr("172.64.1.1")); got {
		t.Error("edge_ips_file must replace the built-in ranges")
	}
}

func TestCloudflareBanSyncNeedsToken(t *testing.T) {
	y := "cloudflare: {ban_sync: {enabled: true, account_id: acc}}\n"
	if _, err := loadYAML(t, y); err == nil {
		t.Fatal("ban_sync without token accepted")
	}
	t.Setenv("BIMA_CLOUDFLARE_API_TOKEN", "tok")
	c, err := loadYAML(t, y)
	if err != nil {
		t.Fatal(err)
	}
	if c.Cloudflare.BanSync.ListName != "bima_blocklist" || c.Cloudflare.APIToken != "tok" {
		t.Fatalf("%+v", c.Cloudflare)
	}
}

func TestExamplesLoad(t *testing.T) {
	t.Setenv("BIMA_TELEGRAM_TOKEN", "x")
	t.Setenv("BIMA_TELEGRAM_CHAT_ID", "1")
	t.Setenv("BIMA_DISCORD_BOT_TOKEN", "x")
	t.Setenv("BIMA_DISCORD_CHANNEL_ID", "1")
	t.Setenv("BIMA_CLOUDFLARE_API_TOKEN", "x")
	files, _ := filepath.Glob("../../examples/config/*.yaml")
	if len(files) < 12 {
		t.Fatalf("expected the example configs, found %d", len(files))
	}
	for _, f := range files {
		edge := ""
		if strings.Contains(f, "cloudflare") { // edge_ips_file points at a host path
			edge = t.TempDir() + "/edge.lst"
			_ = os.WriteFile(edge, []byte("173.245.48.0/20\n"), 0o644)
		}
		b, _ := os.ReadFile(f)
		y := string(b)
		if edge != "" {
			y = strings.ReplaceAll(y, "/etc/haproxy/bima-cloudflare.lst", edge)
		}
		p := t.TempDir() + "/c.yaml"
		_ = os.WriteFile(p, []byte(y), 0o600)
		c, err := Load(p)
		if err != nil {
			t.Errorf("%s: %v", filepath.Base(f), err)
			continue
		}
		if c.Listen == "" || c.MetricsAddr == "" {
			t.Errorf("%s: listen/metrics_addr missing", filepath.Base(f))
		}
	}
}
