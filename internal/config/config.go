// Package config loads Bima configuration from YAML with env overrides for secrets.
package config

import (
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Mode string

const (
	ModeEnforce Mode = "enforce" // block/tarpit/ban for real
	ModeDetect  Mode = "detect"  // shadow mode: alert only, always allow
)

type Config struct {
	Listen      string `yaml:"listen"`       // SPOP listen address, e.g. ":12345"
	MetricsAddr string `yaml:"metrics_addr"` // /healthz and /metrics, e.g. ":9101"
	Mode        Mode   `yaml:"mode"`
	Host        string `yaml:"host"` // label shown in alerts

	Allowlist []string       `yaml:"allowlist"` // CIDRs never inspected
	allow     []netip.Prefix `yaml:"-"`

	// TrustedProxies are the CDN/LB addresses allowed to set the client IP via
	// X-Forwarded-For. When HAProxy rewrote the client IP for a peer outside this
	// list (misconfiguration), Bima uses the TCP peer as the client identity.
	TrustedProxies []string       `yaml:"trusted_proxies"`
	trusted        []netip.Prefix `yaml:"-"`

	// Bots: verify User-Agents that claim to be well-known crawlers
	// (reverse DNS + forward confirmation, asynchronous and cached).
	Bots struct {
		Verify  bool          `yaml:"verify"`
		Timeout time.Duration `yaml:"timeout"`
	} `yaml:"bots"`

	MaxBodyInspect int `yaml:"max_body_inspect"` // bytes of body to inspect

	CRS struct {
		Enabled        bool   `yaml:"enabled"`
		Paranoia       int    `yaml:"paranoia"`
		Threshold      int    `yaml:"inbound_threshold"` // CRS inbound anomaly threshold
		AllowedMethods string `yaml:"allowed_methods"`
		// FastPath skips CRS for requests whose inputs are all trivially
		// plain (see engine.crsNeeded). Bima signatures always run.
		FastPath bool `yaml:"fast_path"`
		// Timeout is CRS's own deadline; keep it well under the SPOE
		// "timeout processing" (100ms) so the agent always answers in time.
		Timeout time.Duration `yaml:"timeout"`
		// Extra SecLang directives appended after CRS (rule exclusions / tuning).
		ExtraDirectives string `yaml:"extra_directives"`
	} `yaml:"crs"`

	Score struct {
		Tarpit   float64       `yaml:"tarpit"`
		Ban      float64       `yaml:"ban"`
		HalfLife time.Duration `yaml:"half_life"` // exponential decay half-life
		Window   time.Duration `yaml:"window"`    // counting window for enumeration signals
	} `yaml:"score"`

	// Distributed enumeration (many IPs, one ASN / client fingerprint).
	Group struct {
		By          []string      `yaml:"by"` // any of: asn, fingerprint
		Distinct404 int           `yaml:"distinct_404"`
		MinIPs      int           `yaml:"min_ips"`
		Member404   int           `yaml:"member_404"`
		Penalty     float64       `yaml:"penalty"`
		FlagTTL     time.Duration `yaml:"flag_ttl"`
	} `yaml:"group"`

	Ban struct {
		Enabled bool `yaml:"enabled"`
		// One entry per HAProxy instance: "tcp:host:port" or "unix:/path".
		RuntimeAPIs       []string        `yaml:"runtime_apis"`
		RuntimeAPI        string          `yaml:"runtime_api"` // single-instance shorthand
		MapFile           string          `yaml:"map_file"`    // must match path in haproxy.cfg
		Durations         []time.Duration `yaml:"durations"`   // escalation ladder
		ReconcileInterval time.Duration   `yaml:"reconcile_interval"`
	} `yaml:"ban"`

	// Shared state. memory = single agent (bans persisted to ban_file);
	// redis = several agents share scores, windows and bans.
	State struct {
		Backend string `yaml:"backend"`
		BanFile string `yaml:"ban_file"`
		Redis   struct {
			Addr     string `yaml:"addr"`
			Password string `yaml:"password"`
			DB       int    `yaml:"db"`
			Prefix   string `yaml:"prefix"`
		} `yaml:"redis"`
	} `yaml:"state"`

	GeoIP struct {
		CountryDB string `yaml:"country_db"`
		ASNDB     string `yaml:"asn_db"`
	} `yaml:"geoip"`

	// Exclusions suppress findings (false-positive tuning). A finding is
	// dropped when its rule matches one of Rules (exact, or prefix with
	// trailing '*'), the request path matches Path (regex, optional) and its
	// location starts with one of Locations (optional).
	Exclusions []Exclusion `yaml:"exclusions"`

	Alert struct {
		DedupWindow    time.Duration `yaml:"dedup_window"`
		DigestInterval time.Duration `yaml:"digest_interval"`
		Telegram       struct {
			Enabled bool   `yaml:"enabled"`
			APIBase string `yaml:"api_base"`
			Token   string `yaml:"token"`
			ChatID  string `yaml:"chat_id"`
		} `yaml:"telegram"`
		Discord struct {
			Enabled bool `yaml:"enabled"`
			// Either an incoming webhook, or a bot token + channel id.
			WebhookURL string `yaml:"webhook_url"`
			BotToken   string `yaml:"bot_token"`
			ChannelID  string `yaml:"channel_id"`
			APIBase    string `yaml:"api_base"`
		} `yaml:"discord"`
	} `yaml:"alert"`
}

type Exclusion struct {
	Rules     []string       `yaml:"rules"`
	Path      string         `yaml:"path"`
	Locations []string       `yaml:"locations"`
	Reason    string         `yaml:"reason"`
	PathRe    *regexp.Regexp `yaml:"-"`
}

func (x *Exclusion) Match(rule, path, location string) bool {
	ok := false
	for _, r := range x.Rules {
		if r == rule || (strings.HasSuffix(r, "*") && strings.HasPrefix(rule, strings.TrimSuffix(r, "*"))) {
			ok = true
			break
		}
	}
	if !ok {
		return false
	}
	if x.PathRe != nil && !x.PathRe.MatchString(path) {
		return false
	}
	if len(x.Locations) == 0 {
		return true
	}
	for _, l := range x.Locations {
		if strings.HasPrefix(location, l) {
			return true
		}
	}
	return false
}

func Default() *Config {
	c := &Config{
		Listen:         ":12345",
		MetricsAddr:    ":9101",
		Mode:           ModeEnforce,
		Host:           "bima",
		MaxBodyInspect: 64 * 1024,
	}
	c.CRS.Enabled = true
	c.CRS.Paranoia = 1
	c.CRS.Threshold = 5
	c.CRS.FastPath = true
	c.CRS.Timeout = 50 * time.Millisecond
	c.Bots.Verify = true
	c.Bots.Timeout = 2 * time.Second
	c.Score.Tarpit = 50
	c.Score.Ban = 80
	c.Score.HalfLife = 5 * time.Minute
	c.Score.Window = time.Minute
	c.Group.By = []string{"asn", "fingerprint"}
	c.Group.Distinct404 = 60
	c.Group.MinIPs = 3
	c.Group.Member404 = 3
	c.Group.Penalty = 80
	c.Group.FlagTTL = 10 * time.Minute
	c.State.Backend = "memory"
	c.State.Redis.Prefix = "bima:"
	c.Ban.ReconcileInterval = 2 * time.Second
	c.Ban.Enabled = true
	c.Ban.MapFile = "/usr/local/etc/haproxy/bima-blocklist.map"
	c.Ban.Durations = []time.Duration{10 * time.Minute, time.Hour, 24 * time.Hour}
	c.Alert.DedupWindow = 5 * time.Minute
	c.Alert.DigestInterval = 5 * time.Minute
	c.Alert.Telegram.APIBase = "https://api.telegram.org"
	return c
}

func Load(path string) (*Config, error) {
	c := Default()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if err := yaml.Unmarshal(b, c); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
	}
	// Secrets come from env so they never live in committed config.
	if v := os.Getenv("BIMA_TELEGRAM_TOKEN"); v != "" {
		c.Alert.Telegram.Token = v
	}
	if v := os.Getenv("BIMA_TELEGRAM_CHAT_ID"); v != "" {
		c.Alert.Telegram.ChatID = v
	}
	if v := os.Getenv("BIMA_DISCORD_WEBHOOK"); v != "" {
		c.Alert.Discord.WebhookURL = v
	}
	if v := os.Getenv("BIMA_DISCORD_BOT_TOKEN"); v != "" {
		c.Alert.Discord.BotToken = v
	}
	if v := os.Getenv("BIMA_DISCORD_CHANNEL_ID"); v != "" {
		c.Alert.Discord.ChannelID = v
	}
	if v := os.Getenv("BIMA_DISCORD_API_BASE"); v != "" {
		c.Alert.Discord.APIBase = v
	}
	if v := os.Getenv("BIMA_MODE"); v != "" {
		c.Mode = Mode(v)
	}
	if c.Mode != ModeEnforce && c.Mode != ModeDetect {
		return nil, fmt.Errorf("invalid mode %q", c.Mode)
	}
	if v := os.Getenv("BIMA_REDIS_PASSWORD"); v != "" {
		c.State.Redis.Password = v
	}
	if c.Ban.RuntimeAPI != "" {
		c.Ban.RuntimeAPIs = append(c.Ban.RuntimeAPIs, c.Ban.RuntimeAPI)
	}
	if c.Ban.Enabled && len(c.Ban.RuntimeAPIs) == 0 {
		return nil, fmt.Errorf("ban.runtime_apis is empty")
	}
	if c.State.Backend != "memory" && c.State.Backend != "redis" {
		return nil, fmt.Errorf("state.backend must be memory or redis")
	}
	if c.State.Backend == "redis" && c.State.Redis.Addr == "" {
		return nil, fmt.Errorf("state.redis.addr required")
	}
	for i := range c.Exclusions {
		x := &c.Exclusions[i]
		if len(x.Rules) == 0 {
			return nil, fmt.Errorf("exclusions[%d]: rules required", i)
		}
		if x.Path != "" {
			re, err := regexp.Compile(x.Path)
			if err != nil {
				return nil, fmt.Errorf("exclusions[%d].path: %w", i, err)
			}
			x.PathRe = re
		}
	}
	if len(c.Ban.Durations) == 0 {
		return nil, fmt.Errorf("ban.durations must not be empty")
	}
	var err error
	if c.allow, err = parsePrefixes(c.Allowlist); err != nil {
		return nil, fmt.Errorf("allowlist: %w", err)
	}
	if c.trusted, err = parsePrefixes(c.TrustedProxies); err != nil {
		return nil, fmt.Errorf("trusted_proxies: %w", err)
	}
	return c, nil
}

func parsePrefixes(list []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range list {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			a, err2 := netip.ParseAddr(s)
			if err2 != nil {
				return nil, fmt.Errorf("%q: %w", s, err)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		out = append(out, p)
	}
	return out, nil
}

// SetAllowlist replaces the allowlist (tests).
func (c *Config) SetAllowlist(list []string) error {
	p, err := parsePrefixes(list)
	if err == nil {
		c.Allowlist, c.allow = list, p
	}
	return err
}

// SetTrustedProxies replaces the trusted proxy list (tests).
func (c *Config) SetTrustedProxies(list []string) error {
	p, err := parsePrefixes(list)
	if err == nil {
		c.TrustedProxies, c.trusted = list, p
	}
	return err
}

// Trusted reports whether a is a configured trusted proxy. ok=false when no
// trusted proxies are configured (unknown).
func (c *Config) Trusted(a netip.Addr) (trusted, configured bool) {
	if len(c.trusted) == 0 {
		return false, false
	}
	a = a.Unmap()
	for _, p := range c.trusted {
		if p.Contains(a) {
			return true, true
		}
	}
	return false, true
}

func (c *Config) Allowed(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range c.allow {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
