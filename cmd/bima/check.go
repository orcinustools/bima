package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/orcinustools/bima/internal/alert"
	"github.com/orcinustools/bima/internal/ban"
	"github.com/orcinustools/bima/internal/config"
	"github.com/orcinustools/bima/internal/detect"
	"github.com/orcinustools/bima/internal/geoip"
	"github.com/orcinustools/bima/internal/store"
)

type checkResult struct {
	Name   string `json:"name"`
	Status string `json:"status"` // pass | warn | fail | skip
	Detail string `json:"detail,omitempty"`
	Hint   string `json:"hint,omitempty"`
}

type checker struct{ res []checkResult }

func (c *checker) add(name, status, detail, hint string) {
	c.res = append(c.res, checkResult{name, status, detail, hint})
}

func cmdCheck(args []string) int {
	f := flag.NewFlagSet("check", flag.ExitOnError)
	cfgPath := f.String("config", "config.yaml", "path to config file")
	asJSON := f.Bool("json", false, "machine-readable output")
	send := f.Bool("send", false, "also deliver a test alert to every notifier")
	_ = f.Parse(args)
	c := &checker{}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		c.add("config", "fail", err.Error(), "fix the YAML / missing env secrets; see `bima skills show bima-setup references/config.md`")
		return c.report(*asJSON)
	}
	c.add("config", "pass", fmt.Sprintf("%s (mode=%s, state=%s)", *cfgPath, cfg.Mode, cfg.State.Backend), "")
	if cfg.Mode == config.ModeDetect {
		c.add("mode", "warn", "detect (shadow): nothing is blocked", "switch to enforce after reviewing GET /report")
	} else {
		c.add("mode", "pass", "enforce", "")
	}

	if cfg.CRS.Enabled {
		t := time.Now()
		if _, err := detect.NewCRS(cfg.CRS.Paranoia, cfg.CRS.Threshold, cfg.CRS.AllowedMethods, cfg.CRS.ExtraDirectives); err != nil {
			c.add("crs", "fail", err.Error(), "check crs.extra_directives syntax")
		} else {
			c.add("crs", "pass", fmt.Sprintf("OWASP CRS paranoia %d loaded in %s", cfg.CRS.Paranoia, time.Since(t).Round(time.Millisecond)), "")
		}
	} else {
		c.add("crs", "warn", "disabled", "only Bima signatures are active")
	}

	if cfg.GeoIP.CountryDB == "" && cfg.GeoIP.ASNDB == "" {
		c.add("geoip", "skip", "not configured (alerts without ASN/country; group.by asn inactive)", "optional: DB-IP Lite or GeoLite2 MMDB")
	} else if db, err := geoip.Open(cfg.GeoIP.CountryDB, cfg.GeoIP.ASNDB); err != nil {
		c.add("geoip", "fail", err.Error(), "check geoip paths and permissions")
	} else {
		c.add("geoip", "pass", "8.8.8.8 → "+db.Lookup("8.8.8.8").String(), "")
	}

	switch cfg.State.Backend {
	case "redis":
		if r, err := store.NewRedis(cfg.State.Redis.Addr, cfg.State.Redis.Password, cfg.State.Redis.DB, cfg.State.Redis.Prefix, 2); err != nil {
			c.add("state", "fail", "redis "+cfg.State.Redis.Addr+": "+err.Error(), "Redis must be reachable from every agent (BIMA_REDIS_PASSWORD if auth)")
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			bans, _ := r.Bans(ctx)
			cancel()
			_ = r.Close()
			c.add("state", "pass", fmt.Sprintf("redis %s reachable, %d active bans", cfg.State.Redis.Addr, len(bans)), "")
		}
	default:
		if cfg.State.BanFile == "" {
			c.add("state", "warn", "memory without ban_file: bans are lost on restart", "set state.ban_file, e.g. /var/lib/bima/bans.json")
		} else if err := writable(filepath.Dir(cfg.State.BanFile)); err != nil {
			c.add("state", "fail", err.Error(), "create the directory owned by the bima user (install -d -o bima /var/lib/bima)")
		} else {
			c.add("state", "pass", "memory, bans persisted to "+cfg.State.BanFile, "")
		}
	}

	if cfg.Ban.Enabled {
		for _, api := range cfg.Ban.RuntimeAPIs {
			c.haproxy(api, cfg)
		}
	} else {
		c.add("runtime_api", "skip", "ban.enabled=false", "")
	}

	agent := cfg.Listen
	if strings.HasPrefix(agent, ":") {
		agent = "127.0.0.1" + agent
	}
	if conn, err := net.DialTimeout("tcp", agent, time.Second); err == nil {
		conn.Close()
		c.add("agent", "pass", "agent listening on "+agent, "")
	} else {
		c.add("agent", "warn", "nothing listening on "+agent, "start it: systemctl enable --now bima (expected before first start)")
	}
	metricsURL := "http://" + strings.Replace(cfg.MetricsAddr, ":", "127.0.0.1:", 1) + "/healthz"
	if !strings.HasPrefix(cfg.MetricsAddr, ":") {
		metricsURL = "http://" + cfg.MetricsAddr + "/healthz"
	}
	if resp, err := (&http.Client{Timeout: time.Second}).Get(metricsURL); err == nil && resp.StatusCode == 200 {
		resp.Body.Close()
		c.add("metrics", "pass", metricsURL, "")
	} else {
		c.add("metrics", "warn", "not reachable: "+metricsURL, "agent not running yet, or metrics_addr bound elsewhere")
	}

	notifiers, err := buildNotifiers(cfg)
	switch {
	case err != nil:
		c.add("notifiers", "fail", err.Error(), "put secrets in /etc/bima/bima.env (EnvironmentFile of bima.service)")
	case len(notifiers) == 0:
		c.add("notifiers", "warn", "no notifier enabled", "enable alert.telegram / alert.discord")
	default:
		var names []string
		for _, n := range notifiers {
			names = append(names, n.Name())
		}
		c.add("notifiers", "pass", "configured: "+strings.Join(names, ", "), "")
		if *send {
			a := alert.New(cfg.Host, time.Minute, time.Minute, notifiers...)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			for name, err := range a.SendTest(ctx) {
				if err != nil {
					c.add("deliver:"+name, "fail", err.Error(), "check token/chat/channel; Telegram bot must be in the chat; Discord bot needs Send Messages + Embed Links")
				} else {
					c.add("deliver:"+name, "pass", "test alert delivered", "")
				}
			}
			cancel()
		}
	}
	return c.report(*asJSON)
}

var versionRe = regexp.MustCompile(`(?m)^Version: (\d+)\.(\d+)`)

func (c *checker) haproxy(api string, cfg *config.Config) {
	info, err := ban.Exec(api, "show info")
	if err != nil {
		hint := "is HAProxy running with `stats socket ... level admin` at this path?"
		if strings.Contains(err.Error(), "permission denied") {
			hint = "add the bima user to the socket's group (usermod -aG haproxy bima) and use mode 660"
		}
		c.add("runtime_api", "fail", api+": "+err.Error(), hint)
		return
	}
	ver := "?"
	if m := versionRe.FindStringSubmatch(info); m != nil {
		ver = m[1] + "." + m[2]
		maj, _ := strconv.Atoi(m[1])
		min, _ := strconv.Atoi(m[2])
		if maj < 2 || (maj == 2 && min < 8) {
			c.add("runtime_api", "fail", api+": HAProxy "+ver, "HAProxy >= 2.8 required (3.0 LTS recommended)")
			return
		}
	}
	c.add("runtime_api", "pass", api+": HAProxy "+ver+", admin level", "")

	if out, err := ban.Exec(api, "show map "+cfg.Ban.MapFile); err != nil {
		c.add("blocklist_map", "fail", api+": "+strings.TrimSpace(firstLine(err.Error())),
			"the HAProxy frontend must reference exactly this file: http-request deny ... if { src,map_ip("+cfg.Ban.MapFile+") -m found }; create the file and reload")
	} else {
		n := strings.Count(out, "0x")
		c.add("blocklist_map", "pass", fmt.Sprintf("%s: %s loaded (%d entries)", api, cfg.Ban.MapFile, n), "")
	}

	out, err := ban.Exec(api, "show servers state be_bima_agents")
	if err != nil || strings.Contains(out, "Can't find backend") {
		c.add("spoe_backend", "fail", api+": backend be_bima_agents not found",
			"add the be_bima_agents backend and the SPOE filter from haproxy-bima.cfg")
		return
	}
	up, total := 0, 0
	for line := range strings.SplitSeq(out, "\n") {
		f := strings.Fields(line)
		if len(f) > 5 && f[1] == "be_bima_agents" {
			total++
			if f[5] == "2" { // srv_op_state 2 = running
				up++
			}
		}
	}
	switch {
	case total == 0:
		c.add("spoe_backend", "fail", api+": be_bima_agents has no servers", "add `server bima1 <listen addr> check`")
	case up == 0:
		c.add("spoe_backend", "warn", fmt.Sprintf("%s: 0/%d agents UP in be_bima_agents (traffic is NOT inspected)", api, total), "start bima; server address must match `listen`")
	default:
		c.add("spoe_backend", "pass", fmt.Sprintf("%s: %d/%d agents UP in be_bima_agents", api, up, total), "")
	}
}

func firstLine(s string) string { l, _, _ := strings.Cut(s, "\n"); return l }

func writable(dir string) error {
	f, err := os.CreateTemp(dir, ".bima-check-*")
	if err != nil {
		return fmt.Errorf("%s not writable: %w", dir, err)
	}
	name := f.Name()
	f.Close()
	return os.Remove(name)
}

func (c *checker) report(asJSON bool) int {
	failed := false
	for _, r := range c.res {
		if r.Status == "fail" {
			failed = true
		}
	}
	if asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"ok": !failed, "checks": c.res})
	} else {
		icon := map[string]string{"pass": "✔", "warn": "!", "fail": "✘", "skip": "-"}
		for _, r := range c.res {
			fmt.Printf("%s %-14s %s\n", icon[r.Status], r.Name, r.Detail)
			if r.Hint != "" && r.Status != "pass" {
				fmt.Printf("  %-14s → %s\n", "", r.Hint)
			}
		}
		if failed {
			fmt.Println("\nRESULT: FAIL")
		} else {
			fmt.Println("\nRESULT: OK")
		}
	}
	if failed {
		return 1
	}
	return 0
}
