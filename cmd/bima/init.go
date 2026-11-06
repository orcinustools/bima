package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/orcinustools/bima"
	"github.com/orcinustools/bima/internal/cloudflare"
)

type initOpts struct {
	Dir, Mode, Host, Listen, Metrics        string
	RuntimeAPIs                             []string
	MapFile, SpoeFile, TrustedFile, Backend string
	TrustedProxies                          []string
	State, Redis, BanFile                   string
	Telegram, Discord, DiscordBot           bool
	GeoCountry, GeoASN, TLSCrtDir           string
	AgentAddr                               string // host:port HAProxy uses to reach the agent
	SocketLine                              string
	JSON, Force                             bool
	// Cloudflare in front of HAProxy
	Cloudflare, CloudflareOnly bool
	CloudflareFile             string
	CloudflareAccount          string
}

func cmdInit(args []string) int {
	o := initOpts{}
	f := flag.NewFlagSet("init", flag.ExitOnError)
	f.StringVar(&o.Dir, "dir", "./bima-setup", "output directory")
	f.StringVar(&o.Mode, "mode", "detect", "detect (shadow, recommended first) or enforce")
	f.StringVar(&o.Host, "host", "bima", "label used in alerts (e.g. public hostname)")
	f.StringVar(&o.Listen, "listen", "127.0.0.1:12345", "agent SPOP listen address")
	f.StringVar(&o.Metrics, "metrics", "127.0.0.1:9101", "metrics/report listen address")
	apis := f.String("runtime-api", "unix:/var/run/haproxy/admin.sock", "comma-separated HAProxy Runtime APIs (unix:/path or tcp:host:port), one per node")
	f.StringVar(&o.MapFile, "map-file", "/etc/haproxy/bima-blocklist.map", "blocklist map path on the HAProxy host")
	f.StringVar(&o.SpoeFile, "spoe-file", "/etc/haproxy/bima-spoe.conf", "SPOE config path on the HAProxy host")
	f.StringVar(&o.Backend, "backend", "127.0.0.1:8000", "application address (used in the full example haproxy.cfg)")
	trusted := f.String("trusted-proxies", "", "comma-separated CIDRs of CDN/LB allowed to set X-Forwarded-For")
	f.StringVar(&o.State, "state", "memory", "memory (single agent) or redis (multiple agents/nodes)")
	f.StringVar(&o.Redis, "redis", "", "redis address host:port (with --state redis)")
	f.StringVar(&o.BanFile, "ban-file", "/var/lib/bima/bans.json", "ban persistence file (memory state)")
	f.BoolVar(&o.Telegram, "telegram", false, "enable Telegram alerts (secrets in bima.env)")
	f.BoolVar(&o.Discord, "discord", false, "enable Discord alerts via webhook")
	f.BoolVar(&o.DiscordBot, "discord-bot", false, "enable Discord alerts via bot token + channel id")
	f.StringVar(&o.GeoCountry, "geoip-country", "", "country MMDB path (GeoLite2/DB-IP Lite)")
	f.StringVar(&o.GeoASN, "geoip-asn", "", "ASN MMDB path")
	f.StringVar(&o.TLSCrtDir, "tls-crt-dir", "", "directory of cert+key PEMs; adds a :443 bind to the example haproxy.cfg")
	f.BoolVar(&o.Cloudflare, "cloudflare", false, "HAProxy is behind Cloudflare: client IP from CF-Connecting-IP (edge ranges only), trust_edge in config")
	f.BoolVar(&o.CloudflareOnly, "cloudflare-only", false, "with --cloudflare: refuse requests that do not come through Cloudflare (origin lockdown)")
	f.StringVar(&o.CloudflareAccount, "cloudflare-account", "", "Cloudflare account ID: enable ban sync to an IP list (token in bima.env)")
	f.BoolVar(&o.JSON, "json", false, "print a JSON summary")
	f.BoolVar(&o.Force, "force", false, "overwrite existing files")
	_ = f.Parse(args)

	o.RuntimeAPIs = splitList(*apis)
	o.TrustedProxies = splitList(*trusted)
	if err := o.validate(); err != nil {
		fmt.Fprintln(os.Stderr, "init:", err)
		return 2
	}
	o.TrustedFile = path.Join(path.Dir(o.MapFile), "bima-trusted.lst")
	o.CloudflareFile = path.Join(path.Dir(o.MapFile), "bima-cloudflare.lst")
	if o.CloudflareOnly {
		o.Cloudflare = true
	}
	o.AgentAddr = o.Listen
	if strings.HasPrefix(o.AgentAddr, ":") {
		o.AgentAddr = "127.0.0.1" + o.AgentAddr
	}
	if network, addr, _ := strings.Cut(o.RuntimeAPIs[0], ":"); network == "unix" {
		o.SocketLine = "stats socket " + addr + " mode 660 level admin"
	} else {
		o.SocketLine = "stats socket ipv4@" + addr + " level admin   # internal interface only!"
	}

	files := map[string]string{
		"config.yaml":        render(configTmpl, o),
		"haproxy-bima.cfg":   render(snippetTmpl, o),
		"haproxy.cfg":        render(fullTmpl, o),
		"bima.service":       render(serviceTmpl, o),
		"bima.env":           render(envTmpl, o),
		"bima-blocklist.map": "",
		"NEXT_STEPS.md":      render(nextTmpl, o),
	}
	if o.Cloudflare {
		files["bima-cloudflare.lst"] = "# Cloudflare edge ranges — refresh: bima cloudflare ips -fetch -o " + o.CloudflareFile + "\n" +
			strings.Join(cloudflare.EdgeRanges, "\n") + "\n"
	}
	if len(o.TrustedProxies) > 0 {
		files["bima-trusted.lst"] = strings.Join(o.TrustedProxies, "\n") + "\n"
	}
	spoe, _ := fs.ReadFile(bima.Assets, "deploy/bima-spoe.conf")
	files["bima-spoe.conf"] = string(spoe)
	_ = fs.WalkDir(bima.Assets, "deploy/monitoring", func(p string, d fs.DirEntry, _ error) error {
		if d != nil && !d.IsDir() {
			b, _ := fs.ReadFile(bima.Assets, p)
			files["monitoring/"+strings.TrimPrefix(p, "deploy/monitoring/")] = string(b)
		}
		return nil
	})

	var written []string
	for name, content := range files {
		dst := filepath.Join(o.Dir, filepath.FromSlash(name))
		if _, err := os.Stat(dst); err == nil && !o.Force {
			fmt.Fprintf(os.Stderr, "init: %s exists (use --force)\n", dst)
			return 1
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			fmt.Fprintln(os.Stderr, "init:", err)
			return 1
		}
		mode := os.FileMode(0o644)
		if name == "bima.env" {
			mode = 0o600
		}
		if err := os.WriteFile(dst, []byte(content), mode); err != nil {
			fmt.Fprintln(os.Stderr, "init:", err)
			return 1
		}
		written = append(written, dst)
	}
	if o.JSON {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"dir": o.Dir, "files": written, "next_steps": filepath.Join(o.Dir, "NEXT_STEPS.md")})
	} else {
		fmt.Printf("wrote %d files to %s — read %s\n", len(written), o.Dir, filepath.Join(o.Dir, "NEXT_STEPS.md"))
	}
	return 0
}

func splitList(s string) []string {
	var out []string
	for v := range strings.SplitSeq(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func (o *initOpts) validate() error {
	if o.Mode != "detect" && o.Mode != "enforce" {
		return fmt.Errorf("--mode must be detect or enforce")
	}
	if o.State != "memory" && o.State != "redis" {
		return fmt.Errorf("--state must be memory or redis")
	}
	if o.State == "redis" && o.Redis == "" {
		return fmt.Errorf("--state redis needs --redis host:port")
	}
	if len(o.RuntimeAPIs) > 1 && o.State != "redis" {
		return fmt.Errorf("several --runtime-api (HAProxy nodes) need --state redis")
	}
	if len(o.RuntimeAPIs) == 0 {
		return fmt.Errorf("--runtime-api is required")
	}
	for _, a := range o.RuntimeAPIs {
		if !strings.HasPrefix(a, "unix:") && !strings.HasPrefix(a, "tcp:") {
			return fmt.Errorf("--runtime-api %q must start with unix: or tcp:", a)
		}
	}
	for _, c := range o.TrustedProxies {
		if _, err := netip.ParsePrefix(c); err != nil {
			if _, err2 := netip.ParseAddr(c); err2 != nil {
				return fmt.Errorf("--trusted-proxies: %q is not a CIDR/IP", c)
			}
		}
	}
	if o.Discord && o.DiscordBot {
		return fmt.Errorf("choose --discord (webhook) or --discord-bot, not both")
	}
	return nil
}

func render(t *template.Template, o initOpts) string {
	var b bytes.Buffer
	if err := t.Execute(&b, o); err != nil {
		panic(err)
	}
	return b.String()
}

var funcs = template.FuncMap{"quote": func(s string) string { return fmt.Sprintf("%q", s) }}

var configTmpl = template.Must(template.New("config").Funcs(funcs).Parse(`# Generated by "bima init". Secrets live in bima.env, never here.
listen: {{quote .Listen}}
metrics_addr: {{quote .Metrics}}       # /healthz /metrics /bans /report — keep private
mode: {{.Mode}}                          # detect = shadow mode (alerts only). Switch to enforce after tuning.
host: {{quote .Host}}
allowlist: []                          # office / monitoring / payment-provider webhook CIDRs
trusted_proxies: [{{range $i, $a := .TrustedProxies}}{{if $i}}, {{end}}{{quote $a}}{{end}}]   # must match set-src trust in haproxy.cfg
bots: {verify: true, timeout: 2s}      # reverse-DNS check of claimed crawlers
max_body_inspect: 65536
crs:
  enabled: true
  paranoia: 1
  inbound_threshold: 5
  fast_path: true
score: {tarpit: 50, ban: 80, half_life: 5m, window: 1m}
group:
  by: [{{if .GeoASN}}asn, {{end}}fingerprint]
  distinct_404: 60
  min_ips: 3
  member_404: 3
  penalty: 80
  flag_ttl: 10m
state:
  backend: {{.State}}
{{- if eq .State "memory"}}
  ban_file: {{quote .BanFile}}
{{- else}}
  redis:
    addr: {{quote .Redis}}            # password: BIMA_REDIS_PASSWORD
    prefix: "bima:"
{{- end}}
geoip:
  country_db: {{quote .GeoCountry}}
  asn_db: {{quote .GeoASN}}
ban:
  enabled: true
  runtime_apis: [{{range $i, $a := .RuntimeAPIs}}{{if $i}}, {{end}}{{quote $a}}{{end}}]
  map_file: {{quote .MapFile}}         # must equal the map_ip() path in haproxy.cfg
  durations: [10m, 1h, 24h]
  reconcile_interval: 2s
alert:
  dedup_window: 5m
  digest_interval: 5m
  telegram:
    enabled: {{.Telegram}}
    api_base: https://api.telegram.org
  discord:
    enabled: {{or .Discord .DiscordBot}}
{{- if or .Cloudflare .CloudflareAccount}}
cloudflare:
  trust_edge: {{.Cloudflare}}                    # behind Cloudflare: edge ranges trusted, never banned
  # edge_ips_file: {{.CloudflareFile}}   # default: ranges built into bima
  ban_sync:                            # mirror bans into a Cloudflare IP list (edge blocking)
    enabled: {{if .CloudflareAccount}}true{{else}}false{{end}}
    account_id: {{quote .CloudflareAccount}}
    list_name: bima_blocklist          # rule: ip.src in $bima_blocklist (bima cloudflare rules)
    interval: 30s
{{- end}}
exclusions: []                         # add from GET /report suggested_exclusion
`))

const frontendBlock = `    option http-buffer-request
    unique-id-format %{+X}o\ %ci:%cp_%fi:%fp_%Ts_%rt:%pid
    unique-id-header X-Request-ID
{{- if .Cloudflare}}
    # behind Cloudflare: real client IP from CF-Connecting-IP, only when the peer is a Cloudflare edge
    acl bima_cf_edge src -f {{.CloudflareFile}}
{{- if .CloudflareOnly}}
    http-request deny deny_status 403 if !bima_cf_edge      # origin lockdown: Cloudflare only
{{- end}}
    http-request set-src req.hdr_ip(cf-connecting-ip) if bima_cf_edge { req.hdr(cf-connecting-ip) -m found }
{{- end}}
{{- if .TrustedProxies}}
    # restore the real client IP — only from trusted CDN/LB addresses
    acl bima_trusted_proxy src -f {{.TrustedFile}}
    http-request set-src hdr_ip(x-forwarded-for,-1) if bima_trusted_proxy { req.hdr(x-forwarded-for) -m found }
{{- end}}
    # L0: IPs banned by Bima never reach the agent
    http-request deny deny_status 403 if { src,map_ip({{.MapFile}}) -m found }
    http-request deny deny_status 403 if { fc_src,map_ip({{.MapFile}}) -m found }
    # L1-2: Bima via SPOE (fail-open on agent error/timeout)
    http-request set-var(txn.path) path
    http-request set-var(txn.method) method
    filter spoe engine bima config {{.SpoeFile}}
    http-request send-spoe-group bima check-request
    http-request deny deny_status 403 if { var(txn.bima.action) -m str block }
    http-request tarpit deny_status 429 if { var(txn.bima.action) -m str tarpit }
    http-response send-spoe-group bima check-response`

const backendBlock = `backend be_bima_agents
    mode tcp
    balance roundrobin
    timeout connect 1s
    timeout server 3m
    server bima1 {{.AgentAddr}} check inter 2s`

var snippetTmpl = template.Must(template.New("snippet").Parse(`# Generated by "bima init": lines to MERGE into the existing haproxy.cfg.
# Keep the order inside the frontend. Validate with: haproxy -c -f /etc/haproxy/haproxy.cfg

### [global] — add (reuse an existing admin socket instead if there is one)
    ` + "{{.SocketLine}}" + `
    tune.bufsize 65536
    tune.ssl.capture-buffer-size 128

### [defaults] — add if missing
    timeout tarpit 5s

### [frontend <yours>] — add to every frontend serving the app, before use_backend/default_backend
` + frontendBlock + `

### new section
` + backendBlock + `
`))

var fullTmpl = template.Must(template.New("full").Parse(`# Generated by "bima init": complete reference config (single node).
global
    log /dev/log local0 info
    ` + "{{.SocketLine}}" + `
    stats timeout 10s
    tune.bufsize 65536
    tune.ssl.capture-buffer-size 128

defaults
    mode http
    log global
    option httplog
    timeout connect 5s
    timeout client 30s
    timeout server 60s
    timeout tarpit 5s

frontend fe_web
    bind :80
{{- if .TLSCrtDir}}
    bind :443 ssl crt {{.TLSCrtDir}} alpn h2,http/1.1
{{- end}}
` + frontendBlock + `
    default_backend be_app

frontend fe_stats
    bind 127.0.0.1:8404
    http-request use-service prometheus-exporter if { path /metrics }
    no log

backend be_app
    server app1 {{.Backend}} check

` + backendBlock + `
`))

var serviceTmpl = template.Must(template.New("service").Parse(`[Unit]
Description=Bima WAF agent (HAProxy SPOE)
After=network-online.target haproxy.service
Wants=network-online.target

[Service]
User=bima
Group=bima
SupplementaryGroups=haproxy
EnvironmentFile=/etc/bima/bima.env
ExecStart=/usr/local/bin/bima run -config /etc/bima/config.yaml
Restart=always
RestartSec=2
StateDirectory=bima
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/bima
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`))

var envTmpl = template.Must(template.New("env").Parse(`# /etc/bima/bima.env — mode 0600, owner bima. Fill in, never commit.
{{- if .Telegram}}
BIMA_TELEGRAM_TOKEN=
BIMA_TELEGRAM_CHAT_ID=
{{- end}}
{{- if .Discord}}
BIMA_DISCORD_WEBHOOK=
{{- end}}
{{- if .DiscordBot}}
BIMA_DISCORD_BOT_TOKEN=
BIMA_DISCORD_CHANNEL_ID=
{{- end}}
{{- if .CloudflareAccount}}
BIMA_CLOUDFLARE_API_TOKEN=             # Account Filter Lists: Edit
{{- end}}
{{- if eq .State "redis"}}
BIMA_REDIS_PASSWORD=
{{- end}}
GOGC=400
GOMEMLIMIT=512MiB
`))

var nextTmpl = template.Must(template.New("next").Parse(`# Next steps (generated by bima init)

1. Install files (as root):
   install -d -o bima -g bima /etc/bima /var/lib/bima
   install -m 644 config.yaml /etc/bima/config.yaml
   install -m 600 -o bima bima.env /etc/bima/bima.env      # then fill in the secrets
   install -m 644 bima-spoe.conf {{.SpoeFile}}
   test -f {{.MapFile}} || install -m 644 bima-blocklist.map {{.MapFile}}
{{- if .TrustedProxies}}
   install -m 644 bima-trusted.lst {{.TrustedFile}}
{{- end}}
{{- if .Cloudflare}}
   install -m 644 bima-cloudflare.lst {{.CloudflareFile}}   # refresh monthly: bima cloudflare ips -fetch -o {{.CloudflareFile}}
{{- end}}
   install -m 644 bima.service /etc/systemd/system/bima.service

2. Merge haproxy-bima.cfg into the HAProxy config (see haproxy.cfg for a complete example), then:
   haproxy -c -f /etc/haproxy/haproxy.cfg     # must be valid
   # show the diff to the owner and get approval before:
   systemctl reload haproxy

3. Start: systemctl daemon-reload && systemctl enable --now bima

4. Verify: bima check -config /etc/bima/config.yaml --json   (all checks pass)
           bima test-alert -config /etc/bima/config.yaml
           curl -s -o /dev/null -w '%{http_code}\n' 'http://<host>/?x=;id'   # {{if eq .Mode "detect"}}200 + would-block alert (detect mode){{else}}403{{end}}

5. Tune in detect mode: curl -s http://{{.Metrics}}/report | jq   → add exclusions → mode: enforce.

6. Monitoring: monitoring/bima-rules.yml, monitoring/alertmanager.yml, monitoring/grafana/.
{{- if or .Cloudflare .CloudflareAccount}}

7. Cloudflare edge rules (optional, blocks before traffic reaches you):
   bima cloudflare rules                          # review / paste into Security > WAF > Custom rules
   BIMA_CLOUDFLARE_API_TOKEN=... bima cloudflare apply -zone <ZONE_ID> -account <ACCOUNT_ID>        # plan
   BIMA_CLOUDFLARE_API_TOKEN=... bima cloudflare apply -zone <ZONE_ID> -account <ACCOUNT_ID> -yes   # apply
{{- end}}
`))
