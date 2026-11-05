// Command bima is an HAProxy SPOE agent WAF: it detects RCE/injection payloads
// and enumeration behaviour, bans abusive IPs via the HAProxy Runtime API and
// alerts to Telegram and Discord.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/dropmorepackets/haproxy-go/spop"
	"github.com/orcinustools/bima/internal/alert"
	"github.com/orcinustools/bima/internal/ban"
	"github.com/orcinustools/bima/internal/config"
	"github.com/orcinustools/bima/internal/detect"
	"github.com/orcinustools/bima/internal/engine"
	"github.com/orcinustools/bima/internal/enum"
	"github.com/orcinustools/bima/internal/geoip"
	"github.com/orcinustools/bima/internal/metrics"
	"github.com/orcinustools/bima/internal/spoe"
	"github.com/orcinustools/bima/internal/store"
)

var version = "dev" // set with -ldflags "-X main.version=..."

const usage = `bima — WAF agent for HAProxy (SPOE)

Usage:
  bima run        -config FILE                 run the agent (default command)
  bima check      -config FILE [--json] [--send]
                                               validate config + live wiring (HAProxy, Redis, notifiers)
  bima init       [flags]                      generate config, HAProxy snippet, SPOE, systemd unit, monitoring
  bima test-alert -config FILE                 send a test alert to every notifier
  bima skills     list | show [NAME [FILE]] | install [--dir DIR] [--force]
                                               agent skills embedded in this binary (e.g. for Claude Code)
  bima version

Legacy: "bima -config FILE [-test-alert]" still works.
Run "bima <command> -h" for command flags.
`

func main() {
	args := os.Args[1:]
	cmd := "run"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "run":
		cmdRun(args)
	case "check":
		os.Exit(cmdCheck(args))
	case "init":
		os.Exit(cmdInit(args))
	case "test-alert":
		os.Exit(cmdTestAlert(args))
	case "skills":
		os.Exit(cmdSkills(args))
	case "version", "--version":
		fmt.Println("bima", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
}

func cmdTestAlert(args []string) int {
	fs := flag.NewFlagSet("test-alert", flag.ExitOnError)
	cfgPath := fs.String("config", "config.yaml", "path to config file")
	_ = fs.Parse(args)
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 1
	}
	notifiers, err := buildNotifiers(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "notifiers:", err)
		return 1
	}
	if len(notifiers) == 0 {
		fmt.Println("no notifiers enabled in config")
		return 1
	}
	alerter := alert.New(cfg.Host, cfg.Alert.DedupWindow, cfg.Alert.DigestInterval, notifiers...)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	failed := false
	for name, err := range alerter.SendTest(ctx) {
		if err != nil {
			failed = true
			fmt.Printf("✘ %s: %v\n", name, err)
		} else {
			fmt.Printf("✔ %s: delivered\n", name)
		}
	}
	if failed {
		return 1
	}
	return 0
}

func cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	cfgPath := fs.String("config", "config.yaml", "path to config file")
	testAlert := fs.Bool("test-alert", false, "legacy: same as `bima test-alert`")
	_ = fs.Parse(args)
	if *testAlert {
		os.Exit(cmdTestAlert([]string{"-config", *cfgPath}))
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fatal("config", err)
	}
	notifiers, err := buildNotifiers(cfg)
	if err != nil {
		fatal("notifiers", err)
	}
	alerter := alert.New(cfg.Host, cfg.Alert.DedupWindow, cfg.Alert.DigestInterval, notifiers...)

	var crs *detect.CRS
	if cfg.CRS.Enabled {
		t := time.Now()
		if crs, err = detect.NewCRS(cfg.CRS.Paranoia, cfg.CRS.Threshold, cfg.CRS.AllowedMethods, cfg.CRS.ExtraDirectives); err != nil {
			fatal("load CRS", err)
		}
		slog.Info("OWASP CRS loaded", "paranoia", cfg.CRS.Paranoia, "took", time.Since(t).String())
	}

	var st store.Store
	switch cfg.State.Backend {
	case "redis":
		r, err := store.NewRedis(cfg.State.Redis.Addr, cfg.State.Redis.Password, cfg.State.Redis.DB, cfg.State.Redis.Prefix, 20)
		if err != nil {
			fatal("redis", err)
		}
		st = r
	default:
		st = store.NewMemory(cfg.State.BanFile)
	}
	defer st.Close()
	slog.Info("state store ready", "backend", cfg.State.Backend)

	geo, err := geoip.Open(cfg.GeoIP.CountryDB, cfg.GeoIP.ASNDB)
	if err != nil {
		fatal("geoip", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go alerter.Run(ctx)

	bans, err := ban.New(st, cfg.Ban.RuntimeAPIs, cfg.Ban.MapFile, cfg.Ban.Durations, cfg.Ban.Enabled)
	if err != nil {
		fatal("ban manager", err)
	}
	go bans.Run(ctx, cfg.Ban.ReconcileInterval)

	th := enum.DefaultThresholds
	th.GroupDistinct404, th.GroupMinIPs, th.GroupMember404 = cfg.Group.Distinct404, cfg.Group.MinIPs, cfg.Group.Member404
	th.GroupPenalty, th.GroupFlagTTL = cfg.Group.Penalty, cfg.Group.FlagTTL
	scorer := enum.NewScorer(st, cfg.Score.HalfLife, cfg.Score.Window, th)
	eng := engine.New(cfg, crs, scorer, bans, alerter, geo)

	metrics.GaugeFunc("bima_active_bans", "Currently banned IPs.", func() float64 { return float64(len(bans.Active())) })
	metrics.CounterFunc("bima_alerts_dropped_total", "Alerts dropped because the queue was full.", func() float64 { return float64(alerter.Dropped.Load()) })
	metrics.CounterFunc("bima_store_errors_total", "State store errors (fail-open).", func() float64 { return float64(scorer.Errors.Load()) })
	metrics.CounterFunc("bima_store_skipped_total", "Store calls skipped while the circuit breaker was open.", func() float64 { return float64(scorer.Skipped.Load()) })
	metrics.CounterFunc("bima_runtime_api_errors_total", "HAProxy Runtime API errors.", func() float64 { return float64(bans.APIErrors.Load()) })
	go serveHTTP(cfg.MetricsAddr, eng, bans)

	slog.Info("bima agent listening", "addr", cfg.Listen, "mode", cfg.Mode, "notifiers", len(notifiers))
	agent := spop.Agent{Addr: cfg.Listen, Handler: &spoe.Handler{Engine: eng}, BaseContext: ctx}
	if err := agent.ListenAndServe(); err != nil && ctx.Err() == nil {
		fatal("spop", err)
	}
}

func fatal(what string, err error) {
	slog.Error(what, "err", err)
	os.Exit(1)
}

func buildNotifiers(cfg *config.Config) ([]alert.Notifier, error) {
	var n []alert.Notifier
	if cfg.Alert.Telegram.Enabled {
		if cfg.Alert.Telegram.Token == "" || cfg.Alert.Telegram.ChatID == "" {
			return nil, fmt.Errorf("telegram enabled but BIMA_TELEGRAM_TOKEN / BIMA_TELEGRAM_CHAT_ID missing")
		}
		n = append(n, &alert.Telegram{APIBase: cfg.Alert.Telegram.APIBase, Token: cfg.Alert.Telegram.Token, ChatID: cfg.Alert.Telegram.ChatID})
	}
	if cfg.Alert.Discord.Enabled {
		d := cfg.Alert.Discord
		if d.WebhookURL == "" && (d.BotToken == "" || d.ChannelID == "") {
			return nil, fmt.Errorf("discord enabled but neither BIMA_DISCORD_WEBHOOK nor BIMA_DISCORD_BOT_TOKEN + BIMA_DISCORD_CHANNEL_ID set")
		}
		n = append(n, &alert.Discord{WebhookURL: d.WebhookURL, BotToken: d.BotToken, ChannelID: d.ChannelID, APIBase: d.APIBase})
	}
	return n, nil
}

func serveHTTP(addr string, eng *engine.Engine, bans *ban.Manager) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.Handle("/metrics", metrics.Handler())
	mux.HandleFunc("/bans", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(bans.Active())
	})
	// Shadow-mode tuning report: hits per rule, top paths/locations, FP hints.
	mux.HandleFunc("/report", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			eng.Report.Reset()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(eng.Report.Snapshot())
	})
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		slog.Error("http server", "err", err)
	}
}
