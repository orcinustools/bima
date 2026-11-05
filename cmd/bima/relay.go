package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/orcinustools/bima/internal/alert"
	"github.com/orcinustools/bima/internal/config"
	"github.com/orcinustools/bima/internal/detect"
)

// cmdRelay runs a small Alertmanager webhook receiver that forwards alerts
// through Bima's notifiers (Telegram, Discord webhook or Discord bot). It is a
// separate process from the agent so "agent down" alerts still go out, and it
// lets Alertmanager use a Discord *bot* token, which Alertmanager can't.
func cmdRelay(args []string) int {
	fs := flag.NewFlagSet("relay", flag.ExitOnError)
	cfgPath := fs.String("config", "config.yaml", "path to config file (alert section is used)")
	listen := fs.String("listen", "127.0.0.1:9098", "address for Alertmanager webhook_configs")
	_ = fs.Parse(args)
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 1
	}
	notifiers, err := buildNotifiers(cfg)
	if err != nil || len(notifiers) == 0 {
		fmt.Fprintln(os.Stderr, "notifiers:", err, "(at least one notifier is required)")
		return 1
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	mux.HandleFunc("POST /alertmanager", func(w http.ResponseWriter, r *http.Request) {
		var msg struct {
			Status string `json:"status"`
			Alerts []struct {
				Status      string            `json:"status"`
				Labels      map[string]string `json:"labels"`
				Annotations map[string]string `json:"annotations"`
				StartsAt    time.Time         `json:"startsAt"`
			} `json:"alerts"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&msg); err != nil {
			http.Error(w, "bad payload", http.StatusBadRequest)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
		defer cancel()
		failed := 0
		for _, a := range msg.Alerts {
			sev := map[string]detect.Severity{"critical": detect.Critical, "warning": detect.Medium, "info": detect.Low}[a.Labels["severity"]]
			if a.Labels["severity"] == "" {
				sev = detect.Medium
			}
			text := a.Annotations["summary"]
			if d := a.Annotations["description"]; d != "" {
				text += " — " + d
			}
			ev := alert.Event{Time: a.StartsAt, Severity: sev, Category: "monitoring", RuleID: a.Labels["alertname"],
				Msg: text, IP: a.Labels["instance"], Host: cfg.Host, Agent: "alertmanager",
				Action: strings.ToUpper(a.Status), Path: a.Labels["job"]}
			for _, n := range notifiers {
				if err := n.SendEvent(ctx, ev); err != nil {
					failed++
					slog.Error("relay send failed", "notifier", n.Name(), "alert", a.Labels["alertname"], "err", err)
				}
			}
			slog.Info("relayed", "alert", a.Labels["alertname"], "status", a.Status)
		}
		if failed > 0 {
			http.Error(w, "delivery failed", http.StatusBadGateway) // Alertmanager retries
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	slog.Info("alert relay listening", "addr", *listen, "notifiers", len(notifiers))
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}
