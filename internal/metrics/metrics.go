// Package metrics exposes Bima's Prometheus metrics.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var Registry = prometheus.NewRegistry()

var (
	Requests = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "bima_requests_total", Help: "Requests inspected."})
	Responses = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "bima_responses_total", Help: "Responses observed."})
	Verdicts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "bima_verdicts_total", Help: "Verdicts by action (would_* in detect mode)."}, []string{"action"})
	Detections = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "bima_detections_total", Help: "Findings by rule."}, []string{"rule", "category", "severity"})
	Excluded = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "bima_excluded_total", Help: "Findings suppressed by configured exclusions."}, []string{"rule"})
	Inspect = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "bima_inspect_duration_seconds", Help: "Time spent inspecting a request, by stage.",
		Buckets: []float64{.00005, .0001, .00025, .0005, .001, .002, .005, .01, .025, .05, .1}}, []string{"stage"})
	CRSSkipped = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "bima_crs_fastpath_total", Help: "Requests where CRS was skipped because every input was plain."})
	CRSTimeouts = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "bima_crs_timeouts_total", Help: "CRS evaluations abandoned at the CRS deadline (verdict from other layers)."})
	CRSOverload = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "bima_crs_overload_total", Help: "Requests where CRS was skipped because all CRS slots were busy."})
	UntrustedForwarder = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "bima_untrusted_forwarder_total", Help: "Requests where HAProxy took the client IP from a header sent by a peer outside trusted_proxies."})
	Spoofers = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "bima_spoofers_total", Help: "Peers flagged for rotating forwarding-header addresses."})
	BotChecks = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "bima_bot_verifications_total", Help: "Crawler verifications by result."}, []string{"crawler", "result"})
	Bans = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "bima_bans_total", Help: "Bans placed."})
	AlertsSent = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "bima_alerts_sent_total", Help: "Notifier deliveries."}, []string{"notifier", "kind", "status"})
	Mode = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "bima_mode", Help: "1 for the active mode."}, []string{"mode"})
)

func init() {
	Registry.MustRegister(UntrustedForwarder, Spoofers, BotChecks, CRSSkipped, CRSTimeouts, CRSOverload, Requests, Responses, Verdicts, Detections, Excluded, Inspect, Bans, AlertsSent, Mode,
		collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
}

// GaugeFunc registers a gauge whose value is computed at scrape time.
func GaugeFunc(name, help string, f func() float64) {
	Registry.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: name, Help: help}, f))
}

// CounterFunc registers a counter whose value is computed at scrape time.
func CounterFunc(name, help string, f func() float64) {
	Registry.MustRegister(prometheus.NewCounterFunc(prometheus.CounterOpts{Name: name, Help: help}, f))
}

func Handler() http.Handler {
	return promhttp.HandlerFor(Registry, promhttp.HandlerOpts{})
}
