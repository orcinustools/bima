# Monitoring

Bima cannot alert about itself being down — Prometheus + Alertmanager do that.
`bima init` writes ready files into `<dir>/monitoring/`:

- `bima-rules.yml` — alert rules: BimaAgentDown, BimaNoAgentInHAProxy,
  BimaAlertDeliveryFailing, BimaStateStoreErrors, BimaRuntimeAPIErrors,
  BimaInspectLatencyHigh, BimaAttackSpike.
- `alertmanager.yml` — Telegram + Discord receivers (secrets via `*_file`).
- `grafana/dashboards/bima.json` + provisioning — dashboard "Bima WAF".

## Prometheus scrape config
```yaml
scrape_configs:
  - job_name: bima                      # job name is used by the rules
    static_configs: [{targets: ["<node>:9101"]}]
  - job_name: haproxy
    static_configs: [{targets: ["<node>:8404"]}]
rule_files: [/etc/prometheus/rules/bima-rules.yml]
```
HAProxy exporter (add once per HAProxy, internal bind only):
```
frontend fe_stats
    bind 127.0.0.1:8404
    http-request use-service prometheus-exporter if { path /metrics }
```
If Bima's `metrics_addr` is 127.0.0.1, Prometheus must run on the same host or you
bind metrics to an internal interface.

## Verify
- `curl -s <prometheus>/api/v1/targets` → bima and haproxy targets `up`.
- Stop bima briefly (with the user's consent) → `BimaAgentDown` reaches the chat
  within ~1 min, and a resolved message after starting it again.
