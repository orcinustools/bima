package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/orcinustools/bima/internal/cloudflare"
	"github.com/orcinustools/bima/internal/config"
	"github.com/orcinustools/bima/internal/store"
)

const cfUsage = `bima cloudflare — Cloudflare integration

  bima cloudflare rules [rule flags] [-format text|json|terraform]
        print Bima's Cloudflare WAF custom rules (paste into the dashboard,
        PUT to the API, or use with Terraform)
  bima cloudflare apply -zone ZONE_ID [-account ACCOUNT_ID] [rule flags] [-replace-existing] [-yes]
        install/update the rules in a zone; other custom rules are kept.
        Without -yes it only prints the plan. Token: BIMA_CLOUDFLARE_API_TOKEN
        (Zone WAF Edit; + Account Filter Lists Edit to create the ban list)
  bima cloudflare ips [-fetch] [-o FILE]
        Cloudflare edge ranges for HAProxy (acl src -f FILE)
  bima cloudflare sync -config FILE
        push current Bima bans to the Cloudflare IP list once (the agent does
        this continuously when cloudflare.ban_sync.enabled is true)

Rule flags:
`

func cmdCloudflare(args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(os.Stderr, cfUsage)
		ruleFlags(flag.NewFlagSet("rules", flag.ContinueOnError)).fs.PrintDefaults()
		return 2
	}
	switch args[0] {
	case "rules":
		return cfRules(args[1:])
	case "apply":
		return cfApply(args[1:])
	case "ips":
		return cfIPs(args[1:])
	case "sync":
		return cfSync(args[1:])
	}
	fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n%s", args[0], cfUsage)
	return 2
}

type ruleOpts struct {
	fs                               *flag.FlagSet
	action, list, scriptHosts        *string
	exemptPaths, cloudASNs, emptyOK  *string
	aiBots, emptyUA, noFake, noScans *bool
}

func ruleFlags(fs *flag.FlagSet) *ruleOpts {
	d := cloudflare.DefaultOptions()
	return &ruleOpts{fs: fs,
		action:      fs.String("action", d.Action, "block | managed_challenge | js_challenge | log (log needs Enterprise)"),
		list:        fs.String("list", d.ListName, `IP list with Bima bans ("" = no blocklist rule)`),
		scriptHosts: fs.String("script-hosts", "", "comma-separated hosts that legitimately serve .php/.asp/WordPress paths"),
		exemptPaths: fs.String("exempt-path", "", "comma-separated path prefixes skipped by the URI injection rules"),
		cloudASNs:   fs.String("cloud-asn", "", "comma-separated ASNs whose unverified bot-like User-Agents are blocked (e.g. 396982)"),
		emptyOK:     fs.String("empty-ua-allow", "", "with -block-empty-ua: hosts where an empty User-Agent is allowed (APIs)"),
		aiBots:      fs.Bool("ai-bots", false, "also block AI crawlers / assistants (GPTBot, ClaudeBot, PerplexityBot, ...)"),
		emptyUA:     fs.Bool("block-empty-ua", false, "block requests without a User-Agent"),
		noFake:      fs.Bool("no-fake-crawlers", false, "do not block search-crawler UAs that Cloudflare did not verify"),
		noScans:     fs.Bool("no-scanners", false, "do not block vulnerability-scanner User-Agents"),
	}
}

func (r *ruleOpts) options() (cloudflare.Options, error) {
	o := cloudflare.DefaultOptions()
	o.Action, o.ListName = *r.action, *r.list
	o.ScriptHosts, o.ExemptPaths, o.EmptyUAHosts = splitList(*r.scriptHosts), splitList(*r.exemptPaths), splitList(*r.emptyOK)
	o.AIBots, o.EmptyUA, o.FakeCrawlers, o.ScannerAgents = *r.aiBots, *r.emptyUA, !*r.noFake, !*r.noScans
	for _, s := range splitList(*r.cloudASNs) {
		n, err := strconv.Atoi(strings.TrimPrefix(strings.ToUpper(s), "AS"))
		if err != nil {
			return o, fmt.Errorf("-cloud-asn: %q is not a number", s)
		}
		o.CloudASNs = append(o.CloudASNs, n)
	}
	return o, nil
}

// freePlanRules is the number of custom rules on Cloudflare's Free plan.
const freePlanRules = 5

func cfRules(args []string) int {
	fs := flag.NewFlagSet("cloudflare rules", flag.ExitOnError)
	ro := ruleFlags(fs)
	format := fs.String("format", "text", "text | json | terraform")
	_ = fs.Parse(args)
	o, err := ro.options()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	rules, err := cloudflare.Generate(o)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	switch *format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		_ = enc.Encode(map[string]any{"rules": rules})
	case "terraform", "tf":
		fmt.Print(terraform(rules, o))
	case "text":
		fmt.Printf("# ============ Bima — Cloudflare custom rules (action: %s) ============\n", o.Action)
		fmt.Printf("# Security > WAF > Custom rules > Create rule > Edit expression. %d rules", len(rules))
		if len(rules) > freePlanRules {
			fmt.Printf(" (more than the %d custom rules of the Free plan)", freePlanRules)
		}
		fmt.Println()
		if o.ListName != "" {
			fmt.Printf("# Rule 1 needs the IP list %q (Manage Account > Configurations > Lists, type IP),\n# filled by Bima's ban sync (cloudflare.ban_sync) — or drop it with -list \"\".\n", o.ListName)
		}
		for i, r := range rules {
			fmt.Printf("\n# %d. %s  [ref %s, %d chars]\n%s\n", i+1, strings.TrimPrefix(r.Description, cloudflare.DescPrefix), r.Ref, len(r.Expression), r.Expression)
		}
	default:
		fmt.Fprintln(os.Stderr, "-format must be text, json or terraform")
		return 2
	}
	return 0
}

func terraform(rules []cloudflare.Rule, o cloudflare.Options) string {
	// HCL heredocs interpolate ${...} and %{...}: escape them.
	esc := strings.NewReplacer("${", "$${", "%{", "%%{")
	var b strings.Builder
	b.WriteString("# Bima — Cloudflare custom rules (Terraform provider cloudflare/cloudflare v5)\n")
	b.WriteString("# NOTE: this resource owns the zone's whole custom-rules phase; add your own rules to it.\n")
	if o.ListName != "" {
		fmt.Fprintf(&b, "# Requires the account IP list %q (resource cloudflare_list, kind = \"ip\").\n", o.ListName)
	}
	b.WriteString("variable \"zone_id\" { type = string }\n\n")
	b.WriteString("resource \"cloudflare_ruleset\" \"bima_waf\" {\n  zone_id = var.zone_id\n  name    = \"default\"\n  kind    = \"zone\"\n  phase   = \"http_request_firewall_custom\"\n  rules = [\n")
	for _, r := range rules {
		fmt.Fprintf(&b, "    {\n      ref         = %q\n      description = %q\n      action      = %q\n      enabled     = true\n      expression  = <<-EOT\n        %s\n      EOT\n    },\n",
			r.Ref, r.Description, r.Action, esc.Replace(r.Expression))
	}
	b.WriteString("  ]\n}\n")
	return b.String()
}

func cfToken() (string, error) {
	t := os.Getenv("BIMA_CLOUDFLARE_API_TOKEN")
	if t == "" {
		return "", fmt.Errorf("set BIMA_CLOUDFLARE_API_TOKEN (API token with Zone WAF Edit; Account Filter Lists Edit for the ban list)")
	}
	return t, nil
}

func cfApply(args []string) int {
	fs := flag.NewFlagSet("cloudflare apply", flag.ExitOnError)
	ro := ruleFlags(fs)
	zone := fs.String("zone", os.Getenv("BIMA_CLOUDFLARE_ZONE_ID"), "zone ID (Overview page of the domain)")
	account := fs.String("account", os.Getenv("BIMA_CLOUDFLARE_ACCOUNT_ID"), "account ID: creates the ban IP list if missing")
	apiBase := fs.String("api-base", "", "API base URL (tests)")
	replace := fs.Bool("replace-existing", false, "DROP every custom rule not managed by Bima (e.g. older hand-written copies)")
	yes := fs.Bool("yes", false, "apply; without it only the plan is printed")
	_ = fs.Parse(args)
	if *zone == "" {
		fmt.Fprintln(os.Stderr, "-zone is required")
		return 2
	}
	tok, err := cfToken()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	o, err := ro.options()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	rules, err := cloudflare.Generate(o)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	c := cloudflare.NewClient(*apiBase, tok)

	if o.ListName != "" {
		if *account == "" {
			fmt.Printf("! rule bima_blocklist references $%s: the list must already exist (or pass -account to create it)\n", o.ListName)
		} else if *yes {
			l, created, err := c.EnsureList(ctx, *account, o.ListName)
			if err != nil {
				fmt.Fprintln(os.Stderr, "ip list:", err)
				return 1
			}
			fmt.Printf("✔ ip list %s (%s)%s\n", l.Name, l.ID, map[bool]string{true: " created", false: ""}[created])
		} else {
			fmt.Printf("• ip list %s: ensured on apply\n", o.ListName)
		}
	}

	var existing []map[string]any
	rs, err := c.CustomRules(ctx, *zone)
	switch {
	case cloudflare.NotFound(err):
	case err != nil:
		fmt.Fprintln(os.Stderr, "read custom rules:", err)
		return 1
	default:
		existing = rs.Rules
	}
	merged, kept, replaced := cloudflare.Merge(existing, rules, *replace)
	fmt.Printf("plan: %d Bima rules (%d already installed, updated in place), %d other rules kept", len(rules), replaced, kept)
	if *replace {
		fmt.Printf(", %d other rules DROPPED", len(existing)-replaced)
	}
	fmt.Printf(" → %d custom rules\n", len(merged))
	for _, r := range existing {
		if !cloudflare.Managed(r) {
			verb := "keep"
			if *replace {
				verb = "DROP"
			}
			fmt.Printf("  %s  %v\n", verb, r["description"])
		}
	}
	for _, r := range rules {
		fmt.Printf("  bima  %s (%d chars)\n", r.Description, len(r.Expression))
	}
	if len(merged) > freePlanRules {
		fmt.Printf("! %d rules exceed the Free plan's %d custom rules (Pro 20, Business 100). If the API refuses,\n  remove older copies of these checks (-replace-existing drops all non-Bima rules) or upgrade.\n", len(merged), freePlanRules)
	}
	if !*yes {
		fmt.Println("dry run: re-run with -yes to apply")
		return 0
	}
	if err := c.PutCustomRules(ctx, *zone, merged); err != nil {
		fmt.Fprintln(os.Stderr, "apply:", err)
		return 1
	}
	fmt.Println("✔ applied")
	return 0
}

func cfIPs(args []string) int {
	fs := flag.NewFlagSet("cloudflare ips", flag.ExitOnError)
	fetch := fs.Bool("fetch", false, "download the current ranges from api.cloudflare.com (default: built-in list)")
	out := fs.String("o", "", "write to FILE instead of stdout")
	_ = fs.Parse(args)
	ranges := cloudflare.EdgeRanges
	if *fetch {
		r, err := cloudflare.FetchRanges(context.Background(), "")
		if err != nil {
			fmt.Fprintln(os.Stderr, "fetch:", err)
			return 1
		}
		ranges = r
	}
	body := "# Cloudflare edge ranges (bima cloudflare ips" + map[bool]string{true: " -fetch", false: ""}[*fetch] + ")\n" + strings.Join(ranges, "\n") + "\n"
	if *out == "" {
		fmt.Print(body)
		return 0
	}
	if err := os.WriteFile(*out, []byte(body), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("✔ %d ranges → %s (reload HAProxy to apply)\n", len(ranges), *out)
	return 0
}

func cfSync(args []string) int {
	fs := flag.NewFlagSet("cloudflare sync", flag.ExitOnError)
	cfgPath := fs.String("config", "config.yaml", "config file (cloudflare.ban_sync and state are used)")
	_ = fs.Parse(args)
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 1
	}
	bs := cfg.Cloudflare.BanSync
	if bs.AccountID == "" || cfg.Cloudflare.APIToken == "" {
		fmt.Fprintln(os.Stderr, "need cloudflare.ban_sync.account_id and BIMA_CLOUDFLARE_API_TOKEN")
		return 2
	}
	var st store.Store
	if cfg.State.Backend == "redis" {
		r, err := store.NewRedis(cfg.State.Redis.Addr, cfg.State.Redis.Password, cfg.State.Redis.DB, cfg.State.Redis.Prefix, 3)
		if err != nil {
			fmt.Fprintln(os.Stderr, "redis:", err)
			return 1
		}
		st = r
	} else {
		st = store.NewMemory(cfg.State.BanFile)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	bans, err := st.Bans(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bans:", err)
		return 1
	}
	active := map[string]time.Time{}
	for ip, until := range bans {
		if until.After(time.Now()) {
			active[ip] = until
		}
	}
	s := cloudflare.NewSyncer(cloudflare.NewClient(cfg.Cloudflare.APIBase, cfg.Cloudflare.APIToken), bs.AccountID, bs.ListName, 0,
		func() map[string]time.Time { return active })
	if err := s.SyncOnce(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "sync:", err)
		return 1
	}
	fmt.Printf("✔ %d active bans → list %s: +%d −%d (%d items)\n", len(active), bs.ListName, s.Added.Load(), s.Removed.Load(), s.Items.Load())
	return 0
}
