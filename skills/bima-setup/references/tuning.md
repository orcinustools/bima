# Shadow mode and false-positive tuning

## Procedure
1. Run with `mode: detect` on real traffic. Longer is better (cover weekly jobs,
   admin flows, webhooks, mobile apps).
2. Read the report: `curl -s http://127.0.0.1:9101/report | jq`.
   Each rule has `hits`, `blocking` (would have blocked/tarpitted), `distinct_ips`,
   `top_paths`, `top_locations`, `samples`, `likely_false_positive` and a ready
   `suggested_exclusion`.
3. For every rule with `blocking > 0`, classify with the user:
   - **Attack** (few IPs, scanner UAs, random paths, payload-looking samples) → leave it.
   - **False positive** (many distinct IPs, one path + one field, samples look like
     normal content) → add an exclusion.
4. Apply, restart (`systemctl restart bima`), reset the report
   (`curl -X DELETE http://127.0.0.1:9101/report`) and observe again.
5. Enforce only when `blocking` is attack-only, and the user agrees.

## Writing exclusions (narrow!)
```yaml
exclusions:
  - rules: ["CRS-941160"]                 # exact rule, or prefix "CRS-941*"
    path: "^/api/products$"               # regex on the path (no query string)
    locations: ["body:json.description"]  # prefix match on the location
    reason: "rich text editor"
```
Rules of thumb:
- Always set `path` and `locations`. An exclusion without them disables the rule site-wide.
- Exclude the **specific** CRS rule that fires (e.g. `CRS-941160` HTML injection),
  not the whole family, so `<script>`/event-handler XSS rules stay active.
- Prefer excluding CRS heuristics over Bima signatures: `BIMA-RCE-*`, `BIMA-LFI-*`
  are separator/structure based and rarely false-positive.
- Free-text fields (search, bio, comments): exclude `CRS-932*` / `CRS-930*` on that
  field only; Bima's RCE/LFI signatures still cover real injections.
- Code/snippet features: exclude `BIMA-RCE-001`, `BIMA-RCE-002`, `CRS-932*` on that
  endpoint's body only.
- Common CRS false-positive shapes seen in testing (exclude per field):
  free-text search (`CRS-932*`, `CRS-930*` on `query:q`), GraphQL documents
  (`CRS-932*` on the `/graphql` body), data-URL image fields
  (`data:image/png;base64,...` → `CRS-932235`), rich-text HTML (`CRS-941160`).
- Never exclude `BIMA-L4J-004`, `BIMA-JAVA-*`, `BIMA-UPL-009` without a very specific reason.

## After tuning — prove it
Re-send a representative attack to every excluded endpoint (e.g. `<script>` to the
rich-text field, `;cat /etc/passwd` to search) and confirm it is still reported/blocked.

Metrics: `bima_excluded_total{rule=...}` shows how often each exclusion is used;
`bima_verdicts_total{action="would_block"}` in detect mode is the FP+attack volume.
