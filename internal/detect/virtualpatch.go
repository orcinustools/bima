package detect

import (
	"bytes"
	"mime"
	"net/url"
	"regexp"
	"strings"

	"github.com/corazawaf/libinjection-go"
	"github.com/orcinustools/bima/internal/normalize"
)

// HTTPRequest is the request-level view virtual patches need (several parts
// of the request at once, unlike per-value signatures).
type HTTPRequest struct {
	Method  string
	Path    string // raw, undecoded
	Query   string // raw, undecoded
	Headers [][2]string
	Body    []byte
}

func (r *HTTPRequest) header(name string) (string, bool) {
	for _, h := range r.Headers {
		if strings.EqualFold(h[0], name) {
			return h[1], true
		}
	}
	return "", false
}

type vpRule struct {
	id, cve, cat, msg string
	sev               Severity
	match             func(r *HTTPRequest, path string) (string, string) // returns location, snippet
}

var (
	phpCGIArg      = regexp.MustCompile(`(?i)(?:^|[+&]|%20)(?:%ad|%2d|-)d(?:\+|%20)*(?:allow_url_include|auto_prepend_file|auto_append_file|cgi\.force_redirect|disable_functions|open_basedir|safe_mode)`)
	deepNesting    = regexp.MustCompile(`(?:\[[^][]*\]){24,}`)
	dotSegment     = regexp.MustCompile(`(?:^|/)\.\.?(?:/|;|$)`)
	authHeaderSQLi = map[string]bool{"authorization": true, "x-api-key": true, "x-auth-token": true, "x-access-token": true}
)

var vpRules = []vpRule{
	{id: "BIMA-VP-001", cve: "CVE-2025-29927", cat: "auth-bypass", sev: Critical,
		msg: "Next.js middleware bypass header (x-middleware-subrequest)",
		match: func(r *HTTPRequest, _ string) (string, string) {
			if v, ok := r.header("x-middleware-subrequest"); ok {
				return "header:x-middleware-subrequest", v
			}
			return "", ""
		}},
	{id: "BIMA-VP-002", cve: "CVE-2025-53770", cat: "rce", sev: Critical,
		msg: "SharePoint ToolShell (ToolPane.aspx with SignOut referer)",
		match: func(r *HTTPRequest, path string) (string, string) {
			ref, _ := r.header("referer")
			if strings.Contains(path, "/_layouts/") && strings.Contains(path, "toolpane.aspx") && strings.Contains(strings.ToLower(ref), "signout.aspx") {
				return "path", path
			}
			return "", ""
		}},
	{id: "BIMA-VP-003", cve: "CVE-2025-24813", cat: "rce", sev: Critical,
		msg: "Tomcat partial PUT / session-file deserialization",
		match: func(r *HTTPRequest, _ string) (string, string) {
			if strings.EqualFold(r.Method, "PUT") {
				if v, ok := r.header("content-range"); ok {
					return "header:content-range", v
				}
			}
			if c, ok := r.header("cookie"); ok {
				for kv := range strings.SplitSeq(c, ";") {
					k, v, _ := strings.Cut(strings.TrimSpace(kv), "=")
					if strings.EqualFold(k, "JSESSIONID") && strings.HasPrefix(v, ".") {
						return "cookie:jsessionid", v
					}
				}
			}
			return "", ""
		}},
	{id: "BIMA-VP-004", cve: "CVE-2024-27198", cat: "auth-bypass", sev: Critical,
		msg: "Path-parameter auth bypass (;.jsp / ;.css suffix trick, TeamCity & co.)",
		match: func(r *HTTPRequest, path string) (string, string) {
			q := normalize.Decode(r.Query)
			for _, s := range []string{path, q} {
				if strings.Contains(s, ";.jsp") || strings.Contains(s, ";.css") || strings.Contains(s, ";.js") {
					return "path", s
				}
			}
			return "", ""
		}},
	{id: "BIMA-VP-005", cve: "CVE-2026-48710 / CVE-2023-4966", cat: "protocol-attack", sev: High,
		msg: "Malformed Host header (path/userinfo injection, oversized)",
		match: func(r *HTTPRequest, _ string) (string, string) {
			h, ok := r.header("host")
			if !ok {
				return "", ""
			}
			if len(h) > 255 || strings.ContainsAny(h, "/\\@ \t?#%") {
				return "header:host", h
			}
			return "", ""
		}},
	{id: "BIMA-VP-006", cve: "CVE-2025-31161", cat: "auth-bypass", sev: Critical,
		msg: "CrushFTP AWS4-HMAC auth bypass",
		match: func(r *HTTPRequest, _ string) (string, string) {
			if a, ok := r.header("authorization"); ok && strings.Contains(strings.ToLower(a), "credential=crushadmin/") {
				return "header:authorization", a
			}
			return "", ""
		}},
	{id: "BIMA-VP-007", cve: "CVE-2024-4577", cat: "rce", sev: Critical,
		msg: "PHP-CGI argument injection (soft hyphen -d)",
		match: func(r *HTTPRequest, _ string) (string, string) {
			if phpCGIArg.MatchString(r.Query) {
				return "query", r.Query
			}
			return "", ""
		}},
	{id: "BIMA-VP-008", cve: "CVE-2025-0108 / CVE-2024-21887", cat: "lfi", sev: High,
		msg: "Dot-segment in request path (clients always normalize paths)",
		match: func(r *HTTPRequest, path string) (string, string) {
			if dotSegment.MatchString(path) {
				return "path", path
			}
			return "", ""
		}},
	{id: "BIMA-VP-009", cve: "CVE-2026-109618 / CVE-2026-109619", cat: "protocol-attack", sev: High,
		msg: "Abusive multipart / deep input nesting (PHP OOM & upload-progress RCE)",
		match: func(r *HTTPRequest, _ string) (string, string) {
			if m := deepNesting.FindString(normalize.Decode(r.Query)); m != "" {
				return "query", m
			}
			ct, _ := r.header("content-type")
			mt, params, err := mime.ParseMediaType(ct)
			if err != nil {
				return "", ""
			}
			switch {
			case mt == "application/x-www-form-urlencoded":
				if m := deepNesting.FindString(normalize.Decode(string(r.Body))); m != "" {
					return "body", m
				}
			case strings.HasPrefix(mt, "multipart/") && params["boundary"] != "":
				delim := []byte("--" + params["boundary"])
				if n := bytes.Count(r.Body, delim); n > 500 {
					return "body", "multipart parts > 500"
				}
				if m := deepNesting.Find(r.Body); m != nil {
					return "body", string(m)
				}
				for part := range bytes.SplitSeq(r.Body, delim) {
					hdr, _, _ := bytes.Cut(part, []byte("\r\n\r\n"))
					if bytes.Count(hdr, []byte("\r\n")) > 16 {
						return "body", "multipart part with > 16 headers"
					}
				}
			}
			return "", ""
		}},
	{id: "BIMA-VP-010", cve: "CVE-2025-31324", cat: "upload", sev: Critical,
		msg: "SAP NetWeaver Visual Composer metadatauploader",
		match: func(r *HTTPRequest, path string) (string, string) {
			if strings.Contains(path, "/developmentserver/metadatauploader") {
				return "path", path
			}
			return "", ""
		}},
	{id: "BIMA-SQLI-014", cve: "CVE-2025-25257", cat: "sqli", sev: High,
		msg: "SQL injection in an auth/API-key header (libinjection)",
		match: func(r *HTTPRequest, _ string) (string, string) {
			for _, h := range r.Headers {
				name := strings.ToLower(h[0])
				if !authHeaderSQLi[name] && !strings.HasPrefix(name, "x-") {
					continue
				}
				v := normalize.Decode(h[1])
				_, tok, _ := strings.Cut(v, " ") // "Bearer <token>"
				for _, s := range []string{v, tok} {
					if s != "" && strings.ContainsAny(s, "'\"") {
						if ok, _ := libinjection.IsSQLi(s); ok {
							return "header:" + name, h[1]
						}
					}
				}
			}
			return "", ""
		}},
}

// VirtualPatches evaluates request-level rules for specific CVEs and
// protocol abuses that per-value signatures cannot express.
func VirtualPatches(r *HTTPRequest) []Finding {
	path := r.Path
	if p, err := url.PathUnescape(r.Path); err == nil {
		path = p
	}
	path = normalize.Decode(path)
	var out []Finding
	for i := range vpRules {
		v := &vpRules[i]
		if loc, snip := v.match(r, path); loc != "" {
			score := 30.0
			if v.sev == Critical {
				score = 50
			}
			out = append(out, Finding{RuleID: v.id, Category: v.cat, Severity: v.sev,
				Msg: v.msg + " [" + v.cve + "]", Location: loc, Match: snippet(snip, 200), Score: score, Block: true})
		}
	}
	return out
}
