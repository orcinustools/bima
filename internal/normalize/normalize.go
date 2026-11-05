// Package normalize turns attacker-controlled input into a canonical form
// before signature matching, defeating common encoding-based bypasses.
package normalize

import (
	"encoding/base64"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

const maxDecodeRounds = 4

// Decode applies URL-decoding repeatedly until stable (handles %252e etc),
// fixes overlong UTF-8 slash/dot sequences, applies NFKC (fullwidth chars),
// strips NUL bytes and lowercases.
func Decode(s string) string {
	for i := 0; i < maxDecodeRounds; i++ {
		d := overlong.Replace(s)
		if u, err := url.QueryUnescape(d); err == nil {
			d = u
		} else if u, err := url.PathUnescape(d); err == nil {
			d = u
		}
		d = decodeHTMLish(d)
		if d == s {
			break
		}
		s = d
	}
	s = norm.NFKC.String(s)
	s = strings.ReplaceAll(s, "\x00", "")
	return strings.ToLower(s)
}

// overlong UTF-8 / IIS %u encodings used to smuggle '.', '/' and '\'.
var overlong = strings.NewReplacer(
	"%c0%ae", ".", "%C0%AE", ".", "%c0%af", "/", "%C0%AF", "/",
	"%c1%9c", "\\", "%C1%9C", "\\", "%e0%80%af", "/",
	"%u002e", ".", "%u002f", "/", "%u005c", "\\", "%U002E", ".", "%U002F", "/",
)

var htmlEnt = strings.NewReplacer("&lt;", "<", "&gt;", ">", "&quot;", `"`, "&#39;", "'", "&amp;", "&", "&#x24;", "$", "&#36;", "$")

func decodeHTMLish(s string) string {
	if !strings.Contains(s, "&") {
		return s
	}
	return htmlEnt.Replace(s)
}

// CollapseShell removes characters attackers insert to break up shell keywords:
// empty quote pairs, c\at, c"a"t, $@ and ${IFS}. Used only for the shell-command matcher.
func CollapseShell(s string) string {
	s = strings.ReplaceAll(s, "${ifs}", " ")
	s = strings.ReplaceAll(s, "$ifs", " ")
	s = strings.ReplaceAll(s, "$@", "")
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '\'', '"', '\\':
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

var b64Token = regexp.MustCompile(`[A-Za-z0-9+/_-]{16,}={0,2}`)

// Base64Candidates decodes base64-looking tokens that turn into printable text,
// so payloads like `echo <b64> | base64 -d | sh` or b64 params get inspected.
func Base64Candidates(raw string) []string {
	var out []string
	for _, tok := range b64Token.FindAllString(raw, 8) {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
			b, err := enc.DecodeString(tok)
			if err == nil && len(b) >= 8 && printable(b) {
				out = append(out, strings.ToLower(string(b)))
				break
			}
		}
	}
	return out
}

func printable(b []byte) bool {
	n := 0
	for _, r := range string(b) {
		if unicode.IsPrint(r) || r == '\n' || r == '\t' {
			n++
		}
	}
	return n*10 >= len([]rune(string(b)))*9
}
