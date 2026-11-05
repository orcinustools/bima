package detect

import (
	"regexp"
	"strings"

	"github.com/orcinustools/bima/internal/normalize"
)

type sigRule struct {
	id       string
	category string
	sev      Severity
	msg      string
	score    float64
	re       *regexp.Regexp
	// shell rules match against input with quote/backslash obfuscation collapsed
	shell bool
	// raw rules match against the original (case-sensitive) input
	raw bool
	// reBody, when set, replaces re for whole multi-line bodies (location "body"),
	// where a newline is a line break, not a command separator.
	reBody *regexp.Regexp
	// need: cheap prefilter; the regex only runs if any of these substrings is present
	need []string
}

func (r *sigRule) candidate(s string) bool {
	for _, n := range r.need {
		if strings.Contains(s, n) {
			return true
		}
	}
	return len(r.need) == 0
}

const shellCmds = `(?:id|whoami|uname|cat|tac|head|tail|more|less|ls|wget|curl|nc|ncat|netcat|bash|sh|zsh|dash|ksh|python[23]?|perl|ruby|php|powershell|pwsh|cmd(?:\.exe)?|ping|nslookup|dig|sleep|chmod|chown|rm|echo|printf|busybox|telnet|ifconfig|env|printenv|xargs|awk|sed|find|socat|mkfifo|crontab|useradd|passwd)`

// shellTerm: a command is followed by whitespace, end, a redirection/separator, or a path argument.
const shellTerm = `(?:\s|$|[;|&<>\x60)/},\]])`

var sigRules = []sigRule{
	{id: "BIMA-RCE-001", need: []string{";", "|", "`", "\n", "$(", "&&"}, category: "rce", sev: Critical, score: 50, shell: true,
		msg:    "OS command injection (separator + shell command)",
		re:     regexp.MustCompile(`(?:[;|\x60\n]|\$\(|&&|\|\|)\s*(?:/(?:usr/)?(?:local/)?s?bin/)?` + shellCmds + shellTerm),
		reBody: regexp.MustCompile(`(?:[;|\x60]|\$\(|&&|\|\|)[ \t]*(?:/(?:usr/)?(?:local/)?s?bin/)?` + shellCmds + shellTerm)},
	{id: "BIMA-RCE-002", need: []string{"/dev/", "sh", "nc", "mkfifo", "powershell", "cmd"}, category: "rce", sev: Critical, score: 50, shell: true,
		msg: "Reverse shell / remote payload execution",
		re: regexp.MustCompile(`(?:curl|wget)\s[^|;]*\|\s*(?:ba|z|da)?sh\b|/dev/(?:tcp|udp)/|\bnc(?:at)?\s+(?:-\S+\s+)*-[ec]\s|\bbash\s+-[ic]\b|/bin/(?:ba|z|da)?sh\b|\bmkfifo\s|` +
			`\bbase64\s+(?:-d|--decode)\b.*\|\s*(?:ba)?sh|\bpowershell(?:\.exe)?\s+.*-(?:enc|e|encodedcommand)\s|\bcmd(?:\.exe)?\s+/c\s`)},
	{id: "BIMA-RCE-003", need: []string{"(", "://", "<?", "data:"}, category: "rce", sev: Critical, score: 50,
		msg: "PHP code execution function / stream wrapper",
		re: regexp.MustCompile(`\b(?:system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec|assert|eval|create_function|call_user_func(?:_array)?|preg_replace)\s*\(\s*(?:\$|["'\x60]|base64_decode|str_rot13|gzinflate|\$_(?:get|post|request|cookie|server))|` +
			`\b(?:php|expect|phar|zip|glob)://|\bdata:(?://)?text/plain;base64,|<\?php|<\?=`)},
	{id: "BIMA-L4J-004", need: []string{"${"}, category: "log4shell", sev: Critical, score: 50,
		msg: "Log4Shell JNDI lookup (CVE-2021-44228)",
		re:  regexp.MustCompile(`\$\{\s*jndi\s*:\s*(?:ldaps?|rmi|dns|iiop|corba|nds|nis|http)?`)},
	{id: "BIMA-JAVA-005", need: []string{"class", "runtime", "processbuilder", "scriptengine"}, category: "java", sev: Critical, score: 50,
		msg: "Spring4Shell / Java class manipulation",
		re:  regexp.MustCompile(`class\.module\.classloader|class\[module\]|\.getruntime\(\)\.exec|java\.lang\.(?:runtime|processbuilder)|\bscriptengine(?:manager)?\b`)},
	{id: "BIMA-JAVA-006", need: []string{"rO0AB", "\xac\xed", "H4sI"}, category: "java", sev: Critical, score: 50, raw: true,
		msg: "Java serialized object (deserialization attack)",
		re:  regexp.MustCompile(`rO0AB[A-Za-z0-9+/]|\xac\xed\x00\x05|H4sIAAAAAAAA[A-Za-z0-9+/]{20,}`)},
	{id: "BIMA-SSTI-007", need: []string{"{{", "${", "#{", "<%", "__", "{%"}, category: "ssti", sev: High, score: 30,
		msg: "Server-side template injection",
		re: regexp.MustCompile(`\{\{\s*['\"]?\d+['\"]?\s*[*+]\s*['\"]?\d+['\"]?\s*\}\}|\$\{\s*\d+\s*[*+]\s*\d+\s*\}|#\{\s*\d+\s*[*+]\s*\d+\s*\}|<%=?\s*\d+\s*[*+]\s*\d+\s*%>|` +
			`__(?:class|mro|subclasses|globals|builtins|init)__|\{\{[^}]*\b(?:config|self|request|lipsum|cycler|joiner|namespace|_self\.env)\b[^}]*\}\}|\{%[^%]*\bimport\b`)},
	{id: "BIMA-LFI-008", need: []string{"..", "/etc/", "/proc/", "c:", "win.ini"}, category: "lfi", sev: High, score: 30,
		msg: "Path traversal / local file inclusion",
		re: regexp.MustCompile(`(?:\.\.[/\\]){2,}|\.\.[/\\][^\s]*(?:etc|windows|winnt|boot\.ini|proc|var/log)|` +
			`/etc/(?:passwd|shadow|group|hosts|issue|crontab)\b|/proc/(?:self|\d+)/(?:environ|cmdline|maps|fd)|c:[/\\](?:windows|winnt|boot\.ini)|\bwin\.ini\b`)},
	{id: "BIMA-RCE-004", need: []string{"child_process", "mainmodule", "execsync", "spawnsync", "__import__", "os.system", "os.popen", "subprocess"}, category: "rce", sev: Critical, score: 50,
		msg: "Node.js / Python code execution",
		re:  regexp.MustCompile(`child_process|process\.mainmodule|\b(?:exec|spawn)sync\s*\(|__import__\s*\(\s*['"](?:os|subprocess|pty)|\bos\.(?:system|popen|exec[lv]p?e?)\s*\(|subprocess\.(?:popen|run|call|check_output|getoutput)\s*\(`)},
	{id: "BIMA-JAVA-007", need: []string{"ognl", "memberaccess", "struts2", "freemarker", "velocity", "@java."}, category: "java", sev: Critical, score: 50,
		msg: "OGNL / Struts2 / template-engine gadget (Confluence, Struts)",
		re:  regexp.MustCompile(`#_memberaccess|@org\.apache\.struts2|ognl(?:context|\.ognlcontext|util)|freemarker\.template\.utility\.(?:execute|objectconstructor|jythonruntime)|\.key_velocity\.struts2|@java\.lang\.(?:runtime|processbuilder|system)@|\(#[a-z_]+=`)},
	{id: "BIMA-SSRF-010", need: []string{"://"}, category: "ssrf", sev: High, score: 30,
		msg: "SSRF to internal/metadata address or dangerous scheme",
		re:  regexp.MustCompile(`(?:^|["'=\s(,])(?:gopher|dict|ldap|tftp|jar|netdoc|file)://|(?:^|["'=\s(,])(?:https?|ftp)://(?:[^/\s"'@]*@)?(?:169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com|100\.100\.100\.200|fd00:ec2::254|localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|0x7f[0-9a-f]*|2130706433|2852039166|\[?(?:::1|::ffff:[0-9a-f.:]+|0:0:0:0:0:0:0:1)\]?)(?:[:/\s"'?#]|$)`)},
	{id: "BIMA-XXE-011", need: []string{"<!entity", "<!doctype"}, category: "xxe", sev: Critical, score: 50,
		msg: "XML external entity (XXE)",
		re:  regexp.MustCompile(`<!entity\s+(?:%\s*)?[\w.-]+\s+(?:system|public)\b|<!doctype[^>]*\[[^\]]*<!entity`)},
	{id: "BIMA-PROTO-012", need: []string{"__proto__", "prototype", ":constructor"}, category: "proto-pollution", sev: High, score: 30,
		msg: "Prototype pollution (incl. React Server Components Flight gadgets)",
		re:  regexp.MustCompile(`__proto__|constructor\s*(?:\]?\s*\[\s*['"]?|\.)\s*prototype|"constructor"\s*:\s*\{\s*"prototype"|\$[0-9a-f]*:constructor:constructor|:__proto__:`)},
	{id: "BIMA-PHP-013", need: []string{"o:", "c:", "fnstream", "_fn_"}, category: "php-object-injection", sev: Critical, score: 50,
		msg: "PHP object injection / known gadget chain",
		re:  regexp.MustCompile(`(?:^|[;{"=|\s])[oc]:\d+:"[a-z_\\][\w\\]*":\d+:\{|guzzlehttp\\{1,2}psr7\\{1,2}fnstream|"_fn_[a-z]+"\s*:`)},
	{id: "BIMA-UPL-009", need: []string{"filename"}, category: "upload", sev: Critical, score: 50,
		msg: "Executable/webshell file upload",
		re:  regexp.MustCompile(`filename\s*=\s*"?[^"\r\n;]*\.(?:php\d?|phtml|phar|pht|jsp|jspx|jsw|asp|aspx|ashx|asmx|cer|cgi|pl|py|sh)(?:\.[a-z0-9]{1,4})?(?:"|\s|;|$)`)},
}

// log4j obfuscations: ${lower:j}, ${upper:N}, ${::-d}, ${env:FOO:-i}, ${date:'j'}
var l4jLookup = regexp.MustCompile(`\$\{(?:lower:|upper:|::-|[a-z]+:[^:}]*:-|date:')([^${}']*)'?\}`)

func deobfuscateL4J(s string) string {
	for i := 0; i < 6 && strings.Contains(s, "${"); i++ {
		n := l4jLookup.ReplaceAllString(s, "$1")
		if n == s {
			break
		}
		s = n
	}
	return s
}

// Signatures runs the built-in signature set against every target.
// At most one finding per rule ID is returned.
func Signatures(targets []Target) []Finding {
	var out []Finding
	seen := map[string]bool{}
	for _, t := range targets {
		if t.Raw == "" || (len(t.Raw) < 16 && plain(t.Raw)) {
			continue // short [A-Za-z0-9 _-.] values can't carry any signature
		}
		norm := normalize.Decode(t.Raw)
		variants := []string{norm}
		if strings.Contains(norm, "${") {
			variants = append(variants, deobfuscateL4J(norm))
		}
		variants = append(variants, normalize.Base64Candidates(t.Raw)...)
		shellVariants := make([]string, len(variants))
		for i, v := range variants {
			shellVariants[i] = normalize.CollapseShell(v)
		}

		for _, r := range sigRules {
			if seen[r.id] {
				continue
			}
			var m string
			switch {
			case r.raw:
				if r.candidate(t.Raw) {
					m = r.re.FindString(t.Raw)
				}
			case r.shell:
				re := r.re
				if r.reBody != nil && t.Location == "body" {
					re = r.reBody
				}
				for _, v := range shellVariants {
					if !r.candidate(v) {
						continue
					}
					if m = re.FindString(v); m != "" {
						break
					}
				}
			default:
				for _, v := range variants {
					if !r.candidate(v) {
						continue
					}
					if m = r.re.FindString(v); m != "" {
						break
					}
				}
			}
			if m == "" {
				continue
			}
			seen[r.id] = true
			out = append(out, Finding{
				RuleID: r.id, Category: r.category, Severity: r.sev, Msg: r.msg,
				Location: t.Location, Match: snippet(t.Raw, 200), Score: r.score,
				Block: r.sev >= High,
			})
		}
	}
	return out
}

func plain(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == ' ' || c == '_' || c == '-' || c == '.' || c == '+') {
			return false
		}
	}
	return true
}

func snippet(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
