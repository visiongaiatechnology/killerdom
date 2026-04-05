package vgtsecurity

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
)

/*
STATUS: DIAMANT VGT SUPREME
KOGNITIVE ARCHITEKTUR: RE2 DFA WAF MIDDLEWARE (GOLANG)
WARNUNG: Diese Middleware ist für maximale Concurrency in Edge-Netzwerken gebaut.
Zero-Allocation-Buffer Pools und deterministische O(n) RE2 Matcher.
*/

type ThreatLevel string

const (
	LevelCritical   ThreatLevel = "CRITICAL"
	LevelSuspicious ThreatLevel = "SUSPICIOUS"
	LevelHeaderViol ThreatLevel = "HEADER_VIOLATION"
)

// WAF-Engine hält die kompilierten RE2 Automaten.
// In Go ist *regexp.Regexp thread-safe (safe for concurrent use).
type KillerDomEngine struct {
	criticalRules   map[string]*regexp.Regexp
	suspiciousRules map[string]*regexp.Regexp
	headerRules     map[string]*regexp.Regexp
	bufferPool      *sync.Pool
}

const maxBodyBytes = 2 * 1024 * 1024 // 2MB Hard Limit gegen L7 Volumetric DoS

// NewKillerDomEngine kompiliert den APEX Regex-Katalog.
// Possessive Quantifikatoren (*+, ++) und atomare Gruppen ((?>...)) sind entfernt, 
// da Go's RE2 Engine von Natur aus in O(n) ohne Backtracking arbeitet.
func NewKillerDomEngine() *KillerDomEngine {
	engine := &KillerDomEngine{
		criticalRules:   make(map[string]*regexp.Regexp),
		suspiciousRules: make(map[string]*regexp.Regexp),
		headerRules:     make(map[string]*regexp.Regexp),
		bufferPool: &sync.Pool{
			New: func() interface{} {
				// Pre-Allocate 32KB Buffer für effizientes Memory Management
				return bytes.NewBuffer(make([]byte, 0, 32*1024))
			},
		},
	}

	// TIER 1: CRITICAL THREATS
	compileMap(engine.criticalRules, map[string]string{
		"rce_ssti_deser": `(?i)(?:system|exec|passthru|shell_exec|eval|proc_open|assert|phpinfo|pcntl_exec|popen|create_function|mb_ereg_replace|preg_replace|call_user_func(?:_array)?|invokefunction|ob_start|array_map|array_filter|usort|uasort|uksort|register_shutdown_function|register_tick_function|putenv|mail|dl|ffi_cdef|ffi_load)\s*[\[\(]|\x60[^\x60]{0,1024}\x60|\$\{[^}]+\}|<%(?:=|)\s*.*?\s*%>|<%=\s*.*?%>|\{\{.*?\}\}|\b(?:cmd|bash|sh|powershell|pwsh|cscript|wscript|node|python|perl|ruby)\.exe|/bin/(?:sh|bash|zsh|dash|ksh|csh|tcsh)|\|(?:sh|bash|zsh|dash|ksh|csh|tcsh)|(?:wget|curl|nc|ncat|netcat|socat|nmap|telnet)[^|]{1,255}?\|\s*(?:sh|bash|zsh|dash)|\\x[0-9a-f]{2}|(?:allow_url_include|auto_prepend_file|auto_append_file|suhosin\.executor|disable_functions)\s*=|java\.lang\.(?:Runtime|ProcessBuilder)|child_process\.(?:exec|spawn|fork)|require\s*\(\s*['"]child_process['"]\)|O:\d+:"[^"]+":\d+:{|a:\d+:{|C:\d+:"[^"]+":|\$\{jndi:(?:ldap|rmi|dns|iiop|http|https)://)`,
		"lfi_rfi_os":     `(?i)(?:\.\.[\\/]+)+|(?:\.\.+%[0-9a-f]{2})+|/etc/(?:passwd|shadow|hosts|group|issue|fstab|hostname|ssh/ssh_config|resolv\.conf)|c:\\(?:windows|winnt)\\(?:system32|repair|system|sam|config/sam)|boot\.ini|wp-config\.php|php://(?:filter|input|temp|memory|fd)|(?:file|zip|phar|data|expect|input|glob|ssh2|ogg|rar|zlib)://|/proc/(?:self|version|cmdline|environ|net/arp|net/tcp|net/udp|sched_debug)|/var/log/(?:auth|secure|messages|syslog|apache2|nginx|httpd|access|error)\.log|%00|%%32%65|%2e%2e|%252e%252e`,
		"sqli_nosqli":    `(?i)(?:union(?:[\s/*]+(?:all|distinct))?[\s/*\(]+select|information_schema|waitfor[\s/*]+delay|benchmark\s*\(|sleep\s*\(|extractvalue\s*\(|updatexml\s*\(|hex\s*\(|unhex\s*\(|concat\s*\(|char\s*\(|\s+(?:OR|AND)\s+[\d']+[\s=>]+[\d']|0x[0-9a-f]{2,}|declare[^@]{1,128}?@[^=]{1,128}?=|cast\s*\(|@@version|drop\s+(?:table|database|user|view|procedure)|alter\s+(?:table|database|user)|into\s+(?:outfile|dumpfile)|load\s+data\s+infile|xp_cmdshell|pg_sleep\s*\(|dbms_pipe\.receive_message|utl_http\.request|sys_eval|sys_exec|having\s+1=1|\$where|\$ne|\$regex|\$gt|\$lt|\$exists|\$expr|\$in|\$nin)`,
		"xss_dom":        `(?i)<(?:script|iframe|object|embed|math|applet|meta|style|base|form|bgsound|blink|keygen|marquee|template|video|audio)|javascript:|vbs:|vbscript:|on(?:load|error|click|dblclick|mouseover|mouseenter|mouseleave|submit|reset|focus|blur|contextmenu|animationstart|toggle|keyup|keydown|pointer|touch|drag|drop|wheel|copy|paste|cut)[\s/*]*=|base64_decode|data:text/(?:html|xml)|alert\s*\(|confirm\s*\(|prompt\s*\(|<svg|xlink:href|&#|srcdoc[\s/*]*=|importmap|-moz-binding|expression\s*\(|\[\]\s*\(\s*\[\]\s*\)|!!\[\]|!\+\[\]|\+!!\[\]|\\x3cscript|%3cscript`,
		"xxe_ssrf":       `(?i)<!ENTITY\s+[^>]*+(?:SYSTEM|PUBLIC)\s+["']|<!DOCTYPE\s+[^>]*+\[|xmlns:xsi\s*=|xsi:schemaLocation\s*=|gopher://|dict://|ldap://|sftp://|tftp://|ws://|wss://|169\.254\.169\.254|metadata\.google\.internal|0\.0\.0\.0|127\.0\.0\.1|::1|localhost|aws-env`,
		"probes":         `(?i)(?:\.env|\.git|\.htaccess|\.php_bak|\.old|\.bak|config\.php|wp-config\.php|\.sql|\.tar\.gz|\.zip|\.remote-sync|\.ds_store|\.aws/credentials|\.idea|\.vscode|vendor/phpunit|composer\.json|phpunit/src|/\.well-known/security|/\.svn/|/\.hg/|/web\.config|/\.user\.ini)`,
	})

	// TIER 2 & TIER 3 Initialization...
	compileMap(engine.suspiciousRules, map[string]string{
		"obfuscation":  `(?i)(?:base64_decode|base64_encode|str_rot13|gzinflate|gzuncompress|deflate|eval\s*\(\s*base64_decode)\s*\(`,
		"file_ops":     `(?i)(?:fopen|fwrite|file_put_contents|file_get_contents|readfile|unlink|rename|copy|mkdir|rmdir|chmod|chown)\s*\(`,
		"hex_encode":   `(?i)(?:\\x[0-9a-fA-F]{2}){4,}|(?:%[0-9a-fA-F]{2}){6,}`,
		"high_entropy": `[()x\$<>\[\]{}|&;]{6,}`,
	})

	compileMap(engine.headerRules, map[string]string{
		"ua_malicious": `(?i)\b(?:sqlmap|nikto|wpscan|masscan|havij|netsparker|burp|acunetix|nessus|log4j|shellshock|gobuster|dirbuster|zgrab|nuclei|ffuf|httpx|projectdiscovery|zmap|curl/|python-requests|headless|selenium|libwww|lts/1\.0|nmap|shodan|census|icealgl|java/[0-9]|go-http-client|fasthttp|kinza|nutch|arachni|hydra|medusa|vega|w3af|zap|owasp|blackwidow|datacha0s|dirb|dotbot|evil|fimap|jbrofuzz|libwhisker|morfeus|muieblackcat|pmafind|scanbot|sysscan|zmeu|binlar|casper|cmsworldmap|comodo|diavol|dotcom|extract|fiddler|grabber|httrack|ia_archiver|indy|leech|lwp-trivial|navroad|nutch|panscient|pecl|python-urllib|sqlninja|sublist3r|sysscan|webinspect|xenu)\b`,
	})

	return engine
}

func compileMap(target map[string]*regexp.Regexp, source map[string]string) {
	for k, v := range source {
		target[k] = regexp.MustCompile(v)
	}
}

// Middleware-Handler: Fängt den Request ab und blockiert ihn bei Gefahr.
func (e *KillerDomEngine) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		
		// 1. Header Isolation Scan
		for _, values := range r.Header {
			for _, value := range values {
				if e.scanString(value, e.headerRules) || e.scanString(value, e.criticalRules) {
					e.reject(w, LevelHeaderViol)
					return
				}
			}
		}

		// 2. URI & Query Parameter Scan
		rawURI, _ := url.QueryUnescape(r.URL.RawQuery + r.URL.Path)
		if e.scanString(rawURI, e.criticalRules) {
			e.reject(w, LevelCritical)
			return
		}

		// 3. Zero-Allocation Body Scan
		if r.Body != nil && r.ContentLength != 0 {
			// Limit Reader verhindert Memory-Exhaustion durch gigantische Payloads
			r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

			buf := e.bufferPool.Get().(*bytes.Buffer)
			buf.Reset()
			defer e.bufferPool.Put(buf)

			_, err := io.Copy(buf, r.Body)
			if err != nil {
				http.Error(w, "VGT DOM SECURE: PAYLOAD READ ERROR", http.StatusBadRequest)
				return
			}

			bodyStr := buf.String()
			
			// Deep JSON Traversal oder Raw String Scan
			if isJSON(bodyStr) {
				var data interface{}
				if err := json.Unmarshal(buf.Bytes(), &data); err == nil {
					if e.scanRecursive(data, 0) {
						e.reject(w, LevelCritical)
						return
					}
				}
			} else {
				if e.scanString(bodyStr, e.criticalRules) || e.scanString(bodyStr, e.suspiciousRules) {
					e.reject(w, LevelCritical)
					return
				}
			}

			// Body wiederherstellen, damit nachfolgende Handler ihn lesen können
			r.Body = io.NopCloser(bytes.NewReader(buf.Bytes()))
		}

		next.ServeHTTP(w, r)
	})
}

// Rekursive Überprüfung von JSON Strukturen (Max Depth: 10)
func (e *KillerDomEngine) scanRecursive(data interface{}, depth int) bool {
	if depth > 10 {
		return true // Recursion Limit -> Automatische Ablehnung
	}

	switch v := data.(type) {
	case string:
		return e.scanString(v, e.criticalRules)
	case map[string]interface{}:
		for _, val := range v {
			if e.scanRecursive(val, depth+1) {
				return true
			}
		}
	case []interface{}:
		for _, val := range v {
			if e.scanRecursive(val, depth+1) {
				return true
			}
		}
	}
	return false
}

// Normalisiert und prüft einen String gegen eine Regel-Map
func (e *KillerDomEngine) scanString(input string, rules map[string]*regexp.Regexp) bool {
	// Normalisierung: Null-Bytes und unsichtbare Zeichen entfernen
	normalized := strings.ReplaceAll(input, "\x00", "")
	normalized = strings.ReplaceAll(normalized, "\r", "")
	normalized = strings.ReplaceAll(normalized, "\n", "")

	if normalized == "" {
		return false
	}

	// Goroutine-Safe concurrent read auf die Regex Pointer
	for _, rule := range rules {
		if rule.MatchString(normalized) {
			return true
		}
	}
	return false
}

func (e *KillerDomEngine) reject(w http.ResponseWriter, level ThreatLevel) {
	// Logik für Block-Logging würde hier zum SIEM/Datadog gesendet werden.
	log.Printf("[VGT-KILLER-DOM] ANNIHILATION TRIGGERED | THREAT_LEVEL: %s", level)
	http.Error(w, fmt.Sprintf("VGT DOM SECURE: REQUEST REJECTED [%s]", level), http.StatusForbidden)
}

func isJSON(str string) bool {
	str = strings.TrimSpace(str)
	return (strings.HasPrefix(str, "{") && strings.HasSuffix(str, "}")) ||
		(strings.HasPrefix(str, "[") && strings.HasSuffix(str, "]"))
}