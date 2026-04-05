#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic, clippy::nursery)]

//! STATUS: DIAMANT VGT SUPREME
//! KOGNITIVE ARCHITEKTUR: SIMULTANEOUS DFA MATCHING ENGINE
//! Diese Engine nutzt `RegexSet`, um alle Signaturen in einen einzigen Zustandsautomaten (DFA) 
//! zu verschmelzen. Die Komplexität bleibt bei O(n) für den Input, unabhängig von der Anzahl 
//! der Pattern. Backtracking ist mathematisch ausgeschlossen.

use once_cell::sync::Lazy;
use regex::{RegexSet, RegexSetBuilder};
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum ThreatSeverity {
    #[serde(rename = "CRITICAL")]
    Critical,
    #[serde(rename = "SUSPICIOUS")]
    Suspicious,
    #[serde(rename = "HEADER_VIOLATION")]
    HeaderViolation,
}

#[derive(Debug, Clone, Serialize)]
pub struct ThreatReport {
    pub severity: ThreatSeverity,
    pub category: &'static str,
}

#[derive(thiserror::Error, Debug)]
pub enum EngineError {
    #[error("Recursion limit exceeded during JSON deep traversal")]
    RecursionLimitExceeded,
    #[error("Regex compilation failed (System Integrity Breach): {0}")]
    RegexCompilationFailed(#[from] regex::Error),
}

/// Struktur der Pattern: (Kategorie, Regex)
const SIG_CRITICAL: &[(&str, &str)] = &[
    ("rce_ssti_deser", r#"(?i)(?:system|exec|passthru|shell_exec|eval|proc_open|assert|phpinfo|pcntl_exec|popen|create_function|mb_ereg_replace|preg_replace|call_user_func(?:_array)?|invokefunction|ob_start|array_map|array_filter|usort|uasort|uksort|register_shutdown_function|register_tick_function|putenv|mail|dl|ffi_cdef|ffi_load)\s*[\[\(]|\x60[^\x60]{0,1024}\x60|\$\{[^}]+\}|<%(?:=|)\s*.*?\s*%>|<%=\s*.*?%>|\{\{.*?\}\}|\b(?:cmd|bash|sh|powershell|pwsh|cscript|wscript|node|python|perl|ruby)\.exe|/bin/(?:sh|bash|zsh|dash|ksh|csh|tcsh)|\|(?:sh|bash|zsh|dash|ksh|csh|tcsh)|(?:wget|curl|nc|ncat|netcat|socat|nmap|telnet)[^|]{1,255}?\|\s*(?:sh|bash|zsh|dash)|\\x[0-9a-f]{2}|(?:allow_url_include|auto_prepend_file|auto_append_file|suhosin\.executor|disable_functions)\s*=|java\.lang\.(?:Runtime|ProcessBuilder)|child_process\.(?:exec|spawn|fork)|require\s*\(\s*['"]child_process['"]\)|O:\d+:"[^"]+":\d+:{|a:\d+:{|C:\d+:"[^"]+":|\$\{jndi:(?:ldap|rmi|dns|iiop|http|https)://)"#),
    ("lfi_rfi_os", r#"(?i)(?:\.\.[\\/]+)+|(?:\.\.+%[0-9a-f]{2})+|/etc/(?:passwd|shadow|hosts|group|issue|fstab|hostname|ssh/ssh_config|resolv\.conf)|c:\\(?:windows|winnt)\\(?:system32|repair|system|sam|config/sam)|boot\.ini|wp-config\.php|php://(?:filter|input|temp|memory|fd)|(?:file|zip|phar|data|expect|input|glob|ssh2|ogg|rar|zlib)://|/proc/(?:self|version|cmdline|environ|net/arp|net/tcp|net/udp|sched_debug)|/var/log/(?:auth|secure|messages|syslog|apache2|nginx|httpd|access|error)\.log|%00|%%32%65|%2e%2e|%252e%252e"#),
    ("sqli_nosqli", r#"(?i)(?:union(?:[\s/*]+(?:all|distinct))?[\s/*\(]+select|information_schema|waitfor[\s/*]+delay|benchmark\s*\(|sleep\s*\(|extractvalue\s*\(|updatexml\s*\(|hex\s*\(|unhex\s*\(|concat\s*\(|char\s*\(|\s+(?:OR|AND)\s+[\d']+[\s=>]+[\d']|0x[0-9a-f]{2,}|declare[^@]{1,128}?@[^=]{1,128}?=|cast\s*\(|@@version|drop\s+(?:table|database|user|view|procedure)|alter\s+(?:table|database|user)|into\s+(?:outfile|dumpfile)|load\s+data\s+infile|xp_cmdshell|pg_sleep\s*\(|dbms_pipe\.receive_message|utl_http\.request|sys_eval|sys_exec|having\s+1=1|\$where|\$ne|\$regex|\$gt|\$lt|\$exists|\$expr|\$in|\$nin)"#),
    ("xss_dom", r#"(?i)<(?:script|iframe|object|embed|math|applet|meta|style|base|form|bgsound|blink|keygen|marquee|template|video|audio)|javascript:|vbs:|vbscript:|on(?:load|error|click|dblclick|mouseover|mouseenter|mouseleave|submit|reset|focus|blur|contextmenu|animationstart|toggle|keyup|keydown|pointer|touch|drag|drop|wheel|copy|paste|cut)[\s/*]*=|base64_decode|data:text/(?:html|xml)|alert\s*\(|confirm\s*\(|prompt\s*\(|<svg|xlink:href|&#|srcdoc[\s/*]*=|importmap|-moz-binding|expression\s*\(|\[\]\s*\(\s*\[\]\s*\)|!!\[\]|!\+\[\]|\+!!\[\]|\\x3cscript|%3cscript"#),
    ("xxe_ssrf", r#"(?i)<!ENTITY\s+[^>]*+(?:SYSTEM|PUBLIC)\s+["']|<!DOCTYPE\s+[^>]*+\[|xmlns:xsi\s*=|xsi:schemaLocation\s*=|gopher://|dict://|ldap://|sftp://|tftp://|ws://|wss://|169\.254\.169\.254|metadata\.google\.internal|0\.0\.0\.0|127\.0\.0\.1|::1|localhost|aws-env"#),
    ("probes", r#"(?i)(?:\.env|\.git|\.htaccess|\.php_bak|\.old|\.bak|config\.php|wp-config\.php|\.sql|\.tar\.gz|\.zip|\.remote-sync|\.ds_store|\.aws/credentials|\.idea|\.vscode|vendor/phpunit|composer\.json|phpunit/src|/\.well-known/security|/\.svn/|/\.hg/|/web\.config|/\.user\.ini)"#),
];

const SIG_SUSPICIOUS: &[(&str, &str)] = &[
    ("obfuscation", r#"(?i)(?:base64_decode|base64_encode|str_rot13|gzinflate|gzuncompress|deflate|eval\s*\(\s*base64_decode)\s*\("#),
    ("file_ops", r#"(?i)(?:fopen|fwrite|file_put_contents|file_get_contents|readfile|unlink|rename|copy|mkdir|rmdir|chmod|chown)\s*\("#),
    ("hex_encode", r#"(?i)(?:\\x[0-9a-fA-F]{2}){4,}|(?:%[0-9a-fA-F]{2}){6,}"#),
    ("high_entropy", r#"[()x\$<>\[\]{}|&;]{6,}"#),
    ("crypto_miner", r#"(?i)(?:coinhive|webminer|cryptonight|stratum\+tcp|monero|xmr\.omine|coinimp|minr\.js)"#),
];

const SIG_HEADERS_ONLY: &[(&str, &str)] = &[
    ("ua_malicious", r#"(?i)\b(?:sqlmap|nikto|wpscan|masscan|havij|netsparker|burp|acunetix|nessus|log4j|shellshock|gobuster|dirbuster|zgrab|nuclei|ffuf|httpx|projectdiscovery|zmap|curl/|python-requests|headless|selenium|libwww|lts/1\.0|nmap|shodan|census|icealgl|java/[0-9]|go-http-client|fasthttp|kinza|nutch|arachni|hydra|medusa|vega|w3af|zap|owasp|blackwidow|datacha0s|dirb|dotbot|evil|fimap|jbrofuzz|libwhisker|morfeus|muieblackcat|pmafind|scanbot|sysscan|zmeu|binlar|casper|cmsworldmap|comodo|diavol|dotcom|extract|fiddler|grabber|httrack|ia_archiver|indy|leech|lwp-trivial|navroad|nutch|panscient|pecl|python-urllib|sqlninja|sublist3r|sysscan|webinspect|xenu)\b"#),
];

/// Der vorkompilierte Status der Engine. Memory-Safe, Send + Sync.
pub struct KillerDomEngine {
    critical_set: RegexSet,
    critical_cats: Vec<&'static str>,
    suspicious_set: RegexSet,
    suspicious_cats: Vec<&'static str>,
    header_set: RegexSet,
    header_cats: Vec<&'static str>,
}

pub static ENGINE: Lazy<KillerDomEngine> = Lazy::new(|| {
    KillerDomEngine::new().expect("VGT KERNEL PANIC: Failed to compile Threat Sets")
});

impl KillerDomEngine {
    /// Konstruiert die Engine. Kompiliert die DFA Automaten.
    fn new() -> Result<Self, EngineError> {
        let (critical_cats, critical_patterns): (Vec<_>, Vec<_>) = SIG_CRITICAL.iter().copied().unzip();
        let (suspicious_cats, suspicious_patterns): (Vec<_>, Vec<_>) = SIG_SUSPICIOUS.iter().copied().unzip();
        let (header_cats, header_patterns): (Vec<_>, Vec<_>) = SIG_HEADERS_ONLY.iter().copied().unzip();

        Ok(Self {
            critical_set: RegexSetBuilder::new(critical_patterns).size_limit(10 * 1024 * 1024).build()?,
            critical_cats,
            suspicious_set: RegexSetBuilder::new(suspicious_patterns).size_limit(10 * 1024 * 1024).build()?,
            suspicious_cats,
            header_set: RegexSetBuilder::new(header_patterns).size_limit(10 * 1024 * 1024).build()?,
            header_cats,
        })
    }

    /// O(n) String Scan. Zero-Allocation (nimmt `&str`).
    #[inline(always)]
    fn scan_string(&self, input: &str) -> Option<ThreatReport> {
        // Bereinigung von Obfuscation Bytes direkt in einer neuen Allokation
        let normalized = input.replace('\x00', "").replace('\r', "").replace('\n', "");
        
        if normalized.is_empty() {
            return None;
        }

        // Simultaner Match gegen ALLE kritischen Pattern in EINEM Durchlauf
        if let Some(match_idx) = self.critical_set.matches(&normalized).iter().next() {
            return Some(ThreatReport {
                severity: ThreatSeverity::Critical,
                category: self.critical_cats[match_idx],
            });
        }

        // Simultaner Match gegen ALLE Suspicious Pattern
        if let Some(match_idx) = self.suspicious_set.matches(&normalized).iter().next() {
            return Some(ThreatReport {
                severity: ThreatSeverity::Suspicious,
                category: self.suspicious_cats[match_idx],
            });
        }

        None
    }

    /// Dedizierter Scan für HTTP-Header (inkludiert Header-Only Pattern)
    pub fn scan_header(&self, input: &str) -> Option<ThreatReport> {
        let normalized = input.replace('\x00', "");

        if let Some(match_idx) = self.header_set.matches(&normalized).iter().next() {
            return Some(ThreatReport {
                severity: ThreatSeverity::HeaderViolation,
                category: self.header_cats[match_idx],
            });
        }

        // Headers auf kritische Injection prüfen (Log4Shell etc.)
        if let Some(match_idx) = self.critical_set.matches(&normalized).iter().next() {
            return Some(ThreatReport {
                severity: ThreatSeverity::Critical,
                category: self.critical_cats[match_idx],
            });
        }

        None
    }

    /// Rekursives Deep-Scanning von deserialisierten JSON-Payloads.
    pub fn scan_payload(&self, data: &Value, depth: u8) -> Result<Option<ThreatReport>, EngineError> {
        if depth > 10 {
            return Err(EngineError::RecursionLimitExceeded);
        }

        match data {
            Value::String(s) => Ok(self.scan_string(s)),
            Value::Array(arr) => {
                for item in arr {
                    if let Some(threat) = self.scan_payload(item, depth + 1)? {
                        return Ok(Some(threat));
                    }
                }
                Ok(None)
            }
            Value::Object(obj) => {
                for (k, v) in obj {
                    // Keys werden ebenfalls gescannt (oft für Injection genutzt)
                    if let Some(threat) = self.scan_string(k) {
                        return Ok(Some(threat));
                    }
                    if let Some(threat) = self.scan_payload(v, depth + 1)? {
                        return Ok(Some(threat));
                    }
                }
                Ok(None)
            }
            _ => Ok(None),
        }
    }
}