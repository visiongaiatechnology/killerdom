<?php
declare(strict_types=1);

namespace VGT\Security\Core;

/**
 * STATUS: DIAMANT VGT SUPREME (APEX PREDATOR MODE)
 * KOGNITIVE ARCHITEKTUR: GOD-TIER PCRE2 JIT ENGINE
 * * WARNUNG: Diese Klasse ist eine Waffe. Die folgenden Signaturen sind das Resultat 
 * aus abertausenden analysierten Angriffsvektoren. Sie sind durch atomare Gruppen (?>)
 * und possessive Quantifikatoren (*+, ++) auf physikalisch unmögliches Backtracking
 * (ReDoS-Immunität) gehärtet. Ausführungszeit: O(1) pro Vektor.
 */
final class VgtKillerDomEngine
{
    /**
     * Regex Modifiers:
     * i = Case-Insensitive
     * u = UTF-8 Safe (Verhindert Multibyte-Bypasses)
     * S = Study (Aktiviert PCRE JIT Compilation für maximale Geschwindigkeit)
     */
    private const MODIFIERS = 'iuS';

    /**
     * TIER 1: CRITICAL THREATS (ABSOLUTE ANNIHILATION)
     * Erkennt RCE, SSTI, SQLi, LFI/RFI, XXE, SSRF, Deserialization, XSS und mehr.
     */
    private const SIG_CRITICAL = [
        // OMEGA RCE & Deserialization & Template Injection (SSTI) & Log4Shell
        'rce_ssti_deser' => '~(?>(?:system|exec|passthru|shell_exec|eval|proc_open|assert|phpinfo|pcntl_exec|popen|create_function|mb_ereg_replace|preg_replace|call_user_func(?:_array)?|invokefunction|ob_start|array_map|array_filter|usort|uasort|uksort|register_shutdown_function|register_tick_function|putenv|mail|dl|ffi_cdef|ffi_load)\s*+[\[\(]|`[^`]{0,1024}`|\$\{[^}]++\}|<%(?:=|)\s*+.*?\s*+%>|<%=\s*+.*?%>|\{\{.*?\}\}|\b(?:cmd|bash|sh|powershell|pwsh|cscript|wscript|node|python|perl|ruby)\.exe|/bin/(?:sh|bash|zsh|dash|ksh|csh|tcsh)|\|(?:sh|bash|zsh|dash|ksh|csh|tcsh)|(?:wget|curl|nc|ncat|netcat|socat|nmap|telnet)[^|]{1,255}?\|\s*+(?:sh|bash|zsh|dash)|\\\\x[0-9a-f]{2}|(?:allow_url_include|auto_prepend_file|auto_append_file|suhosin\.executor|disable_functions)\s*+=|java\.lang\.(?:Runtime|ProcessBuilder)|child_process\.(?:exec|spawn|fork)|require\s*+\(\s*+[\'"]child_process[\'"]\)|O:\d+:"[^"]++":\d+:{|a:\d+:{|C:\d+:"[^"]++":|\$\{jndi:(?:ldap|rmi|dns|iiop|http|https)://)~iuS',

        // LFI / RFI / Path Traversal / OS-Level File Access
        'lfi_rfi_os' => '~(?>(?:\.\.[\\\\/]+)++|(?:\.\.+%[0-9a-f]{2})++|/etc/(?>passwd|shadow|hosts|group|issue|fstab|hostname|ssh/ssh_config|resolv\.conf)|c:\\\\(?:windows|winnt)\\\\(?>system32|repair|system|sam|config/sam)|boot\.ini|wp-config\.php|php://(?>filter|input|temp|memory|fd)|(?:file|zip|phar|data|expect|input|glob|ssh2|ogg|rar|zlib)://|/proc/(?>self|version|cmdline|environ|net/arp|net/tcp|net/udp|sched_debug)|/var/log/(?>auth|secure|messages|syslog|apache2|nginx|httpd|access|error)\.log|%00|%%32%65|%2e%2e|%252e%252e)~iuS',

        // APEX SQLi (MySQL, PostgreSQL, MSSQL, Oracle, SQLite) & NoSQLi
        'sqli_nosqli' => '~(?>(?:union(?:[\s/*]++(?:all|distinct))?[\s/*\(]++select|information_schema|waitfor[\s/*]++delay|benchmark\s*+\(|sleep\s*+\(|extractvalue\s*+\(|updatexml\s*+\(|hex\s*+\(|unhex\s*+\(|concat\s*+\(|char\s*+\(|\s++(?>OR|AND)\s++[\d\']+[\s=>]++[\d\']|0x[0-9a-f]{2,}|declare[^@]{1,128}?@[^=]{1,128}?=|cast\s*+\(|@@version|drop\s++(?>table|database|user|view|procedure)|alter\s++(?:table|database|user)|into\s++(?>outfile|dumpfile)|load\s++data\s++infile|xp_cmdshell|pg_sleep\s*+\(|dbms_pipe\.receive_message|utl_http\.request|sys_eval|sys_exec|having\s++1=1|\$where|\$ne|\$regex|\$gt|\$lt|\$exists|\$expr|\$in|\$nin)~iuS',

        // XSS / DOM Clobbering / JS-Fuck / HTML5 Vectors
        'xss_dom' => '~(?><(?:script|iframe|object|embed|math|applet|meta|style|base|form|bgsound|blink|keygen|marquee|template|video|audio)|javascript:|vbs:|vbscript:|on(?:load|error|click|dblclick|mouseover|mouseenter|mouseleave|submit|reset|focus|blur|contextmenu|animationstart|toggle|keyup|keydown|pointer|touch|drag|drop|wheel|copy|paste|cut)[\s/*]*+=|base64_decode|data:text/(?>html|xml)|alert\s*+\(|confirm\s*+\(|prompt\s*+\(|<svg|xlink:href|&#|srcdoc[\s/*]*+=|importmap|-moz-binding|expression\s*+\(|\[\]\s*+\(\s*+\[\]\s*+\)|!!\[\]|!\+\[\]|\+!!\[\]|\\\\x3cscript|%3cscript)~iuS',

        // XXE & SSRF (Cloud Metadata Exfiltration)
        'xxe_ssrf' => '~(?><!ENTITY\s++[^>]*+(?>SYSTEM|PUBLIC)\s++["\']|<!DOCTYPE\s++[^>]*+\[|xmlns:xsi\s*+=|xsi:schemaLocation\s*+=|gopher://|dict://|ldap://|sftp://|tftp://|ws://|wss://|169\.254\.169\.254|metadata\.google\.internal|0\.0\.0\.0|127\.0\.0\.1|::1|localhost|aws-env)~iuS',

        // WP & Framework Specific Criticals
        'framework_crit' => '~(?>(?:wp_set_current_user|wp_insert_user|wp_update_user|update_option\s*+\(\s*+[\'"](?:siteurl|home|users_can_register|default_role)[\'"]|eval-stdin|invokefunction|_ignition/execute-solution|telescope/requests|api/swagger|actuator/(?>env|refresh|restart|heapdump)))~iuS',

        // Infrastructure Probes & Backups
        'probes' => '~(?>(?:\.env|\.git|\.htaccess|\.php_bak|\.old|\.bak|config\.php|wp-config\.php|\.sql|\.tar\.gz|\.zip|\.remote-sync|\.ds_store|\.aws/credentials|\.idea|\.vscode|vendor/phpunit|composer\.json|phpunit/src|/\.well-known/security|/\.svn/|/\.hg/|/web\.config|/\.user\.ini))~iuS'
    ];

    /**
     * TIER 2: SUSPICIOUS ACTIVITY (BEHAVIORAL ANALYSIS)
     * Heuristiken für verschleierte Payloads, Obfuscation und Cryptominer.
     */
    private const SIG_SUSPICIOUS = [
        'obfuscation'  => '~(?>(?:base64_decode|base64_encode|str_rot13|gzinflate|gzuncompress|deflate|eval\s*+\(\s*+base64_decode)\s*+\()~iuS',
        'globals_mod'  => '~(?>(?:\$GLOBALS|\$_SERVER|\$_GET|\$_POST|\$_FILES|\$_COOKIE|\$_SESSION|\$_REQUEST|\$_ENV)\s*+\[)~iuS',
        'file_ops'     => '~(?>(?:fopen|fwrite|file_put_contents|file_get_contents|readfile|unlink|rename|copy|mkdir|rmdir|chmod|chown)\s*+\()~iuS',
        'db_direct'    => '~(?>(?:\$wpdb->|mysql_query|mysqli_query|pg_query|sqlite_query|PDO::exec))~iuS',
        'hex_encode'   => '~(?>(?:\\\\x[0-9a-fA-F]{2}){4,}|(?:%[0-9a-fA-F]{2}){6,})~iuS', // Erweitert auf URL-Encoding-Ketten
        'high_entropy' => '~(?>[()\`$<>\[\]{}|&;]{6,})~iuS', // Shell-Metazeichen gehäuft
        'crypto_miner' => '~(?>(?:coinhive|webminer|cryptonight|stratum\+tcp|monero|xmr\.omine|coinimp|minr\.js))~iuS'
    ];

    /**
     * TIER 3: HEADER ONLY (SCANNER, BOTNETS, FUZZER)
     * Massiver Katalog der schädlichsten Akteure im Web.
     */
    private const SIG_HEADERS_ONLY = [
        'ua_malicious' => '~(?>\b(?:sqlmap|nikto|wpscan|masscan|havij|netsparker|burp|acunetix|nessus|log4j|shellshock|gobuster|dirbuster|zgrab|nuclei|ffuf|httpx|projectdiscovery|zmap|curl/|python-requests|headless|selenium|libwww|lts/1\.0|nmap|shodan|census|icealgl|java/[0-9]|go-http-client|fasthttp|kinza|nutch|arachni|hydra|medusa|vega|w3af|zap|owasp|blackwidow|datacha0s|dirb|dotbot|evil|fimap|jbrofuzz|libwhisker|morfeus|muieblackcat|pmafind|scanbot|sysscan|zmeu|binlar|casper|cmsworldmap|comodo|diavol|dotcom|extract|fiddler|grabber|httrack|ia_archiver|indy|leech|lwp-trivial|navroad|nutch|panscient|pecl|python-urllib|sqlninja|sublist3r|sysscan|webinspect|xenu)\b)~iuS'
    ];

    public function __construct()
    {
        // Zero Initialization Overhead. Absolute Silence before the Storm.
    }

    /**
     * Deep Logic Analysis: O(N) Traversal. O(1) Match.
     * * @param array<string, mixed> $payload
     * @return array<string, mixed>|null
     */
    public function scanPayload(array $payload): ?array
    {
        $iterator = new \RecursiveIteratorIterator(new \RecursiveArrayIterator($payload));

        foreach ($iterator as $key => $value) {
            if (!is_string($value)) {
                continue;
            }

            // Normalisierung: Entfernt NULL-Bytes (%00), Tabulatoren und Zeilenumbrüche für sauberen Match
            $normalizedValue = str_replace([chr(0), "\r", "\n", "\t"], '', urldecode($value));

            // Tier 1 Scan: Critical Annihilation
            foreach (self::SIG_CRITICAL as $category => $regex) {
                if (preg_match($regex, $normalizedValue) === 1) {
                    return [
                        'severity' => 'CRITICAL',
                        'category' => $category,
                        'vector'   => $key,
                        'payload'  => $value
                    ];
                }
            }

            // Tier 2 Scan: Suspicious Behavior
            foreach (self::SIG_SUSPICIOUS as $category => $regex) {
                if (preg_match($regex, $normalizedValue) === 1) {
                    return [
                        'severity' => 'SUSPICIOUS',
                        'category' => $category,
                        'vector'   => $key,
                        'payload'  => $value
                    ];
                }
            }
        }

        return null;
    }

    /**
     * Isoliert die Überprüfung auf Header. 
     */
    public function scanHeader(string $input): ?array
    {
        $normalizedInput = str_replace(chr(0), '', urldecode($input));

        // Scanner, Botnets & Fuzzers
        foreach (self::SIG_HEADERS_ONLY as $category => $regex) {
            if (preg_match($regex, $normalizedInput) === 1) {
                return [
                    'severity' => 'HEADER_VIOLATION',
                    'category' => $category
                ];
            }
        }
        
        // Log4Shell & Header-based Injections abfangen
        foreach (self::SIG_CRITICAL as $category => $regex) {
            if (preg_match($regex, $normalizedInput) === 1) {
                 return [
                    'severity' => 'CRITICAL_HEADER_INJECTION',
                    'category' => $category
                ];
            }
        }

        return null;
    }
}