# -*- coding: utf-8 -*-
"""
STATUS: DIAMANT VGT SUPREME
KOGNITIVE ARCHITEKTUR: ASYNC ASGI WAF MIDDLEWARE & PRE-COMPILED PCRE ENGINE
WARNUNG: Dieses Modul erfordert zwingend Python 3.11+ für native Atomic Grouping (?>)
und possessive Quantifikatoren (*+). Es agiert als absoluter Gatekeeper.
"""

import re
import sys
import json
from typing import Any, Dict, List, Optional, Union
from urllib.parse import unquote

# VGT Systemintegritäts-Prüfung
if sys.version_info < (3, 11):
    raise RuntimeError("VGT KILLER DOM erfordert Python 3.11+ für ReDoS-Immunität (Atomic Groups). System halt.")

class VGTKillerDomEngine:
    """
    Core Threat Annihilation Engine.
    Zustandslos, Thread-safe und pre-compiled für maximalen Durchsatz.
    """

    # TIER 1: CRITICAL THREATS (Absolute Annihilation)
    SIG_CRITICAL: Dict[str, str] = {
        'rce_ssti_deser': r"(?>(?:system|exec|passthru|shell_exec|eval|proc_open|assert|phpinfo|pcntl_exec|popen|create_function|mb_ereg_replace|preg_replace|call_user_func(?:_array)?|invokefunction|ob_start|array_map|array_filter|usort|uasort|uksort|register_shutdown_function|register_tick_function|putenv|mail|dl|ffi_cdef|ffi_load)\s*+[\[\(]|`[^`]{0,1024}`|\$\{[^}]++\}|<%(?:=|)\s*+.*?\s*+%>|<%=\s*+.*?%>|\{\{.*?\}\}|\b(?:cmd|bash|sh|powershell|pwsh|cscript|wscript|node|python|perl|ruby)\.exe|/bin/(?:sh|bash|zsh|dash|ksh|csh|tcsh)|\|(?:sh|bash|zsh|dash|ksh|csh|tcsh)|(?:wget|curl|nc|ncat|netcat|socat|nmap|telnet)[^|]{1,255}?\|\s*+(?:sh|bash|zsh|dash)|\\\\x[0-9a-f]{2}|(?:allow_url_include|auto_prepend_file|auto_append_file|suhosin\.executor|disable_functions)\s*+=|java\.lang\.(?:Runtime|ProcessBuilder)|child_process\.(?:exec|spawn|fork)|require\s*+\(\s*+['\"]child_process['\"]\)|O:\d+:\"[^\"]++\":\d+:{|a:\d+:{|C:\d+:\"[^\"]++\":|\$\{jndi:(?:ldap|rmi|dns|iiop|http|https)://)",
        'lfi_rfi_os': r"(?>(?:\.\.[\\/]+)++|(?:\.\.+%[0-9a-f]{2})++|/etc/(?>passwd|shadow|hosts|group|issue|fstab|hostname|ssh/ssh_config|resolv\.conf)|c:\\(?:windows|winnt)\\(?>system32|repair|system|sam|config/sam)|boot\.ini|wp-config\.php|php://(?>filter|input|temp|memory|fd)|(?:file|zip|phar|data|expect|input|glob|ssh2|ogg|rar|zlib)://|/proc/(?>self|version|cmdline|environ|net/arp|net/tcp|net/udp|sched_debug)|/var/log/(?>auth|secure|messages|syslog|apache2|nginx|httpd|access|error)\.log|%00|%%32%65|%2e%2e|%252e%252e)",
        'sqli_nosqli': r"(?>(?:union(?:[\s/*]++(?:all|distinct))?[\s/*\(]++select|information_schema|waitfor[\s/*]++delay|benchmark\s*+\(|sleep\s*+\(|extractvalue\s*+\(|updatexml\s*+\(|hex\s*+\(|unhex\s*+\(|concat\s*+\(|char\s*+\(|\s++(?>OR|AND)\s++[\d']+[\s=>]++[\d']|0x[0-9a-f]{2,}|declare[^@]{1,128}?@[^=]{1,128}?=|cast\s*+\(|@@version|drop\s++(?>table|database|user|view|procedure)|alter\s++(?:table|database|user)|into\s++(?>outfile|dumpfile)|load\s++data\s++infile|xp_cmdshell|pg_sleep\s*+\(|dbms_pipe\.receive_message|utl_http\.request|sys_eval|sys_exec|having\s++1=1|\$where|\$ne|\$regex|\$gt|\$lt|\$exists|\$expr|\$in|\$nin)",
        'xss_dom': r"(?><(?:script|iframe|object|embed|math|applet|meta|style|base|form|bgsound|blink|keygen|marquee|template|video|audio)|javascript:|vbs:|vbscript:|on(?:load|error|click|dblclick|mouseover|mouseenter|mouseleave|submit|reset|focus|blur|contextmenu|animationstart|toggle|keyup|keydown|pointer|touch|drag|drop|wheel|copy|paste|cut)[\s/*]*+=|base64_decode|data:text/(?>html|xml)|alert\s*+\(|confirm\s*+\(|prompt\s*+\(|<svg|xlink:href|&#|srcdoc[\s/*]*+=|importmap|-moz-binding|expression\s*+\(|\[\]\s*+\(\s*+\[\]\s*+\)|!!\[\]|!\+\[\]|\+!!\[\]|\\\\x3cscript|%3cscript)",
        'xxe_ssrf': r"(?><!ENTITY\s++[^>]*+(?>SYSTEM|PUBLIC)\s++[\"']|<!DOCTYPE\s++[^>]*+\[|xmlns:xsi\s*+=|xsi:schemaLocation\s*+=|gopher://|dict://|ldap://|sftp://|tftp://|ws://|wss://|169\.254\.169\.254|metadata\.google\.internal|0\.0\.0\.0|127\.0\.0\.1|::1|localhost|aws-env)",
        'probes': r"(?>(?:\.env|\.git|\.htaccess|\.php_bak|\.old|\.bak|config\.php|wp-config\.php|\.sql|\.tar\.gz|\.zip|\.remote-sync|\.ds_store|\.aws/credentials|\.idea|\.vscode|vendor/phpunit|composer\.json|phpunit/src|/\.well-known/security|/\.svn/|/\.hg/|/web\.config|/\.user\.ini))"
    }

    # TIER 2: SUSPICIOUS ACTIVITY
    SIG_SUSPICIOUS: Dict[str, str] = {
        'obfuscation': r"(?>(?:base64_decode|base64_encode|str_rot13|gzinflate|gzuncompress|deflate|eval\s*+\(\s*+base64_decode)\s*+\()",
        'file_ops': r"(?>(?:fopen|fwrite|file_put_contents|file_get_contents|readfile|unlink|rename|copy|mkdir|rmdir|chmod|chown)\s*+\()",
        'hex_encode': r"(?>(?:\\\\x[0-9a-fA-F]{2}){4,}|(?:%[0-9a-fA-F]{2}){6,})",
        'high_entropy': r"(?>[()\`$<>\[\]{}|&;]{6,})",
        'crypto_miner': r"(?>(?:coinhive|webminer|cryptonight|stratum\+tcp|monero|xmr\.omine|coinimp|minr\.js))"
    }

    # TIER 3: HEADER ONLY
    SIG_HEADERS_ONLY: Dict[str, str] = {
        'ua_malicious': r"(?>\b(?:sqlmap|nikto|wpscan|masscan|havij|netsparker|burp|acunetix|nessus|log4j|shellshock|gobuster|dirbuster|zgrab|nuclei|ffuf|httpx|projectdiscovery|zmap|curl/|python-requests|headless|selenium|libwww|lts/1\.0|nmap|shodan|census|icealgl|java/[0-9]|go-http-client|fasthttp|kinza|nutch|arachni|hydra|medusa|vega|w3af|zap|owasp|blackwidow|datacha0s|dirb|dotbot|evil|fimap|jbrofuzz|libwhisker|morfeus|muieblackcat|pmafind|scanbot|sysscan|zmeu|binlar|casper|cmsworldmap|comodo|diavol|dotcom|extract|fiddler|grabber|httrack|ia_archiver|indy|leech|lwp-trivial|navroad|nutch|panscient|pecl|python-urllib|sqlninja|sublist3r|sysscan|webinspect|xenu)\b)"
    }

    def __init__(self) -> None:
        """
        Kompiliert alle Pattern in den C-Core von Python für O(1) Match-Performance.
        """
        flags = re.IGNORECASE
        self._compiled_critical = {k: re.compile(v, flags) for k, v in self.SIG_CRITICAL.items()}
        self._compiled_suspicious = {k: re.compile(v, flags) for k, v in self.SIG_SUSPICIOUS.items()}
        self._compiled_headers = {k: re.compile(v, flags) for k, v in self.SIG_HEADERS_ONLY.items()}
        
        # Security Guardrail: Verhindert StackOverflow bei tiefem JSON
        self.MAX_RECURSION_DEPTH = 10

    def scan_payload(self, data: Union[Dict, List, str], current_depth: int = 0) -> Optional[Dict[str, str]]:
        """
        Rekursive Deep-Logic-Analyse für JSON-Bodys, Form-Daten oder Query-Parameter.
        """
        if current_depth > self.MAX_RECURSION_DEPTH:
            return {'severity': 'SUSPICIOUS', 'category': 'payload_too_deep', 'payload': 'DEPTH_LIMIT_EXCEEDED'}

        if isinstance(data, dict):
            for key, value in data.items():
                result = self.scan_payload(value, current_depth + 1)
                if result:
                    result['vector'] = f"{key} -> {result.get('vector', '')}"
                    return result
        elif isinstance(data, list):
            for idx, item in enumerate(data):
                result = self.scan_payload(item, current_depth + 1)
                if result:
                    result['vector'] = f"[{idx}] -> {result.get('vector', '')}"
                    return result
        elif isinstance(data, str):
            return self._analyze_string(data)
            
        return None

    def _analyze_string(self, value: str) -> Optional[Dict[str, str]]:
        """
        Normalisiert und prüft einen einzelnen String gegen die vorkompilierten Pattern.
        """
        # Normalisierung: Null-Bytes entfernen, URL-Decoding
        normalized = unquote(value).replace('\x00', '').replace('\r', '').replace('\n', '').replace('\t', '')
        
        if not normalized:
            return None

        # TIER 1 Scan
        for category, pattern in self._compiled_critical.items():
            if pattern.search(normalized):
                return {
                    'severity': 'CRITICAL',
                    'category': category,
                    'payload': value[:100] # Log-Limitierung zum Schutz vor Log-Forging
                }

        # TIER 2 Scan
        for category, pattern in self._compiled_suspicious.items():
            if pattern.search(normalized):
                return {
                    'severity': 'SUSPICIOUS',
                    'category': category,
                    'payload': value[:100]
                }

        return None

    def scan_header(self, value: str) -> Optional[Dict[str, str]]:
        """
        Isolierte Header-Überprüfung (z.B. User-Agent).
        """
        normalized = unquote(value).replace('\x00', '')
        
        for category, pattern in self._compiled_headers.items():
            if pattern.search(normalized):
                return {'severity': 'HEADER_VIOLATION', 'category': category}
                
        for category, pattern in self._compiled_critical.items():
            if pattern.search(normalized):
                return {'severity': 'CRITICAL_HEADER_INJECTION', 'category': category}
                
        return None


# ==============================================================================
# FASTAPI / STARLETTE ASGI MIDDLEWARE INTEGRATION (PRODUCTION READY)
# ==============================================================================
from starlette.types import ASGIApp, Receive, Scope, Send
from starlette.requests import Request
from starlette.responses import PlainTextResponse

class VGTKillerDomMiddleware:
    """
    ASGI Middleware, die jeden HTTP Request abfängt, den Body liest (ohne ihn für 
    die nachfolgende Applikation zu konsumieren) und durch die VGT Engine jagt.
    """
    def __init__(self, app: ASGIApp):
        self.app = app
        self.engine = VGTKillerDomEngine()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)
        
        # 1. Header Scan (O(1) pro Header)
        for name, value in request.headers.items():
            threat = self.engine.scan_header(value)
            if threat:
                response = PlainTextResponse("VGT DOM SECURE: ANOMALY DETECTED.", status_code=403)
                await response(scope, receive, send)
                return

        # 2. Query Parameter Scan
        threat = self.engine.scan_payload(dict(request.query_params))
        if threat:
            response = PlainTextResponse("VGT DOM SECURE: PAYLOAD ANOMALY DETECTED.", status_code=403)
            await response(scope, receive, send)
            return

        # 3. Body Scan (Asynchrones Lesen des Streams)
        body = b""
        more_body = True
        
        async def receive_wrapper() -> Dict[str, Any]:
            nonlocal body, more_body
            message = await receive()
            if message.get("type") == "http.request":
                body += message.get("body", b"")
                more_body = message.get("more_body", False)
            return message

        # Wir lesen den gesamten Request in den Speicher (Schutz vor riesigen Bodys hier relevant)
        while more_body:
            await receive_wrapper()
            if len(body) > 2_000_000: # 2MB Hard Limit gegen DoS
                response = PlainTextResponse("VGT DOM SECURE: PAYLOAD TOO LARGE.", status_code=413)
                await response(scope, receive, send)
                return

        if body:
            try:
                # Versuch JSON zu parsen, andernfalls als Raw String behandeln
                try:
                    payload_data = json.loads(body.decode('utf-8'))
                except json.JSONDecodeError:
                    payload_data = body.decode('utf-8')
                    
                threat = self.engine.scan_payload(payload_data)
                if threat:
                    response = PlainTextResponse("VGT DOM SECURE: CRITICAL INJECTION DETECTED.", status_code=403)
                    await response(scope, receive, send)
                    return
            except UnicodeDecodeError:
                response = PlainTextResponse("VGT DOM SECURE: MALFORMED ENCODING.", status_code=400)
                await response(scope, receive, send)
                return

        # Body für die eigentliche Applikation wiederherstellen
        async def receive_injected() -> Dict[str, Any]:
            return {"type": "http.request", "body": body, "more_body": False}

        await self.app(scope, receive_injected, send)