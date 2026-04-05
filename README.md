# ☠️ VGT KillerDom — Apex Threat Annihilation Engine

[![License](https://img.shields.io/badge/License-AGPLv3-green?style=for-the-badge)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.0.0-brightgreen?style=for-the-badge)](#)
[![Python](https://img.shields.io/badge/Python-3.11+-blue?style=for-the-badge&logo=python)](#)
[![PHP](https://img.shields.io/badge/PHP-8.0+-777BB4?style=for-the-badge&logo=php)](#)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go)](#)
[![Rust](https://img.shields.io/badge/Rust-1.75+-orange?style=for-the-badge&logo=rust)](#)
[![Engine](https://img.shields.io/badge/Engine-PCRE2_JIT_%2B_RE2_DFA_%2B_RegexSet_DFA-red?style=for-the-badge)](#)
[![Status](https://img.shields.io/badge/Status-DIAMANT_VGT_SUPREME-gold?style=for-the-badge)](#)
[![VGT](https://img.shields.io/badge/VGT-VisionGaia_Technology-red?style=for-the-badge)](https://visiongaiatechnology.de)

> *"No checkboxes. No cloud. No mercy."*
> *AGPLv3 — For Researchers. For Builders. For the Ruthless.*

---

## 🔍 What is VGT KillerDom?

VGT KillerDom is a **polyglot, production-grade WAF signature library** — battle-hardened regex patterns for neutralizing the most dangerous attack vectors on the modern web, available as a **drop-in middleware** for PHP, Python (FastAPI/Starlette ASGI), Go (net/http) and Rust (Tower/Axum).

This is not a tutorial. This is not a toy. This is a raw research engine born in the **VGT Researchlab** — open-sourced for researchers, engineers, and anyone who wants to build something serious on top of it.

> **⚠️ Important:** KillerDom operates with maximum aggression and zero context-awareness. It is **not suitable for CMS platforms, page builders, or any system that generates complex backend traffic** (WordPress, Laravel, Drupal etc.) — it will break them. KillerDom is designed for **static sites, simple APIs and microservices** where legitimate traffic is fully predictable.

```
Traditional WAF Rules:
→ Vendor black-box
→ Opaque signature updates
→ Cloud dependency
→ No control, no transparency

VGT KillerDom:
→ Full source — every pattern visible and auditable
→ ReDoS-immune via Atomic Groups + Possessive Quantifiers (PHP/Python)
→ O(n) deterministic matching via RE2 DFA (Go)
→ Simultaneous DFA via RegexSet — all patterns in one automaton pass (Rust)
→ Three-tier threat classification (CRITICAL / SUSPICIOUS / HEADER_VIOLATION)
→ Drop-in middleware for PHP, FastAPI, Go net/http, Rust Tower/Axum
→ Zero cloud. Zero callbacks. Zero compromise.
```

---

## ⚔️ Threat Coverage

### TIER 1 — CRITICAL (Absolute Annihilation)

| Vector | Coverage |
|---|---|
| **RCE / SSTI / Deserialization** | PHP function chains, backtick execution, SSTI `{{}}`, Log4Shell `${jndi:}`, Java/Node RCE, PHP object injection `O:N:` |
| **LFI / RFI / Path Traversal** | `../` chains, null-byte injection `%00`, PHP wrappers (`php://filter`, `phar://`), `/etc/passwd`, `/proc/self`, Windows paths |
| **SQLi / NoSQLi** | UNION SELECT, Boolean-Blind, Time-Based (`SLEEP`, `WAITFOR`), Error-Based (`extractvalue`, `updatexml`), MongoDB operators (`$where`, `$ne`, `$regex`) |
| **XSS / DOM Clobbering** | HTML5 vectors, event handlers, `javascript:`, `vbscript:`, JSFuck (`!![]`, `!+[]`), `srcdoc`, `importmap`, `-moz-binding` |
| **XXE / SSRF** | External entity injection, cloud metadata (`169.254.169.254`, `metadata.google.internal`), `gopher://`, `dict://`, AWS env |
| **Infrastructure Probes** | `.env`, `.git`, `wp-config.php`, `.aws/credentials`, `phpunit`, `composer.json`, `.user.ini`, `.svn`, `.htaccess` |

### TIER 2 — SUSPICIOUS (Behavioral Analysis)

| Pattern | Description |
|---|---|
| **Obfuscation** | `base64_decode(eval(...))`, `gzinflate`, `str_rot13`, chained encoding |
| **File Operations** | `fopen`, `file_put_contents`, `unlink`, `chmod`, `chown` in payloads |
| **Global Tampering** | `$_SERVER`, `$_POST`, `$GLOBALS` manipulation attempts |
| **Hex/URL Encoding Chains** | 4+ consecutive `\xNN` or 6+ `%NN` sequences |
| **High Entropy Shells** | 6+ consecutive shell metacharacters `()[]{}\|&;$` |
| **Cryptominer Signatures** | `coinhive`, `cryptonight`, `stratum+tcp`, `monero` |

### TIER 3 — HEADER VIOLATIONS (Scanner & Botnet Catalog)

100+ known malicious User-Agents: `sqlmap`, `nikto`, `wpscan`, `nuclei`, `ffuf`, `gobuster`, `masscan`, `zgrab`, `hydra`, `w3af`, `arachni`, `dirbuster`, `shodan`, `nmap`, `burp`, `acunetix` and many more.

---

## 🏛️ Architecture

```
Incoming Request
       ↓
┌──────────────────────────────┐
│  TIER 3 — HEADER SCAN        │  → User-Agent, custom headers
│  O(1) per header             │
└──────────────┬───────────────┘
               ↓
┌──────────────────────────────┐
│  TIER 1 — URI / QUERY SCAN   │  → Double URL-decoded, null-byte stripped
│  O(1) match per pattern      │
└──────────────┬───────────────┘
               ↓
┌──────────────────────────────┐
│  TIER 1+2 — BODY SCAN        │  → Stream / chunked / JSON recursive
│  2MB hard limit              │  → Deep traversal (max depth: 10)
└──────────────┬───────────────┘
               ↓
          ANNIHILATE (403) or PASS
```

---

## 🔐 ReDoS Immunity

KillerDom is built from the ground up to be immune to **Regular Expression Denial of Service (ReDoS)** attacks — the class of vulnerability where a crafted payload causes catastrophic backtracking in a regex engine, consuming 100% CPU.

**PHP / Python:** Atomic groups `(?>...)` and possessive quantifiers `*+`, `++` physically prevent the regex engine from backtracking. There is no input that can cause exponential execution time.

**Go:** The RE2 engine used natively by Go's `regexp` package operates as a deterministic finite automaton (DFA). Backtracking is architecturally impossible — `O(n)` time guaranteed by the engine itself.

**Rust:** Uses `RegexSet` from the `regex` crate — all patterns are merged into a **single simultaneous DFA**. Instead of matching each pattern sequentially, all signatures are evaluated in one pass over the input. This is the most efficient implementation of the four — `O(n)` over the input regardless of how many patterns exist, with zero backtracking by design (the `regex` crate explicitly forbids lookahead and backreferences to guarantee linear time).

```
Standard Regex:   Worst-case O(2^n) — exploitable
KillerDom PHP:    Atomic Groups + Possessives → O(1) per vector
KillerDom Go:     RE2 DFA → O(n) guaranteed
KillerDom Rust:   RegexSet simultaneous DFA → O(n), all patterns in one pass
```

---

## 🚀 Quick Start

**Source Files:**
| Language | File |
|---|---|
| **PHP** | [killerdomphp.php](https://github.com/visiongaiatechnology/killerdom/blob/main/killerdomphp.php) |
| **Python** | [killerdompython.py](https://github.com/visiongaiatechnology/killerdom/blob/main/killerdompython.py) |
| **Go** | [killerdomgo.go](https://github.com/visiongaiatechnology/killerdom/blob/main/killerdomgo.go) |
| **Rust** | [killerdomrust.rs](https://github.com/visiongaiatechnology/killerdom/blob/main/killerdomrust.rs) |

### PHP (Standalone)

```php
use VGT\Security\Core\VgtKillerDomEngine;

$engine = new VgtKillerDomEngine();

// Scan all POST parameters
$threat = $engine->scanPayload($_POST);
if ($threat !== null) {
    http_response_code(403);
    die('VGT DOM SECURE: ANOMALY DETECTED.');
}

// Scan User-Agent
$threat = $engine->scanHeader($_SERVER['HTTP_USER_AGENT'] ?? '');
if ($threat !== null) {
    http_response_code(403);
    die('VGT DOM SECURE: HEADER VIOLATION.');
}
```

**Requirements:** PHP 8.0+ · PCRE2 with JIT (standard on most hosts) · `declare(strict_types=1)`

> **PHP 7.4 Note:** Atomic groups `(?>)` and possessive quantifiers require PCRE2 (bundled since PHP 7.3). Verify with `phpinfo()` that PCRE2 JIT is active for full ReDoS immunity.

---

### Python (FastAPI / Starlette ASGI)

```python
from fastapi import FastAPI
from vgt_killerdom import VGTKillerDomMiddleware

app = FastAPI()
app.add_middleware(VGTKillerDomMiddleware)

@app.get("/")
async def root():
    return {"status": "protected"}
```

**Requirements:** Python 3.11+ · `starlette` · `fastapi` (optional)

> **Why 3.11+?** Python's `re` module added native support for atomic grouping `(?>)` and possessive quantifiers in 3.11. Earlier versions fall back to standard backtracking — functional but not ReDoS-immune.

---

### Go (net/http Middleware)

```go
package main

import (
    "net/http"
    vgtsecurity "github.com/visiongaiatechnology/killerdom"
)

func main() {
    engine := vgtsecurity.NewKillerDomEngine()

    mux := http.NewServeMux()
    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("protected"))
    })

    http.ListenAndServe(":8080", engine.Middleware(mux))
}
```

**Requirements:** Go 1.21+ · Zero external dependencies

---

### Rust (Tower / Axum)

```rust
use killerdom::ENGINE;

// Scan a request body (as JSON Value)
if let Ok(Some(threat)) = ENGINE.scan_payload(&json_value, 0) {
    return StatusCode::FORBIDDEN;
}

// Scan a header value
if let Some(threat) = ENGINE.scan_header(user_agent) {
    return StatusCode::FORBIDDEN;
}
```

**Dependencies (`Cargo.toml`):**
```toml
[package]
name = "vgt-killerdom"
version = "1.0.0"
edition = "2021"
authors = ["VisionGaia Technology"]
description = "VGT KillerDom - Apex Threat Annihilation Engine (DFA RegexSet Core)"
repository = "https://github.com/visiongaiatechnology/killerdom"
license = "AGPL-3.0"

[dependencies]
# RE2-kompatible DFA Engine. Garantiert O(n) Ausführungszeit. Keinerlei Backtracking.
regex = "1.10"
# Lazy Initialization für Zero-Overhead nach dem Bootvorgang.
once_cell = "1.19"
# High-Performance JSON Traversal.
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
# Eliminierung von panics durch striktes Error Handling.
thiserror = "1.0"

[profile.release]
opt-level = 3
lto = true
codegen-units = 1
panic = "abort" # Reduziert Binary-Größe und Overhead. Panics sind Systemfehler.
strip = true
```

**Requirements:** Rust 1.75+ · `#![forbid(unsafe_code)]`

> **Why `RegexSet`?** Instead of iterating patterns sequentially, Rust's `RegexSet` compiles all signatures into a **single simultaneous DFA**. The engine scans the input exactly once regardless of how many patterns are active. This is the highest-throughput implementation in the KillerDom suite.

---

## 📊 Three-Tier Response Matrix

| Tier | Severity | Trigger | HTTP Response |
|---|---|---|---|
| **1** | `CRITICAL` | RCE, SQLi, LFI, XSS, XXE, SSRF | `403 Forbidden` + Connection Close |
| **2** | `SUSPICIOUS` | Obfuscation, file ops, high entropy | `403 Forbidden` |
| **3** | `HEADER_VIOLATION` | Malicious UA, scanner fingerprint | `403 Forbidden` |
| **–** | `CRITICAL_HEADER_INJECTION` | Log4Shell / injection via headers | `403 Forbidden` |

---

## 🧪 For Researchers

KillerDom is intentionally **fully transparent**. Every signature is readable, auditable, and forkable. This is by design.

**What you can do with this:**
- Fork and extend the signature catalog for your own WAF
- Port to other languages (Java, C#, Ruby — PRs welcome)
- Use as a benchmark baseline for WAF evasion research
- Integrate into SIEM pipelines for threat classification
- Build your own middleware stack on top of the engine

**Tested against:**
- OWASP Core Rule Set (CRS) evasion techniques
- PayloadsAllTheThings catalog
- HackTricks bypass techniques
- Real-world attack log analysis

---

## ⚙️ Performance Notes

| Implementation | Match Strategy | Worst-Case Complexity |
|---|---|---|
| **PHP** | PCRE2 JIT + Atomic Groups | O(1) per vector |
| **Python** | CPython re + Atomic Groups (3.11+) | O(1) per vector |
| **Go** | RE2 DFA (native) | O(n) guaranteed |
| **Rust** | `RegexSet` simultaneous DFA (`once_cell` static) | O(n), all patterns — one pass |

All implementations pre-compile patterns at initialization. Runtime cost is pure matching — zero recompilation per request.

---

## 🔗 VGT Ecosystem

| Tool | Type | Purpose |
|---|---|---|
| ☠️ **VGT KillerDom** | **WAF Research Engine** | Polyglot regex annihilation core — you are here |
| ⚔️ **[VGT Sentinel](https://github.com/visiongaiatechnology/vgt-sentinel)** | **WAF / IDS Framework** | Zero-Trust WordPress security suite |
| 🛡️ **[VGT Myrmidon](https://github.com/visiongaiatechnology/vgtmyrmidon)** | **ZTNA** | Zero Trust device registry and cryptographic integrity verification |
| ⚡ **[VGT Auto-Punisher](https://github.com/visiongaiatechnology/vgt-auto-punisher)** | **IDS** | L4+L7 Hybrid IDS — attackers terminated before they even knock |
| 🌐 **[VGT Global Threat Sync](https://github.com/visiongaiatechnology/vgt-global-threat-sync)** | **Preventive** | Daily threat feed — block known attackers before they arrive |
| 🔥 **[VGT Windows Firewall Burner](https://github.com/visiongaiatechnology/vgt-windows-burner)** | **Windows** | 280,000+ APT IPs in native Windows Firewall |

---

## 💰 Support the Project

[![Donate via PayPal](https://img.shields.io/badge/Donate-PayPal-00457C?style=for-the-badge&logo=paypal)](https://www.paypal.com/paypalme/dergoldenelotus)

| Method | Address |
|---|---|
| **PayPal** | [paypal.me/dergoldenelotus](https://www.paypal.com/paypalme/dergoldenelotus) |
| **Bitcoin** | `bc1q3ue5gq822tddmkdrek79adlkm36fatat3lz0dm` |
| **ETH** | `0xD37DEfb09e07bD775EaaE9ccDaFE3a5b2348Fe85` |
| **USDT (ERC-20)** | `0xD37DEfb09e07bD775EaaE9ccDaFE3a5b2348Fe85` |

---

## ⚠️ Disclaimer

VGT KillerDom is a **defensive security tool** published for research and educational purposes. The signatures contained herein are designed to detect and block known attack patterns. Use responsibly and only on systems you own or have explicit authorization to protect.

---

## 🤝 Contributing

Found a bypass? Have a new vector? PRs are welcome — open an issue first for major signature changes.

Licensed under **AGPLv3** — *"For Researchers. For Builders. For the Ruthless."*

---

## 🏢 Built by VisionGaia Technology

[![VGT](https://img.shields.io/badge/VGT-VisionGaia_Technology-red?style=for-the-badge)](https://visiongaiatechnology.de)

VisionGaia Technology builds enterprise-grade security infrastructure — engineered to the DIAMANT VGT SUPREME standard.

> *"KillerDom was born in the VGT Researchlab as a pure experiment — how aggressive can a WAF signature set get before it becomes unusable? The answer is: very. Use it as a foundation, not as a drop-in."*

---

*Version 1.0.0 — VGT KillerDom // Apex Threat Annihilation Engine // PHP + Python + Go + Rust // AGPLv3*
