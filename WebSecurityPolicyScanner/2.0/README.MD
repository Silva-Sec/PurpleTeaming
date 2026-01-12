# Web Security Policy Scanner 2.0 🛡️

A comprehensive command-line Python tool to scan websites for security misconfigurations in HTTP headers, SSL/TLS certificates, and cookie attributes.

Designed to help developers, security professionals, and system administrators quickly verify that security best practices are correctly implemented across multiple domains.

## What's New in v2.0 🚀

- **Security Score**: Get an A-F grade with percentage for each scanned URL
- **TLS Protocol Analysis**: Detects insecure TLS 1.0/1.1 and verifies modern TLS usage
- **Deep CSP Analysis**: Checks for `default-src`, `frame-ancestors`, nonces/hashes, and dangerous sources
- **Enhanced HSTS Validation**: Verifies `max-age` value meets the 1-year recommendation
- **Cookie SameSite Attribute**: Now checks for CSRF protection via `SameSite`
- **Modern Security Headers**: Added checks for COOP, CORP, COEP, Referrer-Policy, and more
- **Structured Reports**: Clear summary of issues to fix and warnings to review

---

## Features ✨

### Connection & TLS Security
| Check | Description |
|-------|-------------|
| ✅ HTTP → HTTPS Redirect | Verifies automatic redirection with proper status codes (301 preferred) |
| ✅ TLS Version | Detects insecure TLS 1.0/1.1 and confirms TLS 1.2/1.3 usage |
| ✅ SSL Certificate | Validates hostname match, expiration, and 398-day validity limit |
| ✅ HSTS Preload | Checks domain status on the official HSTS preload list |

### Security Headers
| Header | Validations |
|--------|-------------|
| ✅ Content-Security-Policy | Presence, `default-src`, `unsafe-inline`, `unsafe-eval`, `frame-ancestors`, dangerous sources (`data:`, `blob:`), nonce/hash usage, reporting |
| ✅ Strict-Transport-Security | Presence, `max-age` ≥ 1 year, `includeSubDomains`, `preload` directive |
| ✅ X-Content-Type-Options | Must be `nosniff` |
| ✅ X-Frame-Options | Must be `DENY` or `SAMEORIGIN` |
| ✅ Referrer-Policy | Checks for secure policy values |
| ✅ Permissions-Policy | Verifies browser feature restrictions |
| ✅ Cross-Origin-Opener-Policy | COOP header presence and value |
| ✅ Cross-Origin-Resource-Policy | CORP header presence |
| ✅ Cross-Origin-Embedder-Policy | COEP header presence |

### Cookie Security
| Attribute | Description |
|-----------|-------------|
| ✅ Secure | Cookie only sent over HTTPS |
| ✅ HttpOnly | Cookie inaccessible to JavaScript |
| ✅ SameSite | CSRF protection (Strict/Lax/None) |

### Information Disclosure
| Check | Description |
|-------|-------------|
| ✅ Server Header | Warns if server version is exposed |
| ✅ X-Powered-By | Fails if technology stack is exposed |

---

## Installation ⚙️

### Prerequisites
- Python 3.8 or higher

### Install Dependencies

```bash
pip install requests
```

Or using requirements file:

```bash
pip install -r requirements.txt
```

---

## Usage 🚀

### Scan a Single URL

```bash
python wsps.py https://example.com
```

### Scan Multiple URLs from File

Create a `urls.txt` file with one domain per line:

```
google.com
github.com
# Comments are supported (lines starting with #)
my-internal-app.dev
```

Run the scanner:

```bash
python wsps.py urls.txt
```

---

## Output Guide 📊

### Status Indicators

| Indicator | Meaning |
|-----------|---------|
| `[PASS]` 🟢 | Security control correctly implemented |
| `[FAIL]` 🔴 | Security control missing or misconfigured |
| `[WARN]` 🟡 | Potential issue or suboptimal configuration |
| `[INFO]` 🔵 | Informational message |

### Security Grades

| Grade | Score | Meaning |
|-------|-------|---------|
| **A** | 90-100% | Excellent security posture |
| **B** | 80-89% | Good, minor improvements needed |
| **C** | 70-79% | Fair, several issues to address |
| **D** | 60-69% | Poor, significant gaps |
| **F** | < 60% | Critical security issues |

---

## Example Output

```
============================================================
Scanning: github.com
============================================================

--- Connection & TLS Analysis ---
[INFO] Checking HTTP -> HTTPS redirect...
[PASS] HTTP redirects to HTTPS with 301 (Permanent Redirect).
[INFO] Checking TLS protocol version...
[PASS] Insecure protocols (TLS 1.0, 1.1) are disabled.
[PASS] Using modern TLS version: TLSv1.3
[INFO] Checking SSL certificate...
[PASS] Hostname 'github.com' matches the SSL certificate.
[PASS] Certificate validity period: 365 days (within 398-day limit).
[PASS] Certificate valid for 245 more days.
[INFO] Certificate issued by: DigiCert Inc

--- HSTS Preload Status ---
[INFO] Checking HSTS Preload List...
[PASS] Domain 'github.com' is on the HSTS Preload List.

--- Security Headers Analysis ---
[INFO] Fetching and analyzing headers from https://github.com/...
[PASS] Content-Security-Policy (CSP) is implemented.
[INFO] Analyzing CSP directives...
[PASS] CSP has restrictive 'default-src'.
[PASS] CSP does not contain 'unsafe-eval'.
[PASS] CSP does not contain 'unsafe-inline' in script-src.
[PASS] CSP 'frame-ancestors' restricts framing (clickjacking protection).
[PASS] Strict-Transport-Security (HSTS) is implemented.
[INFO] Analyzing HSTS configuration...
[PASS] HSTS max-age is 31536000 seconds (365 days) - meets 1-year recommendation.
[PASS] HSTS includes 'includeSubDomains'.
[PASS] HSTS includes 'preload' directive.
[PASS] X-Content-Type-Options is 'nosniff'.
[PASS] X-Frame-Options is 'deny'.
[PASS] Referrer-Policy is set: strict-origin-when-cross-origin
[PASS] Permissions-Policy is configured.
[PASS] Server header is not exposed.
[PASS] X-Powered-By header is not exposed.

--- Cookie Analysis ---
[INFO] Analyzing cookie security...
[PASS] All cookies have 'Secure' attribute.
[PASS] All cookies have 'HttpOnly' attribute.
[PASS] All cookies have secure 'SameSite' attribute (Strict/Lax).

============================================================
SECURITY REPORT: github.com
============================================================

Overall Grade: A (96%)
  Passed: 24
  Failed: 1
  Warnings: 2

Warnings to Review:
  • Permissions-Policy is not set (controls browser features)

============================================================
```

### Multi-URL Summary

When scanning multiple URLs, a summary table is displayed:

```
============================================================
SUMMARY - All Scanned URLs
============================================================
  A ( 96%) - github.com
  B ( 82%) - example.com
  C ( 71%) - legacy-app.dev
  F ( 45%) - insecure-site.com

Scan complete.
```

---

## Checks Reference 📋

### CSP Deep Analysis
The scanner performs thorough CSP validation:

- ✅ Verifies `default-src` is present and restrictive
- ✅ Detects `unsafe-eval` (allows `eval()` - XSS risk)
- ✅ Detects `unsafe-inline` without nonce/hash mitigation
- ✅ Warns about dangerous sources: `data:`, `blob:`, `http:`
- ✅ Checks `frame-ancestors` for clickjacking protection
- ✅ Verifies `upgrade-insecure-requests` directive
- ✅ Checks for CSP reporting configuration

### HSTS Validation
- ✅ `max-age` must be ≥ 31536000 (1 year) for preload eligibility
- ✅ `includeSubDomains` required for complete protection
- ✅ `preload` directive for browser preload list submission

### TLS Security
- ✅ Rejects TLS 1.0 and TLS 1.1 (deprecated protocols)
- ✅ Confirms TLS 1.2 or TLS 1.3 is in use
- ✅ Validates certificate chain and expiration

---

## Roadmap 🗺️

Future improvements planned:

- [ ] HTML/JSON report export
- [ ] Custom policy configuration file
- [ ] CI/CD integration mode (exit codes)
- [ ] Subdomain enumeration and scanning
- [ ] Certificate chain validation details
- [ ] Cipher suite analysis

---

## Contributing 🤝

Contributions are welcome! 

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Ideas for Contributions
- Add new security header checks
- Improve CSP parsing logic
- Add export formats (JSON, HTML, PDF)
- Create Docker image
- Add unit tests

---

## License 📄

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Acknowledgments 🙏

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [Mozilla Web Security Guidelines](https://infosec.mozilla.org/guidelines/web_security)
- [HSTS Preload List](https://hstspreload.org/)
- [SecurityHeaders.com](https://securityheaders.com/)
