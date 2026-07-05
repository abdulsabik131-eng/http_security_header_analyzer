# Advanced HTTP Security Header Analyzer

A powerful, automated Python-based security auditing tool designed to inspect web server response headers, detect potential vulnerabilities, analyze architectural risks, and generate a standardized security posture score. Developed as a final year engineering project.

## Features

- **10+ Core Security Header Evaluations:** Full analysis of critical headers including CSP, HSTS, X-Frame-Options, Referrer-Policy, and more.
- **Cross-Origin Policy Auditing:** Checks advanced modern isolation flags such as COOP, COEP, and CORP to protect against side-channel/Spectre-style attacks.
- **Cookie Security Inspection:** Validates `Set-Cookie` configurations for `HttpOnly` and `Secure` attributes to mitigate session hijacking via XSS.
- **Information Leakage Detection:** Scans for server banner exposures (`Server`) and technology stack signatures (`X-Powered-By`, `X-AspNet-Version`, `X-Runtime`) which aid attackers in finding version-specific exploits.
- **Dynamic Scoring Mechanism:** Starts with a baseline score of 100/100 and applies weighted deductions based on vulnerability severity (Critical, High, Medium, Low, Config, Info).
- **Automated Redirect Resolution:** Automatically resolves URL paths and tracks final destination parameters natively.

---

## Monitored Security Control Matrix

The analyzer evaluates exactly 10 security controls alongside backend leak tracking:

| # | Header / Attribute | Severity Target | Primary Threat Mitigated |
|---|---------------------|-----------------|--------------------------|
| 1 | `Content-Security-Policy` (CSP) | **CRITICAL** | Cross-Site Scripting (XSS) & Data Injection |
| 2 | `Strict-Transport-Security` (HSTS) | **HIGH** | SSL Stripping & Man-In-The-Middle (MITM) |
| 3 | `X-Frame-Options` (XFO) | **HIGH** | Clickjacking / UI Redirection |
| 4 | `X-Content-Type-Options` (XCTO) | **MEDIUM** | MIME-Sniffing Exploits |
| 5 | `Referrer-Policy` | **HIGH / INFO** | Sensitive Data Leakage via Referrer URLs |
| 6 | `Permission-Policy` | **LOW** | Unauthorized Hardware/API Feature Access |
| 7 | `Cross-Origin-Resource-Policy` | **MEDIUM** | Side-Channel Speculative Leaks |
| 8 | `Clear-Site-Data` | **INFO** | Residual Session State Accumulation |
| 9 | `Cross-Origin-Opener-Policy` | **MEDIUM** | Cross-Origin Window Isolation Attacks |
| 10| `Cross-Origin-Embedder-Policy` | **MEDIUM** | Unsanctioned Cross-Origin Embeddings |
| --| `Set-Cookie` Flags (`HttpOnly`/`Secure`) | **HIGH** | Session Hijacking & Plaintext Token Theft |
| --| `Server` / `X-Powered-By` Banners | **HIGH / MEDIUM** | Banner Grabbing & Version Exploitation |

---

## Installation & Dependencies

The project relies on standard Python 3.x libraries along with `requests` for robust HTTP connection handling.

1. Clone or download this project repository.
2. Install the required dependencies using pip:

```bash
pip install requests urllib3