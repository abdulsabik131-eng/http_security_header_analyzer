import requests
import urllib3
import re
from urllib.parse import urlparse

# Disable SSL warnings for scanning purposes
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class AdvancedSecurityScanner:
    def __init__(self, target_url):
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            target_url = "https://" + target_url
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)
        self.headers = {}
        self.findings = []
        self.score = 100  # Start with perfect score, deduct for flaws

    def fetch_headers(self):
        try:
            response = requests.get(
                self.target_url, 
                allow_redirects=True, 
                timeout=5, 
                verify=False, 
                headers={"User-Agent": "Advanced-Security-Scanner/2.0 (Final Year Project)"}
            )
            self.target_url = response.url
            self.headers = {k.lower(): v for k, v in response.headers.items()}
            return True
        except Exception as e:
            print(f"[-] Connection failed to {self.target_url}: {e}")
            return False

    def analyze_security_headers(self):
        print("[*] Auditing security header policies & server leaks...\n")
        
        # 1. Content-Security-Policy (CSP)
        csp = self.headers.get("content-security-policy")
        if not csp:
            self.findings.append("[CRITICAL] CSP Missing: High risk of Cross-Site Scripting (XSS) and data injection.")
            self.score -= 25
        else:
            if "unsafe-inline" in csp:
                self.findings.append("[WEAKNESS] CSP contains 'unsafe-inline': Allows execution of inline scripts, weakening XSS protection.")
                self.score -= 10
            if "*" in csp or "https://" in csp:
                self.findings.append("[WEAKNESS] CSP uses wildcard '*' domains: Allows data exfiltration or script loading from anywhere.")
                self.score -= 10

        # 2. HTTP Strict Transport Security (HSTS) 
        hsts = self.headers.get("strict-transport-security")
        if not hsts:
            self.findings.append("[HIGH] HSTS Missing: High risk of SSL Stripping and Man-in-the-Middle (MITM) attacks.")
            self.score -= 20
        else:
            max_age_match = re.search(r'max-age=(\d+)', hsts)
            if max_age_match:
                max_age = int(max_age_match.group(1))
                if max_age < 31536000:
                    self.findings.append(f"[CONFIG] HSTS max-age is low ({max_age}s): Recommended is at least 1 year (31536000s).")
                    self.score -= 5
            if "includesubdomains" not in hsts.lower():
                self.findings.append("[CONFIG] HSTS missing 'includeSubDomains': Subdomains remain vulnerable to HTTP downgrades.")
                self.score -= 5
                    
        # 3. X-Frame-Options (XFO)
        xfo = self.headers.get("x-frame-options")
        if not xfo:
            self.findings.append("[HIGH] X-Frame-Options Missing: Vulnerable to Clickjacking attacks.")
            self.score -= 15
        elif xfo.upper() not in ["DENY", "SAMEORIGIN"]:
            self.findings.append(f"[CONFIG] Weak X-Frame-Options value ({xfo}): Use DENY or SAMEORIGIN.")
            self.score -= 5
        
        # 4. X-Content-Type-Options (XCTO)
        xcto = self.headers.get("x-content-type-options")
        if not xcto or xcto.lower() != "nosniff":
            self.findings.append("[MEDIUM] X-Content-Type-Options missing or misconfigured: Vulnerable to MIME-sniffing exploits.")
            self.score -= 10
            
        # 5. Referrer-Policy
        ref = self.headers.get("referrer-policy")
        if not ref:
            self.findings.append(" [INFO] Referrer-Policy Missing: Default browser behavior applies; sensitive URLs might leak.")
            self.score -= 5
        elif "unsafe-url" in ref.lower():
            self.findings.append(" [HIGH] Referrer-Policy set to 'unsafe-url': Leaks full URLs across origins.")
            self.score -= 15
            
        # 6. Permission-Policy
        pp = self.headers.get("permission-policy")
        if not pp:
            self.findings.append("[LOW] Permission-Policy Missing: Browser hardware features are not explicitly restricted.")
            self.score -= 5
        
        # 7. Cross-Origin-Resource-Policy (CORP)
        corp = self.headers.get("cross-origin-resource-policy")
        if not corp:
            self.findings.append("[MEDIUM] Cross-Origin-Resource-Policy Missing: Fails to protect against side-channel speculative leaks.")
            self.score -= 10
        else:
            if "same-origin" not in corp.lower() and "same-site" not in corp.lower():
                self.findings.append("[LOW] Cross-Origin-Resource-Policy is loosely configured.")
                self.score -= 5

        # 8. Clear-Site-Data
        csd = self.headers.get("clear-site-data")
        if not csd:
            self.findings.append("📝 [INFO] Clear-Site-Data Missing: Session states are not cleared upon explicit logout routes.")
            self.score -= 2

        # 9. Cross-Origin-Opener-Policy (COOP)
        coop = self.headers.get("cross-origin-opener-policy")
        if not coop:
            self.findings.append("[MEDIUM] Cross-Origin-Opener-Policy Missing: Vulnerable to window-based side-channel attacks.")
            self.score -= 10
        elif "same-origin" not in coop.lower():
            self.findings.append("[LOW] Cross-Origin-Opener-Policy is weak: Use 'same-origin'.")
            self.score -= 5

        # 10. Cross-Origin-Embedder-Policy (COEP)
        coep = self.headers.get("cross-origin-embedder-policy")
        if not coep:
            self.findings.append("[MEDIUM] Cross-Origin-Embedder-Policy Missing: Cannot pair cleanly with strict COOP isolation rules.")
            self.score -= 10

        # --- COOKIE AUDIT ---
        cookie_header = self.headers.get("set-cookie")
        if cookie_header:
            if "httponly" not in cookie_header.lower():
                self.findings.append("[HIGH] Cookie missing 'HttpOnly': Session tokens can be stolen via XSS flaws.")
                self.score -= 15
            if "secure" not in cookie_header.lower():
                self.findings.append("[HIGH] Cookie missing 'Secure': Session data can leak over plaintext connections.")
                self.score -= 15

        # --- SERVER DETAILS INFORMATION LEAKS ---
        server = self.headers.get("server")
        if server:
            if any(char.isdigit() for char in server):
                self.findings.append(f"[MEDIUM] Server header leaks exact software version ({server}): Helps attackers pinpoint vulnerabilities.")
                self.score -= 10
            else:
                self.findings.append(f" [INFO] Server software banner exposed: '{server}'. Best practice is to drop this header completely.")
                self.score -= 2

        tech_headers = ["x-powered-by", "x-aspnet-version", "x-runtime"]
        for t_header in tech_headers:
            tech_val = self.headers.get(t_header)
            if tech_val:
                self.findings.append(f"[HIGH] Information Leakage via '{t_header}' ({tech_val}): Discloses underlying server stack details.")
                self.score -= 15

        self.score = max(0, self.score)

    def display_results(self):
        print("\n" + "="*60)
        print(f" SECURITY REPORT FOR: {self.target_url}")
        print(f" FINAL SECURITY SCORE: {self.score}/100")
        print("="*60)
        if not self.findings:
            print("[+] Excellent! No vulnerabilities detected.")
        else:
            for finding in self.findings:
                print(finding)
        print("="*60)

if __name__ == "__main__":
    target = input("Enter target URL to scan: ")
    scanner = AdvancedSecurityScanner(target)
    if scanner.fetch_headers():
        scanner.analyze_security_headers()
        scanner.display_results()