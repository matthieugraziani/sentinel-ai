"""
HTTP Scanner — passive security checks covering OWASP Top-10 (2021).

Detection categories
--------------------
1.  Security headers (HSTS, CSP, X-Frame-Options, …)
2.  Information disclosure (Server, X-Powered-By, stack traces, …)
3.  HTTPS / TLS (redirect, HSTS weak config, mixed content in body)
4.  CORS misconfiguration
5.  Cookie security (Secure, HttpOnly, SameSite flags)
6.  Cache-control for sensitive content
7.  HTTP methods (TRACE, OPTIONS enumeration)
8.  Content-type / MIME sniffing
9.  Clickjacking (CSP frame-ancestors vs X-Frame-Options)
10. HTML body analysis (forms, CSRF, autocomplete, inline scripts,
    open redirects, sensitive data in URL, directory listing)
11. TLS certificate basic check (expiry, hostname)
12. Dependency & path disclosure (stack traces, debug pages, .git, .env …)
13. Rate-limiting / brute-force protection signals
14. Subresource integrity (SRI) on external scripts/styles
15. DNS prefetch control
"""
from __future__ import annotations

import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlparse

import requests
from requests.exceptions import SSLError

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    owasp_id: str
    title: str
    severity: str          # critical | high | medium | low | info
    description: str
    evidence: str = ""
    remediation: str = ""


@dataclass
class ScanResult:
    url: str
    timestamp: float = field(default_factory=time.time)
    status_code: int | None = None
    response_time_ms: float | None = None
    server: str | None = None
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None

    @property
    def risk_score(self) -> float:
        weights = {"critical": 10.0, "high": 7.0, "medium": 4.0, "low": 1.5, "info": 0.0}
        raw = sum(weights.get(f.severity, 0) for f in self.findings)
        return round(min(raw, 100.0), 1)


# ---------------------------------------------------------------------------
# 1. Security headers
# ---------------------------------------------------------------------------

SECURITY_HEADERS: dict[str, dict] = {
    "Strict-Transport-Security": {
        "owasp_id": "A05:2021",
        "severity": "high",
        "title": "Missing HSTS header",
        "description": "HTTP Strict Transport Security is not set. Clients may connect over insecure HTTP.",
        "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "Content-Security-Policy": {
        "owasp_id": "A03:2021",
        "severity": "high",
        "title": "Missing Content-Security-Policy",
        "description": "No CSP header detected. XSS attacks may be easier to exploit.",
        "remediation": "Define a strict CSP. Start with: Content-Security-Policy: default-src 'self'",
    },
    "X-Frame-Options": {
        "owasp_id": "A05:2021",
        "severity": "medium",
        "title": "Missing X-Frame-Options",
        "description": "Page may be embeddable in iframes, enabling clickjacking attacks.",
        "remediation": "Add: X-Frame-Options: DENY  (or use CSP frame-ancestors)",
    },
    "X-Content-Type-Options": {
        "owasp_id": "A05:2021",
        "severity": "low",
        "title": "Missing X-Content-Type-Options",
        "description": "Browser may sniff MIME types, leading to XSS via uploaded files.",
        "remediation": "Add: X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "owasp_id": "A05:2021",
        "severity": "low",
        "title": "Missing Referrer-Policy",
        "description": "Sensitive URLs may leak to third-party origins via the Referer header.",
        "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "owasp_id": "A05:2021",
        "severity": "info",
        "title": "Missing Permissions-Policy",
        "description": "Browser features (camera, mic, geolocation) are not restricted.",
        "remediation": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
    },
    "X-DNS-Prefetch-Control": {
        "owasp_id": "A05:2021",
        "severity": "info",
        "title": "Missing X-DNS-Prefetch-Control",
        "description": "DNS prefetching may leak browsing intent to external DNS servers.",
        "remediation": "Add: X-DNS-Prefetch-Control: off",
    },
}


def _check_missing_headers(headers: dict) -> list[Finding]:
    lower = {k.lower() for k in headers}
    findings = []
    for header, meta in SECURITY_HEADERS.items():
        if header.lower() not in lower:
            findings.append(Finding(**meta, evidence=f"Header '{header}' absent from response"))
    return findings


# ---------------------------------------------------------------------------
# 2. Information disclosure
# ---------------------------------------------------------------------------

SENSITIVE_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Generator", "X-Drupal-Cache", "X-Wordpress-Theme",
]

_STACK_PATTERNS = [
    (r"at\s+\w+\.\w+\([^)]+\.(?:java|cs|py|rb|php)\:\d+\)", "Java/C#/Python stack trace"),
    (r"Traceback \(most recent call last\)", "Python traceback"),
    (r"Fatal error:.*on line \d+", "PHP fatal error"),
    (r"Warning:.*on line \d+", "PHP warning"),
    (r"Microsoft OLE DB Provider", "MSSQL OLE DB error"),
    (r"You have an error in your SQL syntax", "MySQL syntax error (SQL injection signal)"),
    (r"ORA-\d{5}:", "Oracle DB error"),
    (r"SQLSTATE\[", "PDO/SQL error"),
    (r"pg_query\(\):", "PostgreSQL error"),
    (r"ActiveRecord::StatementInvalid", "Rails/ActiveRecord SQL error"),
]

_DEBUG_PATH_PATTERNS = [
    r"phpinfo\(\)",
    r"<title>Laravel</title>",
    r"Whoops!.*Exception",
    r"DebugKit",
    r"django\.conf",
    r"rails\.env.*development",
]


def _check_information_disclosure(headers: dict, body: str) -> list[Finding]:
    findings = []

    for h in SENSITIVE_HEADERS:
        val = headers.get(h, "")
        if val:
            findings.append(Finding(
                owasp_id="A05:2021",
                title=f"Server version disclosure via {h}",
                severity="low",
                description=f"The '{h}' header exposes implementation details.",
                evidence=f"{h}: {val}",
                remediation=f"Remove or obscure the '{h}' response header.",
            ))

    for pattern, label in _STACK_PATTERNS:
        if re.search(pattern, body, re.IGNORECASE):
            findings.append(Finding(
                owasp_id="A05:2021",
                title=f"Stack trace / error disclosure in response body ({label})",
                severity="high",
                description="Detailed error messages expose internal paths, library versions, or query structure.",
                evidence=f"Pattern matched: {label}",
                remediation="Disable detailed error output in production. Use generic error pages.",
            ))
            break  # one finding per category is enough

    for pattern in _DEBUG_PATH_PATTERNS:
        if re.search(pattern, body, re.IGNORECASE):
            findings.append(Finding(
                owasp_id="A05:2021",
                title="Debug / development page exposed",
                severity="critical",
                description="A debug interface or development error page is publicly reachable.",
                evidence=f"Pattern matched: {pattern}",
                remediation="Disable debug mode in production and restrict access to diagnostic endpoints.",
            ))
            break

    return findings


# ---------------------------------------------------------------------------
# 3. HTTPS / TLS
# ---------------------------------------------------------------------------

def _check_https_redirect(url: str, headers: dict, status_code: int) -> list[Finding]:
    parsed = urlparse(url)
    if parsed.scheme == "http":
        location = headers.get("Location", "")
        if status_code not in (301, 302, 307, 308) or not location.startswith("https://"):
            return [Finding(
                owasp_id="A02:2021",
                title="No HTTPS redirect",
                severity="high",
                description="The target responds over plain HTTP without redirecting to HTTPS.",
                evidence=f"Scheme: {parsed.scheme}, Status: {status_code}",
                remediation="Configure a 301 redirect from HTTP to HTTPS.",
            )]
    return []


def _check_hsts_config(headers: dict) -> list[Finding]:
    hsts = headers.get("Strict-Transport-Security", "")
    if not hsts:
        return []
    findings = []
    match = re.search(r"max-age=(\d+)", hsts)
    if match and int(match.group(1)) < 15_552_000:  # < 180 days
        findings.append(Finding(
            owasp_id="A02:2021",
            title="HSTS max-age too short",
            severity="medium",
            description="HSTS max-age is below the recommended 180 days (15552000 seconds).",
            evidence=f"Strict-Transport-Security: {hsts}",
            remediation="Set max-age to at least 31536000 (1 year).",
        ))
    if "includeSubDomains" not in hsts:
        findings.append(Finding(
            owasp_id="A02:2021",
            title="HSTS missing includeSubDomains",
            severity="low",
            description="Subdomains are not covered by HSTS, leaving them vulnerable to downgrade attacks.",
            evidence=f"Strict-Transport-Security: {hsts}",
            remediation="Add 'includeSubDomains' to the HSTS header.",
        ))
    return findings


def _check_tls_certificate(url: str) -> list[Finding]:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return []
    host = parsed.hostname
    port = parsed.port or 443
    findings = []
    try:
        remaining = None
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((host, port), timeout=5), server_hostname=host) as s:
            cert = s.getpeercert()
            # cert.getpeercert() may return a dict without 'notAfter' (type checkers
            # also complain about uncertain types). Handle safely.
            not_after_str = None
            if isinstance(cert, dict):
                not_after_str = cert.get("notAfter")
            if not_after_str is None or not isinstance(not_after_str, str):
                findings.append(Finding(
                    owasp_id="A02:2021",
                    title="TLS certificate missing notAfter",
                    severity="medium",
                    description="The TLS certificate does not contain a valid 'notAfter' field; cannot determine expiration.",
                    evidence=f"cert: {cert}",
                    remediation="Ensure the server presents a valid X.509 certificate with a notAfter field.",
                ))
            else:
                not_after = ssl.cert_time_to_seconds(not_after_str)
                remaining = not_after - time.time()
            # Only evaluate expiration-based findings if we were able to determine remaining
            if remaining is not None:
                if remaining < 0:
                    findings.append(Finding(
                        owasp_id="A02:2021",
                        title="TLS certificate expired",
                        severity="critical",
                        description="The server's TLS certificate has expired. Connections are insecure.",
                        evidence=f"notAfter: {not_after_str}",
                        remediation="Renew the TLS certificate immediately.",
                    ))
                elif remaining < 30 * 86400:
                    findings.append(Finding(
                        owasp_id="A02:2021",
                        title="TLS certificate expiring soon",
                        severity="medium",
                        description=f"Certificate expires in {int(remaining // 86400)} days.",
                        evidence=f"notAfter: {not_after_str}",
                        remediation="Renew the TLS certificate before it expires.",
                    ))
    except ssl.SSLCertVerificationError as exc:
        findings.append(Finding(
            owasp_id="A02:2021",
            title="TLS certificate validation failure",
            severity="critical",
            description="The server's TLS certificate could not be verified (expired, self-signed, or hostname mismatch).",
            evidence=str(exc),
            remediation="Use a valid certificate from a trusted CA and ensure the hostname matches.",
        ))
    except (socket.timeout, OSError):
        pass  # network-level failure; not a TLS finding
    return findings


def _check_mixed_content(body: str, url: str) -> list[Finding]:
    if urlparse(url).scheme != "https":
        return []
    patterns = [
        r'src=["\']http://[^"\']+["\']',
        r'href=["\']http://[^"\']+["\']',
        r'action=["\']http://[^"\']+["\']',
    ]
    for p in patterns:
        if re.search(p, body, re.IGNORECASE):
            return [Finding(
                owasp_id="A02:2021",
                title="Mixed content detected",
                severity="medium",
                description="The HTTPS page loads resources over HTTP, weakening transport security.",
                evidence="HTTP src/href/action attribute found in HTTPS page body.",
                remediation="Replace all HTTP resource URLs with HTTPS equivalents.",
            )]
    return []


# ---------------------------------------------------------------------------
# 4. CORS
# ---------------------------------------------------------------------------

def _check_cors(headers: dict) -> list[Finding]:
    acao = headers.get("Access-Control-Allow-Origin", "")
    acac = headers.get("Access-Control-Allow-Credentials", "").lower()
    findings = []
    if acao == "*":
        findings.append(Finding(
            owasp_id="A05:2021",
            title="Overly permissive CORS policy (wildcard origin)",
            severity="medium",
            description="Access-Control-Allow-Origin: * allows any origin to read responses.",
            evidence=f"Access-Control-Allow-Origin: {acao}",
            remediation="Restrict CORS to trusted origins. Never combine * with credentials.",
        ))
    if acao == "*" and acac == "true":
        findings.append(Finding(
            owasp_id="A05:2021",
            title="CORS wildcard with credentials allowed",
            severity="high",
            description="Combining ACAO: * with ACAC: true is rejected by browsers but signals a misconfiguration.",
            evidence=f"ACAO: {acao} | ACAC: {acac}",
            remediation="Specify an explicit trusted origin when using credentials.",
        ))
    if acao and acao not in ("*",) and acac == "true":
        # Reflected origin check heuristic
        findings.append(Finding(
            owasp_id="A01:2021",
            title="CORS credentials allowed for explicit origin — verify not reflected",
            severity="info",
            description=(
                "CORS allows credentials for a specific origin. "
                "If the server reflects arbitrary request Origins, this becomes high severity."
            ),
            evidence=f"ACAO: {acao} | ACAC: true",
            remediation="Ensure the allowed origin is a static whitelist, not a reflection of the request Origin header.",
        ))
    return findings


# ---------------------------------------------------------------------------
# 5. Cookie security
# ---------------------------------------------------------------------------

def _check_cookies(resp: requests.Response, url: str) -> list[Finding]:
    findings = []
    is_https = urlparse(url).scheme == "https"
    set_cookie_headers = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw.headers, "getlist") else []
    if not set_cookie_headers:
        set_cookie_raw = resp.headers.get("Set-Cookie", "")
        set_cookie_headers = [set_cookie_raw] if set_cookie_raw else []

    for raw in set_cookie_headers:
        if not raw:
            continue
        raw_lower = raw.lower()
        name = raw.split("=")[0].strip()

        if is_https and "secure" not in raw_lower:
            findings.append(Finding(
                owasp_id="A02:2021",
                title=f"Cookie '{name}' missing Secure flag",
                severity="medium",
                description="Cookie can be transmitted over plain HTTP, exposing it to interception.",
                evidence=raw[:120],
                remediation=f"Add the Secure flag to the '{name}' cookie.",
            ))
        if "httponly" not in raw_lower:
            findings.append(Finding(
                owasp_id="A03:2021",
                title=f"Cookie '{name}' missing HttpOnly flag",
                severity="medium",
                description="Cookie is accessible via JavaScript; XSS can steal session tokens.",
                evidence=raw[:120],
                remediation=f"Add the HttpOnly flag to the '{name}' cookie.",
            ))
        if "samesite" not in raw_lower:
            findings.append(Finding(
                owasp_id="A01:2021",
                title=f"Cookie '{name}' missing SameSite attribute",
                severity="low",
                description="Without SameSite, the cookie is sent on cross-site requests, enabling CSRF.",
                evidence=raw[:120],
                remediation=f"Add SameSite=Lax (or Strict) to the '{name}' cookie.",
            ))
        elif "samesite=none" in raw_lower and "secure" not in raw_lower:
            findings.append(Finding(
                owasp_id="A02:2021",
                title=f"Cookie '{name}' has SameSite=None without Secure",
                severity="medium",
                description="SameSite=None requires the Secure flag; browsers may reject or send over HTTP.",
                evidence=raw[:120],
                remediation=f"Add the Secure flag alongside SameSite=None for '{name}'.",
            ))
    return findings


# ---------------------------------------------------------------------------
# 6. Cache control for sensitive content
# ---------------------------------------------------------------------------

_SENSITIVE_CONTENT_TYPES = re.compile(
    r"application/(json|xml|pdf)|text/(html|plain)", re.IGNORECASE
)


def _check_cache_control(headers: dict) -> list[Finding]:
    cc = headers.get("Cache-Control", "").lower()
    ct = headers.get("Content-Type", "")
    headers.get("Pragma", "").lower()
    findings = []

    if _SENSITIVE_CONTENT_TYPES.search(ct) and not cc:
        findings.append(Finding(
            owasp_id="A05:2021",
            title="Missing Cache-Control header for sensitive content",
            severity="low",
            description="Responses with sensitive content may be cached by proxies or browsers.",
            evidence=f"Content-Type: {ct}, Cache-Control absent",
            remediation="Add: Cache-Control: no-store, no-cache, must-revalidate",
        ))
    if "public" in cc and "no-store" not in cc:
        findings.append(Finding(
            owasp_id="A05:2021",
            title="Response marked as public cache — verify no sensitive data",
            severity="info",
            description="Cache-Control: public allows CDNs and shared caches to store this response.",
            evidence=f"Cache-Control: {cc}",
            remediation="Use Cache-Control: private or no-store for authenticated/sensitive endpoints.",
        ))
    return findings


# ---------------------------------------------------------------------------
# 7. HTTP methods
# ---------------------------------------------------------------------------

def _check_http_methods(url: str, timeout: int) -> list[Finding]:
    findings = []
    headers_ua = {"User-Agent": "SentinelAI/1.0"}
    try:
        r = requests.options(url, timeout=timeout, headers=headers_ua, allow_redirects=False)
        allow = r.headers.get("Allow", "")
        if "TRACE" in allow.upper():
            findings.append(Finding(
                owasp_id="A05:2021",
                title="HTTP TRACE method enabled",
                severity="medium",
                description="TRACE allows cross-site tracing (XST) attacks to steal HTTP-only cookies.",
                evidence=f"Allow: {allow}",
                remediation="Disable TRACE in the web server configuration.",
            ))
        if allow:
            findings.append(Finding(
                owasp_id="A05:2021",
                title="HTTP methods enumerated via OPTIONS",
                severity="info",
                description="The server discloses supported HTTP methods.",
                evidence=f"Allow: {allow}",
                remediation="Restrict allowed methods to the minimum required (GET, POST, HEAD).",
            ))
    except (requests.RequestException, OSError):
        pass
    try:
        r = requests.request("TRACE", url, timeout=timeout, headers=headers_ua, allow_redirects=False)
        if r.status_code not in (405, 403, 501):
            findings.append(Finding(
                owasp_id="A05:2021",
                title="HTTP TRACE method accepted",
                severity="medium",
                description="Server responded to a TRACE request (XST attack surface).",
                evidence=f"TRACE → HTTP {r.status_code}",
                remediation="Disable TRACE in the web server configuration.",
            ))
    except (requests.RequestException, OSError):
        pass
    return findings


# ---------------------------------------------------------------------------
# 8. HTML body analysis
# ---------------------------------------------------------------------------

def _check_html_body(body: str, url: str) -> list[Finding]:
    if not body:
        return []
    findings = []

    # --- Forms without CSRF tokens ---
    forms = re.findall(r"<form[^>]*>.*?</form>", body, re.IGNORECASE | re.DOTALL)
    for form in forms:
        form_lower = form.lower()
        method = re.search(r'method=["\'](\w+)["\']', form_lower)
        is_post = not method or method.group(1) == "post"
        has_csrf = any(x in form_lower for x in [
            "csrf", "_token", "authenticity_token", "__requestverificationtoken",
            "nonce", "xsrf",
        ])
        if is_post and not has_csrf:
            findings.append(Finding(
                owasp_id="A01:2021",
                title="Form without CSRF protection token",
                severity="high",
                description="A POST form lacks a recognisable CSRF token, making it vulnerable to cross-site request forgery.",
                evidence=form[:200],
                remediation="Add a server-generated, unpredictable CSRF token to every state-changing form.",
            ))
            break  # report once per page

    # --- Autocomplete on sensitive fields ---
    sensitive_field_re = re.compile(
        r"""<input[^>]+(?:name|id)=['"](?:[^'"]*(?:password|passwd|pass|secret|credit|card|cvv|ssn|dob)[^'"]*)['"][^>]*>""",
        re.IGNORECASE,
    )
    for match in sensitive_field_re.finditer(body):
        field_html = match.group(0)
        if "autocomplete" not in field_html.lower():
            findings.append(Finding(
                owasp_id="A05:2021",
                title="Sensitive input field missing autocomplete=off",
                severity="low",
                description="Browser may auto-fill or cache sensitive field values (password, card number, etc.).",
                evidence=field_html[:150],
                remediation='Add autocomplete="off" (or autocomplete="new-password") to sensitive fields.',
            ))
            break

    # --- Inline scripts (CSP bypass risk) ---
    if re.search(r"<script(?:\s[^>]*)?>(?!\s*src)", body, re.IGNORECASE):
        findings.append(Finding(
            owasp_id="A03:2021",
            title="Inline JavaScript detected",
            severity="info",
            description="Inline scripts prevent effective use of Content-Security-Policy and increase XSS risk.",
            evidence="<script> tag with inline content found.",
            remediation="Move JavaScript to external files and enforce script-src in CSP.",
        ))

    # --- Inline event handlers ---
    if re.search(r'\bon\w+\s*=\s*["\']', body, re.IGNORECASE):
        findings.append(Finding(
            owasp_id="A03:2021",
            title="Inline event handlers detected",
            severity="info",
            description="Inline handlers (onclick=, onload=, …) cannot be restricted by CSP.",
            evidence="Inline event handler attribute found.",
            remediation="Replace inline handlers with addEventListener() calls in external scripts.",
        ))

    # --- Directory listing ---
    if re.search(r"Index of /|Parent Directory|<title>Directory listing", body, re.IGNORECASE):
        findings.append(Finding(
            owasp_id="A05:2021",
            title="Directory listing enabled",
            severity="high",
            description="The server exposes a browsable directory index, revealing file structure.",
            evidence="Directory index page content detected.",
            remediation="Disable directory listing in server configuration (e.g., Options -Indexes for Apache).",
        ))

    # --- External scripts without SRI ---
    external_scripts = re.findall(
        r'<script[^>]+src=["\']https?://(?!(?:' + re.escape(urlparse(url).hostname or "") + r')["\'/])[^"\']+["\'][^>]*>',
        body, re.IGNORECASE,
    )
    missing_sri = [s for s in external_scripts if "integrity=" not in s.lower()]
    if missing_sri:
        findings.append(Finding(
            owasp_id="A06:2021",
            title="External scripts loaded without Subresource Integrity (SRI)",
            severity="medium",
            description=f"{len(missing_sri)} external script(s) lack an integrity= attribute. A compromised CDN can inject malicious code.",
            evidence=missing_sri[0][:200],
            remediation="Add integrity= and crossorigin= attributes to all external script/link tags.",
        ))

    return findings


# ---------------------------------------------------------------------------
# 9. Sensitive data in URL
# ---------------------------------------------------------------------------

_SENSITIVE_PARAMS = re.compile(
    r"(?:password|passwd|pass|secret|token|api_?key|access_?token|auth|session|sid|ssn|creditcard|cvv)",
    re.IGNORECASE,
)


def _check_sensitive_url_params(url: str) -> list[Finding]:
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    hits = [k for k in params if _SENSITIVE_PARAMS.search(k)]
    if hits:
        return [Finding(
            owasp_id="A02:2021",
            title="Sensitive parameter(s) in URL query string",
            severity="high",
            description="Sensitive values in URLs are logged by servers, proxies, and browsers.",
            evidence=f"Parameters: {', '.join(hits)}",
            remediation="Transmit sensitive values in the request body (POST) or headers, never in the URL.",
        )]
    return []


# ---------------------------------------------------------------------------
# 10. Exposed sensitive paths
# ---------------------------------------------------------------------------

SENSITIVE_PATHS = [
    ("/.git/HEAD", "A05:2021", "critical", ".git repository exposed",
     "The .git directory is publicly accessible, leaking full source code.",
     "Block access to .git/ in server configuration."),
    ("/.env", "A05:2021", "critical", ".env file exposed",
     "Environment file may contain database passwords, API keys, and secrets.",
     "Block access to .env files and move secrets to a secrets manager."),
    ("/wp-login.php", "A07:2021", "info", "WordPress login page detected",
     "Confirms a WordPress installation; brute-force attacks are common.",
     "Enable login rate-limiting and two-factor authentication."),
    ("/admin", "A05:2021", "info", "Admin path accessible",
     "An /admin path is reachable and may expose an admin interface.",
     "Restrict /admin to trusted IPs or require MFA."),
    ("/phpinfo.php", "A05:2021", "critical", "phpinfo() page exposed",
     "phpinfo() reveals PHP version, loaded modules, and server configuration.",
     "Remove phpinfo.php from the server immediately."),
    ("/server-status", "A05:2021", "high", "Apache server-status exposed",
     "mod_status leaks active requests, client IPs, and worker stats.",
     "Restrict /server-status to localhost or trusted IPs."),
    ("/actuator", "A05:2021", "high", "Spring Boot Actuator exposed",
     "Actuator endpoints can expose health, env, beans, and even allow RCE via /actuator/env.",
     "Restrict Actuator endpoints; disable those not needed in production."),
    ("/swagger-ui.html", "A05:2021", "medium", "Swagger UI exposed",
     "API documentation is publicly accessible, aiding reconnaissance.",
     "Disable Swagger in production or restrict to authenticated users."),
    ("/api/swagger.json", "A05:2021", "medium", "OpenAPI schema exposed",
     "API schema reveals all endpoints, parameters, and data models.",
     "Restrict access to API documentation endpoints."),
    ("/.DS_Store", "A05:2021", "low", ".DS_Store file exposed",
     "macOS metadata file can reveal directory structure.",
     "Add .DS_Store to .gitignore and block it in server config."),
]


def _check_sensitive_paths(base_url: str, timeout: int) -> list[Finding]:
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    findings = []
    session = requests.Session()
    session.headers["User-Agent"] = "SentinelAI/1.0"
    for path, owasp_id, severity, title, description, remediation in SENSITIVE_PATHS:
        try:
            r = session.get(base + path, timeout=timeout, allow_redirects=False)
            if r.status_code in (200, 206):
                findings.append(Finding(
                    owasp_id=owasp_id,
                    title=title,
                    severity=severity,
                    description=description,
                    evidence=f"GET {base + path} → HTTP {r.status_code}",
                    remediation=remediation,
                ))
        except requests.RequestException:  # network / HTTP related errors
            pass
    return findings


# ---------------------------------------------------------------------------
# 11. Rate-limiting signals
# ---------------------------------------------------------------------------

def _check_rate_limiting(headers: dict) -> list[Finding]:
    rl_headers = ["X-RateLimit-Limit", "X-RateLimit-Remaining", "Retry-After", "RateLimit-Limit"]
    lower = {k.lower() for k in headers}
    has_rl = any(h.lower() in lower for h in rl_headers)
    if not has_rl:
        return [Finding(
            owasp_id="A07:2021",
            title="No rate-limiting headers detected",
            severity="info",
            description="No X-RateLimit or Retry-After headers were found. Brute-force protection cannot be confirmed passively.",
            evidence="None of: " + ", ".join(rl_headers),
            remediation="Implement rate limiting and expose RateLimit headers (IETF draft-ietf-httpapi-ratelimit-headers).",
        )]
    return []


# ---------------------------------------------------------------------------
# 12. CSP quality
# ---------------------------------------------------------------------------

_UNSAFE_CSP = [
    ("unsafe-inline", "medium", "CSP contains 'unsafe-inline'",
     "'unsafe-inline' negates most XSS protection provided by CSP."),
    ("unsafe-eval", "medium", "CSP contains 'unsafe-eval'",
     "'unsafe-eval' allows dynamic code execution (eval, Function()), increasing XSS risk."),
    ("*", "high", "CSP contains wildcard source (*)",
     "A wildcard source allows any origin, effectively disabling CSP protection."),
]


def _check_csp_quality(headers: dict) -> list[Finding]:
    csp = headers.get("Content-Security-Policy", "")
    if not csp:
        return []
    findings = []
    for token, severity, title, description in _UNSAFE_CSP:
        if token in csp:
            findings.append(Finding(
                owasp_id="A03:2021",
                title=title,
                severity=severity,
                description=description,
                evidence=f"CSP: {csp[:200]}",
                remediation="Remove unsafe directives. Use nonces or hashes for inline scripts.",
            ))
    return findings


# ---------------------------------------------------------------------------
# Public scanner function
# ---------------------------------------------------------------------------

def scan(url: str, timeout: int = 10) -> ScanResult:
    """
    Perform a passive HTTP security scan against *url*.
    Returns a :class:`ScanResult` with all findings populated.
    """
    result = ScanResult(url=url)

    # URL-level checks (no network needed)
    result.findings += _check_sensitive_url_params(url)

    # TLS certificate check (direct socket)
    result.findings += _check_tls_certificate(url)

    try:
        t0 = time.perf_counter()
        resp = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": "SentinelAI/1.0 (+https://github.com/matthieugraziani/sentinelai)"},
        )
        result.response_time_ms = round((time.perf_counter() - t0) * 1000, 1)
        result.status_code = resp.status_code
        result.server = resp.headers.get("Server")

        hdrs = dict(resp.headers)
        body = resp.text or ""

        # Header-based checks
        result.findings += _check_missing_headers(hdrs)
        result.findings += _check_hsts_config(hdrs)
        result.findings += _check_https_redirect(url, hdrs, resp.status_code)
        result.findings += _check_information_disclosure(hdrs, body)
        result.findings += _check_cors(hdrs)
        result.findings += _check_cookies(resp, url)
        result.findings += _check_cache_control(hdrs)
        result.findings += _check_rate_limiting(hdrs)
        result.findings += _check_csp_quality(hdrs)

        # Body checks
        result.findings += _check_html_body(body, url)
        result.findings += _check_mixed_content(body, url)

        # Active follow-up requests
        result.findings += _check_http_methods(url, timeout)
        result.findings += _check_sensitive_paths(url, timeout)

    except SSLError as exc:
        result.error = f"SSL error: {exc}"
    except requests.exceptions.ConnectionError as exc:
        result.error = f"Connection error: {exc}"
    except requests.exceptions.Timeout:
        result.error = f"Request timed out after {timeout}s"
    except requests.exceptions.RequestException as exc:
        result.error = f"Request error: {exc}"

    return result
