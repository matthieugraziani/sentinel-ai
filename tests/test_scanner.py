"""
Tests for scanner.http_scanner and scanner.owasp_scorer.
All HTTP calls are mocked — no real network required.
"""
from __future__ import annotations

import sys
from pathlib import Path

import responses as resp_lib  # type: ignore[import]

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner.http_scanner import Finding, scan
from scanner.owasp_scorer import build_report

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

def _minimal_headers() -> dict:
    return {"Content-Type": "text/html; charset=utf-8"}


def _secure_headers() -> dict:
    return {
        "Content-Type": "text/html; charset=utf-8",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), microphone=()",
        "X-DNS-Prefetch-Control": "off",
        "Cache-Control": "no-store",
    }


def _mock_sensitive_paths(base: str = "https://example.com") -> None:
    """Register 404 responses for all sensitive path probes."""
    paths = [
        "/.git/HEAD", "/.env", "/wp-login.php", "/admin",
        "/phpinfo.php", "/server-status", "/actuator",
        "/swagger-ui.html", "/api/swagger.json", "/.DS_Store",
    ]
    for p in paths:
        resp_lib.add(resp_lib.GET, base + p, status=404)
    resp_lib.add(resp_lib.OPTIONS, base, status=200, headers={"Allow": "GET, POST, HEAD"})
    # passthrough TRACE → 405
    resp_lib.add("TRACE", base, status=405)


# ---------------------------------------------------------------------------
# 1. Security headers
# ---------------------------------------------------------------------------

class TestSecurityHeaders:
    @resp_lib.activate
    def test_missing_headers_produce_high_findings(self):
        resp_lib.add(resp_lib.GET, "https://example.com", headers=_minimal_headers(), status=200)
        _mock_sensitive_paths()
        result = scan("https://example.com")
        severities = {f.severity for f in result.findings}
        assert "high" in severities

    @resp_lib.activate
    def test_secure_headers_no_high_findings(self):
        resp_lib.add(resp_lib.GET, "https://example.com", headers=_secure_headers(), status=200)
        _mock_sensitive_paths()
        result = scan("https://example.com")
        high = [f for f in result.findings if f.severity in ("critical", "high")]
        assert high == []


# ---------------------------------------------------------------------------
# 2. Information disclosure
# ---------------------------------------------------------------------------

class TestInformationDisclosure:
    @resp_lib.activate
    def test_server_version_disclosure(self):
        h = {**_secure_headers(), "Server": "Apache/2.4.51 (Ubuntu)"}
        resp_lib.add(resp_lib.GET, "https://example.com", headers=h, status=200)
        _mock_sensitive_paths()
        result = scan("https://example.com")
        found = [f for f in result.findings if "disclosure" in f.title.lower() and "Server" in f.title]
        assert found
        assert "Apache/2.4.51" in found[0].evidence

    @resp_lib.activate
    def test_stack_trace_in_body(self):
        resp_lib.add(
            resp_lib.GET, "https://example.com",
            headers=_minimal_headers(),
            body="<html>Traceback (most recent call last):\n  File app.py line 42\n</html>",
            status=500,
        )
        _mock_sensitive_paths()
        result = scan("https://example.com")
        found = [f for f in result.findings if "stack trace" in f.title.lower() or "traceback" in f.evidence.lower()]
        assert found
        assert found[0].severity == "high"

    @resp_lib.activate
    def test_debug_page_critical(self):
        resp_lib.add(
            resp_lib.GET, "https://example.com",
            headers=_minimal_headers(),
            body="<html><title>Laravel</title><p>Whoops! Exception</p></html>",
            status=200,
        )
        _mock_sensitive_paths()
        result = scan("https://example.com")
        found = [f for f in result.findings if f.severity == "critical" and "debug" in f.title.lower()]
        assert found


# ---------------------------------------------------------------------------
# 3. HTTPS / TLS
# ---------------------------------------------------------------------------

class TestHTTPS:
    @resp_lib.activate
    def test_http_no_redirect_flagged(self):
        resp_lib.add(resp_lib.GET, "http://example.com", headers=_minimal_headers(), status=200)
        _mock_sensitive_paths("http://example.com")
        result = scan("http://example.com")
        found = [f for f in result.findings if "HTTPS redirect" in f.title]
        assert found

    @resp_lib.activate
    def test_http_with_https_redirect_not_flagged(self):
        resp_lib.add(
            resp_lib.GET, "http://example.com",
            headers={**_minimal_headers(), "Location": "https://example.com"},
            status=301,
        )
        _mock_sensitive_paths("http://example.com")
        result = scan("http://example.com")
        assert not [f for f in result.findings if "No HTTPS redirect" in f.title]

    @resp_lib.activate
    def test_hsts_max_age_too_short(self):
        h = {**_secure_headers(), "Strict-Transport-Security": "max-age=3600"}
        resp_lib.add(resp_lib.GET, "https://example.com", headers=h, status=200)
        _mock_sensitive_paths()
        result = scan("https://example.com")
        found = [f for f in result.findings if "max-age too short" in f.title]
        assert found
        assert found[0].severity == "medium"

    @resp_lib.activate
    def test_hsts_missing_includesubdomains(self):
        h = {**_secure_headers(), "Strict-Transport-Security": "max-age=31536000"}
        resp_lib.add(resp_lib.GET, "https://example.com", headers=h, status=200)
        _mock_sensitive_paths()
        result = scan("https://example.com")
        found = [f for f in result.findings if "includeSubDomains" in f.title]
        assert found

    @resp_lib.activate
    def test_mixed_content_detected(self):
        body = '<html><script src="http://cdn.evil.com/lib.js"></script></html>'
        resp_lib.add(resp_lib.GET, "https://example.com", headers=_secure_headers(), body=body, status=200)
        _mock_sensitive_paths()
        result = scan("https://example.com")
        found = [f for f in result.findings if "Mixed content" in f.title]
        assert found
        assert found[0].severity == "medium"


# ---------------------------------------------------------------------------
# 4. CORS
# ---------------------------------------------------------------------------

class TestCORS:
    @resp_lib.activate
    def test_wildcard_cors(self):
        h = {**_secure_headers(), "Access-Control-Allow-Origin": "*"}
        resp_lib.add(resp_lib.GET, "https://example.com", headers=h, status=200)
        _mock_sensitive_paths()
        result = scan("https://example.com")
        found = [f for f in result.findings if "CORS" in f.title and "wildcard" in f.title.lower()]
        assert found

    @resp_lib.activate
    def test_cors_wildcard_with_credentials(self):
        h = {
            **_secure_headers(),
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        }
        resp_lib.add(resp_lib.GET, "https://example.com", headers=h, status=200)
        _mock_sensitive_paths()
        result = scan("https://example.com")
        found = [f for f in result.findings if "credentials" in f.title.lower() and "CORS" in f.title]
        assert found
        assert found[0].severity == "high"


# ---------------------------------------------------------------------------
# 5. Cookies
# ---------------------------------------------------------------------------

class TestCookies:
    @resp_lib.activate
    def test_cookie_missing_httponly(self):
        h = {**_secure_headers(), "Set-Cookie": "session=abc123; Path=/"}
        resp_lib.add(resp_lib.GET, "https://example.com", headers=h, status=200)
        _mock_sensitive_paths()
        result = scan("https://example.com")
        found = [f for f in result.findings if "HttpOnly" in f.title]
        assert found

    @resp_lib.activate
    def test_cookie_missing_secure_on_https(self):
        h = {**_secure_headers(), "Set-Cookie": "session=abc123; HttpOnly; SameSite=Lax"}
        resp_lib.add(resp_lib.GET, "https://example.com", headers=h, status=200)
        _mock_sensitive_paths()
        result = scan("https://example.com")
        found = [f for f in result.findings if "Secure flag" in f.title]
        assert found

    @resp_lib.activate
    def test_cookie_missing_samesite(self):
        h = {**_secure_headers(), "Set-Cookie": "session=abc123; HttpOnly; Secure"}
        resp_lib.add(resp_lib.GET, "https://example.com", headers=h, status=200)
        _mock_sensitive_paths()
        result = scan("https://example.com")
        found = [f for f in result.findings if "SameSite" in f.title]
        assert found


# ---------------------------------------------------------------------------
# 6. HTML body checks
# ---------------------------------------------------------------------------

class TestHTMLBody:
    @resp_lib.activate
    def test_form_without_csrf_token(self):
        body = '<html><form method="POST" action="/login"><input name="user"><input name="pass"></form></html>'
        resp_lib.add(resp_lib.GET, "https://example.com", headers=_secure_headers(), body=body, status=200)
        _mock_sensitive_paths()
        result = scan("https://example.com")
        found = [f for f in result.findings if "CSRF" in f.title]
        assert found
        assert found[0].severity == "high"

    @resp_lib.activate
    def test_form_with_csrf_token_not_flagged(self):
        body = '<html><form method="POST"><input name="csrf_token" value="abc"><input name="pass"></form></html>'
        resp_lib.add(resp_lib.GET, "https://example.com", headers=_secure_headers(), body=body, status=200)
        _mock_sensitive_paths()
        result = scan("https://example.com")
        found = [f for f in result.findings if "CSRF" in f.title]
        assert not found

    @resp_lib.activate
    def test_directory_listing(self):
        body = "<html><title>Index of /</title><p>Parent Directory</p></html>"
        resp_lib.add(resp_lib.GET, "https://example.com", headers=_secure_headers(), body=body, status=200)
        _mock_sensitive_paths()
        result = scan("https://example.com")
        found = [f for f in result.findings if "Directory listing" in f.title]
        assert found
        assert found[0].severity == "high"

    @resp_lib.activate
    def test_external_script_without_sri(self):
        body = '<html><script src="https://cdn.jquery.com/jquery.min.js"></script></html>'
        resp_lib.add(resp_lib.GET, "https://example.com", headers=_secure_headers(), body=body, status=200)
        _mock_sensitive_paths()
        result = scan("https://example.com")
        found = [f for f in result.findings if "SRI" in f.title or "Subresource Integrity" in f.title]
        assert found
        assert found[0].severity == "medium"

    @resp_lib.activate
    def test_inline_script_flagged(self):
        body = "<html><script>alert(1)</script></html>"
        resp_lib.add(resp_lib.GET, "https://example.com", headers=_secure_headers(), body=body, status=200)
        _mock_sensitive_paths()
        result = scan("https://example.com")
        found = [f for f in result.findings if "Inline JavaScript" in f.title]
        assert found


# ---------------------------------------------------------------------------
# 7. URL parameter checks
# ---------------------------------------------------------------------------

class TestURLParams:
    @resp_lib.activate
    def test_password_in_url_flagged(self):
        resp_lib.add(resp_lib.GET, "https://example.com", headers=_secure_headers(), status=200)
        _mock_sensitive_paths()
        result = scan("https://example.com?password=hunter2")
        found = [f for f in result.findings if "Sensitive parameter" in f.title]
        assert found
        assert found[0].severity == "high"

    @resp_lib.activate
    def test_benign_params_not_flagged(self):
        resp_lib.add(resp_lib.GET, "https://example.com", headers=_secure_headers(), status=200)
        _mock_sensitive_paths()
        result = scan("https://example.com?page=2&sort=asc")
        found = [f for f in result.findings if "Sensitive parameter" in f.title]
        assert not found


# ---------------------------------------------------------------------------
# 8. Sensitive paths
# ---------------------------------------------------------------------------

class TestSensitivePaths:
    @resp_lib.activate
    def test_git_exposed(self):
        resp_lib.add(resp_lib.GET, "https://example.com", headers=_secure_headers(), status=200)
        resp_lib.add(resp_lib.GET, "https://example.com/.git/HEAD", status=200, body="ref: refs/heads/main")
        for path in ["/.env", "/wp-login.php", "/admin", "/phpinfo.php",
                     "/server-status", "/actuator", "/swagger-ui.html",
                     "/api/swagger.json", "/.DS_Store"]:
            resp_lib.add(resp_lib.GET, "https://example.com" + path, status=404)
        resp_lib.add(resp_lib.OPTIONS, "https://example.com", status=200, headers={"Allow": "GET, HEAD"})
        result = scan("https://example.com")
        found = [f for f in result.findings if ".git" in f.title]
        assert found
        assert found[0].severity == "critical"

    @resp_lib.activate
    def test_env_file_exposed(self):
        resp_lib.add(resp_lib.GET, "https://example.com", headers=_secure_headers(), status=200)
        resp_lib.add(resp_lib.GET, "https://example.com/.env", status=200, body="DB_PASSWORD=secret")
        for path in ["/.git/HEAD", "/wp-login.php", "/admin", "/phpinfo.php",
                     "/server-status", "/actuator", "/swagger-ui.html",
                     "/api/swagger.json", "/.DS_Store"]:
            resp_lib.add(resp_lib.GET, "https://example.com" + path, status=404)
        resp_lib.add(resp_lib.OPTIONS, "https://example.com", status=200, headers={"Allow": "GET, HEAD"})
        result = scan("https://example.com")
        found = [f for f in result.findings if ".env" in f.title]
        assert found
        assert found[0].severity == "critical"


# ---------------------------------------------------------------------------
# 9. CSP quality
# ---------------------------------------------------------------------------

class TestCSPQuality:
    @resp_lib.activate
    def test_unsafe_inline_csp(self):
        h = {**_secure_headers(), "Content-Security-Policy": "default-src 'self' 'unsafe-inline'"}
        resp_lib.add(resp_lib.GET, "https://example.com", headers=h, status=200)
        _mock_sensitive_paths()
        result = scan("https://example.com")
        found = [f for f in result.findings if "unsafe-inline" in f.title]
        assert found

    @resp_lib.activate
    def test_wildcard_csp_high(self):
        h = {**_secure_headers(), "Content-Security-Policy": "default-src *"}
        resp_lib.add(resp_lib.GET, "https://example.com", headers=h, status=200)
        _mock_sensitive_paths()
        result = scan("https://example.com")
        found = [f for f in result.findings if "wildcard" in f.title.lower() and "CSP" in f.title]
        assert found
        assert found[0].severity == "high"


# ---------------------------------------------------------------------------
# 10. Rate limiting
# ---------------------------------------------------------------------------

class TestRateLimiting:
    @resp_lib.activate
    def test_no_rate_limit_headers_flagged(self):
        resp_lib.add(resp_lib.GET, "https://example.com", headers=_secure_headers(), status=200)
        _mock_sensitive_paths()
        result = scan("https://example.com")
        found = [f for f in result.findings if "rate-limit" in f.title.lower()]
        assert found

    @resp_lib.activate
    def test_rate_limit_headers_not_flagged(self):
        h = {**_secure_headers(), "X-RateLimit-Limit": "100", "X-RateLimit-Remaining": "95"}
        resp_lib.add(resp_lib.GET, "https://example.com", headers=h, status=200)
        _mock_sensitive_paths()
        result = scan("https://example.com")
        found = [f for f in result.findings if "rate-limit" in f.title.lower()]
        assert not found


# ---------------------------------------------------------------------------
# 11. Misc / scoring
# ---------------------------------------------------------------------------

class TestScoring:
    def test_connection_error(self):
        result = scan("https://this-does-not-exist-sentinelai-test.invalid")
        assert result.error is not None

    @resp_lib.activate
    def test_risk_score_increases_with_findings(self):
        resp_lib.add(resp_lib.GET, "https://clean.com", headers=_secure_headers(), status=200)
        _mock_sensitive_paths("https://clean.com")
        resp_lib.add(resp_lib.GET, "https://vuln.com", headers=_minimal_headers(), status=200)
        _mock_sensitive_paths("https://vuln.com")
        assert scan("https://vuln.com").risk_score > scan("https://clean.com").risk_score

    @resp_lib.activate
    def test_response_time_populated(self):
        resp_lib.add(resp_lib.GET, "https://example.com", headers=_minimal_headers(), status=200)
        _mock_sensitive_paths()
        result = scan("https://example.com")
        assert result.response_time_ms is not None and result.response_time_ms >= 0


class TestBuildReport:
    def _make_result(self, findings):
        from scanner.http_scanner import ScanResult
        r = ScanResult(url="https://example.com", status_code=200)
        r.findings = findings
        return r

    def test_empty_grade_a(self):
        r = build_report(self._make_result([]))
        assert r.grade == "A" and r.score == 0.0

    def test_high_findings_degrade_grade(self):
        findings = [Finding("A05:2021", "X", "high", "") for _ in range(3)]
        r = build_report(self._make_result(findings))
        assert r.grade in ("C", "D", "F")

    def test_owasp_categories_listed(self):
        findings = [Finding("A05:2021", "X", "low", ""), Finding("A03:2021", "Y", "high", "")]
        r = build_report(self._make_result(findings))
        ids = [c.split(" — ")[0] for c in r.owasp_categories]
        assert "A05:2021" in ids and "A03:2021" in ids

    def test_breakdown_counts(self):
        findings = [
            Finding("A05:2021", "A", "high", ""),
            Finding("A05:2021", "B", "medium", ""),
            Finding("A05:2021", "C", "medium", ""),
            Finding("A05:2021", "D", "low", ""),
        ]
        r = build_report(self._make_result(findings))
        assert r.breakdown["high"] == 1
        assert r.breakdown["medium"] == 2
        assert r.breakdown["low"] == 1
