# <p align="center">🛡️ SentinelAI </p>

> AI-powered OWASP vulnerability scanner — passive HTTP analysis with zero dependencies beyond `requests`.

<div align="center">

[![CI](https://github.com/matthieugraziani/sentinelai/actions/workflows/ci.yml/badge.svg)](https://github.com/matthieugraziani/sentinelai/actions)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![OWASP Top 10](https://img.shields.io/badge/OWASP-Top%2010%3A2021-red.svg)](https://owasp.org/Top10/)

</div>

---

## What it does ?

SentinelAI scans any HTTP(S) target and surfaces security misconfigurations mapped to the **OWASP Top 10 (2021)**. It works out-of-the-box with a deterministic mock AI engine, and upgrades automatically to real **Claude-powered analysis** when an `ANTHROPIC_API_KEY` is set.

```
$ python cli/run.py https://target.com

  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗      █████╗ ██╗
  ...

  Scanning https://target.com …

────────────────────────────────────────────────────────────
 SCAN RESULTS
────────────────────────────────────────────────────────────
  URL          https://target.com
  Status       200
  Response     212.4 ms
  Risk Score   21.5/100   Grade: C

  OWASP Top-10 coverage:
    ▸ A02:2021 — Cryptographic Failures
    ▸ A03:2021 — Injection
    ▸ A05:2021 — Security Misconfiguration

────────────────────────────────────────────────────────────
 FINDINGS  (5 total)
────────────────────────────────────────────────────────────
  01  [HIGH    ]  Missing HSTS header
       A05:2021  —  HTTP Strict Transport Security is not set.
       Fix: Add: Strict-Transport-Security: max-age=31536000; includeSubDomains
  ...
```

---

## Features

| Feature | Details |
|---|---|
| **Header analysis** | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| **Information disclosure** | Server, X-Powered-By, X-AspNet-Version, X-Generator |
| **HTTPS enforcement** | Detects missing redirects from HTTP |
| **OWASP mapping** | Every finding tagged with its Top-10 (2021) category |
| **Risk scoring** | Weighted 0–100 score + letter grade (A–F) |
| **AI analysis** | Attack narrative, top priority, remediation plan (mock or Claude) |
| **JSON output** | Machine-readable reports via `--output report.json` |
| **CI-ready** | GitHub Actions workflow included |

---

## Quick start

```bash
# Clone
git clone https://github.com/matthieugraziani/sentinelai.git
cd sentinelai

# Install
pip install -r requirements.txt

# Scan
python cli/run.py https://example.com

# Save JSON report
python cli/run.py https://example.com --output report.json

# Skip AI step
python cli/run.py https://example.com --no-ai
```

### Enable real AI analysis (optional)

```bash
pip install anthropic
export ANTHROPIC_API_KEY=sk-ant-...
python cli/run.py https://example.com
```

---

## CLI reference

```
usage: sentinelai [-h] [--output FILE] [--no-ai] [--timeout N] url

positional arguments:
  url             Target URL to scan (e.g. https://example.com)

options:
  --output FILE   Save JSON report to FILE
  --no-ai         Skip AI analysis step
  --timeout N     HTTP timeout in seconds (default: 10)
```

---

## JSON report schema

```json
{
  "url": "https://example.com",
  "timestamp": 1718000000.0,
  "status_code": 200,
  "response_time_ms": 212.4,
  "risk_score": 21.5,
  "grade": "C",
  "owasp_categories": ["A05:2021 — Security Misconfiguration"],
  "findings": [
    {
      "owasp_id": "A05:2021",
      "title": "Missing HSTS header",
      "severity": "high",
      "description": "...",
      "evidence": "Header 'Strict-Transport-Security' absent from response",
      "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    }
  ],
  "ai_analysis": {
    "executive_summary": "...",
    "top_priority": "...",
    "attack_narrative": "...",
    "remediation_plan": ["..."],
    "confidence": 0.92,
    "source": "claude"
  }
}
```

---

## Project structure

```
sentinelai/
├── cli/
│   └── run.py              # CLI entry point
├── scanner/
│   ├── http_scanner.py     # HTTP checks + Finding/ScanResult models
│   └── owasp_scorer.py     # Risk scoring + RiskReport
├── ai/
│   └── analyser.py         # AI analysis (mock + Claude)
├── tests/
│   └── test_scanner.py     # pytest test suite
├── .github/
│   └── workflows/
│       └── ci.yml          # GitHub Actions CI
├── pyproject.toml
├── requirements.txt
└── requirements-dev.txt
```

---

## Development

```bash
pip install -r requirements-dev.txt

# Tests
pytest

# Tests with coverage
pytest --cov=scanner --cov=ai --cov-report=term-missing

# Lint
ruff check .
```

---

## Roadmap

- [ ] Crawl mode (follow links on the same domain)
- [ ] Cookie security analysis (HttpOnly, Secure, SameSite)
- [ ] TLS/certificate checks
- [ ] HTML report output
- [ ] Docker image

---

## Ethical use

SentinelAI performs **passive, read-only** HTTP requests. Only scan targets you own or have explicit permission to test. Unauthorized scanning may violate applicable law.

---

## License

MIT — see [LICENSE](LICENSE).
