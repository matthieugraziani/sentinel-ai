"""
OWASP risk scoring utilities.
Maps raw scan findings to a structured risk report.
"""
from __future__ import annotations

from dataclasses import dataclass

from scanner.http_scanner import ScanResult

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

OWASP_LABELS: dict[str, str] = {
    "A01:2021": "Broken Access Control",
    "A02:2021": "Cryptographic Failures",
    "A03:2021": "Injection",
    "A04:2021": "Insecure Design",
    "A05:2021": "Security Misconfiguration",
    "A06:2021": "Vulnerable and Outdated Components",
    "A07:2021": "Identification and Authentication Failures",
    "A08:2021": "Software and Data Integrity Failures",
    "A09:2021": "Security Logging and Monitoring Failures",
    "A10:2021": "Server-Side Request Forgery",
}


@dataclass
class RiskReport:
    score: float           # 0.0 – 100.0
    grade: str             # A–F
    summary: str
    breakdown: dict[str, int]   # severity → count
    owasp_categories: list[str]


def _grade(score: float) -> str:
    if score == 0:
        return "A"
    if score < 10:
        return "B"
    if score < 25:
        return "C"
    if score < 50:
        return "D"
    return "F"


def build_report(result: ScanResult) -> RiskReport:
    breakdown = dict.fromkeys(SEVERITY_ORDER, 0)
    owasp_seen: set[str] = set()

    for f in result.findings:
        breakdown[f.severity] = breakdown.get(f.severity, 0) + 1
        owasp_seen.add(f.owasp_id)

    owasp_categories = [
        f"{oid} — {OWASP_LABELS.get(oid, 'Unknown')}"
        for oid in sorted(owasp_seen)
    ]

    total = sum(breakdown.values())
    score = result.risk_score
    grade = _grade(score)

    if total == 0:
        summary = "No issues detected. The target appears to follow security best practices."
    elif score < 15:
        summary = f"{total} minor issue(s) found. Low overall exposure."
    elif score < 40:
        summary = f"{total} issue(s) found across {len(owasp_seen)} OWASP categor(y/ies). Moderate risk."
    else:
        summary = (
            f"{total} issue(s) found — {breakdown.get('critical', 0)} critical, "
            f"{breakdown.get('high', 0)} high. Immediate remediation recommended."
        )

    return RiskReport(
        score=score,
        grade=grade,
        summary=summary,
        breakdown=breakdown,
        owasp_categories=owasp_categories,
    )
