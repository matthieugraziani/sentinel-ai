#!/usr/bin/env python3
"""
SentinelAI — CLI entry point.

Usage:
    python cli/run.py https://example.com
    python cli/run.py https://example.com --output report.json
    python cli/run.py https://example.com --no-ai
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Allow running from repo root without installing
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ai.analyser import analyse
from scanner.http_scanner import scan
from scanner.owasp_scorer import SEVERITY_ORDER, build_report

# ANSI colours
_C = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "red": "\033[91m",
    "yellow": "\033[93m",
    "green": "\033[92m",
    "cyan": "\033[96m",
    "grey": "\033[90m",
    "white": "\033[97m",
    "magenta": "\033[95m",
}

SEV_COLOR = {
    "critical": _C["red"],
    "high": _C["red"],
    "medium": _C["yellow"],
    "low": _C["cyan"],
    "info": _C["grey"],
}

GRADE_COLOR = {
    "A": _C["green"],
    "B": _C["green"],
    "C": _C["yellow"],
    "D": _C["yellow"],
    "F": _C["red"],
}


def _c(text: str, color: str) -> str:
    return f"{color}{text}{_C['reset']}"


def _banner() -> None:
    print(f"""
{_C['cyan']}{_C['bold']}
  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗      █████╗ ██╗
  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     ██╔══██╗██║
  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     ███████║██║
  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     ██╔══██║██║
  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗██║  ██║██║
  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝
{_C['reset']}{_C['grey']}  AI-powered OWASP vulnerability scanner  •  github.com/matthieugraziani/sentinelai{_C['reset']}
""")


def _section(title: str) -> None:
    print(f"\n{_C['bold']}{_C['white']}{'─'*60}{_C['reset']}")
    print(f"{_C['bold']} {title}{_C['reset']}")
    print(f"{_C['bold']}{_C['white']}{'─'*60}{_C['reset']}")


def _print_finding(f, index: int) -> None:
    color = SEV_COLOR.get(f.severity, _C["white"])
    sev_label = f.severity.upper().ljust(8)
    print(f"  {_C['grey']}{index:02d}{_C['reset']}  {color}[{sev_label}]{_C['reset']}  {_C['bold']}{f.title}{_C['reset']}")
    print(f"       {_C['grey']}{f.owasp_id}  —  {f.description}{_C['reset']}")
    if f.evidence:
        print(f"       {_C['yellow']}Evidence:{_C['reset']} {f.evidence}")
    if f.remediation:
        print(f"       {_C['green']}Fix:{_C['reset']} {f.remediation}")
    print()


def _print_report(result, report, analysis=None) -> None:
    _section("SCAN RESULTS")
    print(f"  URL          {_C['cyan']}{result.url}{_C['reset']}")
    print(f"  Status       {result.status_code or _c('error', _C['red'])}")
    if result.response_time_ms:
        print(f"  Response     {result.response_time_ms} ms")
    if result.server:
        print(f"  Server       {result.server}")
    if result.error:
        print(f"  {_c('ERROR', _C['red'])}      {result.error}")

    grade_col = GRADE_COLOR.get(report.grade, _C["white"])
    print(f"\n  Risk Score   {_c(str(report.score), grade_col)}/100   Grade: {_c(report.grade, grade_col)}")
    print(f"  Summary      {report.summary}")

    if report.owasp_categories:
        print("\n  OWASP Top-10 coverage:")
        for cat in report.owasp_categories:
            print(f"    {_C['grey']}▸{_C['reset']} {cat}")

    if result.findings:
        _section(f"FINDINGS  ({len(result.findings)} total)")
        for i, f in enumerate(
            sorted(result.findings, key=lambda x: SEVERITY_ORDER.index(x.severity)), start=1
        ):
            _print_finding(f, i)
    else:
        print(f"\n  {_c('✓ No findings — clean result', _C['green'])}")

    if analysis:
        _section("AI ANALYSIS")
        src_label = _c(f"[source: {analysis.source}]", _C["grey"])
        print(f"  {_C['bold']}Executive Summary{_C['reset']}  {src_label}")
        print(f"  {analysis.executive_summary}\n")
        print(f"  {_C['bold']}Top Priority{_C['reset']}")
        print(f"  {_c(analysis.top_priority, _C['red'])}\n")
        print(f"  {_C['bold']}Attack Narrative{_C['reset']}")
        print(f"  {analysis.attack_narrative}\n")
        print(f"  {_C['bold']}Remediation Plan{_C['reset']}")
        for step in analysis.remediation_plan:
            print(f"  {_C['green']}▸{_C['reset']} {step}")

    print()


def _to_dict(result, report, analysis=None) -> dict:
    data: dict = {
        "url": result.url,
        "timestamp": result.timestamp,
        "status_code": result.status_code,
        "response_time_ms": result.response_time_ms,
        "server": result.server,
        "error": result.error,
        "risk_score": report.score,
        "grade": report.grade,
        "summary": report.summary,
        "owasp_categories": report.owasp_categories,
        "breakdown": report.breakdown,
        "findings": [
            {
                "owasp_id": f.owasp_id,
                "title": f.title,
                "severity": f.severity,
                "description": f.description,
                "evidence": f.evidence,
                "remediation": f.remediation,
            }
            for f in result.findings
        ],
    }
    if analysis:
        data["ai_analysis"] = {
            "executive_summary": analysis.executive_summary,
            "top_priority": analysis.top_priority,
            "attack_narrative": analysis.attack_narrative,
            "remediation_plan": analysis.remediation_plan,
            "confidence": analysis.confidence,
            "source": analysis.source,
        }
    return data


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sentinelai",
        description="AI-powered OWASP vulnerability scanner",
    )
    parser.add_argument("url", help="Target URL to scan (e.g. https://example.com)")
    parser.add_argument("--output", "-o", metavar="FILE", help="Save JSON report to FILE")
    parser.add_argument("--no-ai", action="store_true", help="Skip AI analysis step")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout in seconds (default: 10)")
    args = parser.parse_args()

    _banner()
    print(f"  Scanning {_c(args.url, _C['cyan'])} …\n")

    result = scan(args.url, timeout=args.timeout)
    report = build_report(result)
    analysis = None if args.no_ai else analyse(result, report)

    _print_report(result, report, analysis)

    if args.output:
        path = Path(args.output)
        path.write_text(json.dumps(_to_dict(result, report, analysis), indent=2), encoding="utf-8")
        print(f"  {_c('✓', _C['green'])} Report saved to {path}\n")

    sys.exit(1 if result.error else 0)


if __name__ == "__main__":
    main()
