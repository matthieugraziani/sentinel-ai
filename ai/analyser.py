"""
AI analysis layer.

By default uses a deterministic mock so the tool works without an API key.
Set ANTHROPIC_API_KEY in the environment to enable real AI analysis.
"""
from __future__ import annotations

import os
import textwrap
from dataclasses import dataclass

from scanner.http_scanner import ScanResult
from scanner.owasp_scorer import RiskReport


@dataclass
class AIAnalysis:
    executive_summary: str
    top_priority: str
    attack_narrative: str
    remediation_plan: list[str]
    confidence: float   # 0.0 – 1.0
    source: str         # "mock" | "claude"


# ---------------------------------------------------------------------------
# Mock analysis (deterministic, offline)
# ---------------------------------------------------------------------------

def _mock_analysis(result: ScanResult, report: RiskReport) -> AIAnalysis:
    critical = [f for f in result.findings if f.severity == "critical"]
    high = [f for f in result.findings if f.severity == "high"]
    top = (critical or high or result.findings)

    if not result.findings:
        return AIAnalysis(
            executive_summary="The scanned target has a clean security posture with no passive issues detected.",
            top_priority="None — continue monitoring and re-scan periodically.",
            attack_narrative="No exploitable misconfiguration vectors were identified during this scan.",
            remediation_plan=["Schedule periodic re-scans.", "Enable dependency vulnerability alerts."],
            confidence=0.85,
            source="mock",
        )

    top_finding = top[0]
    plan = [
        f"[{f.severity.upper()}] {f.title}: {f.remediation}"
        for f in sorted(result.findings, key=lambda x: ["critical","high","medium","low","info"].index(x.severity))
    ]

    return AIAnalysis(
        executive_summary=(
            f"Scan of {result.url} yielded a risk score of {report.score}/100 (grade {report.grade}). "
            f"{report.summary}"
        ),
        top_priority=f"{top_finding.title} ({top_finding.owasp_id})",
        attack_narrative=(
            f"An attacker targeting {result.url} could leverage {top_finding.title.lower()} "
            f"({top_finding.owasp_id}) to {top_finding.description.lower()} "
            f"This is particularly relevant given the server fingerprint: {result.server or 'unknown'}."
        ),
        remediation_plan=plan[:5],
        confidence=0.72,
        source="mock",
    )


# ---------------------------------------------------------------------------
# Claude-powered analysis (requires ANTHROPIC_API_KEY)
# ---------------------------------------------------------------------------

def _claude_analysis(result: ScanResult, report: RiskReport) -> AIAnalysis:
    try:
        import anthropic  # type: ignore
    except ImportError as exc:
        raise ImportError("Install the 'anthropic' package: pip install anthropic") from exc

    client = anthropic.Anthropic()

    findings_text = "\n".join(
        f"- [{f.severity.upper()}] {f.owasp_id} {f.title}: {f.description}"
        for f in result.findings
    ) or "No findings."

    prompt = textwrap.dedent(f"""
        You are a senior application security engineer.
        Analyse the following passive HTTP scan results and respond in JSON with these keys:
        executive_summary, top_priority, attack_narrative, remediation_plan (list of strings).

        Target: {result.url}
        Status: {result.status_code}
        Risk score: {report.score}/100 (grade {report.grade})
        Server: {result.server or "unknown"}

        Findings:
        {findings_text}

        Respond ONLY with valid JSON, no markdown fences.
    """).strip()

    message = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}],
    )
    import json
    data = json.loads(message.content[0].text)

    return AIAnalysis(
        executive_summary=data.get("executive_summary", ""),
        top_priority=data.get("top_priority", ""),
        attack_narrative=data.get("attack_narrative", ""),
        remediation_plan=data.get("remediation_plan", []),
        confidence=0.92,
        source="claude",
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def analyse(result: ScanResult, report: RiskReport) -> AIAnalysis:
    """
    Return an :class:`AIAnalysis` for *result*.
    Uses Claude if ``ANTHROPIC_API_KEY`` is set, otherwise falls back to mock.
    """
    if os.getenv("ANTHROPIC_API_KEY"):
        try:
            return _claude_analysis(result, report)
        except (ImportError, ValueError) as exc:
            print(f"[ai] Claude analysis failed ({exc}), falling back to mock.")
    return _mock_analysis(result, report)
