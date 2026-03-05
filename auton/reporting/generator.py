"""Report generator — produces markdown reports from scan results.

Extracts structured findings from Claude's freeform output and formats them
into a professional penetration test report.

Claude formats findings in many different ways:
- "### 1. Finding Title"  or  "### Finding Title"
- "**Severity:** Critical"  or  "**Severity:** 🔴 **CRITICAL**"
- Payloads in ```code blocks``` or inline `backticks`
- Evidence as prose, bullet points, or code blocks
- Sometimes wraps entire report in its own format with emoji headings

The parser must handle all of these gracefully.
"""

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def generate_report(
    target: str,
    output: str,
    findings: list[dict[str, Any]],
    session_id: str,
    cost_usd: float,
    tool_calls: int,
    output_path: Path,
) -> None:
    """Generate a markdown penetration test report.

    Args:
        target: Target URL
        output: Raw output from the agent
        findings: List of detected finding dicts (from controller)
        session_id: Session identifier
        cost_usd: Total API cost
        tool_calls: Number of tool invocations
        output_path: Where to save the report
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Extract structured findings from the raw output
    structured_findings = _extract_findings_from_output(output)

    report_lines = [
        "# Auton Security Scan Report",
        "",
        f"**Target:** {target}",
        f"**Date:** {now}",
        f"**Session:** {session_id}",
        f"**Model Cost:** ${cost_usd:.4f}",
        f"**Tool Invocations:** {tool_calls}",
        "",
        "---",
        "",
    ]

    # Summary
    if structured_findings:
        severity_counts: dict[str, int] = {}
        for f in structured_findings:
            sev = f.get("severity", "Info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        report_lines.append("## Summary")
        report_lines.append("")
        report_lines.append(f"**Total Findings:** {len(structured_findings)}")
        report_lines.append("")
        report_lines.append("| Severity | Count |")
        report_lines.append("|----------|-------|")
        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            if sev in severity_counts:
                report_lines.append(f"| {sev} | {severity_counts[sev]} |")
        report_lines.append("")
        report_lines.append("---")
        report_lines.append("")

        # Individual findings
        report_lines.append("## Findings")
        report_lines.append("")
        for i, finding in enumerate(structured_findings, 1):
            report_lines.append(f"### {i}. {finding.get('title', 'Untitled Finding')}")
            report_lines.append("")
            if finding.get("severity"):
                report_lines.append(f"**Severity:** {finding['severity']}")
            if finding.get("url"):
                report_lines.append(f"**URL:** {finding['url']}")
            report_lines.append("")
            if finding.get("description"):
                report_lines.append(finding["description"])
                report_lines.append("")
            if finding.get("payload"):
                report_lines.append("**Payload:**")
                report_lines.append("```")
                report_lines.append(finding["payload"])
                report_lines.append("```")
                report_lines.append("")
            if finding.get("evidence"):
                report_lines.append("**Evidence:**")
                report_lines.append(finding["evidence"])
                report_lines.append("")
            if finding.get("impact"):
                report_lines.append("**Impact:**")
                report_lines.append(finding["impact"])
                report_lines.append("")
            if finding.get("reproduction"):
                report_lines.append("**Reproduction Steps:**")
                report_lines.append(finding["reproduction"])
                report_lines.append("")
            if finding.get("remediation"):
                report_lines.append("**Remediation:**")
                report_lines.append(finding["remediation"])
                report_lines.append("")
            report_lines.append("---")
            report_lines.append("")
    else:
        report_lines.append("## Summary")
        report_lines.append("")
        report_lines.append("No confirmed vulnerabilities were found during this scan.")
        report_lines.append("")

    # Raw output section (truncated)
    report_lines.append("## Scan Log")
    report_lines.append("")
    report_lines.append("<details>")
    report_lines.append("<summary>Click to expand full scan log</summary>")
    report_lines.append("")
    report_lines.append("```")
    if len(output) > 20000:
        report_lines.append(output[:10000])
        report_lines.append("\n... [truncated] ...\n")
        report_lines.append(output[-5000:])
    else:
        report_lines.append(output)
    report_lines.append("```")
    report_lines.append("")
    report_lines.append("</details>")

    # Write report
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(report_lines), encoding="utf-8")


# ============================================================
# Finding Extraction — Multiple strategies, best one wins
# ============================================================

def _extract_findings_from_output(output: str) -> list[dict[str, Any]]:
    """Extract structured findings from Claude's freeform output.

    Uses multiple extraction strategies and picks the best result.
    """
    strategies = [
        _strategy_numbered_sections,    # "### 1. Finding Title" (most common)
        _strategy_vuln_sections,        # "### Finding Title" with severity markers
        _strategy_confirmed_vulns,      # "CONFIRMED VULNERABILITIES" section
        _strategy_inline_detection,     # Fallback: any mention of vuln found/confirmed
    ]

    best_findings: list[dict[str, Any]] = []

    for strategy in strategies:
        try:
            findings = strategy(output)
            # Pick the strategy that returns the most complete findings
            if _score_findings(findings) > _score_findings(best_findings):
                best_findings = findings
        except Exception:
            continue  # Never crash on parsing — just try next strategy

    return best_findings


def _score_findings(findings: list[dict[str, Any]]) -> int:
    """Score a list of findings by completeness. Higher = better."""
    if not findings:
        return 0
    score = 0
    for f in findings:
        if f.get("title"):
            score += 10
        if f.get("severity") and f["severity"] != "Unknown":
            score += 5
        if f.get("payload"):
            score += 8
        if f.get("evidence"):
            score += 5
        if f.get("description"):
            score += 3
        if f.get("url"):
            score += 2
    return score


def _normalize_severity(text: str) -> str:
    """Normalize severity from Claude's varied formats.

    Handles: 'CRITICAL', '🔴 **CRITICAL**', 'critical', '🟡 Medium', etc.
    """
    # Strip emoji, markdown bold, whitespace
    cleaned = re.sub(r"[🔴🟠🟡🟢⚪\*\s]+", " ", text).strip()
    cleaned_lower = cleaned.lower()

    if "critical" in cleaned_lower:
        return "Critical"
    elif "high" in cleaned_lower:
        return "High"
    elif "medium" in cleaned_lower:
        return "Medium"
    elif "low" in cleaned_lower:
        return "Low"
    elif "info" in cleaned_lower:
        return "Info"
    return "High"  # Default to High if we can't parse


def _extract_section_fields(section: str) -> dict[str, Any]:
    """Extract common fields from a text section."""
    finding: dict[str, Any] = {}

    # === Severity ===
    # Match: "**Severity:** 🔴 **CRITICAL**" or "Severity: Critical" or "**Severity:** High"
    sev_patterns = [
        r"(?i)\*?\*?severity\*?\*?\s*:?\s*[:]?\s*(.*?)(?:\n|$)",
    ]
    for pat in sev_patterns:
        m = re.search(pat, section)
        if m:
            finding["severity"] = _normalize_severity(m.group(1))
            break

    # === URL / Endpoint ===
    url_patterns = [
        r"(?i)\*?\*?(?:affected\s+)?(?:url|endpoint)\*?\*?\s*:?\s*[:]?\s*\n?\s*`?(https?://\S+?)`?\s*(?:\n|$)",
        r"(?i)(?:url|endpoint|affected)\s*:\s*(https?://\S+)",
        r"`(https?://\S+?)`",
    ]
    for pat in url_patterns:
        m = re.search(pat, section)
        if m:
            finding["url"] = m.group(1).rstrip("`").rstrip(")")
            break

    # === Payload ===
    # Try code block first
    payload_match = re.search(
        r"(?i)(?:payload|proof\s+of\s+concept|poc)[:\s]*\n+```[^\n]*\n(.*?)```",
        section, re.DOTALL
    )
    if payload_match:
        finding["payload"] = payload_match.group(1).strip()
    else:
        # Try inline code
        payload_match = re.search(r"(?i)payload[:\s]*`([^`]+)`", section)
        if payload_match:
            finding["payload"] = payload_match.group(1).strip()
        else:
            # Try any URL with obvious XSS/SQLi patterns in it
            payload_url = re.search(
                r"`(https?://\S*(?:alert|script|onerror|onload|SELECT|UNION|javascript:)\S*?)`",
                section, re.IGNORECASE
            )
            if payload_url:
                finding["payload"] = payload_url.group(1)

    # === Evidence ===
    evidence_patterns = [
        r"(?i)\*?\*?evidence\*?\*?[:\s]*\n?(.*?)(?:\n\*\*|\n#{1,3}\s|\n---|\Z)",
        r"(?i)\*?\*?(?:exploitation|verification|result)\*?\*?[:\s]*\n?(.*?)(?:\n\*\*|\n#{1,3}\s|\n---|\Z)",
    ]
    for pat in evidence_patterns:
        m = re.search(pat, section, re.DOTALL)
        if m:
            text = m.group(1).strip()
            if len(text) > 10:  # Skip empty/trivial matches
                finding["evidence"] = text[:500]  # Cap length
                break

    # === Description ===
    desc_patterns = [
        r"(?i)\*?\*?(?:vulnerability\s+)?description\*?\*?[:\s]*\n?(.*?)(?:\n\*\*|\n#{1,3}\s|\n---|\Z)",
        r"(?i)\*?\*?finding\*?\*?[:\s]*\n?(.*?)(?:\n\*\*|\n#{1,3}\s|\n---|\Z)",
    ]
    for pat in desc_patterns:
        m = re.search(pat, section, re.DOTALL)
        if m:
            text = m.group(1).strip()
            if len(text) > 10:
                finding["description"] = text[:500]
                break

    # === Impact ===
    impact_match = re.search(
        r"(?i)\*?\*?impact\*?\*?[:\s]*\n?(.*?)(?:\n\*\*|\n#{1,3}\s|\n---|\Z)",
        section, re.DOTALL
    )
    if impact_match:
        text = impact_match.group(1).strip()
        if len(text) > 10:
            finding["impact"] = text[:500]

    # === CVSS ===
    cvss_match = re.search(r"(?i)CVSS[:\s]*(\d+\.?\d*)", section)
    if cvss_match:
        score = float(cvss_match.group(1))
        if score >= 9.0:
            finding.setdefault("severity", "Critical")
        elif score >= 7.0:
            finding.setdefault("severity", "High")
        elif score >= 4.0:
            finding.setdefault("severity", "Medium")
        else:
            finding.setdefault("severity", "Low")

    # === Remediation ===
    rem_match = re.search(
        r"(?i)\*?\*?(?:remediation|fix|recommendation)s?\*?\*?[:\s]*\n?(.*?)(?:\n#{1,3}\s|\n---|\Z)",
        section, re.DOTALL
    )
    if rem_match:
        text = rem_match.group(1).strip()
        if len(text) > 10:
            finding["remediation"] = text[:500]

    return finding


# ============================================================
# Extraction Strategies
# ============================================================

def _strategy_numbered_sections(output: str) -> list[dict[str, Any]]:
    """Strategy 1: Split on '### N. Title' headings.

    Common format: "### 1. DOM-Based Cross-Site Scripting (XSS)"
    """
    findings: list[dict[str, Any]] = []

    # Match "### 1. Title" or "## 1. Title" with optional emoji
    pattern = r"(?:^|\n)(#{2,3})\s+(\d+)\.\s+(.*?)(?=\n#{2,3}\s+\d+\.|\n#{1,2}\s+(?![\d])|---\n|$)"
    matches = re.findall(pattern, output, re.DOTALL)

    if not matches:
        return []

    # Re-split to get full sections
    sections = re.split(r"\n#{2,3}\s+\d+\.\s+", output)

    for section in sections[1:]:
        lines = section.strip().split("\n")
        if not lines:
            continue

        # Title is the first line
        title = lines[0].strip().rstrip(":")
        # Strip emoji and markdown formatting from title
        title = re.sub(r"^[🔴🟠🟡🟢⚪🔒🚨\s]+", "", title)
        title = re.sub(r"\*+", "", title).strip()

        if not title or len(title) < 3:
            continue

        # Skip non-finding sections
        skip_keywords = ["reproduction", "remediation", "recommendation",
                         "attack scenario", "conclusion", "methodology",
                         "verification artifact", "additional testing",
                         "security configuration"]
        if any(kw in title.lower() for kw in skip_keywords):
            continue

        finding = _extract_section_fields("\n".join(lines[1:]))
        finding["title"] = title

        # If no description was found, use first paragraph
        if not finding.get("description"):
            for line in lines[1:]:
                line = line.strip()
                if line and not line.startswith("**") and not line.startswith("#"):
                    finding["description"] = line[:300]
                    break

        findings.append(finding)

    return findings


def _strategy_vuln_sections(output: str) -> list[dict[str, Any]]:
    """Strategy 2: Split on '### Title' headings that contain vuln keywords."""
    findings: list[dict[str, Any]] = []

    vuln_keywords = [
        "xss", "cross-site", "injection", "sqli", "ssrf", "csrf",
        "redirect", "traversal", "overflow", "rce", "lfi", "rfi",
        "idor", "authentication", "authorization", "disclosure",
        "misconfiguration", "header", "cookie", "session",
        "vulnerability", "insecure", "missing", "disabled",
    ]

    # Split on any ### heading
    sections = re.split(r"\n(#{2,3})\s+([^\n]+)", output)

    # sections comes as: [pre, level, title, content, level, title, content, ...]
    i = 1
    while i < len(sections) - 1:
        title = sections[i + 1].strip()
        content = sections[i + 2] if i + 2 < len(sections) else ""
        i += 3

        # Check if this looks like a vulnerability section
        title_lower = title.lower()
        if not any(kw in title_lower for kw in vuln_keywords):
            continue

        # Strip numbering if present
        title = re.sub(r"^\d+\.\s*", "", title)
        title = re.sub(r"^[🔴🟠🟡🟢⚪🔒🚨\s]+", "", title)
        title = re.sub(r"\*+", "", title).strip()

        if not title or len(title) < 3:
            continue

        finding = _extract_section_fields(content)
        finding["title"] = title
        findings.append(finding)

    return findings


def _strategy_confirmed_vulns(output: str) -> list[dict[str, Any]]:
    """Strategy 3: Look for 'CONFIRMED VULNERABILITIES' section."""
    # Find the confirmed vulnerabilities section
    match = re.search(
        r"(?i)(?:confirmed|verified)\s+vulnerabilit(?:y|ies)(.*?)(?:(?:##?\s+(?:SECURITY CONFIG|ATTACK SCENARIO|REMEDIATION|REPRODUCTION|CONCLUSION))|$)",
        output, re.DOTALL
    )
    if not match:
        return []

    vuln_section = match.group(1)
    # Now extract individual findings from this section
    return _strategy_numbered_sections(vuln_section)


def _strategy_inline_detection(output: str) -> list[dict[str, Any]]:
    """Strategy 4 (fallback): Detect vulnerability mentions anywhere in text."""
    findings: list[dict[str, Any]] = []
    seen_types: set[str] = set()

    vuln_patterns = [
        (r"(?i)(?:reflected|stored|dom-based)?\s*(?:XSS|cross-site\s+scripting)\s+(?:vulnerability|found|confirmed|detected|verified|successful)", "Cross-Site Scripting (XSS)"),
        (r"(?i)SQL\s+injection\s+(?:vulnerability|found|confirmed|detected|verified|successful)", "SQL Injection"),
        (r"(?i)(?:SSRF|server-side\s+request\s+forgery)\s+(?:vulnerability|found|confirmed|detected|verified)", "Server-Side Request Forgery (SSRF)"),
        (r"(?i)command\s+injection\s+(?:vulnerability|found|confirmed|detected|verified)", "Command Injection"),
        (r"(?i)(?:open|unvalidated)\s+redirect\s+(?:vulnerability|found|confirmed|detected|verified)", "Open Redirect"),
        (r"(?i)(?:path|directory)\s+traversal\s+(?:vulnerability|found|confirmed|detected|verified)", "Path Traversal"),
        (r"(?i)(?:IDOR|insecure\s+direct\s+object)\s+(?:reference|vulnerability|found|confirmed)", "Insecure Direct Object Reference (IDOR)"),
        (r"(?i)(?:CSRF|cross-site\s+request\s+forgery)\s+(?:vulnerability|found|confirmed|detected)", "Cross-Site Request Forgery (CSRF)"),
        (r"(?i)(?:authentication|auth)\s+bypass\s+(?:vulnerability|found|confirmed|detected)", "Authentication Bypass"),
        (r"(?i)(?:information|data)\s+(?:disclosure|leak|exposure)\s+(?:vulnerability|found|confirmed|detected)", "Information Disclosure"),
        (r"(?i)(?:missing|disabled|absent)\s+(?:CSP|content.security.policy|X-XSS|security\s+header)", "Missing Security Header"),
    ]

    for pattern, vuln_type in vuln_patterns:
        if vuln_type in seen_types:
            continue
        match = re.search(pattern, output)
        if match:
            seen_types.add(vuln_type)

            # Try to extract a payload near the match
            context_start = max(0, match.start() - 500)
            context_end = min(len(output), match.end() + 1000)
            context = output[context_start:context_end]

            payload = None
            # Look for URLs with payloads
            payload_url = re.search(
                r"`(https?://\S*(?:alert|script|onerror|SELECT|UNION|javascript:)\S*?)`",
                context, re.IGNORECASE
            )
            if payload_url:
                payload = payload_url.group(1)
            else:
                # Look for code blocks
                code_match = re.search(r"```[^\n]*\n(.*?)```", context, re.DOTALL)
                if code_match:
                    payload = code_match.group(1).strip()[:200]

            finding: dict[str, Any] = {
                "title": vuln_type,
                "severity": "High",
                "description": f"Auton detected and confirmed a {vuln_type} vulnerability. See scan log for detailed evidence.",
            }
            if payload:
                finding["payload"] = payload

            findings.append(finding)

    return findings
