"""Report generator — produces markdown reports from scan results.

Extracts structured findings from Claude's output and formats them
into a professional penetration test report.
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
        findings: List of detected finding dicts
        session_id: Session identifier
        cost_usd: Total API cost
        tool_calls: Number of tool invocations
        output_path: Where to save the report
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Extract structured findings from the raw output
    structured_findings = _extract_findings_from_output(output)

    report_lines = [
        f"# Auton Security Scan Report",
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
        severity_counts = {}
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
            report_lines.append(f"### {i}. {finding.get('title', 'Untitled')}")
            report_lines.append("")
            report_lines.append(f"**Severity:** {finding.get('severity', 'Unknown')}")
            if finding.get("url"):
                report_lines.append(f"**URL:** {finding['url']}")
            report_lines.append("")
            if finding.get("description"):
                report_lines.append(finding["description"])
                report_lines.append("")
            if finding.get("payload"):
                report_lines.append("**Payload:**")
                report_lines.append(f"```")
                report_lines.append(finding["payload"])
                report_lines.append(f"```")
                report_lines.append("")
            if finding.get("evidence"):
                report_lines.append("**Evidence:**")
                report_lines.append(finding["evidence"])
                report_lines.append("")
            if finding.get("reproduction"):
                report_lines.append("**Reproduction Steps:**")
                report_lines.append(finding["reproduction"])
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
    # Truncate if too long
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


def _extract_findings_from_output(output: str) -> list[dict[str, Any]]:
    """Try to extract structured findings from Claude's freeform output.

    Looks for patterns like:
    - "Vulnerability: <title>" sections
    - "Severity: High" markers
    - "Payload: <code>" blocks
    - "Evidence: <description>" blocks
    """
    findings: list[dict[str, Any]] = []

    # Pattern 1: Look for "### N. <title>" style sections (Claude often formats this way)
    sections = re.split(r"(?:^|\n)#+\s+\d+\.\s+", output)

    for section in sections[1:]:  # Skip text before first heading
        finding: dict[str, Any] = {}

        # Extract title (first line)
        lines = section.strip().split("\n")
        if lines:
            finding["title"] = lines[0].strip().rstrip(":")

        # Extract severity
        sev_match = re.search(
            r"(?i)\*?\*?severity\*?\*?:\s*(critical|high|medium|low|info)",
            section,
        )
        if sev_match:
            finding["severity"] = sev_match.group(1).capitalize()

        # Extract URL
        url_match = re.search(
            r"(?i)(?:url|endpoint|affected):\s*(https?://\S+)", section
        )
        if url_match:
            finding["url"] = url_match.group(1)

        # Extract payload (often in code blocks)
        payload_match = re.search(r"(?i)payload[:\s]*\n?```\n?(.*?)\n?```", section, re.DOTALL)
        if payload_match:
            finding["payload"] = payload_match.group(1).strip()
        else:
            # Try inline payload
            payload_match = re.search(r"(?i)payload[:\s]*`([^`]+)`", section)
            if payload_match:
                finding["payload"] = payload_match.group(1).strip()

        # Extract evidence
        evidence_match = re.search(
            r"(?i)evidence[:\s]*\n?(.*?)(?:\n(?:#+|\*\*)|$)",
            section,
            re.DOTALL,
        )
        if evidence_match:
            finding["evidence"] = evidence_match.group(1).strip()

        # Extract description
        desc_match = re.search(
            r"(?i)description[:\s]*\n?(.*?)(?:\n(?:#+|\*\*)|$)",
            section,
            re.DOTALL,
        )
        if desc_match:
            finding["description"] = desc_match.group(1).strip()

        if finding.get("title"):
            findings.append(finding)

    # If no structured findings found, check for inline vulnerability mentions
    if not findings:
        vuln_patterns = [
            (r"(?i)(XSS|cross-site scripting)\s+(?:vulnerability|found|confirmed)", "XSS"),
            (r"(?i)(SQL injection)\s+(?:found|confirmed|detected)", "SQL Injection"),
            (r"(?i)(SSRF|server-side request forgery)\s+(?:found|confirmed)", "SSRF"),
            (r"(?i)(command injection)\s+(?:found|confirmed)", "Command Injection"),
            (r"(?i)(open redirect)\s+(?:found|confirmed)", "Open Redirect"),
        ]
        for pattern, vuln_type in vuln_patterns:
            if re.search(pattern, output):
                findings.append({
                    "title": f"{vuln_type} Detected",
                    "severity": "High",
                    "description": f"Claude detected a {vuln_type} vulnerability. See scan log for details.",
                })

    return findings
