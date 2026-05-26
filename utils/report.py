"""
Report generator — outputs findings as text or JSON.
"""

import json


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLOR = {
    "CRITICAL": "\033[91m",  # red
    "HIGH": "\033[93m",       # yellow
    "MEDIUM": "\033[94m",     # blue
    "LOW": "\033[92m",        # green
}
RESET = "\033[0m"


def generate_report(findings: list, fmt: str = "text") -> str:
    if fmt == "json":
        return json.dumps(findings, indent=2, default=str)

    if not findings:
        return "\n✅ No findings. Your AWS environment looks clean!\n"

    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "LOW"), 9))

    lines = ["\n" + "═" * 60, "  AWS Security Hardener — Findings Report", "═" * 60]
    for f in sorted_findings:
        sev = f.get("severity", "INFO")
        color = SEVERITY_COLOR.get(sev, "")
        lines.append(f"\n{color}[{sev}]{RESET} {f.get('id', '')} — {f.get('title', '')}")
        if f.get("remediation"):
            lines.append(f"  ↳ Fix: {f['remediation']}")

    lines.append("\n" + "═" * 60)
    return "\n".join(lines)
