"""
AWS Security Hub Integration — pulls active CRITICAL/HIGH findings.
"""

import boto3


def run(profile: str, region: str) -> list:
    session = boto3.Session(profile_name=profile, region_name=region)
    hub = session.client("securityhub")
    findings = []

    try:
        raw = hub.get_findings(
            Filters={
                "SeverityLabel": [
                    {"Value": "CRITICAL", "Comparison": "EQUALS"},
                    {"Value": "HIGH", "Comparison": "EQUALS"},
                ],
                "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
            },
            MaxResults=50,
        ).get("Findings", [])

        for f in raw:
            findings.append({
                "id": f"SH-{f.get('Id', '')[:16]}",
                "severity": f.get("Severity", {}).get("Label", "HIGH"),
                "title": f.get("Title", "Security Hub finding"),
                "detail": f.get("Description", ""),
                "remediation": f.get("Remediation", {}).get("Recommendation", {}).get("Text", "Review in Security Hub"),
            })

    except hub.exceptions.InvalidAccessException:
        findings.append({
            "id": "SH-DISABLED", "severity": "HIGH",
            "title": "AWS Security Hub is not enabled",
            "remediation": "Enable Security Hub and subscribe to CIS AWS Foundations standard"
        })

    return findings
