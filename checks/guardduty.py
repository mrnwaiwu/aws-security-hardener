"""
GuardDuty Integration — pulls active HIGH/CRITICAL findings.
"""

import boto3


def run(profile: str, region: str) -> list:
    session = boto3.Session(profile_name=profile, region_name=region)
    gd = session.client("guardduty")
    findings = []

    detectors = gd.list_detectors().get("DetectorIds", [])
    if not detectors:
        return [{"id": "GD-DISABLED", "severity": "HIGH",
                 "title": "GuardDuty is not enabled in this region",
                 "remediation": "Enable GuardDuty for continuous threat detection"}]

    detector_id = detectors[0]
    finding_ids = gd.list_findings(
        DetectorId=detector_id,
        FindingCriteria={
            "Criterion": {
                "severity": {"Gte": 7},  # HIGH and CRITICAL
                "service.archived": {"Eq": ["false"]},
            }
        },
    ).get("FindingIds", [])

    if not finding_ids:
        return []

    raw = gd.get_findings(DetectorId=detector_id, FindingIds=finding_ids[:50])
    for f in raw.get("Findings", []):
        severity = "CRITICAL" if f["Severity"] >= 9 else "HIGH"
        findings.append({
            "id": f"GD-{f['Type'].replace('/', '-')}",
            "severity": severity,
            "title": f"GuardDuty: {f['Title']}",
            "detail": f.get("Description", ""),
            "remediation": "Investigate and remediate via AWS GuardDuty console",
        })

    return findings
