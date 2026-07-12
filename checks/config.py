"""
AWS Config — verifies a Config recorder is enabled and delivering.

CIS AWS Foundations Benchmark 3.5: Ensure AWS Config is enabled in all regions.
A running recorder with an active delivery channel is required so that
resource configuration changes are captured for audit and drift detection.
"""

import boto3


def run(profile: str, region: str) -> list:
    session = boto3.Session(profile_name=profile, region_name=region)
    cfg = session.client("config")
    findings = []

    recorders = cfg.describe_configuration_recorders().get(
        "ConfigurationRecorders", []
    )
    if not recorders:
        return [{
            "id": "CONFIG-NO-RECORDER",
            "severity": "HIGH",
            "title": "AWS Config has no configuration recorder in this region",
            "remediation": "Create a Config recorder capturing all supported "
                           "resource types and enable global resource recording",
        }]

    statuses = {
        s["name"]: s
        for s in cfg.describe_configuration_recorder_status().get(
            "ConfigurationRecordersStatus", []
        )
    }

    for rec in recorders:
        name = rec["name"]
        status = statuses.get(name, {})
        group = rec.get("recordingGroup", {})

        if not status.get("recording", False):
            findings.append({
                "id": f"CONFIG-RECORDER-STOPPED-{name}",
                "severity": "HIGH",
                "title": f"Config recorder '{name}' is not recording",
                "remediation": "Start the recorder so configuration changes are captured",
            })

        last_status = status.get("lastStatus")
        if last_status and last_status != "SUCCESS":
            findings.append({
                "id": f"CONFIG-DELIVERY-FAIL-{name}",
                "severity": "MEDIUM",
                "title": f"Config recorder '{name}' last delivery status: {last_status}",
                "remediation": "Check the delivery channel S3 bucket policy and permissions",
            })

        records_all = group.get("allSupported", False)
        includes_global = group.get("includeGlobalResourceTypes", False)
        if not records_all:
            findings.append({
                "id": f"CONFIG-PARTIAL-COVERAGE-{name}",
                "severity": "MEDIUM",
                "title": f"Config recorder '{name}' is not recording all supported resource types",
                "remediation": "Set recordingGroup.allSupported = true for complete coverage",
            })
        if not includes_global:
            findings.append({
                "id": f"CONFIG-NO-GLOBAL-{name}",
                "severity": "LOW",
                "title": f"Config recorder '{name}' excludes global resource types (IAM, etc.)",
                "remediation": "Enable includeGlobalResourceTypes in at least one region",
            })

    return findings
