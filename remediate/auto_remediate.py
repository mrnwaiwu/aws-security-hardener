"""
Auto-remediation for fixable findings.
Only runs when --remediate flag is passed explicitly.
"""

import boto3


REMEDIABLE = {
    "CIS-2.2.1",   # EBS encryption by default
    "EC2-IMDSV2",  # IMDSv2 enforcement
}


def fix(findings: list, profile: str, region: str):
    session = boto3.Session(profile_name=profile, region_name=region)
    ec2 = session.client("ec2")

    for finding in findings:
        fid = finding.get("id")

        if fid == "CIS-2.2.1":
            _enable_ebs_encryption(ec2)

        elif fid == "EC2-IMDSV2":
            instance_id = _extract_instance_id(finding.get("title", ""))
            if instance_id:
                _enforce_imdsv2(ec2, instance_id)


def _enable_ebs_encryption(ec2):
    ec2.enable_ebs_encryption_by_default()
    print("  [✓] Enabled EBS encryption by default")


def _enforce_imdsv2(ec2, instance_id: str):
    ec2.modify_instance_metadata_options(
        InstanceId=instance_id,
        HttpTokens="required",
        HttpEndpoint="enabled",
    )
    print(f"  [✓] Enforced IMDSv2 on {instance_id}")


def _extract_instance_id(title: str) -> str:
    """Parse instance ID from finding title string."""
    parts = title.split()
    for part in parts:
        if part.startswith("i-"):
            return part
    return ""
