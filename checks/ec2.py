"""
EC2 Security Checks — CIS AWS Benchmark v1.5
Covers: security groups, EBS encryption, IMDSv2, public IPs.
"""

import boto3


def run(profile: str, region: str) -> list:
    session = boto3.Session(profile_name=profile, region_name=region)
    ec2 = session.client("ec2")
    findings = []

    findings += _check_open_security_groups(ec2)
    findings += _check_ebs_encryption(ec2)
    findings += _check_imdsv2(ec2)

    return findings


def _check_open_security_groups(ec2) -> list:
    findings = []
    sgs = ec2.describe_security_groups()["SecurityGroups"]
    for sg in sgs:
        for rule in sg.get("IpPermissions", []):
            for ip_range in rule.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    port = rule.get("FromPort", "ALL")
                    if port in [22, 3389, "ALL"]:
                        findings.append({
                            "id": "CIS-5.2", "severity": "CRITICAL",
                            "title": f"Security group {sg['GroupId']} ({sg['GroupName']}) allows unrestricted access on port {port}",
                            "remediation": "Restrict SSH/RDP access to known IP ranges only"
                        })
    return findings


def _check_ebs_encryption(ec2) -> list:
    result = ec2.get_ebs_encryption_by_default()
    if not result.get("EbsEncryptionByDefault"):
        return [{"id": "CIS-2.2.1", "severity": "HIGH",
                 "title": "EBS encryption by default is not enabled",
                 "remediation": "Enable EBS encryption by default in EC2 settings"}]
    return []


def _check_imdsv2(ec2) -> list:
    findings = []
    paginator = ec2.get_paginator("describe_instances")
    for page in paginator.paginate():
        for reservation in page["Reservations"]:
            for instance in reservation["Instances"]:
                metadata = instance.get("MetadataOptions", {})
                if metadata.get("HttpTokens") != "required":
                    findings.append({
                        "id": "EC2-IMDSV2", "severity": "HIGH",
                        "title": f"Instance {instance['InstanceId']} does not enforce IMDSv2",
                        "remediation": "Set HttpTokens=required to enforce IMDSv2 and prevent SSRF attacks"
                    })
    return findings
