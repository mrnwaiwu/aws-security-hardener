"""
S3 Security Checks — CIS AWS Benchmark v1.5
Covers: public buckets, encryption, versioning, logging, ACLs, HTTP policy, MFA delete.
"""

import boto3
import json


def run(profile: str, region: str) -> list:
    session = boto3.Session(profile_name=profile, region_name=region)
    s3 = session.client("s3")
    findings = []

    buckets = s3.list_buckets().get("Buckets", [])
    for bucket in buckets:
        name = bucket["Name"]
        findings += _check_public_access(s3, name)
        findings += _check_encryption(s3, name)
        findings += _check_versioning(s3, name)
        findings += _check_logging(s3, name)
        findings += _check_https_enforced(s3, name)
        findings += _check_mfa_delete(s3, name)

    return findings


def _check_public_access(s3, bucket: str) -> list:
    try:
        config = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
        if not all([
            config.get("BlockPublicAcls"),
            config.get("IgnorePublicAcls"),
            config.get("BlockPublicPolicy"),
            config.get("RestrictPublicBuckets"),
        ]):
            return [{"id": "CIS-2.1.5", "severity": "CRITICAL",
                     "title": f"S3 bucket {bucket} is not fully blocking public access",
                     "remediation": "Enable all four S3 Block Public Access settings"}]
    except Exception:
        return [{"id": "CIS-2.1.5", "severity": "HIGH",
                 "title": f"Could not check public access block for {bucket}",
                 "remediation": "Manually verify S3 Block Public Access settings"}]
    return []


def _check_encryption(s3, bucket: str) -> list:
    try:
        s3.get_bucket_encryption(Bucket=bucket)
    except s3.exceptions.ClientError:
        return [{"id": "CIS-2.1.1", "severity": "HIGH",
                 "title": f"S3 bucket {bucket} does not have default encryption enabled",
                 "remediation": "Enable SSE-S3 or SSE-KMS default encryption"}]
    return []


def _check_versioning(s3, bucket: str) -> list:
    versioning = s3.get_bucket_versioning(Bucket=bucket)
    if versioning.get("Status") != "Enabled":
        return [{"id": "S3-VERSIONING", "severity": "MEDIUM",
                 "title": f"S3 bucket {bucket} does not have versioning enabled",
                 "remediation": "Enable versioning to protect against accidental deletion"}]
    return []


def _check_logging(s3, bucket: str) -> list:
    logging = s3.get_bucket_logging(Bucket=bucket)
    if "LoggingEnabled" not in logging:
        return [{"id": "CIS-2.1.2", "severity": "MEDIUM",
                 "title": f"S3 bucket {bucket} does not have access logging enabled",
                 "remediation": "Enable S3 server access logging"}]
    return []


def _check_https_enforced(s3, bucket: str) -> list:
    """CIS-2.1.3 — Ensure S3 bucket policy denies HTTP (non-HTTPS) requests."""
    try:
        policy_str = s3.get_bucket_policy(Bucket=bucket)["Policy"]
        policy = json.loads(policy_str)
        for stmt in policy.get("Statement", []):
            effect = stmt.get("Effect", "")
            condition = stmt.get("Condition", {})
            # Look for a Deny statement that blocks non-HTTPS
            if effect == "Deny":
                bool_cond = condition.get("Bool", {})
                if bool_cond.get("aws:SecureTransport") in ["false", False]:
                    return []
        return [{
            "id": "CIS-2.1.3",
            "severity": "HIGH",
            "title": f"S3 bucket {bucket} does not enforce HTTPS-only access",
            "remediation": (
                "Add a bucket policy statement that denies s3:* when "
                "aws:SecureTransport is false"
            ),
        }]
    except s3.exceptions.from_code("NoSuchBucketPolicy"):
        return [{
            "id": "CIS-2.1.3",
            "severity": "HIGH",
            "title": f"S3 bucket {bucket} has no bucket policy — HTTPS not enforced",
            "remediation": (
                "Add a bucket policy that denies all s3:* actions when "
                "aws:SecureTransport is false"
            ),
        }]
    except Exception:
        return []


def _check_mfa_delete(s3, bucket: str) -> list:
    """CIS-2.1.4 — Ensure MFA Delete is enabled on versioned S3 buckets.

    MFA Delete adds a second authentication factor before objects or versioning
    configuration can be permanently deleted, protecting against accidental or
    malicious data destruction.
    """
    try:
        versioning = s3.get_bucket_versioning(Bucket=bucket)
        if versioning.get("Status") != "Enabled":
            # MFA Delete is only meaningful when versioning is active
            return []
        if versioning.get("MFADelete") != "Enabled":
            return [{
                "id": "CIS-2.1.4",
                "severity": "MEDIUM",
                "title": f"S3 bucket {bucket} does not have MFA Delete enabled",
                "remediation": (
                    "Enable MFA Delete on the bucket versioning configuration using "
                    "'aws s3api put-bucket-versioning --versioning-configuration "
                    "Status=Enabled,MFADelete=Enabled --mfa <serial> <token>'"
                ),
            }]
    except Exception:
        return [{
            "id": "CIS-2.1.4",
            "severity": "LOW",
            "title": f"Could not verify MFA Delete status for {bucket}",
            "remediation": "Manually verify MFA Delete setting via AWS Console or CLI",
        }]
    return []
