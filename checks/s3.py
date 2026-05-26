"""
S3 Security Checks — CIS AWS Benchmark v1.5
Covers: public buckets, encryption, versioning, logging, ACLs.
"""

import boto3


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
