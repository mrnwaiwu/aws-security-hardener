"""
checks/cloudtrail.py

CIS AWS Foundations Benchmark checks for CloudTrail.
Covers CIS controls 2.1 – 2.7.
"""

import boto3
from botocore.exceptions import ClientError


def get_client(region="us-east-1"):
    return boto3.client("cloudtrail", region_name=region)


def check_cloudtrail_enabled(region="us-east-1"):
    """CIS 2.1 – Ensure CloudTrail is enabled in all regions."""
    client = get_client(region)
    trails = client.describe_trails(includeShadowTrails=True).get("trailList", [])
    multi_region = [t for t in trails if t.get("IsMultiRegionTrail")]
    passed = len(multi_region) > 0
    return {
        "check": "CIS 2.1 - CloudTrail enabled in all regions",
        "passed": passed,
        "detail": f"{len(multi_region)} multi-region trail(s) found" if passed
                  else "No multi-region CloudTrail trail found",
    }


def check_cloudtrail_log_validation(region="us-east-1"):
    """CIS 2.2 – Ensure CloudTrail log file validation is enabled."""
    client = get_client(region)
    trails = client.describe_trails(includeShadowTrails=False).get("trailList", [])
    failing = [t["Name"] for t in trails if not t.get("LogFileValidationEnabled")]
    passed = len(failing) == 0
    return {
        "check": "CIS 2.2 - CloudTrail log file validation enabled",
        "passed": passed,
        "detail": "All trails have log file validation enabled" if passed
                  else f"Trails without validation: {', '.join(failing)}",
    }


def check_cloudtrail_s3_not_public(region="us-east-1"):
    """CIS 2.3 – Ensure the S3 bucket used by CloudTrail is not publicly accessible."""
    ct_client = get_client(region)
    s3_client = boto3.client("s3")
    trails = ct_client.describe_trails(includeShadowTrails=False).get("trailList", [])
    public_buckets = []
    for trail in trails:
        bucket = trail.get("S3BucketName")
        if not bucket:
            continue
        try:
            acl = s3_client.get_bucket_acl(Bucket=bucket)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                if grantee.get("URI", "").endswith(("AllUsers", "AuthenticatedUsers")):
                    public_buckets.append(bucket)
                    break
        except ClientError:
            pass
    passed = len(public_buckets) == 0
    return {
        "check": "CIS 2.3 - CloudTrail S3 bucket not publicly accessible",
        "passed": passed,
        "detail": "No public CloudTrail buckets found" if passed
                  else f"Public buckets: {', '.join(public_buckets)}",
    }


def check_cloudtrail_cloudwatch_integration(region="us-east-1"):
    """CIS 2.4 – Ensure CloudTrail trails are integrated with CloudWatch Logs."""
    client = get_client(region)
    trails = client.describe_trails(includeShadowTrails=False).get("trailList", [])
    failing = [
        t["Name"] for t in trails
        if not t.get("CloudWatchLogsLogGroupArn")
    ]
    passed = len(failing) == 0
    return {
        "check": "CIS 2.4 - CloudTrail integrated with CloudWatch Logs",
        "passed": passed,
        "detail": "All trails stream to CloudWatch Logs" if passed
                  else f"Trails missing CloudWatch integration: {', '.join(failing)}",
    }


def check_cloudtrail_s3_access_logging(region="us-east-1"):
    """CIS 2.5 – Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket."""
    ct_client = get_client(region)
    s3_client = boto3.client("s3")
    trails = ct_client.describe_trails(includeShadowTrails=False).get("trailList", [])
    failing = []
    for trail in trails:
        bucket = trail.get("S3BucketName")
        if not bucket:
            continue
        try:
            response = s3_client.get_bucket_logging(Bucket=bucket)
            if not response.get("LoggingEnabled"):
                failing.append(bucket)
        except ClientError:
            failing.append(bucket)
    passed = len(failing) == 0
    return {
        "check": "CIS 2.5 - S3 access logging enabled on CloudTrail bucket",
        "passed": passed,
        "detail": "All CloudTrail S3 buckets have access logging enabled" if passed
                  else f"Buckets without access logging: {', '.join(failing)}",
    }


def check_cloudtrail_encryption_at_rest(region="us-east-1"):
    """CIS 2.6 – Ensure CloudTrail logs are encrypted at rest using KMS CMKs."""
    client = get_client(region)
    trails = client.describe_trails(includeShadowTrails=False).get("trailList", [])
    failing = [
        t["Name"] for t in trails
        if not t.get("KMSKeyId")
    ]
    passed = len(failing) == 0
    return {
        "check": "CIS 2.6 - CloudTrail logs encrypted at rest with KMS CMK",
        "passed": passed,
        "detail": "All trails use KMS CMK encryption" if passed
                  else f"Trails without KMS encryption: {', '.join(failing)}",
    }


def check_cloudtrail_kms_key_rotation(region="us-east-1"):
    """CIS 2.7 – Ensure rotation for customer-created KMS CMKs is enabled."""
    ct_client = get_client(region)
    kms_client = boto3.client("kms", region_name=region)
    trails = ct_client.describe_trails(includeShadowTrails=False).get("trailList", [])
    failing = []
    seen_keys = set()
    for trail in trails:
        key_id = trail.get("KMSKeyId")
        if not key_id or key_id in seen_keys:
            continue
        seen_keys.add(key_id)
        try:
            response = kms_client.get_key_rotation_status(KeyId=key_id)
            if not response.get("KeyRotationEnabled"):
                failing.append(key_id)
        except ClientError:
            # AWS-managed keys do not support rotation status check; skip
            pass
    passed = len(failing) == 0
    return {
        "check": "CIS 2.7 - KMS CMK rotation enabled for CloudTrail keys",
        "passed": passed,
        "detail": "All CloudTrail KMS CMKs have key rotation enabled" if passed
                  else f"Keys without rotation enabled: {', '.join(failing)}",
    }


def run_all_checks(region="us-east-1"):
    """Run all CloudTrail CIS checks and return a list of results."""
    checks = [
        check_cloudtrail_enabled,
        check_cloudtrail_log_validation,
        check_cloudtrail_s3_not_public,
        check_cloudtrail_cloudwatch_integration,
        check_cloudtrail_s3_access_logging,
        check_cloudtrail_encryption_at_rest,
        check_cloudtrail_kms_key_rotation,
    ]
    results = []
    for check_fn in checks:
        try:
            results.append(check_fn(region))
        except Exception as exc:  # noqa: BLE001
            results.append({
                "check": check_fn.__doc__.split("–")[0].strip(),
                "passed": False,
                "detail": f"Error running check: {exc}",
            })
    return results


if __name__ == "__main__":
    import json
    print(json.dumps(run_all_checks(), indent=2))
