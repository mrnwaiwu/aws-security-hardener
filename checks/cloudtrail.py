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


def run_all_checks(region="us-east-1"):
    """Run all CloudTrail CIS checks and return a list of results."""
    checks = [
        check_cloudtrail_enabled,
        check_cloudtrail_log_validation,
        check_cloudtrail_s3_not_public,
        check_cloudtrail_cloudwatch_integration,
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
