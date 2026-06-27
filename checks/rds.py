"""
CIS / AWS Security Best Practices — RDS checks
"""
import boto3
from botocore.exceptions import ClientError


def check_rds_encryption_at_rest(session: boto3.Session) -> list[dict]:
    """CIS 2.3.1 — Ensure RDS instances have encryption at rest enabled."""
    client = session.client("rds")
    findings = []
    paginator = client.get_paginator("describe_db_instances")
    for page in paginator.paginate():
        for db in page["DBInstances"]:
            if not db.get("StorageEncrypted", False):
                findings.append({
                    "check": "CIS-2.3.1",
                    "resource": db["DBInstanceIdentifier"],
                    "status": "FAIL",
                    "detail": "RDS instance does not have storage encryption enabled.",
                    "remediation": (
                        "Enable encryption at rest when creating the DB instance. "
                        "Existing unencrypted instances must be migrated via snapshot."
                    ),
                })
            else:
                findings.append({
                    "check": "CIS-2.3.1",
                    "resource": db["DBInstanceIdentifier"],
                    "status": "PASS",
                    "detail": "RDS instance has storage encryption enabled.",
                })
    return findings


def check_rds_multi_az(session: boto3.Session) -> list[dict]:
    """CIS 2.3.2 — Ensure RDS instances have Multi-AZ enabled for high availability."""
    client = session.client("rds")
    findings = []
    paginator = client.get_paginator("describe_db_instances")
    for page in paginator.paginate():
        for db in page["DBInstances"]:
            # Aurora manages HA differently — skip
            if db.get("Engine", "") in ("aurora", "aurora-mysql", "aurora-postgresql"):
                continue
            if not db.get("MultiAZ", False):
                findings.append({
                    "check": "CIS-2.3.2",
                    "resource": db["DBInstanceIdentifier"],
                    "status": "FAIL",
                    "detail": "RDS instance does not have Multi-AZ enabled.",
                    "remediation": "Enable Multi-AZ in the DB instance settings to improve resilience.",
                })
            else:
                findings.append({
                    "check": "CIS-2.3.2",
                    "resource": db["DBInstanceIdentifier"],
                    "status": "PASS",
                    "detail": "RDS instance has Multi-AZ enabled.",
                })
    return findings


def check_rds_public_access(session: boto3.Session) -> list[dict]:
    """CIS 2.3.3 — Ensure RDS instances are not publicly accessible."""
    client = session.client("rds")
    findings = []
    paginator = client.get_paginator("describe_db_instances")
    for page in paginator.paginate():
        for db in page["DBInstances"]:
            if db.get("PubliclyAccessible", False):
                findings.append({
                    "check": "CIS-2.3.3",
                    "resource": db["DBInstanceIdentifier"],
                    "status": "FAIL",
                    "detail": "RDS instance is publicly accessible.",
                    "remediation": (
                        "Set PubliclyAccessible to false and restrict access "
                        "via VPC security groups and private subnets."
                    ),
                })
            else:
                findings.append({
                    "check": "CIS-2.3.3",
                    "resource": db["DBInstanceIdentifier"],
                    "status": "PASS",
                    "detail": "RDS instance is not publicly accessible.",
                })
    return findings


def check_rds_deletion_protection(session: boto3.Session) -> list[dict]:
    """Ensure RDS instances have deletion protection enabled."""
    client = session.client("rds")
    findings = []
    paginator = client.get_paginator("describe_db_instances")
    for page in paginator.paginate():
        for db in page["DBInstances"]:
            if not db.get("DeletionProtection", False):
                findings.append({
                    "check": "RDS-DEL-PROT",
                    "resource": db["DBInstanceIdentifier"],
                    "status": "FAIL",
                    "detail": "RDS instance does not have deletion protection enabled.",
                    "remediation": "Enable deletion protection to prevent accidental database deletion.",
                })
            else:
                findings.append({
                    "check": "RDS-DEL-PROT",
                    "resource": db["DBInstanceIdentifier"],
                    "status": "PASS",
                    "detail": "RDS instance has deletion protection enabled.",
                })
    return findings


def check_rds_auto_minor_version_upgrade(session: boto3.Session) -> list[dict]:
    """Ensure RDS instances have auto minor version upgrade enabled."""
    client = session.client("rds")
    findings = []
    paginator = client.get_paginator("describe_db_instances")
    for page in paginator.paginate():
        for db in page["DBInstances"]:
            if not db.get("AutoMinorVersionUpgrade", False):
                findings.append({
                    "check": "RDS-AUTO-UPGRADE",
                    "resource": db["DBInstanceIdentifier"],
                    "status": "FAIL",
                    "detail": "RDS instance does not have auto minor version upgrade enabled.",
                    "remediation": (
                        "Enable AutoMinorVersionUpgrade to ensure the instance receives "
                        "security patches during the maintenance window."
                    ),
                })
            else:
                findings.append({
                    "check": "RDS-AUTO-UPGRADE",
                    "resource": db["DBInstanceIdentifier"],
                    "status": "PASS",
                    "detail": "RDS instance has auto minor version upgrade enabled.",
                })
    return findings


def run_all_checks(session: boto3.Session) -> list[dict]:
    """Run all RDS security checks and return combined findings."""
    results = []
    for fn in (
        check_rds_encryption_at_rest,
        check_rds_multi_az,
        check_rds_public_access,
        check_rds_deletion_protection,
        check_rds_auto_minor_version_upgrade,
    ):
        try:
            results.extend(fn(session))
        except ClientError as exc:
            results.append({
                "check": fn.__name__,
                "status": "ERROR",
                "detail": str(exc),
            })
    return results
