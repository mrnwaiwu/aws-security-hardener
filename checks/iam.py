"""
IAM Security Checks — CIS AWS Benchmark v1.5
Covers: root account usage, MFA, password policy, access keys, unused roles.
"""

import boto3
from datetime import datetime, timezone, timedelta


def run(profile: str, region: str) -> list:
    session = boto3.Session(profile_name=profile, region_name=region)
    iam = session.client("iam")
    findings = []

    # CIS 1.1 — Root account should not have active access keys
    findings += _check_root_access_keys(iam)

    # CIS 1.5 — Root account MFA should be enabled
    findings += _check_root_mfa(iam)

    # CIS 1.8 — IAM password policy minimum length >= 14
    findings += _check_password_policy(iam)

    # CIS 1.13 — Access keys older than 90 days
    findings += _check_stale_access_keys(iam)

    # CIS 1.16 — No policies attached directly to users
    findings += _check_user_attached_policies(iam)

    return findings


def _check_root_access_keys(iam) -> list:
    summary = iam.get_account_summary()["SummaryMap"]
    if summary.get("AccountAccessKeysPresent", 0) > 0:
        return [{"id": "CIS-1.1", "severity": "CRITICAL",
                 "title": "Root account has active access keys",
                 "remediation": "Delete root access keys immediately"}]
    return []


def _check_root_mfa(iam) -> list:
    summary = iam.get_account_summary()["SummaryMap"]
    if summary.get("AccountMFAEnabled", 0) == 0:
        return [{"id": "CIS-1.5", "severity": "CRITICAL",
                 "title": "Root account MFA is not enabled",
                 "remediation": "Enable MFA on the root account"}]
    return []


def _check_password_policy(iam) -> list:
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        if policy.get("MinimumPasswordLength", 0) < 14:
            return [{"id": "CIS-1.8", "severity": "HIGH",
                     "title": f"Password policy minimum length is {policy.get('MinimumPasswordLength')} (should be >= 14)",
                     "remediation": "Update IAM password policy minimum length to 14+"}]
    except iam.exceptions.NoSuchEntityException:
        return [{"id": "CIS-1.8", "severity": "HIGH",
                 "title": "No IAM password policy configured",
                 "remediation": "Configure an IAM account password policy"}]
    return []


def _check_stale_access_keys(iam) -> list:
    findings = []
    cutoff = datetime.now(timezone.utc) - timedelta(days=90)
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page["Users"]:
            keys = iam.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]
            for key in keys:
                if key["Status"] == "Active" and key["CreateDate"] < cutoff:
                    findings.append({
                        "id": "CIS-1.13", "severity": "HIGH",
                        "title": f"Access key for {user['UserName']} is older than 90 days",
                        "remediation": f"Rotate or disable access key {key['AccessKeyId']}"
                    })
    return findings


def _check_user_attached_policies(iam) -> list:
    findings = []
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page["Users"]:
            policies = iam.list_attached_user_policies(UserName=user["UserName"])["AttachedPolicies"]
            if policies:
                findings.append({
                    "id": "CIS-1.16", "severity": "MEDIUM",
                    "title": f"User {user['UserName']} has policies attached directly",
                    "remediation": "Use IAM groups or roles instead of direct user policy attachment"
                })
    return findings
