"""
AWS Security Hardener — CLI entry point
Runs CIS Benchmark checks, GuardDuty findings, and Security Hub summary.
"""

import argparse
import json
import sys
from checks import iam, s3, ec2, guardduty, security_hub
from remediate import auto_remediate
from utils.report import generate_report


def parse_args():
    parser = argparse.ArgumentParser(
        description="AWS Security Hardener — audit and remediate AWS misconfigs"
    )
    parser.add_argument(
        "--profile", default="default", help="AWS CLI profile name"
    )
    parser.add_argument(
        "--region", default="us-east-1", help="AWS region"
    )
    parser.add_argument(
        "--checks",
        nargs="+",
        choices=["iam", "s3", "ec2", "guardduty", "securityhub", "all"],
        default=["all"],
        help="Which checks to run",
    )
    parser.add_argument(
        "--remediate",
        action="store_true",
        help="Auto-remediate fixable findings (use with caution)",
    )
    parser.add_argument(
        "--output",
        choices=["json", "text"],
        default="text",
        help="Output format",
    )
    parser.add_argument(
        "--out-file", default=None, help="Save report to file"
    )
    return parser.parse_args()


def run_checks(args):
    findings = []
    run_all = "all" in args.checks

    if run_all or "iam" in args.checks:
        print("[*] Running IAM checks...")
        findings += iam.run(args.profile, args.region)

    if run_all or "s3" in args.checks:
        print("[*] Running S3 checks...")
        findings += s3.run(args.profile, args.region)

    if run_all or "ec2" in args.checks:
        print("[*] Running EC2 checks...")
        findings += ec2.run(args.profile, args.region)

    if run_all or "guardduty" in args.checks:
        print("[*] Fetching GuardDuty findings...")
        findings += guardduty.run(args.profile, args.region)

    if run_all or "securityhub" in args.checks:
        print("[*] Fetching Security Hub findings...")
        findings += security_hub.run(args.profile, args.region)

    return findings


def main():
    args = parse_args()
    print(f"\n🔒 AWS Security Hardener\n   Profile: {args.profile} | Region: {args.region}\n")

    findings = run_checks(args)

    if args.remediate:
        print("\n[!] Auto-remediation enabled — applying fixes...")
        auto_remediate.fix(findings, args.profile, args.region)

    report = generate_report(findings, fmt=args.output)

    if args.out_file:
        with open(args.out_file, "w") as f:
            f.write(report)
        print(f"\n✅ Report saved to {args.out_file}")
    else:
        print(report)

    critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high = sum(1 for f in findings if f.get("severity") == "HIGH")
    print(f"\nSummary: {len(findings)} findings — {critical} CRITICAL, {high} HIGH\n")

    sys.exit(1 if critical > 0 else 0)


if __name__ == "__main__":
    main()
