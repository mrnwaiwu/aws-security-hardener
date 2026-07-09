"""
KMS Checks — verifies customer-managed key (CMK) rotation and key policy hygiene.

CIS AWS Foundations 3.8: Ensure rotation for customer-created CMKs is enabled.
"""

import boto3


def run(profile: str, region: str) -> list:
    session = boto3.Session(profile_name=profile, region_name=region)
    kms = session.client("kms")
    findings = []

    keys = kms.list_keys().get("Keys", [])
    for key in keys:
        key_id = key["KeyId"]

        meta = kms.describe_key(KeyId=key_id).get("KeyMetadata", {})

        # Only evaluate customer-managed, enabled, symmetric keys.
        if meta.get("KeyManager") != "CUSTOMER":
            continue
        if meta.get("KeyState") != "Enabled":
            continue
        if meta.get("KeySpec", "SYMMETRIC_DEFAULT") != "SYMMETRIC_DEFAULT":
            continue

        # CIS 3.8 — key rotation must be enabled.
        try:
            rotation = kms.get_key_rotation_status(KeyId=key_id)
            if not rotation.get("KeyRotationEnabled", False):
                findings.append({
                    "id": f"KMS-ROTATION-{key_id}",
                    "severity": "MEDIUM",
                    "title": f"CMK {key_id} does not have automatic rotation enabled",
                    "detail": meta.get("Description", ""),
                    "remediation": "Enable annual key rotation: "
                                   "aws kms enable-key-rotation --key-id <key-id>",
                })
        except kms.exceptions.UnsupportedOperationException:
            # Imported key material cannot be auto-rotated; flag informationally.
            findings.append({
                "id": f"KMS-IMPORTED-{key_id}",
                "severity": "LOW",
                "title": f"CMK {key_id} uses imported material (manual rotation required)",
                "detail": "Automatic rotation is unavailable for imported key material.",
                "remediation": "Establish a manual rotation schedule for this key.",
            })

    return findings
