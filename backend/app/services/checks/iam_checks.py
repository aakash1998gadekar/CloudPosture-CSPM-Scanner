"""IAM Security Checks - CIS AWS Benchmark v2.0 Section 1"""
from __future__ import annotations

from backend.app.models.schemas import Finding, Severity, CheckStatus, ServiceCategory
from backend.app.services.demo_data import get_iam_data


async def run_iam_checks() -> list[Finding]:
    data = get_iam_data()
    findings = []

    # Check 1.1 - Root account MFA
    findings.append(Finding(
        check_id="IAM-001",
        title="Root Account MFA Enabled",
        description="The root account should have MFA enabled to prevent unauthorized access",
        severity=Severity.CRITICAL,
        status=CheckStatus.FAIL if not data["root_mfa_enabled"] else CheckStatus.PASS,
        service=ServiceCategory.IAM,
        cis_benchmark="CIS 1.5",
        resource="arn:aws:iam::123456789012:root",
        remediation="Enable MFA for the root account via IAM console > Security credentials",
        remediation_cli="# Enable virtual MFA for root (must be done via console)"
    ))

    # Check 1.2 - Root access keys
    findings.append(Finding(
        check_id="IAM-002",
        title="No Root Account Access Keys",
        description="Root account should not have access keys. Use IAM users instead.",
        severity=Severity.CRITICAL,
        status=CheckStatus.FAIL if data["root_access_keys"] else CheckStatus.PASS,
        service=ServiceCategory.IAM,
        cis_benchmark="CIS 1.4",
        resource="arn:aws:iam::123456789012:root",
        remediation="Delete root access keys and create IAM users with least privilege",
        remediation_cli="aws iam delete-access-key --access-key-id <key-id>"
    ))

    # Check 1.3 - Password policy
    policy = data["password_policy"]
    strong_policy = (
        policy.get("MinimumPasswordLength", 0) >= 14
        and policy.get("RequireSymbols", False)
        and policy.get("RequireNumbers", False)
        and policy.get("RequireUppercaseCharacters", False)
        and policy.get("RequireLowercaseCharacters", False)
        and policy.get("MaxPasswordAge", 999) <= 90
    )
    findings.append(Finding(
        check_id="IAM-003",
        title="Strong Password Policy Configured",
        description="Password policy should require minimum 14 chars, symbols, numbers, mixed case, and 90-day rotation",
        severity=Severity.HIGH,
        status=CheckStatus.FAIL if not strong_policy else CheckStatus.PASS,
        service=ServiceCategory.IAM,
        cis_benchmark="CIS 1.8",
        resource="arn:aws:iam::123456789012:account-password-policy",
        remediation="Update password policy: min 14 chars, require symbols/numbers/uppercase/lowercase, max age 90 days",
        remediation_cli="aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters --max-password-age 90"
    ))

    # Check 1.4 - Users without MFA
    for user in data["users_without_mfa"]:
        findings.append(Finding(
            check_id="IAM-004",
            title=f"User '{user}' Has No MFA Enabled",
            description="All IAM users with console access should have MFA enabled",
            severity=Severity.HIGH,
            status=CheckStatus.FAIL,
            service=ServiceCategory.IAM,
            cis_benchmark="CIS 1.10",
            resource=f"arn:aws:iam::123456789012:user/{user}",
            remediation=f"Enable MFA for user '{user}' via IAM console or CLI",
            remediation_cli=f"aws iam enable-mfa-device --user-name {user} --serial-number <mfa-arn> --authentication-code1 <code1> --authentication-code2 <code2>"
        ))

    # Check 1.5 - Unused credentials
    for cred in data["unused_credentials"]:
        findings.append(Finding(
            check_id="IAM-005",
            title=f"Unused Credentials for '{cred['user']}' ({cred['days_unused']} days)",
            description="Credentials unused for 90+ days should be disabled or removed",
            severity=Severity.MEDIUM,
            status=CheckStatus.FAIL,
            service=ServiceCategory.IAM,
            cis_benchmark="CIS 1.12",
            resource=f"arn:aws:iam::123456789012:user/{cred['user']}",
            remediation=f"Disable or delete credentials for '{cred['user']}' — unused for {cred['days_unused']} days",
            remediation_cli=f"aws iam update-access-key --user-name {cred['user']} --access-key-id <key-id> --status Inactive"
        ))

    # Check 1.6 - Overpermissive policies
    for policy_info in data["overpermissive_policies"]:
        findings.append(Finding(
            check_id="IAM-006",
            title=f"Overpermissive Policy: '{policy_info['name']}'",
            description="Policies with Action: * and Resource: * grant full access — violates least privilege",
            severity=Severity.HIGH,
            status=CheckStatus.FAIL,
            service=ServiceCategory.IAM,
            cis_benchmark="CIS 1.16",
            resource=f"arn:aws:iam::123456789012:policy/{policy_info['name']}",
            remediation="Replace wildcard permissions with specific actions and resources needed",
            remediation_cli="# Review and scope down policy permissions"
        ))

    # Check 1.7 - Access key rotation
    for key_info in data["old_access_keys"]:
        findings.append(Finding(
            check_id="IAM-007",
            title=f"Access Key Not Rotated for '{key_info['user']}' ({key_info['age_days']} days)",
            description="Access keys should be rotated every 90 days",
            severity=Severity.MEDIUM,
            status=CheckStatus.FAIL,
            service=ServiceCategory.IAM,
            cis_benchmark="CIS 1.14",
            resource=f"arn:aws:iam::123456789012:user/{key_info['user']}",
            remediation=f"Rotate access key for '{key_info['user']}' — key is {key_info['age_days']} days old",
            remediation_cli=f"aws iam create-access-key --user-name {key_info['user']}"
        ))

    return findings
