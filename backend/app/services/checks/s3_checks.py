"""S3 Security Checks - CIS AWS Benchmark v2.0 Section 2"""
from __future__ import annotations

from backend.app.models.schemas import Finding, Severity, CheckStatus, ServiceCategory
from backend.app.services.demo_data import get_s3_data


async def run_s3_checks() -> list[Finding]:
    data = get_s3_data()
    findings = []

    for bucket in data["buckets"]:
        name = bucket["name"]
        arn = f"arn:aws:s3:::{name}"

        # Check 2.1 - Public access
        if bucket.get("public_access"):
            findings.append(Finding(
                check_id="S3-001",
                title=f"Bucket '{name}' Has Public Access",
                description="S3 buckets should not allow public access unless explicitly required",
                severity=Severity.CRITICAL,
                status=CheckStatus.FAIL,
                service=ServiceCategory.S3,
                cis_benchmark="CIS 2.1.5",
                resource=arn,
                remediation=f"Enable S3 Block Public Access for bucket '{name}'",
                remediation_cli=f"aws s3api put-public-access-block --bucket {name} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
            ))
        else:
            findings.append(Finding(
                check_id="S3-001",
                title=f"Bucket '{name}' Public Access Blocked",
                description="S3 bucket has public access blocked correctly",
                severity=Severity.CRITICAL,
                status=CheckStatus.PASS,
                service=ServiceCategory.S3,
                cis_benchmark="CIS 2.1.5",
                resource=arn,
                remediation="No action needed"
            ))

        # Check 2.2 - Encryption
        if not bucket.get("encryption_enabled"):
            findings.append(Finding(
                check_id="S3-002",
                title=f"Bucket '{name}' Not Encrypted",
                description="S3 buckets should have default encryption enabled (SSE-S3 or SSE-KMS)",
                severity=Severity.HIGH,
                status=CheckStatus.FAIL,
                service=ServiceCategory.S3,
                cis_benchmark="CIS 2.1.1",
                resource=arn,
                remediation=f"Enable default encryption for bucket '{name}'",
                remediation_cli=f"aws s3api put-bucket-encryption --bucket {name} --server-side-encryption-configuration '{{\"Rules\":[{{\"ApplyServerSideEncryptionByDefault\":{{\"SSEAlgorithm\":\"AES256\"}}}}]}}'"
            ))
        else:
            findings.append(Finding(
                check_id="S3-002",
                title=f"Bucket '{name}' Encryption Enabled",
                description="S3 bucket has default encryption configured",
                severity=Severity.HIGH,
                status=CheckStatus.PASS,
                service=ServiceCategory.S3,
                cis_benchmark="CIS 2.1.1",
                resource=arn,
                remediation="No action needed"
            ))

        # Check 2.3 - Versioning
        if not bucket.get("versioning_enabled"):
            findings.append(Finding(
                check_id="S3-003",
                title=f"Bucket '{name}' Versioning Disabled",
                description="S3 bucket versioning should be enabled for data protection",
                severity=Severity.MEDIUM,
                status=CheckStatus.FAIL,
                service=ServiceCategory.S3,
                cis_benchmark="CIS 2.1.3",
                resource=arn,
                remediation=f"Enable versioning for bucket '{name}'",
                remediation_cli=f"aws s3api put-bucket-versioning --bucket {name} --versioning-configuration Status=Enabled"
            ))
        else:
            findings.append(Finding(
                check_id="S3-003",
                title=f"Bucket '{name}' Versioning Enabled",
                description="S3 bucket versioning is properly configured",
                severity=Severity.MEDIUM,
                status=CheckStatus.PASS,
                service=ServiceCategory.S3,
                cis_benchmark="CIS 2.1.3",
                resource=arn,
                remediation="No action needed"
            ))

        # Check 2.4 - Access logging
        if not bucket.get("logging_enabled"):
            findings.append(Finding(
                check_id="S3-004",
                title=f"Bucket '{name}' Access Logging Disabled",
                description="S3 bucket access logging should be enabled for audit trail",
                severity=Severity.MEDIUM,
                status=CheckStatus.FAIL,
                service=ServiceCategory.S3,
                cis_benchmark="CIS 2.1.2",
                resource=arn,
                remediation=f"Enable access logging for bucket '{name}'",
                remediation_cli=f"aws s3api put-bucket-logging --bucket {name} --bucket-logging-status '{{\"LoggingEnabled\":{{\"TargetBucket\":\"logging-bucket\",\"TargetPrefix\":\"{name}/\"}}}}'"
            ))
        else:
            findings.append(Finding(
                check_id="S3-004",
                title=f"Bucket '{name}' Access Logging Enabled",
                description="S3 bucket has access logging configured",
                severity=Severity.MEDIUM,
                status=CheckStatus.PASS,
                service=ServiceCategory.S3,
                cis_benchmark="CIS 2.1.2",
                resource=arn,
                remediation="No action needed"
            ))

    return findings
