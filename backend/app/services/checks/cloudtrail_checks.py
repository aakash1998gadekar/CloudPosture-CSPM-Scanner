"""CloudTrail Security Checks - CIS AWS Benchmark v2.0 Section 3"""
from __future__ import annotations

from backend.app.models.schemas import Finding, Severity, CheckStatus, ServiceCategory
from backend.app.services.demo_data import get_cloudtrail_data


async def run_cloudtrail_checks() -> list[Finding]:
    data = get_cloudtrail_data()
    findings = []

    # Check 3.1 - CloudTrail enabled in all regions
    if not data.get("multi_region_enabled"):
        findings.append(Finding(
            check_id="CT-001",
            title="CloudTrail Not Enabled in All Regions",
            description="CloudTrail should be enabled in all regions to capture global activity",
            severity=Severity.CRITICAL,
            status=CheckStatus.FAIL,
            service=ServiceCategory.CLOUDTRAIL,
            cis_benchmark="CIS 3.1",
            resource="arn:aws:cloudtrail:us-east-1:123456789012:trail/management-trail",
            remediation="Enable multi-region CloudTrail to capture API activity across all regions",
            remediation_cli="aws cloudtrail update-trail --name management-trail --is-multi-region-trail"
        ))
    else:
        findings.append(Finding(
            check_id="CT-001",
            title="CloudTrail Enabled in All Regions",
            description="CloudTrail is properly configured for multi-region logging",
            severity=Severity.CRITICAL,
            status=CheckStatus.PASS,
            service=ServiceCategory.CLOUDTRAIL,
            cis_benchmark="CIS 3.1",
            resource="arn:aws:cloudtrail:us-east-1:123456789012:trail/management-trail",
            remediation="No action needed"
        ))

    # Check 3.2 - Log file validation
    if not data.get("log_file_validation"):
        findings.append(Finding(
            check_id="CT-002",
            title="CloudTrail Log File Validation Disabled",
            description="Log file validation ensures logs haven't been tampered with",
            severity=Severity.HIGH,
            status=CheckStatus.FAIL,
            service=ServiceCategory.CLOUDTRAIL,
            cis_benchmark="CIS 3.2",
            resource="arn:aws:cloudtrail:us-east-1:123456789012:trail/management-trail",
            remediation="Enable log file validation on CloudTrail",
            remediation_cli="aws cloudtrail update-trail --name management-trail --enable-log-file-validation"
        ))
    else:
        findings.append(Finding(
            check_id="CT-002",
            title="CloudTrail Log File Validation Enabled",
            description="Log file integrity validation is properly configured",
            severity=Severity.HIGH,
            status=CheckStatus.PASS,
            service=ServiceCategory.CLOUDTRAIL,
            cis_benchmark="CIS 3.2",
            resource="arn:aws:cloudtrail:us-east-1:123456789012:trail/management-trail",
            remediation="No action needed"
        ))

    # Check 3.3 - CloudWatch integration
    if not data.get("cloudwatch_logs_enabled"):
        findings.append(Finding(
            check_id="CT-003",
            title="CloudTrail Not Integrated with CloudWatch Logs",
            description="CloudTrail should send logs to CloudWatch for real-time alerting",
            severity=Severity.HIGH,
            status=CheckStatus.FAIL,
            service=ServiceCategory.CLOUDTRAIL,
            cis_benchmark="CIS 3.4",
            resource="arn:aws:cloudtrail:us-east-1:123456789012:trail/management-trail",
            remediation="Configure CloudTrail to send logs to a CloudWatch Log Group",
            remediation_cli="aws cloudtrail update-trail --name management-trail --cloud-watch-logs-log-group-arn arn:aws:logs:us-east-1:123456789012:log-group:cloudtrail-logs --cloud-watch-logs-role-arn arn:aws:iam::123456789012:role/CloudTrail_CloudWatchLogs"
        ))

    # Check 3.4 - KMS encryption
    if not data.get("kms_encryption"):
        findings.append(Finding(
            check_id="CT-004",
            title="CloudTrail Logs Not KMS Encrypted",
            description="CloudTrail logs should be encrypted with a customer-managed KMS key",
            severity=Severity.MEDIUM,
            status=CheckStatus.FAIL,
            service=ServiceCategory.CLOUDTRAIL,
            cis_benchmark="CIS 3.5",
            resource="arn:aws:cloudtrail:us-east-1:123456789012:trail/management-trail",
            remediation="Enable KMS encryption for CloudTrail logs",
            remediation_cli="aws cloudtrail update-trail --name management-trail --kms-key-id arn:aws:kms:us-east-1:123456789012:key/<key-id>"
        ))

    # Check 3.5 - S3 bucket access logging for CloudTrail bucket
    if not data.get("s3_access_logging"):
        findings.append(Finding(
            check_id="CT-005",
            title="CloudTrail S3 Bucket Access Logging Disabled",
            description="The S3 bucket storing CloudTrail logs should have access logging enabled",
            severity=Severity.MEDIUM,
            status=CheckStatus.FAIL,
            service=ServiceCategory.CLOUDTRAIL,
            cis_benchmark="CIS 3.6",
            resource="arn:aws:s3:::cloudtrail-logs-bucket",
            remediation="Enable access logging on the CloudTrail S3 bucket",
            remediation_cli="aws s3api put-bucket-logging --bucket cloudtrail-logs-bucket --bucket-logging-status '{\"LoggingEnabled\":{\"TargetBucket\":\"access-logs-bucket\",\"TargetPrefix\":\"cloudtrail-access/\"}}'"
        ))

    return findings
