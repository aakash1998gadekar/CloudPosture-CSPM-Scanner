"""EC2/VPC Security Checks - CIS AWS Benchmark v2.0 Section 5"""
from __future__ import annotations

from backend.app.models.schemas import Finding, Severity, CheckStatus, ServiceCategory
from backend.app.services.demo_data import get_ec2_data


async def run_ec2_checks() -> list[Finding]:
    data = get_ec2_data()
    findings = []

    # Check 5.1 - Security groups with open ingress
    for sg in data["security_groups"]:
        for rule in sg.get("open_rules", []):
            findings.append(Finding(
                check_id="EC2-001",
                title=f"Security Group '{sg['name']}' Allows {rule['port']} from 0.0.0.0/0",
                description=f"Security group allows unrestricted ingress on port {rule['port']} from any source",
                severity=Severity.CRITICAL if rule["port"] in [22, 3389, 3306, 5432] else Severity.HIGH,
                status=CheckStatus.FAIL,
                service=ServiceCategory.EC2,
                cis_benchmark="CIS 5.2",
                resource=f"arn:aws:ec2:us-east-1:123456789012:security-group/{sg['id']}",
                region="us-east-1",
                remediation=f"Restrict port {rule['port']} access in security group '{sg['name']}' to specific CIDR ranges",
                remediation_cli=f"aws ec2 revoke-security-group-ingress --group-id {sg['id']} --protocol tcp --port {rule['port']} --cidr 0.0.0.0/0"
            ))

    # Check 5.2 - Default VPC in use
    if data.get("default_vpc_in_use"):
        findings.append(Finding(
            check_id="EC2-002",
            title="Default VPC Has Active Resources",
            description="Default VPC should not be used for production workloads — create custom VPCs",
            severity=Severity.MEDIUM,
            status=CheckStatus.FAIL,
            service=ServiceCategory.EC2,
            cis_benchmark="CIS 5.4",
            resource="arn:aws:ec2:us-east-1:123456789012:vpc/vpc-default",
            remediation="Migrate resources from default VPC to a custom VPC with proper network segmentation",
            remediation_cli="# Create custom VPC and migrate resources"
        ))

    # Check 5.3 - EBS encryption
    for vol in data.get("unencrypted_volumes", []):
        findings.append(Finding(
            check_id="EC2-003",
            title=f"EBS Volume '{vol['id']}' Not Encrypted",
            description="EBS volumes should be encrypted at rest",
            severity=Severity.HIGH,
            status=CheckStatus.FAIL,
            service=ServiceCategory.EC2,
            cis_benchmark="CIS 2.2.1",
            resource=f"arn:aws:ec2:us-east-1:123456789012:volume/{vol['id']}",
            remediation=f"Create encrypted copy of volume '{vol['id']}' and replace the original",
            remediation_cli=f"aws ec2 create-snapshot --volume-id {vol['id']} --description 'Pre-encryption snapshot'"
        ))

    # Check 5.4 - IMDSv2 enforcement
    for instance in data.get("imdsv1_instances", []):
        findings.append(Finding(
            check_id="EC2-004",
            title=f"Instance '{instance['id']}' Uses IMDSv1",
            description="EC2 instances should enforce IMDSv2 to prevent SSRF-based credential theft",
            severity=Severity.HIGH,
            status=CheckStatus.FAIL,
            service=ServiceCategory.EC2,
            cis_benchmark="CIS 5.6",
            resource=f"arn:aws:ec2:us-east-1:123456789012:instance/{instance['id']}",
            remediation=f"Enforce IMDSv2 on instance '{instance['id']}'",
            remediation_cli=f"aws ec2 modify-instance-metadata-options --instance-id {instance['id']} --http-tokens required --http-endpoint enabled"
        ))

    # Check 5.5 - VPC Flow Logs
    if not data.get("flow_logs_enabled"):
        findings.append(Finding(
            check_id="EC2-005",
            title="VPC Flow Logs Not Enabled",
            description="VPC Flow Logs should be enabled for network monitoring and forensics",
            severity=Severity.MEDIUM,
            status=CheckStatus.FAIL,
            service=ServiceCategory.EC2,
            cis_benchmark="CIS 3.7",
            resource="arn:aws:ec2:us-east-1:123456789012:vpc/vpc-0abc123",
            remediation="Enable VPC Flow Logs for all VPCs",
            remediation_cli="aws ec2 create-flow-logs --resource-type VPC --resource-ids vpc-0abc123 --traffic-type ALL --log-destination-type cloud-watch-logs --log-group-name vpc-flow-logs"
        ))

    # Check 5.6 - Public IPs on instances
    for instance in data.get("public_instances", []):
        findings.append(Finding(
            check_id="EC2-006",
            title=f"Instance '{instance['id']}' Has Public IP",
            description="EC2 instances should not have public IPs unless in a public subnet with proper controls",
            severity=Severity.MEDIUM,
            status=CheckStatus.WARNING,
            service=ServiceCategory.EC2,
            cis_benchmark="CIS 5.1",
            resource=f"arn:aws:ec2:us-east-1:123456789012:instance/{instance['id']}",
            remediation=f"Review if instance '{instance['id']}' requires a public IP. Use ALB/NLB or NAT Gateway instead.",
            remediation_cli=f"aws ec2 modify-instance-attribute --instance-id {instance['id']} --no-source-dest-check"
        ))

    return findings
