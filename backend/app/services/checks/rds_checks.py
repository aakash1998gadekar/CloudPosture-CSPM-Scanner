"""RDS Security Checks - CIS AWS Benchmark v2.0"""
from __future__ import annotations

from backend.app.models.schemas import Finding, Severity, CheckStatus, ServiceCategory
from backend.app.services.demo_data import get_rds_data


async def run_rds_checks() -> list[Finding]:
    data = get_rds_data()
    findings = []

    for db in data["instances"]:
        name = db["identifier"]
        arn = f"arn:aws:rds:us-east-1:123456789012:db:{name}"

        # Check - Public accessibility
        if db.get("publicly_accessible"):
            findings.append(Finding(
                check_id="RDS-001",
                title=f"RDS Instance '{name}' Is Publicly Accessible",
                description="RDS instances should not be publicly accessible",
                severity=Severity.CRITICAL,
                status=CheckStatus.FAIL,
                service=ServiceCategory.RDS,
                cis_benchmark="CIS 2.3.2",
                resource=arn,
                remediation=f"Disable public accessibility for RDS instance '{name}'",
                remediation_cli=f"aws rds modify-db-instance --db-instance-identifier {name} --no-publicly-accessible"
            ))
        else:
            findings.append(Finding(
                check_id="RDS-001",
                title=f"RDS Instance '{name}' Not Publicly Accessible",
                description="RDS instance is properly configured as private",
                severity=Severity.CRITICAL,
                status=CheckStatus.PASS,
                service=ServiceCategory.RDS,
                cis_benchmark="CIS 2.3.2",
                resource=arn,
                remediation="No action needed"
            ))

        # Check - Encryption at rest
        if not db.get("encrypted"):
            findings.append(Finding(
                check_id="RDS-002",
                title=f"RDS Instance '{name}' Not Encrypted",
                description="RDS instances should have encryption at rest enabled",
                severity=Severity.HIGH,
                status=CheckStatus.FAIL,
                service=ServiceCategory.RDS,
                cis_benchmark="CIS 2.3.1",
                resource=arn,
                remediation=f"Enable encryption for RDS instance '{name}' (requires creating encrypted snapshot and restoring)",
                remediation_cli=f"# Create snapshot, copy with encryption, restore from encrypted snapshot"
            ))
        else:
            findings.append(Finding(
                check_id="RDS-002",
                title=f"RDS Instance '{name}' Encryption Enabled",
                description="RDS instance has encryption at rest configured",
                severity=Severity.HIGH,
                status=CheckStatus.PASS,
                service=ServiceCategory.RDS,
                cis_benchmark="CIS 2.3.1",
                resource=arn,
                remediation="No action needed"
            ))

        # Check - Multi-AZ
        if not db.get("multi_az"):
            findings.append(Finding(
                check_id="RDS-003",
                title=f"RDS Instance '{name}' Not Multi-AZ",
                description="Production RDS instances should use Multi-AZ for high availability",
                severity=Severity.MEDIUM,
                status=CheckStatus.WARNING,
                service=ServiceCategory.RDS,
                cis_benchmark="CIS 2.3.3",
                resource=arn,
                remediation=f"Enable Multi-AZ for RDS instance '{name}'",
                remediation_cli=f"aws rds modify-db-instance --db-instance-identifier {name} --multi-az"
            ))

        # Check - Backup retention
        if db.get("backup_retention", 0) < 7:
            findings.append(Finding(
                check_id="RDS-004",
                title=f"RDS Instance '{name}' Insufficient Backup Retention ({db.get('backup_retention', 0)} days)",
                description="RDS backup retention should be at least 7 days",
                severity=Severity.MEDIUM,
                status=CheckStatus.FAIL,
                service=ServiceCategory.RDS,
                cis_benchmark="CIS 2.3.4",
                resource=arn,
                remediation=f"Increase backup retention for '{name}' to at least 7 days",
                remediation_cli=f"aws rds modify-db-instance --db-instance-identifier {name} --backup-retention-period 7"
            ))

        # Check - Deletion protection
        if not db.get("deletion_protection"):
            findings.append(Finding(
                check_id="RDS-005",
                title=f"RDS Instance '{name}' Deletion Protection Disabled",
                description="Deletion protection should be enabled to prevent accidental deletion",
                severity=Severity.MEDIUM,
                status=CheckStatus.FAIL,
                service=ServiceCategory.RDS,
                cis_benchmark="CIS 2.3.5",
                resource=arn,
                remediation=f"Enable deletion protection for RDS instance '{name}'",
                remediation_cli=f"aws rds modify-db-instance --db-instance-identifier {name} --deletion-protection"
            ))

    return findings
