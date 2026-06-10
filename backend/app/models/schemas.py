from __future__ import annotations

from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class CheckStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"


class ServiceCategory(str, Enum):
    IAM = "IAM"
    S3 = "S3"
    EC2 = "EC2"
    RDS = "RDS"
    CLOUDTRAIL = "CloudTrail"


class Finding(BaseModel):
    check_id: str
    title: str
    description: str
    severity: Severity
    status: CheckStatus
    service: ServiceCategory
    cis_benchmark: str
    resource: str
    region: str = "us-east-1"
    remediation: str
    remediation_cli: Optional[str] = None
    timestamp: datetime = None

    def __init__(self, **data):
        if data.get("timestamp") is None:
            data["timestamp"] = datetime.utcnow()
        super().__init__(**data)


class ScanResult(BaseModel):
    scan_id: str
    timestamp: datetime
    total_checks: int
    passed: int
    failed: int
    warnings: int
    compliance_score: float
    findings: list[Finding]
    summary_by_service: dict
    summary_by_severity: dict


class ScanRequest(BaseModel):
    categories: Optional[list[str]] = None  # None = scan all


class ComplianceSummary(BaseModel):
    overall_score: float
    total_checks: int
    passed: int
    failed: int
    by_service: dict
    by_severity: dict
    critical_findings: list[Finding]
