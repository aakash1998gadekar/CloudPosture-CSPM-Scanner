"""Scanner Engine - Orchestrates all security checks"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime
from typing import Optional

from backend.app.models.schemas import ScanResult, Severity
from backend.app.services.checks.iam_checks import run_iam_checks
from backend.app.services.checks.s3_checks import run_s3_checks
from backend.app.services.checks.ec2_checks import run_ec2_checks
from backend.app.services.checks.rds_checks import run_rds_checks
from backend.app.services.checks.cloudtrail_checks import run_cloudtrail_checks


async def run_scan(categories: Optional[list[str]] = None) -> ScanResult:
    """Run all security checks in parallel and compile results."""

    check_runners = {
        "IAM": run_iam_checks,
        "S3": run_s3_checks,
        "EC2": run_ec2_checks,
        "RDS": run_rds_checks,
        "CloudTrail": run_cloudtrail_checks,
    }

    # Filter to requested categories
    if categories:
        check_runners = {k: v for k, v in check_runners.items() if k in categories}

    # Run all checks in parallel
    results = await asyncio.gather(*[runner() for runner in check_runners.values()])
    all_findings = []
    for result_list in results:
        all_findings.extend(result_list)

    # Calculate statistics
    passed = sum(1 for f in all_findings if f.status == "PASS")
    failed = sum(1 for f in all_findings if f.status == "FAIL")
    warnings = sum(1 for f in all_findings if f.status == "WARNING")
    total = len(all_findings)
    compliance_score = round((passed / total) * 100, 1) if total > 0 else 0

    # Summary by service
    summary_by_service = {}
    for f in all_findings:
        svc = f.service
        if svc not in summary_by_service:
            summary_by_service[svc] = {"passed": 0, "failed": 0, "warnings": 0, "total": 0}
        summary_by_service[svc]["total"] += 1
        if f.status == "PASS":
            summary_by_service[svc]["passed"] += 1
        elif f.status == "FAIL":
            summary_by_service[svc]["failed"] += 1
        else:
            summary_by_service[svc]["warnings"] += 1

    # Summary by severity
    summary_by_severity = {}
    for f in all_findings:
        sev = f.severity
        if sev not in summary_by_severity:
            summary_by_severity[sev] = {"passed": 0, "failed": 0, "total": 0}
        summary_by_severity[sev]["total"] += 1
        if f.status == "PASS":
            summary_by_severity[sev]["passed"] += 1
        else:
            summary_by_severity[sev]["failed"] += 1

    return ScanResult(
        scan_id=str(uuid.uuid4()),
        timestamp=datetime.utcnow(),
        total_checks=total,
        passed=passed,
        failed=failed,
        warnings=warnings,
        compliance_score=compliance_score,
        findings=all_findings,
        summary_by_service=summary_by_service,
        summary_by_severity=summary_by_severity,
    )
